#include "PCH.h"
#include "FindCellInFileTimer.h"

#include "EngineTypes.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace cog {

namespace {

using FindCellInFile_t = bool (*)(RE::TESWorldSpace*, RE::TESFile*,
                                  std::int32_t, std::int32_t);

FindCellInFile_t g_origFindCell{ nullptr };

std::atomic<std::uint64_t> g_calls{};
std::atomic<std::uint64_t> g_totalNs{};
std::atomic<std::uint64_t> g_maxNs{};
std::atomic<std::uint64_t> g_fastCalls{};
std::atomic<std::uint64_t> g_slowCalls{};
std::atomic<std::uint64_t> g_slowTotalNs{};

// Per-(world, x, y) attribution. Hot-path lookup is mutex-protected; with
// ~150 unique cells per FT × ~150 ns per locked increment that's ~25 µs of
// measurement overhead total per transition — negligible against the 290 ms
// of FindCellInFile work. Map key count is small (unique cells, not calls)
// so memory is bounded.
struct CellKey
{
    RE::TESWorldSpace* world;
    std::int32_t       x;
    std::int32_t       y;

    bool operator==(const CellKey& o) const noexcept
    { return world == o.world && x == o.x && y == o.y; }
};
struct CellKeyHash
{
    std::size_t operator()(const CellKey& k) const noexcept
    {
        auto h = reinterpret_cast<std::uintptr_t>(k.world);
        h = h * 0x9E3779B97F4A7C15ull + static_cast<std::uint32_t>(k.x);
        h = h * 0x9E3779B97F4A7C15ull + static_cast<std::uint32_t>(k.y);
        return static_cast<std::size_t>(h);
    }
};
struct CellTally
{
    std::uint64_t calls   = 0;
    std::uint64_t totalNs = 0;
    std::uint64_t maxNs   = 0;
};

std::mutex                                                      g_perCellMutex;
std::unordered_map<CellKey, CellTally, CellKeyHash>             g_perCell;

bool FindCellInFile_Hook(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                         std::int32_t a_x, std::int32_t a_y)
{
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    const bool result = g_origFindCell(a_world, a_file, a_x, a_y);
    const auto ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now() - t0)
            .count());

    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_totalNs.fetch_add(ns, std::memory_order_relaxed);
    if (ns >= kSlowThresholdNs) {
        g_slowCalls.fetch_add(1, std::memory_order_relaxed);
        g_slowTotalNs.fetch_add(ns, std::memory_order_relaxed);
    } else {
        g_fastCalls.fetch_add(1, std::memory_order_relaxed);
    }

    auto curMax = g_maxNs.load(std::memory_order_relaxed);
    while (ns > curMax &&
           !g_maxNs.compare_exchange_weak(curMax, ns,
                                          std::memory_order_relaxed)) {
    }

    {
        std::lock_guard lock(g_perCellMutex);
        auto& t = g_perCell[CellKey{ a_world, a_x, a_y }];
        ++t.calls;
        t.totalNs += ns;
        if (ns > t.maxNs) {
            t.maxNs = ns;
        }
    }
    return result;
}

[[nodiscard]] std::uintptr_t ResolveFindCellInFile()
{
    if (REL::Module::IsVR()) {
        return REL::Offset(0x2C32D0).address();
    }
    if (IsGOG()) {
        return REL::Offset(0x3062F0).address();
    }
    return REL::RelocationID(20022, 20456).address();
}

}  // namespace

bool FindCellInFileTimer::InitHooks()
{
    const auto addr = ResolveFindCellInFile();
    if (addr == 0) {
        logger::warn("FindCellInFileTimer: no address for this runtime — skipping");
        return false;
    }

    auto& trampoline = SKSE::GetTrampoline();

    // SKSE's write_branch<5> public wrapper assumes the source is already an
    // E8/E9 rel32 instruction (it computes "original target" from the existing
    // disp32). For function-entry splicing we must build the displaced-bytes
    // thunk ourselves, then use write_branch only to install the source JMP
    // (where its address-distance handling via FF 25 sub-thunk is correct).
    //
    // FindCellInFile prologue is identical across all four runtimes
    // (verified by Ghidra dumps for SE 1.5.97, AE 1.6.1170, VR 1.4.15,
    // GOG 1.6.1179):
    //   40 53 55 56 57   push rbx; push rbp; push rsi; push rdi   (5 bytes — clean boundary)
    //
    // v1.4.3: verify the bytes match before we splice. If another mod has
    // already hooked the function or the runtime is unexpected, refuse to
    // patch rather than corrupting the function entry.
    constexpr std::size_t kDisplaced = 5;
    constexpr std::size_t kThunkSize = kDisplaced + 5;
    constexpr std::uint8_t kExpectedPrologue[kDisplaced] = { 0x40, 0x53, 0x55, 0x56, 0x57 };

    const auto* targetBytes = reinterpret_cast<const std::uint8_t*>(addr);
    for (std::size_t i = 0; i < kDisplaced; ++i) {
        if (targetBytes[i] != kExpectedPrologue[i]) {
            logger::error("FindCellInFileTimer: prologue mismatch at +{:X} byte {} — "
                          "expected {:02X}, got {:02X}; refusing to splice",
                          addr - REL::Module::get().base(), i,
                          kExpectedPrologue[i], targetBytes[i]);
            return false;
        }
    }

    auto* thunk = static_cast<std::uint8_t*>(trampoline.allocate(kThunkSize));
    if (!thunk) {
        logger::error("FindCellInFileTimer: trampoline allocate failed");
        return false;
    }
    std::memcpy(thunk, reinterpret_cast<const void*>(addr), kDisplaced);

    const auto thunkJmpSrc = reinterpret_cast<std::uintptr_t>(thunk) + kDisplaced;
    const auto returnTo    = addr + kDisplaced;
    const auto disp        = static_cast<std::int64_t>(returnTo) -
                             static_cast<std::int64_t>(thunkJmpSrc + 5);
    if (disp > std::numeric_limits<std::int32_t>::max() ||
        disp < std::numeric_limits<std::int32_t>::min()) {
        logger::error("FindCellInFileTimer: thunk→source displacement out of int32 range");
        return false;
    }
    const auto disp32 = static_cast<std::int32_t>(disp);
    thunk[kDisplaced] = 0xE9;
    std::memcpy(thunk + kDisplaced + 1, &disp32, sizeof(disp32));

    g_origFindCell = reinterpret_cast<FindCellInFile_t>(thunk);

    // Install JMP at source → hook. Discard write_branch's return (bogus for a
    // non-CALL/non-JMP source); we only use it for the source-side patching.
    (void)trampoline.write_branch<5>(
        addr, reinterpret_cast<std::uintptr_t>(&FindCellInFile_Hook));

    logger::info("FindCellInFileTimer: hook installed at +{:X}, thunk @ +{:X}",
                 addr - REL::Module::get().base(),
                 reinterpret_cast<std::uintptr_t>(thunk) - REL::Module::get().base());
    return true;
}

FindCellStats SnapshotAndResetFindCell()
{
    return {
        g_calls.exchange(0, std::memory_order_relaxed),
        g_totalNs.exchange(0, std::memory_order_relaxed),
        g_maxNs.exchange(0, std::memory_order_relaxed),
        g_fastCalls.exchange(0, std::memory_order_relaxed),
        g_slowCalls.exchange(0, std::memory_order_relaxed),
        g_slowTotalNs.exchange(0, std::memory_order_relaxed),
    };
}

std::vector<PerCellEntry> SnapshotAndResetPerCell()
{
    std::unordered_map<CellKey, CellTally, CellKeyHash> snapshot;
    {
        std::lock_guard lock(g_perCellMutex);
        snapshot.swap(g_perCell);
    }
    std::vector<PerCellEntry> entries;
    entries.reserve(snapshot.size());
    for (const auto& [k, v] : snapshot) {
        entries.push_back({ k.world, k.x, k.y, v.calls, v.totalNs, v.maxNs });
    }
    std::sort(entries.begin(), entries.end(),
              [](const PerCellEntry& a, const PerCellEntry& b) {
                  return a.totalNs > b.totalNs;
              });
    return entries;
}

}  // namespace cog
