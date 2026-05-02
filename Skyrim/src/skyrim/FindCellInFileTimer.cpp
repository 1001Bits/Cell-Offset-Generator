#include "PCH.h"
#include "skyrim/FindCellInFileTimer.h"

#include <atomic>
#include <chrono>

namespace cog::sky {

namespace {

using FindCellInFile_t = bool (*)(RE::TESWorldSpace*, RE::TESFile*,
                                  std::int32_t, std::int32_t);

FindCellInFile_t g_origFindCell{ nullptr };

std::atomic<std::uint64_t> g_calls{};
std::atomic<std::uint64_t> g_totalNs{};
std::atomic<std::uint64_t> g_maxNs{};

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

    auto curMax = g_maxNs.load(std::memory_order_relaxed);
    while (ns > curMax &&
           !g_maxNs.compare_exchange_weak(curMax, ns,
                                          std::memory_order_relaxed)) {
    }
    return result;
}

[[nodiscard]] std::uintptr_t ResolveFindCellInFile()
{
    if (REL::Module::IsVR()) {
        return REL::Offset(0x2C32D0).address();
    }
    return REL::RelocationID(20022, 20456).address();
}

}  // namespace

bool InstallFindCellInFileTimer()
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
    // FindCellInFile prologue (verified in binary):
    //   40 53 55 56 57   push rbx; push rbp; push rsi; push rdi   (5 bytes — clean boundary)
    //
    // Thunk layout:
    //   [0..5]   copy of prologue (position-independent pushes)
    //   [5..10]  E9 + rel32 jump back to source+5
    constexpr std::size_t kDisplaced = 5;
    constexpr std::size_t kThunkSize = kDisplaced + 5;

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
    };
}

}  // namespace cog::sky
