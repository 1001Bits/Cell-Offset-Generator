#include "PCH.h"
#include "CellLoadTimer.h"

#include "EngineTypes.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <mutex>

namespace cog {

namespace {

// Per-cell loader — the function that, given a request struct
// {[0]=cellFormID, [1]=worldOrCellFormID, [2]=packed (x|y) coords, ...},
// locates and instantiates the cell from the appropriate source plugin file.
// Called once per cell that needs to be streamed in.
//
// Signature inferred from decompile: `void f(uint32_t* request, void* out)`.
//
// Prologue (5-byte clean splice point, identical across SE/AE/VR):
//   48 89 5C 24 10   MOV [RSP+0x10], RBX
//
// Byte-verified before splicing. Mismatch → refuse to install (no crash).
//
// Per-runtime addresses verified via Ghidra (callers of TESWorldSpace::sub /
// FindCellInFile that match the (uint32_t* request, void* out) signature).
// GOG body is byte-identical to AE shifted -0x1D0 (same offset as every
// other GOG patch site).
constexpr std::size_t   kDisplaced = 5;
constexpr std::uint8_t  kExpectedPrologue[kDisplaced] = { 0x48, 0x89, 0x5C, 0x24, 0x10 };

[[nodiscard]] std::uintptr_t ResolveCellLoadAddrAbs()
{
    const auto ver = REL::Module::get().version();
    constexpr REL::Version kAE { 1, 6, 1170, 0 };
    constexpr REL::Version kSE { 1, 5, 97,   0 };
    constexpr REL::Version kVR { 1, 4, 15,   0 };
    constexpr REL::Version kGOG{ 1, 6, 1179, 0 };
    if (ver == kAE)  return 0x1402008C0;
    if (ver == kSE)  return 0x1401B3C30;
    if (ver == kVR)  return 0x1401C3C40;
    if (ver == kGOG) return 0x1402006F0;
    return 0;
}

using CellLoad_t = void (__fastcall*)(std::uint32_t*, void*);
CellLoad_t g_origCellLoad = nullptr;

std::mutex                  g_entriesMutex;
std::vector<CellLoadEntry>  g_entries;
std::atomic<std::uint64_t>  g_totalNs{};

void __fastcall CellLoad_Hook(std::uint32_t* a_req, void* a_out)
{
    using clock = std::chrono::steady_clock;

    // Snapshot the request fields BEFORE the call. The vanilla function
    // mutates `a_out` and may shuffle other state; the request struct
    // itself is read-only as far as the decompile shows, but we copy the
    // values we need anyway to be safe.
    std::uint32_t reqFormID = 0;
    std::int16_t  x         = 0;
    std::int16_t  y         = 0;
    if (a_req) {
        try {
            reqFormID = a_req[1];
            const auto packed = a_req[2];
            x = static_cast<std::int16_t>(packed >> 16);
            y = static_cast<std::int16_t>(packed & 0xFFFF);
        } catch (...) {
            // a_req unreadable — fall through with zeros
        }
    }

    const auto t0 = clock::now();
    if (g_origCellLoad) {
        g_origCellLoad(a_req, a_out);
    }
    const auto ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now() - t0)
            .count());

    // Heuristic for exterior vs interior: exterior cells are coord-keyed;
    // packed coords of 0 with x==0,y==0 *might* be exterior origin or
    // *might* be an interior request that ignored the slot. Without a
    // form-type lookup the best we can do is (x|y != 0) → exterior, else
    // ambiguous. Tag conservatively.
    const bool isExterior = (x != 0 || y != 0);

    {
        std::lock_guard lock(g_entriesMutex);
        g_entries.push_back({ reqFormID, x, y, ns, isExterior });
    }
    g_totalNs.fetch_add(ns, std::memory_order_relaxed);
}

}  // namespace

bool CellLoadTimer::InitHooks()
{
    const auto& mod = REL::Module::get();

    const auto absAddr = ResolveCellLoadAddrAbs();
    if (absAddr == 0) {
        logger::info("CellLoadTimer: unsupported runtime {}, skipping",
                     mod.version().string());
        return false;
    }

    constexpr std::uintptr_t kExpectedBase = 0x140000000;
    const auto addr = mod.base() + (absAddr - kExpectedBase);

    const auto* targetBytes = reinterpret_cast<const std::uint8_t*>(addr);
    for (std::size_t i = 0; i < kDisplaced; ++i) {
        if (targetBytes[i] != kExpectedPrologue[i]) {
            logger::error("CellLoadTimer: prologue mismatch at +{:X} byte {} — "
                          "expected {:02X}, got {:02X}; refusing to splice",
                          addr - mod.base(), i,
                          kExpectedPrologue[i], targetBytes[i]);
            return false;
        }
    }

    // Build a 10-byte trampoline: 5 displaced bytes + 5-byte JMP back.
    constexpr std::size_t kThunkSize = kDisplaced + 5;
    auto& trampoline = SKSE::GetTrampoline();
    auto* thunk = static_cast<std::uint8_t*>(trampoline.allocate(kThunkSize));
    if (!thunk) {
        logger::error("CellLoadTimer: trampoline allocate failed");
        return false;
    }
    std::memcpy(thunk, reinterpret_cast<const void*>(addr), kDisplaced);

    const auto thunkJmpSrc = reinterpret_cast<std::uintptr_t>(thunk) + kDisplaced;
    const auto returnTo    = addr + kDisplaced;
    const auto disp        = static_cast<std::int64_t>(returnTo) -
                             static_cast<std::int64_t>(thunkJmpSrc + 5);
    if (disp > std::numeric_limits<std::int32_t>::max() ||
        disp < std::numeric_limits<std::int32_t>::min()) {
        logger::error("CellLoadTimer: thunk→source displacement out of int32 range");
        return false;
    }
    const auto disp32 = static_cast<std::int32_t>(disp);
    thunk[kDisplaced] = 0xE9;  // JMP rel32
    std::memcpy(thunk + kDisplaced + 1, &disp32, sizeof(disp32));

    g_origCellLoad = reinterpret_cast<CellLoad_t>(thunk);

    (void)trampoline.write_branch<5>(
        addr, reinterpret_cast<std::uintptr_t>(&CellLoad_Hook));

    logger::info("CellLoadTimer: hook installed at +{:X}, thunk @ +{:X}",
                 addr - mod.base(),
                 reinterpret_cast<std::uintptr_t>(thunk) - mod.base());
    return true;
}

CellLoadStats SnapshotAndResetCellLoad()
{
    CellLoadStats out;
    {
        std::lock_guard lock(g_entriesMutex);
        out.entries.swap(g_entries);
    }
    out.totalNs = g_totalNs.exchange(0, std::memory_order_relaxed);
    return out;
}

}  // namespace cog
