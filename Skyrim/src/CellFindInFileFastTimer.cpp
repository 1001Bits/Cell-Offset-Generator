#include "PCH.h"
#include "CellFindInFileFastTimer.h"

#include "EngineTypes.h"

#include <atomic>
#include <chrono>

namespace cog {

namespace {

using FindInFileFast_t = bool (__fastcall*)(RE::TESObjectCELL*, RE::TESFile*);
FindInFileFast_t g_origCellFindInFileFast = nullptr;

std::atomic<std::uint64_t> g_intCalls{};
std::atomic<std::uint64_t> g_intTotalNs{};
std::atomic<std::uint64_t> g_intMaxNs{};
std::atomic<std::uint64_t> g_intTrue{};

std::atomic<std::uint64_t> g_extCalls{};
std::atomic<std::uint64_t> g_extTotalNs{};
std::atomic<std::uint64_t> g_extMaxNs{};
std::atomic<std::uint64_t> g_extTrue{};

bool __fastcall CellFindInFileFastHook(RE::TESObjectCELL* a_cell, RE::TESFile* a_file)
{
    if (!g_origCellFindInFileFast) {
        return false;
    }
    if (!a_cell) {
        return g_origCellFindInFileFast(a_cell, a_file);
    }

    // Snapshot interior-flag before the call. The flag doesn't change during
    // the call but reading once avoids a potential second deref.
    const bool isInterior = a_cell->IsInteriorCell();

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    const bool result = g_origCellFindInFileFast(a_cell, a_file);
    const auto ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now() - t0)
            .count());

    auto& calls   = isInterior ? g_intCalls   : g_extCalls;
    auto& total   = isInterior ? g_intTotalNs : g_extTotalNs;
    auto& maxNs   = isInterior ? g_intMaxNs   : g_extMaxNs;
    auto& trueCnt = isInterior ? g_intTrue    : g_extTrue;

    calls.fetch_add(1, std::memory_order_relaxed);
    total.fetch_add(ns, std::memory_order_relaxed);
    auto cur = maxNs.load(std::memory_order_relaxed);
    while (ns > cur &&
           !maxNs.compare_exchange_weak(cur, ns, std::memory_order_relaxed)) {
    }
    if (result) {
        trueCnt.fetch_add(1, std::memory_order_relaxed);
    }
    return result;
}

}  // namespace

bool CellFindInFileFastTimer::InitHooks()
{
    // GOG 1.6.1179 may have no Address Library versionlib — fall back to the
    // image-relative vtable offset captured via Ghidra. Other runtimes use
    // the CommonLib helper for resilience across minor patches.
    const auto vtableAddr = IsGOG()
        ? REL::Offset(0x17ABA50).address()
        : RE::TESObjectCELL::VTABLE[0].address();
    REL::Relocation<std::uintptr_t> vtbl{ vtableAddr };

    const auto orig = vtbl.write_vfunc(0x0C, &CellFindInFileFastHook);
    if (orig == 0) {
        logger::error("CellFindInFileFastTimer: vtable swap at slot 0xC returned 0");
        return false;
    }
    g_origCellFindInFileFast = reinterpret_cast<FindInFileFast_t>(orig);
    logger::info("CellFindInFileFastTimer: TESObjectCELL::FindInFileFast "
                 "vtable[0xC] swapped (orig +{:X})",
                 orig - REL::Module::get().base());
    return true;
}

CellFindStats SnapshotAndResetCellFind()
{
    return {
        g_intCalls.exchange(0,    std::memory_order_relaxed),
        g_intTotalNs.exchange(0,  std::memory_order_relaxed),
        g_intMaxNs.exchange(0,    std::memory_order_relaxed),
        g_intTrue.exchange(0,     std::memory_order_relaxed),
        g_extCalls.exchange(0,    std::memory_order_relaxed),
        g_extTotalNs.exchange(0,  std::memory_order_relaxed),
        g_extMaxNs.exchange(0,    std::memory_order_relaxed),
        g_extTrue.exchange(0,     std::memory_order_relaxed),
    };
}

}  // namespace cog
