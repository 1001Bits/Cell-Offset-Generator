#pragma once

#include "PCH.h"

namespace cog {

// Vtable swap on TESObjectCELL::VTABLE[0] slot 0xC — the cell-level
// FindInFileFast (per the LE 4C0BC0 / SE+AE equivalent decompile).
//
// For exterior cells it delegates to TESWorldSpace::sub (already covered by
// FindCellInFileTimer). For interior cells it does the cached-offset seek
// via sub4C08F0 — that's the path Wall asked us to measure separately.
//
// Counters split interior/exterior so we can answer:
//   1. How often is the cell-level lookup called per transition?
//   2. How often does it return true (cell found) vs false (master gate or
//      no cached offset)?
//   3. Average per-call time, broken down interior vs exterior.
//
// Slow-path on the interior side here = `sub4C08F0` returned 0 (no cached
// offset) and the function returned false. Caller (LoadChildrenOfAllMyRecords)
// then falls back to TESFile::SeekToRecordOf (linear scan) — that's the cost
// we'd want to track next if interior false-rate is high.
class CellFindInFileFastTimer
{
public:
    [[nodiscard]] static bool InitHooks();
};

struct CellFindStats
{
    std::uint64_t interiorCalls;
    std::uint64_t interiorTotalNs;
    std::uint64_t interiorMaxNs;
    std::uint64_t interiorReturnedTrue;

    std::uint64_t exteriorCalls;
    std::uint64_t exteriorTotalNs;
    std::uint64_t exteriorMaxNs;
    std::uint64_t exteriorReturnedTrue;
};

// Atomically read-and-zero the cell-find counters.
[[nodiscard]] CellFindStats SnapshotAndResetCellFind();

}  // namespace cog
