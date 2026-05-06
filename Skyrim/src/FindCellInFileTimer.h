#pragma once

#include "PCH.h"

#include <utility>
#include <vector>

namespace cog {

// Function-entry hook on TESWorldSpace::FindCellInFile that accumulates
// per-call timing. Installed regardless of patch state so baseline vs
// optimized runs measure the same code path. Snapshots are read out at
// LoadingMenu close and kPostLoadGame to give per-transition / per-save-load
// numbers in the log.
class FindCellInFileTimer
{
public:
    [[nodiscard]] static bool InitHooks();
};

struct FindCellStats
{
    std::uint64_t calls;
    std::uint64_t totalNs;
    std::uint64_t maxNs;
    // Fast/slow split: a call faster than kSlowThresholdNs almost certainly
    // hit the populated `pCellFileOffsets` table. A slower call indicates the
    // engine fell back to the linear-scan slow path inside TESWorldSpace::sub
    // (or hit a cold cache line). Threshold picked from synthetic benchmark:
    // master/fast ≈ 1.1 µs, ESP/fast (with our table) ≈ 0.35 µs, slow ≈ 85 µs.
    // 10 µs comfortably separates fast bucket from slow bucket.
    std::uint64_t fastCalls;
    std::uint64_t slowCalls;
    std::uint64_t slowTotalNs;
};

constexpr std::uint64_t kSlowThresholdNs = 10'000;  // 10 µs

// Reads the current accumulator and zeroes it. Safe to call from any thread.
[[nodiscard]] FindCellStats SnapshotAndResetFindCell();

// Per-cell attribution: aggregates calls + totalNs per (worldspace, x, y).
// Lets us answer "which specific cells are slow?" for vanilla-vs-optimized
// comparison runs. Mirrors WallSoGB's recommended measurement approach
// (hook FindCellInFile, log each cell, sum per cell, repeat with/without
// offsets and diff).
struct PerCellEntry
{
    RE::TESWorldSpace* world;
    std::int32_t       x;
    std::int32_t       y;
    std::uint64_t      calls;
    std::uint64_t      totalNs;
    std::uint64_t      maxNs;
};

// Read-and-reset the per-cell map. Returns entries sorted by totalNs desc.
[[nodiscard]] std::vector<PerCellEntry> SnapshotAndResetPerCell();

}  // namespace cog
