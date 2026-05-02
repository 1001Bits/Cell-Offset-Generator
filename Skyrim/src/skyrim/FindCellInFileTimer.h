#pragma once

#include "PCH.h"

namespace cog::sky {

// Function-entry hook on TESWorldSpace::FindCellInFile that accumulates
// per-call timing. Installed regardless of patch state so baseline vs
// optimized runs measure the same code path. Snapshots are read out at
// LoadingMenu close and kPostLoadGame to give per-transition / per-save-load
// numbers in the log.
bool InstallFindCellInFileTimer();

struct FindCellStats
{
    std::uint64_t calls;
    std::uint64_t totalNs;
    std::uint64_t maxNs;
};

// Reads the current accumulator and zeroes it. Safe to call from any thread.
[[nodiscard]] FindCellStats SnapshotAndResetFindCell();

}  // namespace cog::sky
