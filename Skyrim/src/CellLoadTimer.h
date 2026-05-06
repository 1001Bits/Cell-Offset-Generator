#pragma once

#include "PCH.h"

#include <cstdint>
#include <vector>

namespace cog {

// Wall-clock timer for the per-cell load function (FUN_1402008c0 in
// AE 1.6.1170). Mirrors WallSoGB's NVSE `ExteriorCellLoader::LoadCellData`
// instrumentation: hook the function, record (cell coords, duration) per
// invocation, dump on save-load / transition. This gives the user-visible
// "how long did each cell take" signal — much higher signal than per-call
// FindCellInFile timing for vanilla-vs-optimized comparisons.
//
// FUN_1402008c0 dispatches both interior (form-type 'CELL') and exterior
// (form-type 'WRLD' + (x, y)) loads. Each entry tagged with which path it
// took.
class CellLoadTimer
{
public:
    [[nodiscard]] static bool InitHooks();
};

struct CellLoadEntry
{
    std::uint32_t reqFormID;        // request struct slot 1 — world or cell formID
    std::int16_t  x;                // valid only when isExterior == true
    std::int16_t  y;
    std::uint64_t durationNs;
    bool          isExterior;       // true: world-coord path; false: direct-cell path
};

struct CellLoadStats
{
    std::vector<CellLoadEntry> entries;
    std::uint64_t              totalNs;
};

// Atomically take and clear the accumulated entries.
[[nodiscard]] CellLoadStats SnapshotAndResetCellLoad();

}  // namespace cog
