#pragma once

namespace cog {
struct Settings;
}

namespace cog::sky {

// Runs after generation completes. For every (target file × worldspace) where
// the engine produced an OFFSET_DATA, sample N cell coordinates inside the
// declared bounds and time FindCellInFile across the sample. Aggregates ns
// totals by file type (master/ESP/ESL) and by pCellFileOffsets state
// (table-present vs null), and logs a per-bucket summary.
void RunFindCellBenchmark(const cog::Settings& a_settings);

}  // namespace cog::sky
