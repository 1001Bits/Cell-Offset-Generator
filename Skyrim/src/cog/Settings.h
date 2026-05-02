#pragma once

#include <filesystem>

namespace cog {

struct Settings
{
    // Master switch: if false, no NOPs are installed at all.
    bool enablePatches{ true };
    // OFST-load gates (Load.fileOffset, Load.offsetMinCoords, Load.offsetMaxCoords,
    // LoadPartial.gate1, LoadPartial.gate2). When off, ESP plugins won't get
    // pCellFileOffsets populated by the engine, so cell lookups have no table.
    bool enableLoadGates{ true };
    // Lookup gates (FindCellInFile, FindInFileFast). When off, both lookup
    // entry points bail at the IsESM check for ESPs and never use the table.
    bool enableLookupGates{ true };

    // Run the synthetic benchmark after data load and emit per-bucket stats.
    bool runBenchmark{ false };
    // Cells to sample per (file × world) pair during the benchmark.
    int benchmarkSamplesPerWorld{ 16 };

    // Run the one-shot validator after generation: open each plugin file and
    // verify our offset table entries land at "CELL" record headers.
    bool runValidator{ false };

    static Settings Load(const std::filesystem::path& a_iniPath);
};

}  // namespace cog
