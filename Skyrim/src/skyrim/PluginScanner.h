#pragma once

#include "PCH.h"

#include <vector>

namespace cog::sky {

// One discovered exterior CELL during plugin scanning.
struct ExtCellRecord
{
    std::int32_t  cellX;       // from XCLC
    std::int32_t  cellY;       // from XCLC
    std::uint32_t fileOffset;  // file offset where the CELL record header begins
};

// One discovered worldspace within a plugin (along with its cells).
struct WorldscanResult
{
    RE::TESWorldSpace*         worldSpace{ nullptr };
    std::uint32_t              worldFileOffset{ 0 };  // offset of the WRLD record header
    std::vector<ExtCellRecord> cells;
};

// Scan a single plugin file and recover (worldspace, cell-coords, offset)
// triples for every exterior CELL record it contains. Returns one entry per
// worldspace that this plugin contributes to, even if the cell list is empty.
//
// Implemented by walking the TES4 group structure with public TESFile APIs —
// no engine RE required. See docs/skyrim-engine-map.md for the format spec.
[[nodiscard]] std::vector<WorldscanResult> ScanPluginExteriorCells(RE::TESFile* a_file);

}  // namespace cog::sky
