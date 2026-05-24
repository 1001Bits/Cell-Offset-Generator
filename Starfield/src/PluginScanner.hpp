#pragma once

#include "PCH.h"

#include <cstdint>
#include <filesystem>
#include <unordered_map>
#include <vector>

namespace cog::sf {

// Per-cell entry discovered by walking the plugin's record graph.
struct ScannedCell
{
    std::uint32_t worldFormID;  // formID of the owning TESWorldSpace
    std::int32_t  x;
    std::int32_t  y;
    std::uint32_t fileOffset;   // absolute byte offset of the CELL record header
    std::uint32_t recordTotal;  // CELL record size including 24-byte header
                                // (used for the CLSZ chunk = engine's
                                // pData->unk08 buffer; verified against CK's
                                // OFST writer FUN_141defd10 which stores
                                // `cellRecord.size + 0x18` per slot)
};

// Per-worldspace data collected during the scan.
//
// Two coordinate systems are tracked:
//   • XCLC-observed bounds (xclcMinX..xclcMaxY)  — actual cell coords seen
//     while walking the WRLD's children. Used for diagnostics; do NOT use
//     to size the engine's pCellFileOffsets table.
//   • NAM0/NAM9 bounds (nam0CellX..nam9CellY)    — read from the WRLD record's
//     NAM0/NAM9 subrecords (NAM0 = min corner in world units, NAM9 = max).
//     Engine's GetIndexForCellCoord uses these in idx = (y-min)*width+(x-min);
//     our table MUST be sized to match or every fast-path read goes OOB after
//     the engine lazily walks NAM0/NAM9 and overwrites pData->offsetMinCoords.
struct ScannedWorld
{
    std::uint32_t wrldFileOffset = 0;
    std::int32_t  xclcMinX = INT32_MAX;
    std::int32_t  xclcMinY = INT32_MAX;
    std::int32_t  xclcMaxX = INT32_MIN;
    std::int32_t  xclcMaxY = INT32_MIN;
    bool          hasNam = false;
    std::int32_t  nam0CellX = 0;   // floor(NAM0.x / 100), inclusive
    std::int32_t  nam0CellY = 0;
    std::int32_t  nam9CellX = 0;   // floor(NAM9.x / 100), inclusive
    std::int32_t  nam9CellY = 0;
};

struct ScanResult
{
    std::vector<ScannedCell>                                       cells;
    std::unordered_map<std::uint32_t /*WRLD formID*/, ScannedWorld> worlds;
};

// Open the plugin and walk records to find every exterior CELL. Returns
// false on I/O error or malformed file.
bool ScanPluginFile(const std::filesystem::path& a_path, ScanResult& a_out);

// On-disk cache: write the scan result alongside a hash of the plugin file
// so subsequent launches can skip the 10+ second walk. Cache version is
// bumped if the binary layout changes. Returns false on I/O error.
bool SaveScanCache(const std::filesystem::path& a_cachePath,
                   std::uint64_t a_pluginHash,
                   const ScanResult& a_scan);

// Try to load a previous scan from disk. Validates the cache hash against
// `a_pluginHash`; if they don't match (plugin was updated / replaced), the
// cache is treated as stale and the function returns false.
bool LoadScanCache(const std::filesystem::path& a_cachePath,
                   std::uint64_t a_pluginHash,
                   ScanResult& a_scan);

// 64-bit xxhash of the plugin file. Used as the cache validity key.
std::uint64_t HashPluginFile(const std::filesystem::path& a_path);

}  // namespace cog::sf
