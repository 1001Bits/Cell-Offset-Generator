#pragma once

#include "PCH.h"

namespace cog::fo4 {

// Per-(file × worldspace) offset record. F4 layout differs slightly from
// FNV — verified by reading the Min/Max coord stores in TESWorldSpace::Load
// (Func10) and the +0x20 read in FindCellInFile.
//
// FNV had MinCoords at +0x08 and MaxCoords at +0x10. F4 shifted both by 8,
// putting an extra qword at +0x08 (purpose unknown — possibly cached cell
// count or a back-pointer; we never read it).
//
//   0x00  uint32_t*  pCellFileOffsets;
//   0x08  uint64_t   unk08;            // pad or count — leave alone
//   0x10  NiPoint2   offsetMinCoords;  // floats at +0x10 / +0x14
//   0x18  NiPoint2   offsetMaxCoords;  // floats at +0x18 / +0x1C
//   0x20  uint32_t   fileOffset;       // WRLD record header offset
//   0x24  uint32_t   pad24;
//   total 0x28
struct OFFSET_DATA
{
    std::uint32_t* pCellFileOffsets;
    std::uint64_t  unk08;
    RE::NiPoint2   offsetMinCoords;
    RE::NiPoint2   offsetMaxCoords;
    std::uint32_t  fileOffset;
    std::uint32_t  pad24;
};
static_assert(sizeof(OFFSET_DATA) == 0x28);
static_assert(offsetof(OFFSET_DATA, offsetMinCoords) == 0x10);
static_assert(offsetof(OFFSET_DATA, offsetMaxCoords) == 0x18);
static_assert(offsetof(OFFSET_DATA, fileOffset)      == 0x20);

// The engine's NiTMap<TESFile*, OFFSET_DATA*> lives at TESWorldSpace+0x1E8 in
// all three runtimes (verified by decompiling GetOffsetData in OG; the same
// embedded map pattern is used in AE and VR). We never touch the map directly
// — we always go through TESWorldSpace::GetOffsetData /
// GetOrCreateOffsetData via REL::Relocation, which avoids depending on
// CommonLibF4 exposing a typed NiTMap accessor and matches what WallSoGB's
// NVSE original does.

}  // namespace cog::fo4
