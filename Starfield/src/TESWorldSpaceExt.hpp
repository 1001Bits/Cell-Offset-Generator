#pragma once

#include "PCH.h"

// Starfield-side extensions to RE::TESWorldSpace.
//
// CommonLibSF's `RE::TESWorldSpace` exposes the form's outer layout but leaves
// the internal cell-offset machinery as `unkXXX` blobs — same situation the
// NVSE original navigated by hand-typing OFFSET_DATA + a small set of
// non-virtual member functions reached via fixed addresses. This file mirrors
// that layer, but routes all engine calls through `REL::Relocation` so the
// addresses can move between Starfield builds without source edits as long as
// the address library covers them.
//
// Address status (Starfield 1.7.x, verified via GhidrAssistMCP):
//   ✅ FindCellInFile         — 0x141A4AAA0  (fast + slow path; walks XCLC)
//   ✅ GetIndexForCellCoord   — 0x141A4C214
//   ✅ GetOffsetData          — 0x141A4CB50
//   ✅ GetOrCreateOffsetData  — 0x141A49AB4

namespace cog::sf {

// Per-(file × worldspace) record. Layout verified against the engine's own
// allocator at TESWorldSpace::GetOrCreateOffsetData (0x141A49AB4): the
// function calls a 0x28-byte malloc and initializes each field at the
// offsets shown below.
//
//   +0x00  pCellFileOffsets   = nullptr     (OFST chunk data — per-cell file
//                                            offset delta from WRLD record
//                                            start; size = width*height ints)
//   +0x08  unk08              = nullptr     (CLSZ chunk data — per-cell
//                                            "extent" the engine reads; size
//                                            = width*height ints. Written by
//                                            RE::TESWorldSpace::Unk_12 from
//                                            the CLSZ ('CLSZ'=0x5A534C43)
//                                            subrecord. Formula verified
//                                            byte-identical:
//                                              CLSZ[idx] = cellRecord.size + 24
//                                                + (childrenGrup.size + 24
//                                                   if a CELL CHILDREN GRUP
//                                                   (groupType=6) immediately
//                                                   follows the cell)
//                                            NOT optional — engine consumers
//                                            assume the buffer is present when
//                                            pCellFileOffsets is.)
//   +0x10  minX               = +FLT_MAX    (0x7f7fffff)
//   +0x14  minY               = +FLT_MAX
//   +0x18  maxX               = -FLT_MAX    (0xff7fffff)
//   +0x1C  maxY               = -FLT_MAX
//   +0x20  fileOffset         = 0           (base of WRLD record)
//   +0x24  pad24              = 0
//
// Per-cell entries inside pCellFileOffsets[i] are deltas from `fileOffset`;
// 0 means "no cell at this index". Confirmed by RebaseOffsetTable
// (0x141A485B4), which adds `delta` to every non-zero entry.
struct OFFSET_DATA
{
    std::uint32_t* pCellFileOffsets;       // 0x00
    std::uint64_t  unk08;                  // 0x08
    RE::NiPoint2   offsetMinCoords;        // 0x10 (minX, minY)
    RE::NiPoint2   offsetMaxCoords;        // 0x18 (maxX, maxY)
    std::uint32_t  fileOffset;             // 0x20
    std::uint32_t  pad24;                  // 0x24
};
static_assert(sizeof(OFFSET_DATA) == 0x28,
              "OFFSET_DATA must match the engine layout — see the allocator "
              "at TESWorldSpace::GetOrCreateOffsetData (0x141A49AB4).");

// True if the per-runtime engine address table is filled in. When false, all
// of the wrappers below are inert (return null / false) and the generator
// skips the run.
[[nodiscard]] bool RuntimeHasEngineAddresses();

// True if the runtime exposes TESWorldSpace::FindCellInFile. The current
// generator uses direct plugin parsing for table generation, but the wrapper
// remains useful for diagnostics and older fallback paths.
[[nodiscard]] bool HasFindCellInFile();

// TESWorldSpace::FindCellInFile — slow-path linear scan of the plugin's WRLD
// group. On success the file's read cursor is left at the matched CELL
// header; the file's `fileOffset` stores the absolute position. Inert on
// Starfield until/unless an equivalent engine function is located.
[[nodiscard]] bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                  std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetIndexForCellCoord — row-major index into pCellFileOffsets.
// Returns UINT32_MAX if (x, y) lies outside the per-plugin worldspace bounds.
[[nodiscard]] std::uint32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world,
                                                 RE::TESFile* a_file,
                                                 std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetOffsetData — lookup-only. Returns nullptr if the plugin
// doesn't contribute anything to this worldspace.
[[nodiscard]] OFFSET_DATA* GetOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file);

// TESWorldSpace::GetOrCreateOffsetData — inserts an empty record if missing.
[[nodiscard]] OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world,
                                                 RE::TESFile* a_file);

// Read the worldspace editorID without depending on a CommonLibSF accessor —
// CommonLibSF only knows about the `BGSEditorID formEditorID` member; for
// logging consistency with the NVSE original we expose a const char*.
[[nodiscard]] const char* GetWorldEditorID(const RE::TESWorldSpace* a_world);

// ── FindCellInFile benchmark hooks ─────────────────────────────────────────
// Every call to FindCellInFile() above is timed with steady_clock and the
// elapsed nanoseconds are added to a thread-local accumulator. The generator
// calls Reset() before each (file × world) scan and Get() after, so each
// file's log entry includes "cells=N hits=M min/avg/max=...ns".
//
// Per-call lines are emitted at debug level (suppressed by default — set the
// SFSE InitInfo log level to Debug to see them). The summary is info-level.
struct FindCellStats
{
    std::uint64_t calls   = 0;   // total invocations on this thread
    std::uint64_t hits    = 0;   // calls that returned true
    std::int64_t  totalNs = 0;
    std::int64_t  minNs   = 0;   // 0 when calls==0; first call seeds the min
    std::int64_t  maxNs   = 0;
};

[[nodiscard]] FindCellStats GetFindCellStats();
void                        ResetFindCellStats();

}  // namespace cog::sf
