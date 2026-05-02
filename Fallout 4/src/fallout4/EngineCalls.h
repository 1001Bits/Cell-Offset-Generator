#pragma once

#include "PCH.h"
#include "fallout4/EngineTypes.h"

namespace cog::fo4 {

// Direct calls into Fallout 4's worldspace internals. Per-runtime addresses
// resolved at first call via REL::Relocation.
//
// All functions are non-virtual member functions; on x64 Windows the `this`
// pointer is just the first __fastcall arg, so we model them as free
// functions for simplicity.

[[nodiscard]] bool RuntimeHasEngineAddresses();

// TESWorldSpace::FindCellInFile
//   OG 1.10.163:  0x140491EF0
//   NG 1.10.984:  0x14051E8E0
//   AE 1.11.x:    0x140572860
//   VR 1.2.72:    0x14047B030
// On success, file's internal cursor is left at the matched CELL record
// header. The fast path (used after our patches install) reads
// pCellFileOffsets[GetIndexForCellCoord]; the slow path linear-scans the
// plugin's WRLD group.
[[nodiscard]] bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                  std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetIndexForCellCoord
//   OG: 0x140492270  |  NG: 0x14051EC60  |  AE: 0x140572BE0  |  VR: 0x14047B3B0
// Returns row-major index into pCellFileOffsets[], or -1 if (x,y) is out of
// the per-plugin worldspace bounds.
[[nodiscard]] std::int32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world,
                                                RE::TESFile* a_file,
                                                std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetOffsetData (lookup-only — returns nullptr if missing)
//   OG: 0x1404981F0  |  NG: 0x140525590  |  AE: 0x140579510  |  VR: 0x140481330
[[nodiscard]] OFFSET_DATA* GetOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file);

// TESWorldSpace::GetOrCreateOffsetData (inserts an empty record if missing)
//   OG: 0x1404982B0  |  NG: 0x140525670  |  AE: 0x1405795F0  |  VR: 0x1404813F0
// Always non-null on supported runtimes.
[[nodiscard]] OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world,
                                                 RE::TESFile* a_file);

// ── Thread-safe file primitives (NVSE-equivalent) ──────────────────────────
// The engine maintains a per-file thread→clone hashmap at TESFile+0x18.
// Each worker thread calls GetThreadSafeFile to get a clone with its own
// BSFile cursor (TESFile::OpenTES is invoked lazily). GetOffsetData,
// FindCellInFile, etc. all walk GetThreadSafeParent up to the master before
// keying into the worldspace's offset map, so passing a clone returns the
// same OFFSET_DATA as passing the original.
//
// Returns nullptr if the runtime's address isn't filled in
// (HasThreadSafeFilePrimitives == false). Callers must fall back to serial.

[[nodiscard]] bool HasThreadSafeFilePrimitives();

// TESFile::GetThreadSafeFile
//   OG: 0x1401322B0  |  NG: 0x1402A4ED0  |  AE: 0x1402F91B0  |  VR: 0x140138EB0
// On worker threads, returns/creates a per-thread clone keyed by
// GetCurrentThreadId(). On the main thread, returns a_file unchanged.
// `a_bufSize` matches NVSE — 0x4000.
[[nodiscard]] RE::TESFile* GetThreadSafeFile(RE::TESFile* a_file,
                                              std::uint32_t a_bufSize = 0x4000);

// TESFile::ClearThreadSafeFiles
//   OG: 0x140132430  |  NG: 0x1402A5050  |  AE: 0x1402F9330  |  VR: 0x140139030
// Tears down the entire thread→clone map for one file. Call once per file
// from the main thread after all worker threads have joined.
void ClearThreadSafeFiles(RE::TESFile* a_file);

}  // namespace cog::fo4
