#pragma once

#include "PCH.h"
#include "skyrim/EngineTypes.h"

namespace cog::sky {

// Direct calls into Skyrim's worldspace internals. Per-runtime offsets
// configured in EngineCalls.cpp. All functions are non-virtual member
// functions; on x64 Windows the `this` pointer is just the first __fastcall
// arg, so we model them as free functions for simplicity.
//
// Returns false on runtimes without filled-in addresses — caller should
// gate on RuntimeHasEngineAddresses() before doing meaningful work.

[[nodiscard]] bool RuntimeHasEngineAddresses();

// TESWorldSpace::FindCellInFile @ 0x1403064C0
// Two paths: fast (uses pCellFileOffsets if populated) and slow (linear scan).
// On success, file's internal offset is left pointing at the matched CELL
// record header — read `a_file->fileOffset` to capture it.
[[nodiscard]] bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                  std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetIndexForCellCoord @ 0x140306750
// Computes row-major index into pCellFileOffsets[]. Returns -1 if (x,y) is
// out of the worldspace's per-plugin bounds.
[[nodiscard]] std::int32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world,
                                                RE::TESFile* a_file,
                                                std::int32_t a_x, std::int32_t a_y);

// TESWorldSpace::GetOrCreateOffsetData @ 0x14030CA80
// Returns the OFFSET_DATA* for (world, file), inserting an empty entry if
// missing. Always non-null.
[[nodiscard]] OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world,
                                                 RE::TESFile* a_file);

}  // namespace cog::sky
