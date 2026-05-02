#pragma once

#include "PCH.h"

// Per-file interior cell offset map. Mirrors WallSoGB's NVSE
// InteriorOffsets subsystem (see _reference/nvse/InteriorOffsets.hpp).
//
// Skyrim's engine stores interior cell file offsets in a single 32-bit field
// on each CELL record's loaded data. xEdit / CK strip that field on save,
// leaving it 0 (or a formID, depending on the tool). For ESM masters the
// engine repopulates it during initial load; for ESPs the field stays empty
// and FindInFileFast returns nothing, falling back to a slow scan.
//
// This module provides a parallel storage path: as cells are loaded we
// capture (file, formID, offset) tuples; later when the engine asks for an
// interior offset, our hooks redirect through this map.

namespace cog::sky::interior {

// Per-file insert. Thread-safe (vector of inserts during initial load is
// serialized by the engine, but defensively guarded for safety).
void AddOffsetForFile(RE::TESFile* a_file, std::uint32_t a_formID,
                      std::uint32_t a_offset);

// Per-file lookup. Returns 0 if missing — 0 is not a valid CELL offset
// since plugin files always start with a TES4 header, so this doubles as
// "no entry". Thread-safe.
[[nodiscard]] std::uint32_t GetOffsetForFile(const RE::TESFile* a_file,
                                             std::uint32_t a_formID);

// Diagnostics.
[[nodiscard]] std::size_t CountOffsetsForFile(const RE::TESFile* a_file);
[[nodiscard]] std::size_t CountFiles();

// Walk every (file, formID, offset) tuple. Visit returns false to stop.
using TupleVisitor =
    std::function<bool(RE::TESFile*, std::uint32_t /*formID*/, std::uint32_t /*offset*/)>;
void ForEach(const TupleVisitor& a_visitor);

// NVSE-style thread-local "currently parsing this file" pointer. Set by the
// TESFile::GetOffset detour at the start of CELL load; read by the
// SetInteriorOffset detour to know which file owns the cell being loaded.
void                       SetCurrentFile(RE::TESFile* a_file);
[[nodiscard]] RE::TESFile* GetCurrentFile();

// Test-only: drop all state.
void Reset();

}  // namespace cog::sky::interior
