#pragma once

#include "PCH.h"

// Starfield-side extensions to RE::TESFile.
//
// CommonLibSF currently only knows about the `pad0[0x38]` + `fileName[260]`
// header — everything past that (file handle, fileOffset, threadSafeFileMap,
// flags) needs to be reached through engine functions. These helpers wrap
// those calls behind REL::Relocation so the generator can stay portable.

namespace cog::sf {

// True if the file's record-header flags mark it ESM (master). Equivalent to
// NVSE's `TESFile::IsMaster()` — Starfield ESLs and ESMs both report true.
[[nodiscard]] bool IsMaster(const RE::TESFile* a_file);

// Current absolute byte offset of the file's read cursor, set by the engine
// during `FindCellInFile`'s slow-path scan. Equivalent to FNV's
// `TESWorldSpace::uiLastOffset` thread_local and F4's `TESFile::fileoffset`
// field. Returns 0 if the field offset isn't known yet (cache will be saved
// with zero entries — useless until the offset is filled in).
//
// To find this in Ghidra: look at `TESWorldSpace::FindCellInFile`'s slow
// path. The function reads `[file + 0x???]` immediately after a CELL
// record-header match. That `???` is `kTESFileFileOffsetField` below.
[[nodiscard]] std::uint32_t GetFileOffset(const RE::TESFile* a_file);

// Plugin filename (the `Foo.esp` string CommonLibSF already exposes). Trim
// helper used for path building.
[[nodiscard]] std::string_view GetFileName(const RE::TESFile* a_file);

// Per-thread TESFile clone. The engine maintains a hashmap on each TESFile
// keyed by thread id; the first call from a thread allocates a shadow
// TESFile that owns its own read cursor + buffer. Returns null on
// engine-side failure or when the engine declined to clone (in which case
// callers fall back to the original).
//
// The Starfield equivalent of CE1's `TESFile::GetThreadSafeFileForThread` is
// the address that will go into TESFileExt.cpp once located in Ghidra.
[[nodiscard]] RE::TESFile* AcquireThreadSafeFile(RE::TESFile* a_file);

// No-op for now — the F4 port deliberately leaks the thread clone for the
// lifetime of the process to avoid a known engine race. Same expected hazard
// applies to Starfield until proven otherwise.
void ReleaseThreadSafeFile(RE::TESFile* a_file);

}  // namespace cog::sf
