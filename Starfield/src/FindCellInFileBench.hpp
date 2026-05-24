#pragma once

#include "PCH.h"

// A/B benchmark detours for the engine's OFFSET_DATA consumers.
//
// We hook two TESWorldSpace member functions:
//
//   • FindCellInFile(TESWorldSpace*, TESFile*, int x, int y) → bool
//     Fast/slow per-cell lookup. Direct callers: Load_Impl (load-time) +
//     two worker functions. Fires mostly during plugin parse.
//
//   • FindInFileFast(TESWorldSpace*, TESFile*) → bool
//     Per-WRLD record locator: reads OFFSET_DATA.fileOffset and seeks the
//     file directly to the worldspace's WRLD record. Purely
//     vtable-dispatched (TESWorldSpace::vtable[22]). This is the
//     RUNTIME path the engine takes on every cell streaming op — the
//     reason `FindInFileFast.IsMaster` is one of our patched sites.
//
// Both functions consume the OFFSET_DATA tables that the cell-offset
// patches populate. Comparing runs:
//
//   • Baseline (COG_BASELINE=1)  — InitHooks skipped; the 7 IsMaster
//     gates remain, ESPs never reach OFFSET_DATA.
//   • Active                     — InitHooks applied; ESPs populate and
//     consume OFFSET_DATA normally.
//
// Both runs have the same detour overhead (steady_clock + atomics),
// so the delta is the engine's actual OFFSET_DATA usage cost.
//
// Mechanism: byte-verified single-instruction prologue (5 bytes) →
// REL::Trampoline::write_jmp<5> + 19-byte trampoline gadget that
// re-executes the saved prologue and JMP14s back to target+5.

namespace cog::sf::bench {

enum class HookId : std::uint8_t
{
    FindCellInFile,
    FindInFileFast,
    GetIndexForCellCoord,   // FUN_140bb8600: row-major idx from (x,y) + bounds
    SeekFile,               // FUN_1405bb360: file-cursor seek used by fast-path
    Count,
};

struct EngineCallStats
{
    std::uint64_t calls   = 0;
    std::uint64_t hits    = 0;
    std::int64_t  totalNs = 0;
    std::int64_t  minNs   = 0;    // 0 when calls==0
    std::int64_t  maxNs   = 0;
};

// Install both detours. Idempotent. Returns false only if the runtime is
// unknown — partial success (one of the two hooks installed) is logged
// at warn level and reported as true.
[[nodiscard]] bool InstallEngineHooks();

[[nodiscard]] EngineCallStats GetEngineCallStats(HookId);

// One line per installed hook (heartbeat formatter).
[[nodiscard]] std::string FormatAllStatsLines(std::string_view a_label);

// Persist this run's FindCellInFile totals to a per-mode snapshot file and,
// if the opposite-mode snapshot exists, return a line summarizing the
// time-saved comparison. Empty string if no comparison is available.
[[nodiscard]] std::string FormatSavingsLine();

// Persist this run's per-(world, x, y) FCF tally and, if the opposite-mode
// snapshot exists, return a multi-line Skyrim-style cell-by-cell speedup
// table sorted by baseline cost (top 30 rows). Empty string if no comparison
// is available.
[[nodiscard]] std::string FormatPerCellComparison();

// Absolute per-(world, x, y) timing report for the current run. Does not
// require an opposite-mode snapshot. Shows total ms, avg ms, max ms per cell
// sorted by total time, top 40 rows. Useful for baseline measurements where
// no comparison is yet available.
[[nodiscard]] std::string FormatPerCellSingleRun();

// True iff COG_BASELINE=1 (env) or [Benchmark] BaselineMode=1 (INI). Cached.
[[nodiscard]] bool IsBaselineMode();

// True iff [Benchmark] Diagnostics=1 in the INI (or COG_DIAGNOSTICS=1 env).
// Cached. Default OFF. When OFF (clean release), the engine-call detours, the
// heartbeat thread, the [Finder]/[PreScan] struct dumps, and the per-cell/
// [FastPath] timing are all skipped — the log carries only generation results.
// Baseline mode implies diagnostics (it needs the detours to measure).
[[nodiscard]] bool IsDiagnosticsMode();

// True iff COG_STRIP_OFST=1 at plugin load. Cached.
[[nodiscard]] bool IsStripOfstMode();

// True iff COG_ZERO_OFFSETS=1 at plugin load. Cached. When set, the generator
// allocates pCellFileOffsets and assigns it, but leaves every entry zero —
// the engine fast-path then returns false for every cell. Localizes whether
// the crash comes from our offset *values* or the meta-data we write.
[[nodiscard]] bool IsZeroOffsetsMode();

// True iff COG_NO_TABLE=1 at plugin load. Cached. When set, the generator
// fills pData's bounds/fileOffset but does NOT assign pCellFileOffsets — the
// fast path bails on *plVar7!=0 and the engine falls to its slow scan.
// Localizes whether the crash comes from anything we write to pData at all.
[[nodiscard]] bool IsNoTableMode();

// True iff COG_NO_GENERATE=1 at plugin load. Cached. When set, the 7
// InitHooks NOPs are still applied but RunGenerator() is skipped entirely —
// no file scan, no GetOrCreateOffsetData calls, no pData entries created.
// Isolates whether the slowness is from the NOPs alone vs. from the
// generator's side effects.
[[nodiscard]] bool IsNoGenerateMode();

// Apply the OFST-magic strip patch (4-byte write that makes the engine's
// chunk dispatcher never match 'OFST', so every WRLD's OFST subrecord is
// silently ignored at load). Gated on IsStripOfstMode() — no-op when env
// var is unset. Returns true if the patch was applied.
bool InstallOfstStripper();

}  // namespace cog::sf::bench
