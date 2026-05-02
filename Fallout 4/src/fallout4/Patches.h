#pragma once

namespace cog {
struct Settings;
}

namespace cog::fo4 {

// Install the IsESM-gate NOPs in TESWorldSpace::Load / LoadPartial /
// FindInFileFast / FindCellInFile. After this runs, the engine's offset-table
// code path applies to ESPs as well as ESMs.
//
// Per-runtime address tables for OG / AE / VR. Sites without filled-in
// addresses are silently skipped with a log message — that runtime simply
// won't enjoy the optimization until a Ghidra pass fills the table.
//
// Returns true if all enabled patches applied successfully.
[[nodiscard]] bool InstallEsmGateNops(const cog::Settings& a_settings);

}  // namespace cog::fo4
