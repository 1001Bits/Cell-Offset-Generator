#pragma once

namespace cog {
struct Settings;
}

namespace cog::sky {

// Install the IsESM-gate NOPs in TESWorldSpace::Load / LoadPartial /
// FindInFileFast / FindCellInFile. After this runs, the engine's offset-table
// code path applies to ESPs as well as ESMs.
//
// AE 1.6.1170 only for v0. SE/VR support requires Address Library REL::IDs
// or per-runtime address tables — see docs/skyrim-engine-map.md.
//
// The settings let us individually enable/disable the load gates and the
// lookup gates for A/B measurement of the optimization's impact.
//
// Returns true if all requested patches applied successfully.
[[nodiscard]] bool InstallEsmGateNops(const cog::Settings& a_settings);

}  // namespace cog::sky
