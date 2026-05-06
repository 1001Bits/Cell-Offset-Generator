#pragma once

namespace cog {

struct Settings;

// Install the IsESM-gate NOPs in TESWorldSpace::Load / LoadPartial /
// FindInFileFast / FindCellInFile. After this runs, the engine's offset-table
// code path applies to ESPs as well as ESMs.
//
// Supported runtimes (verified): AE 1.6.1170, SE 1.5.97, VR 1.4.15,
// GOG 1.6.1179. Other runtimes silently skip patching with a log entry.
class Patches
{
public:
    [[nodiscard]] static bool InitHooks(const Settings& a_settings);
};

}  // namespace cog
