#pragma once

#include "PCH.h"

#include <chrono>

namespace cog {

// Records the SKSEPluginLoad start timestamp and exposes a handler that logs
// elapsed time at each SKSE message phase (kPostLoad, kPostPostLoad,
// kInputLoaded, kDataLoaded) plus the duration of save loads
// (kPreLoadGame → kPostLoadGame) and any non-save loading screen — fast
// travel, coc, door transitions — by listening to LoadingMenu open/close.
class PhaseTimer
{
public:
    using clock = std::chrono::steady_clock;

    static void MarkPluginLoadStart();
    static void OnMessage(SKSE::MessagingInterface::Message* a_msg);

    // Marks save-load in flight so the LoadingMenu sink can suppress its
    // duplicate log when the loading screen belongs to a save load.
    [[nodiscard]] static bool IsSaveLoadInFlight() { return s_saveLoadInFlight; }

    // Toggles the verbose per-cell logging (top-10 hottest cells +
    // [ ExteriorCellLoader::LoadCellData ] per-entry list). Off by default;
    // set from INI [Logging] FindCellInFileLogging at startup.
    static void SetVerboseCellLogging(bool a_on) { s_verboseCellLogging = a_on; }
    [[nodiscard]] static bool IsVerboseCellLogging() { return s_verboseCellLogging; }

private:
    static void RegisterLoadingMenuSink();

    static inline clock::time_point s_pluginLoadStart{};
    static inline clock::time_point s_saveLoadStart{};
    static inline bool              s_saveLoadInFlight{ false };
    static inline bool              s_verboseCellLogging{ false };
};

}  // namespace cog
