#pragma once

#include "PCH.h"

#include <chrono>

namespace cog::sky {

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

private:
    static void RegisterLoadingMenuSink();

    static inline clock::time_point s_pluginLoadStart{};
    static inline clock::time_point s_saveLoadStart{};
    static inline bool              s_saveLoadInFlight{ false };
};

}  // namespace cog::sky
