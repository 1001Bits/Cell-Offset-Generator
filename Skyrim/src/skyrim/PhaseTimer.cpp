#include "PCH.h"
#include "skyrim/PhaseTimer.h"

#include "skyrim/FindCellInFileTimer.h"

namespace cog::sky {

namespace {

[[nodiscard]] long long MsSince(PhaseTimer::clock::time_point a_t0)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               PhaseTimer::clock::now() - a_t0)
        .count();
}

void LogFindCellSnapshot(const char* a_label)
{
    const auto s = SnapshotAndResetFindCell();
    if (s.calls == 0) {
        return;
    }
    const auto totalUs = s.totalNs / 1000ull;
    const auto maxUs   = s.maxNs / 1000ull;
    const auto avgUs   = s.calls > 0 ? (s.totalNs / s.calls) / 1000ull : 0ull;
    logger::info("FindCellInFile [{}]: calls={}, total={}us, avg={}us, max={}us",
                 a_label, s.calls, totalUs, avgUs, maxUs);
}

class LoadingMenuSink : public RE::BSTEventSink<RE::MenuOpenCloseEvent>
{
public:
    static LoadingMenuSink* GetSingleton()
    {
        static LoadingMenuSink instance;
        return &instance;
    }

    RE::BSEventNotifyControl ProcessEvent(const RE::MenuOpenCloseEvent* a_event,
                                          RE::BSTEventSource<RE::MenuOpenCloseEvent>*) override
    {
        if (!a_event || a_event->menuName != RE::LoadingMenu::MENU_NAME) {
            return RE::BSEventNotifyControl::kContinue;
        }
        if (a_event->opening) {
            m_start = PhaseTimer::clock::now();
            m_inFlight = true;
        } else if (m_inFlight) {
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                PhaseTimer::clock::now() - m_start)
                                .count();
            m_inFlight = false;
            if (PhaseTimer::IsSaveLoadInFlight()) {
                // Save-load case is already logged via kPreLoadGame/kPostLoadGame.
                logger::info("LoadingMenu: closed after {} ms (save-load — see kPostLoadGame)", ms);
            } else {
                logger::info("LoadingMenu: closed after {} ms (fast travel / coc / door)", ms);
                LogFindCellSnapshot("transition");
            }
        }
        return RE::BSEventNotifyControl::kContinue;
    }

private:
    PhaseTimer::clock::time_point m_start{};
    bool                          m_inFlight{ false };
};

}  // namespace

void PhaseTimer::MarkPluginLoadStart()
{
    s_pluginLoadStart = clock::now();
}

void PhaseTimer::OnMessage(SKSE::MessagingInterface::Message* a_msg)
{
    if (!a_msg) {
        return;
    }
    using MI = SKSE::MessagingInterface;
    switch (a_msg->type) {
    case MI::kPostLoad:
        logger::info("Phase: kPostLoad        @ +{} ms", MsSince(s_pluginLoadStart));
        break;
    case MI::kPostPostLoad:
        logger::info("Phase: kPostPostLoad    @ +{} ms", MsSince(s_pluginLoadStart));
        break;
    case MI::kInputLoaded:
        logger::info("Phase: kInputLoaded     @ +{} ms", MsSince(s_pluginLoadStart));
        RegisterLoadingMenuSink();
        break;
    case MI::kDataLoaded:
        logger::info("Phase: kDataLoaded      @ +{} ms", MsSince(s_pluginLoadStart));
        break;
    case MI::kNewGame:
        logger::info("Phase: kNewGame         @ +{} ms", MsSince(s_pluginLoadStart));
        break;
    case MI::kPreLoadGame:
        s_saveLoadStart = clock::now();
        s_saveLoadInFlight = true;
        // Drain any FindCellInFile activity from the menu/idle period so the
        // upcoming save-load snapshot only counts the load itself.
        (void)SnapshotAndResetFindCell();
        logger::info("Phase: kPreLoadGame     — save load starting");
        break;
    case MI::kPostLoadGame:
        if (s_saveLoadInFlight) {
            logger::info("Phase: kPostLoadGame    — save load took {} ms",
                         MsSince(s_saveLoadStart));
            LogFindCellSnapshot("save-load");
            s_saveLoadInFlight = false;
        } else {
            logger::info("Phase: kPostLoadGame    (no matching kPreLoadGame)");
        }
        break;
    case MI::kSaveGame:
        logger::info("Phase: kSaveGame");
        break;
    case MI::kDeleteGame:
        logger::info("Phase: kDeleteGame");
        break;
    default:
        break;
    }
}

void PhaseTimer::RegisterLoadingMenuSink()
{
    if (auto* ui = RE::UI::GetSingleton()) {
        ui->AddEventSink<RE::MenuOpenCloseEvent>(LoadingMenuSink::GetSingleton());
        logger::info("LoadingMenu: timer registered");
    } else {
        logger::warn("LoadingMenu: UI singleton not available, timer not registered");
    }
}

}  // namespace cog::sky
