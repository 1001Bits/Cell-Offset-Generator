#include "PCH.h"
#include "PhaseTimer.h"

#include "CellFindInFileFastTimer.h"
#include "CellLoadTimer.h"
#include "FindCellInFileTimer.h"

namespace cog {

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

    // Fast/slow split — slow bucket counts calls that almost certainly took
    // the linear-scan slow path inside TESWorldSpace::sub instead of the
    // OFFSET_DATA table fast-path. If slowCalls is non-trivial in normal
    // play, the optimization isn't reaching everywhere it should and a
    // population-coverage gap is the next thing to investigate.
    if (s.slowCalls > 0) {
        const auto slowTotalUs = s.slowTotalNs / 1000ull;
        const auto slowAvgUs   = (s.slowTotalNs / s.slowCalls) / 1000ull;
        logger::info("FindCellInFile [{}]: fast={}, slow={} (slow total={}us, "
                     "avg={}us; threshold {}us)",
                     a_label, s.fastCalls, s.slowCalls, slowTotalUs,
                     slowAvgUs, kSlowThresholdNs / 1000ull);
    }

    // Per-cell breakdown — top 10 hottest cells by total time + per-call
    // CellLoad wall-time entries. Wall's diff methodology needs both; both
    // are verbose (potentially hundreds of lines per transition), so they're
    // gated behind [Logging] FindCellInFileLogging in the INI.
    auto perCell = SnapshotAndResetPerCell();
    auto cl      = SnapshotAndResetCellLoad();
    const bool verbose = PhaseTimer::IsVerboseCellLogging();

    // Always log CellLoad summary line (cheap, useful for sanity checking).
    if (!cl.entries.empty()) {
        logger::info("CellLoad [{}]: {} entries, {:.3f} ms total",
                     a_label, cl.entries.size(),
                     static_cast<double>(cl.totalNs) / 1'000'000.0);
    }

    if (verbose) {
        if (!perCell.empty()) {
            const auto top = std::min<std::size_t>(10, perCell.size());
            logger::info("FindCellInFile [{}] top {} cells by total time "
                         "(out of {} unique):",
                         a_label, top, perCell.size());
            for (std::size_t i = 0; i < top; ++i) {
                const auto& e = perCell[i];
                const char* worldName = "?";
                if (e.world) {
                    if (const auto* edid = e.world->GetFormEditorID(); edid && *edid) {
                        worldName = edid;
                    }
                }
                const auto totalUs = e.totalNs / 1000ull;
                const auto maxUs   = e.maxNs / 1000ull;
                const auto avgNs   = e.calls > 0 ? e.totalNs / e.calls : 0ull;
                logger::info("  {} ({}, {}): calls={}, total={}us, avg={}ns, max={}us",
                             worldName, e.x, e.y, e.calls, totalUs, avgNs, maxUs);
            }
        }
        for (const auto& e : cl.entries) {
            const auto ms = static_cast<double>(e.durationNs) / 1'000'000.0;
            if (e.isExterior) {
                logger::info("[ ExteriorCellLoader::LoadCellData ] {:.6f} ms - {}, {}",
                             ms, e.x, e.y);
            } else {
                logger::info("[ InteriorCellLoader::LoadCellData ] {:.6f} ms - cell 0x{:08X}",
                             ms, e.reqFormID);
            }
        }
    }

    // Cell-level FindInFileFast (vtable[0xC]). Interior side is the path
    // Wall asked us to instrument separately — slow-path fallbacks (return
    // false) here lead to TESFile::SeekToRecordOf linear scan in the caller.
    const auto cf = SnapshotAndResetCellFind();
    if (cf.interiorCalls > 0) {
        const auto totalUs = cf.interiorTotalNs / 1000ull;
        const auto maxUs   = cf.interiorMaxNs / 1000ull;
        const auto avgNs   = cf.interiorTotalNs / cf.interiorCalls;
        logger::info("CellFindInFileFast [{}] interior: calls={}, found={}, "
                     "total={}us, avg={}ns, max={}us",
                     a_label, cf.interiorCalls, cf.interiorReturnedTrue,
                     totalUs, avgNs, maxUs);
    }
    if (cf.exteriorCalls > 0) {
        const auto totalUs = cf.exteriorTotalNs / 1000ull;
        const auto maxUs   = cf.exteriorMaxNs / 1000ull;
        const auto avgNs   = cf.exteriorTotalNs / cf.exteriorCalls;
        logger::info("CellFindInFileFast [{}] exterior: calls={}, found={}, "
                     "total={}us, avg={}ns, max={}us",
                     a_label, cf.exteriorCalls, cf.exteriorReturnedTrue,
                     totalUs, avgNs, maxUs);
    }
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
        (void)SnapshotAndResetPerCell();
        (void)SnapshotAndResetCellFind();
        (void)SnapshotAndResetCellLoad();
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

}  // namespace cog
