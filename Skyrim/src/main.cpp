#include "PCH.h"

#include "CellFindInFileFastTimer.h"
#include "CellLoadTimer.h"
#include "EngineCalls.h"
#include "EngineTypes.h"
#include "FindCellInFileTimer.h"
#include "Patches.h"
#include "PhaseTimer.h"
#include "Settings.h"
#include "SkyrimGenerator.h"

#include <ShlObj.h>

namespace
{
    cog::Settings g_settings{};

    // SKSE::log::log_directory() reads the game-folder name from Skyrim.INI,
    // which on this user's setup resolves to "Skyrim.INI" itself instead of
    // "Skyrim Special Edition". Construct the SKSE log path explicitly to
    // avoid that lookup entirely. The folder name varies by runtime — VR
    // uses "Skyrim VR", GOG uses "Skyrim Special Edition GOG", everything
    // else (SE / Steam AE) uses "Skyrim Special Edition". We must call this
    // *after* SKSE::Init so REL::Module::version() is populated.
    [[nodiscard]] std::filesystem::path ResolveSkseDir()
    {
        PWSTR docs = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs))) {
            SKSE::stl::report_and_fail("SHGetKnownFolderPath(Documents) failed");
        }
        std::filesystem::path path = docs;
        CoTaskMemFree(docs);
        path /= L"My Games";
        if (REL::Module::IsVR()) {
            path /= L"Skyrim VR";
        } else if (cog::IsGOG()) {
            path /= L"Skyrim Special Edition GOG";
        } else {
            path /= L"Skyrim Special Edition";
        }
        path /= L"SKSE";
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        return path;
    }

    void InitializeLog()
    {
        auto path = ResolveSkseDir();
        path /= fmt::format("{}.log", SKSE::PluginDeclaration::GetSingleton()->GetName());
        auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path.string(), true);

        auto log = std::make_shared<spdlog::logger>("global log", std::move(sink));
        log->set_level(spdlog::level::info);
        log->flush_on(spdlog::level::info);

        spdlog::set_default_logger(std::move(log));
        spdlog::set_pattern("[%Y-%m-%d %T.%e] [%l] %v");
    }

    void RunPostDataLoadedWork()
    {
        if (!cog::RuntimeHasEngineAddresses()) {
            logger::info("Generator: skipping — no engine addresses for this runtime");
            return;
        }
        const auto t0 = std::chrono::steady_clock::now();
        if (g_settings.enablePatches) {
            cog::SkyrimGenerator generator;
            generator.Run();
        } else {
            logger::info("post-kDataLoaded: skipped (EnablePatches=0)");
        }
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        logger::info("Phase: post-kDataLoaded work took {} ms", ms);

        // Reset measurement counters so the first transition's stats aren't
        // polluted by data-load-time activity (generator's slow-path probes
        // populating tables). The optimization is about runtime lookups.
        const auto pre = cog::SnapshotAndResetFindCell();
        (void)cog::SnapshotAndResetPerCell();
        (void)cog::SnapshotAndResetCellFind();
        (void)cog::SnapshotAndResetCellLoad();
        if (pre.calls > 0) {
            const auto totalUs = pre.totalNs / 1000ull;
            const auto slowTotalUs = pre.slowTotalNs / 1000ull;
            logger::info("FindCellInFile [data-load]: calls={}, total={}us, "
                         "fast={}, slow={} (slow total={}us) "
                         "(reset for runtime measurement)",
                         pre.calls, totalUs, pre.fastCalls, pre.slowCalls,
                         slowTotalUs);
        }
    }

    void MessageHandler(SKSE::MessagingInterface::Message* a_message)
    {
        try {
            cog::PhaseTimer::OnMessage(a_message);
            if (a_message && a_message->type == SKSE::MessagingInterface::kDataLoaded) {
                RunPostDataLoadedWork();
            }
        } catch (const std::exception& e) {
            logger::error("MessageHandler: unhandled exception — {}", e.what());
        } catch (...) {
            logger::error("MessageHandler: unknown unhandled exception");
        }
    }
}

// Patches must install BEFORE plugins parse their WRLD records, so we apply
// them in SKSEPluginLoad (which runs at SKSE init, before kDataLoaded).
SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    cog::PhaseTimer::MarkPluginLoadStart();

    // Must initialize SKSE first — InitializeLog() reads REL::Module::IsVR()
    // to pick the right Documents folder ("Skyrim VR" vs "Skyrim Special Edition").
    SKSE::Init(a_skse);
    InitializeLog();

    const auto plugin = SKSE::PluginDeclaration::GetSingleton();
    logger::info("{} v{} loading", plugin->GetName(), plugin->GetVersion().string());

    const auto ver = REL::Module::get().version();
    logger::info("Detected Skyrim{} v{}", REL::Module::IsVR() ? " VR" : "", ver.string());

    // INI lives next to the DLL: Data/SKSE/Plugins/<name>.ini
    const auto iniPath = std::filesystem::path("Data/SKSE/Plugins") /
                         fmt::format("{}.ini", plugin->GetName());
    g_settings = cog::Settings::Load(iniPath);
    cog::PhaseTimer::SetVerboseCellLogging(g_settings.findCellInFileLogging);
    logger::info("Settings: enable-patches={}, find-cell-logging={}",
                 g_settings.enablePatches, g_settings.findCellInFileLogging);

    const auto messaging = SKSE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener(MessageHandler)) {
        logger::critical("Failed to register message listener");
        return false;
    }

    SKSE::AllocTrampoline(1 << 10);

    if (!cog::Patches::InitHooks(g_settings)) {
        logger::warn("Patches not fully applied — see log for details");
    }
    if (cog::RuntimeHasEngineAddresses()) {
        (void)cog::FindCellInFileTimer::InitHooks();
    }
    (void)cog::CellFindInFileFastTimer::InitHooks();
    (void)cog::CellLoadTimer::InitHooks();

    logger::info("{} loaded", plugin->GetName());
    return true;
}
