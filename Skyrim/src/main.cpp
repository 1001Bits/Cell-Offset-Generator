#include "PCH.h"

#include "cog/Settings.h"
#include "skyrim/Benchmark.h"
#include "skyrim/EngineCalls.h"
#include "skyrim/FindCellInFileTimer.h"
#include "skyrim/GetExtCellDataTest.h"
#include "skyrim/InteriorHooks.h"
#include "skyrim/InteriorValidator.h"
#include "skyrim/Patches.h"
#include "skyrim/PhaseTimer.h"
#include "skyrim/SkyrimGenerator.h"
#include "skyrim/Validator.h"

#include <ShlObj.h>

namespace
{
    cog::Settings g_settings{};

    // SKSE::log::log_directory() reads the game-folder name from Skyrim.INI,
    // which on this user's setup resolves to "Skyrim.INI" itself instead of
    // "Skyrim Special Edition". Construct the SKSE log path explicitly to
    // avoid that lookup entirely. VR uses a different game-folder name; we
    // detect via REL::Module so this must be called *after* SKSE::Init.
    [[nodiscard]] std::filesystem::path ResolveSkseDir()
    {
        PWSTR docs = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &docs))) {
            SKSE::stl::report_and_fail("SHGetKnownFolderPath(Documents) failed");
        }
        std::filesystem::path path = docs;
        CoTaskMemFree(docs);
        path /= L"My Games";
        path /= REL::Module::IsVR() ? L"Skyrim VR" : L"Skyrim Special Edition";
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

    void MessageHandler(SKSE::MessagingInterface::Message* a_message)
    {
        cog::sky::PhaseTimer::OnMessage(a_message);
        if (a_message && a_message->type == SKSE::MessagingInterface::kDataLoaded) {
            if (!cog::sky::RuntimeHasEngineAddresses()) {
                logger::info("Generator: skipping — no engine addresses for this runtime");
                return;
            }
            const auto t0 = std::chrono::steady_clock::now();
            if (g_settings.enablePatches) {
                {
                    cog::sky::SkyrimGenerator generator;
                    generator.Run();
                }
                cog::sky::RunFindCellBenchmark(g_settings);
                cog::sky::ScrapeInteriorCellsFromLoadedForms();
            } else {
                logger::info("post-kDataLoaded: skipped (EnablePatches=0)");
            }
            if (g_settings.runValidator) {
                cog::sky::RunValidator();
                cog::sky::RunInteriorValidator();
                cog::sky::RunGetExtCellDataTest();
            }
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
            logger::info("Phase: post-kDataLoaded work took {} ms", ms);

            // Reset FindCellInFile counters so the first transition's stats
            // aren't polluted by data-load-time activity (generator probes,
            // benchmark calls, etc.). The optimization is about runtime
            // lookups, not data-load lookups.
            const auto pre = cog::sky::SnapshotAndResetFindCell();
            if (pre.calls > 0) {
                const auto totalUs = pre.totalNs / 1000ull;
                logger::info("FindCellInFile [data-load]: calls={}, total={}us "
                             "(reset for runtime measurement)",
                             pre.calls, totalUs);
            }
        }
    }
}

// Patches must install BEFORE plugins parse their WRLD records, so we apply
// them in SKSEPluginLoad (which runs at SKSE init, before kDataLoaded).
SKSEPluginLoad(const SKSE::LoadInterface* a_skse)
{
    cog::sky::PhaseTimer::MarkPluginLoadStart();

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
    logger::info("Settings: load-gates={}, lookup-gates={}, benchmark={}",
                 g_settings.enableLoadGates, g_settings.enableLookupGates,
                 g_settings.runBenchmark);

    const auto messaging = SKSE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener(MessageHandler)) {
        logger::critical("Failed to register message listener");
        return false;
    }

    SKSE::AllocTrampoline(1 << 10);

    if (!cog::sky::InstallEsmGateNops(g_settings)) {
        logger::warn("Patches not fully applied — see log for details");
    }
    if (g_settings.enablePatches) {
        if (!cog::sky::InstallInteriorHooks(g_settings)) {
            logger::warn("Interior hooks not installed — see log for details");
        }
    } else {
        logger::info("InteriorHooks: skipped (EnablePatches=0)");
    }
    if (cog::sky::RuntimeHasEngineAddresses()) {
        cog::sky::InstallFindCellInFileTimer();
    }

    logger::info("{} loaded", plugin->GetName());
    return true;
}
