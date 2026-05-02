#include "PCH.h"
#include "Plugin.h"

#include "cog/Settings.h"
#include "fallout4/EngineCalls.h"
#include "fallout4/Fo4Generator.h"
#include "fallout4/Patches.h"

// Cell Offset Generator — Fallout 4 OG / AE / VR
// Port of WallSoGB's NVSE Cell Offset Generator. Regenerates the per-plugin
// CELL offset tables that xEdit strips from saved plugins, so ESPs can
// override exterior cells the same way ESMs do.
//
// Built on CommonLibF4-NG (alandtse fork) — single DLL drives all three
// runtimes via REL::Relocate.

using namespace std;
using namespace F4SE::stl;
using namespace REL;

constexpr size_t TRAMPOLINE_SIZE = 1u << 11;

// Supported runtime range. The lower bound is the oldest build we'll attempt
// to load on; the upper bound is open (CommonLibF4-NG handles forward versions
// via Address Library v2).
const auto RUNTIME_VERSION_MIN = Relocate(
    F4SE::RUNTIME_1_10_163,   // OG
    F4SE::RUNTIME_1_10_984,   // AE (1.10.984+, subsumes the short-lived NG)
    F4SE::RUNTIME_VR_1_2_72   // VR
);

// AE sub-versions Bethesda has shipped. CommonLibF4-NG only declares constants
// up to 1.10.984, so we declare the later ones here. F4SE's plugin loader
// requires every runtime we want to run on to appear in CompatibleVersions
// (UsesAddressLibrary alone is not sufficient — the version-list check happens
// before the address-library remap).
constexpr REL::Version RUNTIME_AE_1_10_980{ 1, 10, 980, 0 };
constexpr REL::Version RUNTIME_AE_1_10_984{ 1, 10, 984, 0 };
constexpr REL::Version RUNTIME_AE_1_11_163{ 1, 11, 163, 0 };
constexpr REL::Version RUNTIME_AE_1_11_191{ 1, 11, 191, 0 };

namespace
{
    cog::Settings g_settings{};

    void OpenLog()
    {
    #ifndef NDEBUG
        auto sink = make_shared<spdlog::sinks::msvc_sink_mt>();
    #else
        auto path = logger::log_directory();
        if (!path) {
            report_and_fail("Failed to find standard logging directory.");
        }
        const auto gamepath = Module::IsVR() ? "Fallout4VR/F4SE" : "Fallout4/F4SE";
        if (!path.value().generic_string().ends_with(gamepath)) {
            path = path.value().parent_path().append(gamepath);
        }
        *path /= fmt::format("{}.log", Plugin::NAME);
        auto sink = make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);
    #endif

        const auto level = spdlog::level::info;
        auto log = make_shared<spdlog::logger>("global log", move(sink));
        log->set_level(level);
        log->flush_on(level);
        spdlog::set_default_logger(move(log));
        spdlog::set_pattern("[%Y-%m-%d %T.%e] [%l] %v");
    }

    // The generator needs the data handler populated, so it has to wait for
    // kGameDataReady. The patches must be installed before that — earlier is
    // fine since they only edit code bytes, not engine state.
    void RunGenerator()
    {
        if (!cog::fo4::RuntimeHasEngineAddresses()) {
            logger::info("Generator: skipping — engine addresses for this runtime are not yet "
                         "filled in (see fallout4/EngineCalls.cpp).");
            return;
        }
        const auto t0 = chrono::steady_clock::now();
        cog::fo4::Fo4Generator generator;
        generator.Run();
        const auto ms = chrono::duration_cast<chrono::milliseconds>(
                            chrono::steady_clock::now() - t0).count();
        logger::info("Generator: total wall time {} ms", ms);
    }

    void F4SEAPI MessageHandler(F4SE::MessagingInterface::Message* a_message)
    {
        if (!a_message) return;

        // F4SE 0.7+ (AE) provides kGameDataReady, which fires once before the
        // main menu — the ideal hook. F4SE-VR (0.6.21) predates that message
        // and stops at kGameLoaded (fires after a save loads). We listen to
        // both so the generator runs on every supported runtime, and a static
        // guard prevents double-execution if AE happens to send both.
        static std::atomic<bool> ran{ false };
        switch (a_message->type) {
        case F4SE::MessagingInterface::kGameDataReady:
        case F4SE::MessagingInterface::kGameLoaded:
            if (!ran.exchange(true)) {
                RunGenerator();
            }
            break;
        default:
            break;
        }
    }
}

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Query(const F4SE::QueryInterface* a_f4se, F4SE::PluginInfo* a_info)
{
    if (!a_f4se || !a_info) return false;

    OpenLog();

    a_info->infoVersion = F4SE::PluginInfo::kVersion;
    a_info->name = Plugin::NAME.data();
    a_info->version = Plugin::VERSION[0];

    if (a_f4se->IsEditor()) {
        logger::critical("Loading into editor, aborting.");
        return false;
    }

    return true;
}

extern "C" DLLEXPORT bool F4SEAPI F4SEPlugin_Load(const F4SE::LoadInterface* a_f4se)
{
    if (!a_f4se) return false;

    F4SE::Init(a_f4se);

    logger::info("{} v{}.{}.{} [{} {}] is loading",
        Plugin::NAME, Plugin::VERSION[0], Plugin::VERSION[1], Plugin::VERSION[2],
        __DATE__, __TIME__);

    const auto ver = Module::get().version();
    logger::info("Detected runtime: Fallout 4{} (v{}).", Module::IsVR() ? " VR" : "", ver.string());

    if (ver < RUNTIME_VERSION_MIN) {
        logger::critical("Runtime version is not supported, aborting.");
        return false;
    }

    const auto messaging = F4SE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener(MessageHandler)) {
        logger::critical("Failed to register message listener, aborting.");
        return false;
    }

    F4SE::AllocTrampoline(TRAMPOLINE_SIZE);

    // Patches must install before plugins parse their WRLD records, so we
    // apply them here at F4SE init — well before kGameDataReady.
    if (!cog::fo4::InstallEsmGateNops(g_settings)) {
        logger::warn("Patches not fully applied — see log for details");
    }

    logger::info("{} loaded", Plugin::NAME);
    return true;
}

// ── AE version declaration (for Address Library v2) ────────────────────────
F4SE_EXPORT auto F4SEPlugin_Version = []() noexcept {
    F4SE::PluginVersionData data{};
    data.PluginName(Plugin::NAME);
    data.PluginVersion(Plugin::VERSION);
    data.AuthorName("noud");
    data.UsesAddressLibrary(true);
    data.UsesSigScanning(false);
    data.IsLayoutDependent(true);
    data.HasNoStructUse(false);
    data.CompatibleVersions({
        RUNTIME_AE_1_10_980,
        RUNTIME_AE_1_10_984,
        RUNTIME_AE_1_11_163,
        RUNTIME_AE_1_11_191,
    });
    return data;
}();
