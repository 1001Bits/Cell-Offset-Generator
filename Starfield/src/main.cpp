#include "PCH.h"

#include "CellOffsetGenerator.hpp"
#include "FindCellInFileBench.hpp"

// Cell Offset Generator — Starfield (SFSE)
// Port of WallSoGB's NVSE Cell Offset Generator. Regenerates the per-plugin
// CELL offset tables that xEdit strips from saved plugins, so ESPs can
// override exterior cells the same way ESMs do.
//
// Scope: exterior cells only. Interior CELL lookups in Starfield go through
// a separate engine mechanism (per-file `{fileID,offset}` tuple array at
// file+0x3B0), not OFST — so they're out of scope for this plugin.
// Engine bindings are routed through CommonLibSF and a thin wrapper layer
// (TESWorldSpaceExt, TESFileExt) that stand in for NVSE's TESWorldSpace.cpp /
// TESFile.cpp until those types are fully fleshed out in CommonLibSF itself.

namespace
{
    void RunGenerator()
    {
        const auto t0 = std::chrono::steady_clock::now();

        // kPostDataLoad runs after TESDataHandler is populated. Iterate every
        // worldspace's offsetDataMap, find contributing plugins that still lack
        // OFST, parse each owning plugin file once, and install OFST buffers.
        OffsetGenerator::GenerateAllOnMainThread();

        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
        logger::info("CellOffsetGenerator: total wall time {} ms", ms);
    }

    void MessageHandler(SFSE::MessagingInterface::Message* a_message)
    {
        if (!a_message) return;

        // SFSE 0.2.x exposes:
        //   kPostLoad        — all plugins loaded (early)
        //   kPostPostLoad    — after all plugins finished post-load init
        //   kPostDataLoad    — game data loaded (TESDataHandler populated)
        //   kPreLoadGame / kPostLoadGame — save load lifecycle
        //
        // The generator needs `TESDataHandler::GetSingleton()` populated, so
        // we run on `kPostDataLoad`. A guard prevents double-execution if SFSE
        // sends overlapping events.
        //
        // SFSE 0.2.x only exposes the load-time messages above (no
        // kPostLoadGame). A heartbeat thread (spawned in plugin entry)
        // handles periodic stats sampling during gameplay.
        static std::atomic<bool> ran{ false };
        switch (a_message->type) {
        case SFSE::MessagingInterface::kPostDataLoad:
            if (!ran.exchange(true)) {
                // Skip the generator's own slow scan in baseline mode — the
                // run is supposed to mimic vanilla, and the generator would
                // call FindCellInFile thousands of times before any engine
                // call happens, swamping the stats.
                // COG_NO_GENERATE=1 also skips it: the 7 NOPs stay applied
                // but no file scan / GetOrCreateOffsetData calls happen.
                if (cog::sf::bench::IsBaselineMode()) {
                    logger::info("[Bench] BASELINE mode — generator skipped");
                } else if (cog::sf::bench::IsNoGenerateMode()) {
                    logger::info("COG_NO_GENERATE=1 — generator skipped (NOPs still applied)");
                } else {
                    RunGenerator();
                }
                if (cog::sf::bench::IsDiagnosticsMode()) {
                    logger::info("{}", cog::sf::bench::FormatAllStatsLines("kPostDataLoad"));
                }
            }
            break;

        case SFSE::MessagingInterface::kPostPostDataLoad:
            if (cog::sf::bench::IsDiagnosticsMode()) {
                logger::info("{}", cog::sf::bench::FormatAllStatsLines("kPostPostDataLoad"));
            }
            break;

        default:
            break;
        }
    }

    // Heartbeat thread: samples the engine-call counters every 30s and
    // writes a one-line summary. Always emits (even when the counter is
    // unchanged) so the line itself is a liveness signal — "no FindCellInFile
    // activity in the last 30s" is data, not silence. Forces a flush after
    // each write because the default spdlog file sink buffers, and
    // Starfield's exit path doesn't always run DLL destructors that would
    // flush — so without explicit flushes we lose the tail of the run.
    void StartHeartbeatThread()
    {
        std::thread([] {
            int tick = 0;
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                ++tick;
                logger::info("{}", cog::sf::bench::FormatAllStatsLines("heartbeat"));
                const auto savings = cog::sf::bench::FormatSavingsLine();
                if (!savings.empty()) logger::info("{}", savings);
                const auto perCellSingle = cog::sf::bench::FormatPerCellSingleRun();
                if (!perCellSingle.empty()) logger::info("{}", perCellSingle);
                spdlog::default_logger()->flush();
            }
        }).detach();
    }
}

// Game main-thread handle. SFSE_PLUGIN_LOAD runs on the game's main thread,
// so we capture its handle once at boot; CellOffsetGenerator.cpp's worker
// threads use this to suspend the game thread while they mutate
// OFFSET_DATA, avoiding races with engine cell-streaming.
HANDLE g_mainThreadHandle = nullptr;

// ── SFSE plugin entry ───────────────────────────────────────────────────────

SFSE_PLUGIN_LOAD(const SFSE::LoadInterface* a_sfse)
{
    SFSE::Init(a_sfse, {
        .logPattern    = "[%Y-%m-%d %T.%e] [%l] %v",
        .trampoline    = true,
        .trampolineSize = 1u << 11,
    });

    // Flush every info-level message so the tail of the run isn't lost
    // when Starfield exits without running our DLL destructors (which it
    // sometimes does — game uses ExitProcess in some shutdown paths).
    spdlog::default_logger()->flush_on(spdlog::level::info);

    // Capture a real Win32 handle for the game's main thread (SFSE_PLUGIN_LOAD
    // runs on it). DuplicateHandle with the pseudo-handle GetCurrentThread()
    // gives us something we can pass to SuspendThread later from a worker.
    {
        const auto cur = ::GetCurrentThread();
        const auto proc = ::GetCurrentProcess();
        if (!::DuplicateHandle(proc, cur, proc, &g_mainThreadHandle,
                               THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                               FALSE, 0)) {
            g_mainThreadHandle = nullptr;
            logger::warn("Could not duplicate main thread handle (err {}); "
                         "MainThreadGuard will be a no-op",
                         ::GetLastError());
        }
    }

    logger::info("{} v{} loading", SFSE::GetPluginName(),
                 SFSE::GetPluginVersion().string());

    const auto messaging = SFSE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener(MessageHandler)) {
        logger::critical("Failed to register message listener");
        return false;
    }

    // The engine-call detours (FindCellInFile/FindInFileFast/…) and the
    // heartbeat thread exist ONLY to measure cell-lookup timing for A/B
    // benchmarking. They add per-lookup overhead and spam the log, so a clean
    // release build skips them entirely. They turn on only in diagnostics mode
    // ([Benchmark] Diagnostics=1, or baseline mode, or COG_DIAGNOSTICS=1).
    if (cog::sf::bench::IsDiagnosticsMode()) {
        (void)cog::sf::bench::InstallEngineHooks();
        StartHeartbeatThread();
        logger::info("Diagnostics mode ON — engine-call detours + heartbeat installed");
    }

    // OFST strip: simulates xEdit Clean-Masters on Starfield.esm by
    // making the engine's chunk dispatcher never recognize 'OFST'. Applied
    // BEFORE plugin parse (kPostLoad fires before kPostDataLoad), so the
    // engine reads every WRLD with no OFST data — every cell lookup falls
    // to the slow-path scanner. The generator (if InitHooks() ran) can
    // still rebuild OFFSET_DATA at kPostDataLoad, so subsequent save loads
    // benefit. Toggle via COG_STRIP_OFST=1.
    (void)cog::sf::bench::InstallOfstStripper();

    // Hooks must install before plugins parse their WRLD records, so we apply
    // them here at SFSE init — well before kPostDataLoad.
    // OffsetGenerator::InitHooks installs the 7 NOP patches that let ESPs
    // populate and consume OFFSET_DATA (see CellOffsetGenerator.cpp).
    //
    // COG_BASELINE=1 in the environment skips InitHooks entirely so the
    // engine runs vanilla for A/B benchmarking. Set the env var, launch
    // Starfield, drive through a few cell loads; unset it and repeat.
    if (cog::sf::bench::IsBaselineMode()) {
        logger::info("Baseline mode ON (COG_BASELINE env or INI [Benchmark] BaselineMode=1) "
                     "— skipping InitHooks; engine runs vanilla");
    } else {
        OffsetGenerator::InitHooks();
    }

    if (cog::sf::bench::IsZeroOffsetsMode()) {
        logger::info("COG_ZERO_OFFSETS=1 — pCellFileOffsets installed but all zeros");
    }
    if (cog::sf::bench::IsNoTableMode()) {
        logger::info("COG_NO_TABLE=1 — pCellFileOffsets never assigned (engine slow-scans)");
    }
    if (cog::sf::bench::IsNoGenerateMode()) {
        logger::info("COG_NO_GENERATE=1 — generator will be skipped at kPostDataLoad (NOPs still applied)");
    }

    logger::info("{} loaded successfully", SFSE::GetPluginName());
    return true;
}

// ── SFSE plugin version declaration ────────────────────────────────────────

SFSE_PLUGIN_VERSION = []() noexcept {
    SFSE::PluginVersionData data{};
    data.PluginName("CellOffsetGeneratorSF");
    data.PluginVersion(REL::Version{ 1, 0, 0 });
    data.AuthorName("noud");
    data.UsesAddressLibrary(true);
    data.UsesSigScanning(false);
    data.IsLayoutDependent(true);
    data.HasNoStructUse(false);
    data.MinimumRequiredXSEVersion(SFSE::SFSE_PACK_LATEST);
    data.CompatibleVersions({
        SFSE::RUNTIME_SF_1_14_70,
        SFSE::RUNTIME_SF_1_14_74,
        SFSE::RUNTIME_SF_1_15_216,
        SFSE::RUNTIME_SF_1_15_222,
        SFSE::RUNTIME_SF_1_16_236,
        SFSE::RUNTIME_SF_1_16_242,
    });
    return data;
}();
