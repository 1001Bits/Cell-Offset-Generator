#pragma once

#include "PCH.h"

#include <vector>
#include <Windows.h>

namespace RE {
    class TESFile;
    class TESWorldSpace;
}

// Starfield port of WallSoGB's NVSE Cell Offset Generator. Class layout
// matches the original CellOffsetGenerator.hpp 1:1 — OffsetGenThread fans
// files out across worker threads, OffsetGenerator owns the threads + a
// progress-render hook for the loading menu UI.
//
// Differences from NVSE:
//   • RE namespace types come from CommonLibSF, not local TESForm.hpp.
//   • Allocation goes through engine memory (EngineAlloc) so the buffers
//     live in the same heap the engine will eventually free; xxhash is
//     pulled in by the .cpp.
//   • The loading-menu UI hook is left as a no-op stub — Starfield's UI
//     is Scaleform-driven and doesn't ship a 1:1 prefab path. Progress is
//     reported to the SFSE log instead.

class OffsetGenThread {
public:
    OffsetGenThread();
    ~OffsetGenThread();

    void AddFile(const RE::TESFile* a_file);

protected:
    friend class OffsetGenerator;

    HANDLE                       hThread = nullptr;
    std::vector<RE::TESFile*>    kFiles;

    static DWORD WINAPI ThreadProc(LPVOID a_param);

    bool Run();
};

class OffsetGenerator {
public:
    OffsetGenerator();
    ~OffsetGenerator();

    void Start();

    // Drive progress reporting to the log. NVSE's RenderUI() drove a Tile
    // prefab; Starfield doesn't have a 1:1 equivalent so this drains
    // counters until bDone instead.
    void RenderUI();

    // Run the slow-path FindCellInFile loop across the worldspace bounds and
    // install a freshly-built pCellFileOffsets array on `apData`. Returns
    // the number of slots in the array (or UINT32_MAX if the worldspace
    // contributed no cells in this plugin).
    static std::uint32_t GenerateCellOffsets(RE::TESWorldSpace* a_world,
                                             RE::TESFile* a_ownerFile,
                                             RE::TESFile* a_workerFile);

    // NVSE-mirror generation. Runs ON THE MAIN THREAD (call from kPostDataLoad).
    // Iterates every worldspace and, via each world's offsetDataMap (the engine
    // structure keyed by TESFile*, at world+0x280/+0x288), generates OFST for
    // every contributing plugin whose pCellFileOffsets is still null. The
    // generator parses the owning plugin file directly, then installs OFST
    // buffers into the engine's OFFSET_DATA records.
    static void GenerateAllOnMainThread();

    // Install the IsMaster-gate NOPs (write-side and read-side, see
    // CellOffsetGenerator.cpp::kSitesSF for the verified sites).
    static void InitHooks();

    // Diagnostic: at kPostDataLoad, walk every WRLD in TESDataHandler and
    // sample GetOffsetData(world, Starfield.esm) BEFORE our generator runs.
    // Tells us whether the engine populated OFFSET_DATA itself (e.g. via a
    // built-in file scan now that OFST subrecords are absent from the master)
    // or left every entry empty. Logged at info level.
    static void DumpEnginePreState();

private:
    bool                         bRunning      = false;
    volatile bool                bDone         = false;
    HANDLE                       hMainThread   = nullptr;
    std::vector<HANDLE>          kThreadHandles;
    std::vector<OffsetGenThread> kThreads;

    static DWORD WINAPI ThreadProc(LPVOID a_param);
};
