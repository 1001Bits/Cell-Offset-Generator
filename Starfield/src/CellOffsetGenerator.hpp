#pragma once

#include "PCH.h"

#include <Windows.h>

namespace RE {
    class TESFile;
    class TESWorldSpace;
}

// Starfield port of WallSoGB's NVSE Cell Offset Generator. Regenerates the
// per-WRLD CELL offset tables (OFST + CLSZ chunks) that xEdit's "Clean Masters"
// strips from plugins, so cleaned ESPs/ESMs can override exterior cells the
// same way the base masters do.
//
// Generation runs on the engine main thread at kPostDataLoad and enumerates
// contributing plugins through each worldspace's offsetDataMap (the engine
// structure keyed by TESFile*) — it does NOT rely on TESDataHandler's
// compiledFileCollection, whose layout CommonLibSF gets wrong on 1.16.x.
class OffsetGenerator {
public:
    // Enumerate every worldspace's offsetDataMap and, for each contributing
    // plugin whose pCellFileOffsets is still null, parse the owning plugin file
    // and install byte-exact OFST/CLSZ buffers into the engine's OFFSET_DATA.
    static void GenerateAllOnMainThread();

    // Install the IsMaster-gate NOPs (see CellOffsetGenerator.cpp::kSitesSF).
    static void InitHooks();
};
