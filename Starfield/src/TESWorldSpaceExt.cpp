#include "PCH.h"
#include "TESWorldSpaceExt.hpp"
#include "TESFileExt.hpp"

#include <limits>

namespace cog::sf {

namespace {

// Per-thread accumulator for FindCellInFile timing. Each call adds to this;
// the generator reads it via GetFindCellStats() and resets between files.
thread_local FindCellStats t_findCellStats{};

// ── Starfield 1.7.x — verified addresses & layout ──────────────────────────
// All values were located via GhidrAssistMCP against
// `C:\GhidraProjects\Starfield\StarfieldProject.gpr`. Subtract the image base
// (0x140000000) to produce the IMAGE-RELATIVE offsets stored in kOffsetsSF.
//
// RTTI anchors:
//   • `.?AVTESWorldSpace@@`  string : 0x14509E088
//   • Type descriptor               : 0x14509E078
//   • ClassHierarchyDescriptor      : 0x1449449E8
//   • CompleteObjectLocator         : 0x144944CC0
//   • Primary vtable                : 0x1443D8F00 (98 entries)
//
// Member functions (vtable indices via Ghidra RTTI auto-naming as
// `RE::TESWorldSpace::Unk_NN`, post full-analysis pass):
//   • TESWorldSpace::~BaseFormComponent (dtor thunk)   : 0x141A48048
//   • TESWorldSpace::Load_Impl(TESFile*)               : 0x141A4D65C (Unk_12)
//   • TESWorldSpace::LoadPartial(TESFile*)             : 0x141A4EEB4 (Unk_13)
//   • TESWorldSpace::BelongsInGroup                    : 0x141A49370
//   • TESWorldSpace::FindCellInFile(TESFile*, int, int): 0x141A4AAA0
//   • TESWorldSpace::GetOffsetData(TESFile*)           : 0x141A4CB50
//   • TESWorldSpace::GetOrCreateOffsetData(TESFile*)   : 0x141A49AB4
//   • TESWorldSpace::GetIndexForCellCoord(TESFile*,int,int): 0x141A4C214
//
// OFFSET_DATA struct (size 0x28, layout verified — see TESWorldSpaceExt.hpp).
//
// Map field on TESWorldSpace: `this + 0x270`. Storage is NiTMap-like with
// 0x18-byte entries (key/value/next). Verified by the literal `param_1 +
// 0x270` and `local_res18 * 0x18` arithmetic in GetOrCreateOffsetData.
//
// TESFile IsMaster bit: byte at `file + 0x1B8`, bit 0. Verified inline at
// the top of TESWorldSpace::FindCellInFile.
//
// Chunk magics:
//   OFST = 0x5453464F   NAM0 = 0x304D414E   NAM9 = 0x394D414E
//   XCLC = 0x434C4358   (cell coords inside CELL records — used by the
//                        FindCellInFile slow path)
//
// ── Architectural difference vs F4/Skyrim ─────────────────────────────────
// OFST chunk handler is NOT IsMaster-gated — ESPs already load saved OFST.
// The IsMaster-gated sites we DO patch (7 total):
//   • Load_Impl write-side (3 sites): the .fileOffset write at function
//     entry plus the NAM0/NAM9 min/max coord chunk handlers further down.
//     All three gate on the same `[file+0x1B8] & 1` check.
//   • LoadPartial write-side (2 sites): NAM0/NAM9 equivalents for the
//     partial-load path.
//   • FindCellInFile fast-path entry (1 site, 0x141A4AAE3): without this
//     the write-side patches produce data the engine ignores at runtime
//     for ESPs.
//   • FindInFileFast (1 site, 0x141A4ACF4): this is the per-file WRLD
//     locator the engine uses before per-cell lookups. Despite Ghidra's
//     RTTI auto-naming it "AddChange", the body is F4/Skyrim's
//     FindInFileFast verbatim (GetOffsetData → seek pData->fileOffset →
//     verify chunk magic 'V' + formID match). Requires Load.fileOffset
//     to be applied — relies on pData->fileOffset being non-zero.
//
// Patch sites NOT included (vs F4/Skyrim):
//   • F4's `PrefetchCellData` / `GetExtCellByEditorID` (auxiliary fast
//     paths) — Skyrim port already drops these, replaced with a smaller
//     `SafeLookupPatch` trampoline. Not ported.
//   • Interior CELL override path. Starfield's interior cells don't use OFST
//     at all — they go through a per-file `{fileID,offset}` tuple array at
//     `file+0x3B0`, walked by the interior loader. Out of scope for this
//     plugin (OFST is exterior-only); ESP interior override would also carry
//     the F4-port save-corruption hazard, so we intentionally don't go near
//     it.
//
// The slow-path scanner inside FindCellInFile is intact and works the same
// way as F4: walk records, match XCLC against (x,y), leave file cursor at
// the matched CELL header.
//
// Threading note: TESFile::vtable[1] (verified inside TESWorldSpace::
// FindCellInFile) is thread-keyed — main thread returns the original file,
// worker threads return per-thread clones via FUN_1414B83F8. The
// OFFSET_DATA NiTMap at world+0x270 is keyed by whatever vtable[1] returns
// for the calling thread, so a worker-thread generator builds entries
// keyed by clones; the engine's runtime cell loader (likely main-thread)
// looks up by the original. The F4 port has the same structure and works
// in practice — possibly because the engine's loader also runs on a worker
// or because clones share entries. If runtime testing shows the cache
// isn't being consulted, single-threading the generator is the simplest
// fix.

struct EngineOffsets
{
    std::uintptr_t findCellInFile;
    std::uintptr_t getIndexForCellCoord;
    std::uintptr_t getOffsetData;
    std::uintptr_t getOrCreateOffsetData;
};

// Per-version address tables. Verified-from-Ghidra for 1.14.70; derived for
// 1.14.74 by comparing versionlib-1-14-70-0.bin against
// versionlib-1-14-74-0.bin in the [0x1A48000, 0x1A50000] region — every
// common ID shifted by exactly +0x90 there, so the layouts of the
// functions themselves are unchanged. The runtime byte-verification check
// in OffsetGenerator::InitHooks provides safety in case any function body
// did differ unexpectedly.
constexpr EngineOffsets kOffsetsSF_1_14_70{
    // ✅ TESWorldSpace::FindCellInFile(TESFile*, int x, int y) → bool
    //    Fast path: GetOffsetData → pCellFileOffsets[GetIndexForCellCoord]
    //               → file_seek(fileOffset + per-cell delta).
    //    Slow path: walks records reading chunk magics; on `XCLC`
    //               (0x434C4358) reads 12 bytes of cell-coord payload and
    //               compares (x,y). On match, leaves the file's read cursor
    //               at the matched CELL header.
    .findCellInFile        = 0x1A4AAA0,
    .getIndexForCellCoord  = 0x1A4C214,   // ✅ TESWorldSpace::GetIndexForCellCoord(TESFile*, int x, int y) → int (or -1 if OOB)
    .getOffsetData         = 0x1A4CB50,   // ✅ TESWorldSpace::GetOffsetData(TESFile*) → OFFSET_DATA* (lookup-only)
    .getOrCreateOffsetData = 0x1A49AB4,   // ✅ TESWorldSpace::GetOrCreateOffsetData(TESFile*) → OFFSET_DATA* (lookup + alloc-on-miss)
};

constexpr EngineOffsets kOffsetsSF_1_14_74{
    .findCellInFile        = 0x1A4AAA0 + 0x90,
    .getIndexForCellCoord  = 0x1A4C214 + 0x90,
    .getOffsetData         = 0x1A4CB50 + 0x90,
    .getOrCreateOffsetData = 0x1A49AB4 + 0x90,
};

// ── Starfield 1.16.236 — TBD, awaiting Ghidra ──────────────────────────────
// The 1.14.74 → 1.15.216 compiler change reshuffled function layout in this
// region (confirmed via versionlib-bin neighbor-ID gap analysis: ID pairs
// 106048↔106049, 106050↔106051 etc. collapsed from kilobyte-scale gaps to
// 16-byte gaps, meaning our four functions moved out of 141A4xxxx). The
// post-reshuffle layout is then stable across 1.15.216 / 1.15.222 / 1.16.236
// (identical gap shape in the offsets-*.txt for all three), so addresses
// found in the 1.16.236 Ghidra session also yield 1.15.x via the AL
// neighbor-anchor offsets.
//
// Until Ghidra reports back, the four image-relative offsets stay at 0.
// PickOffsets returns an empty struct on 1.16.236 and RuntimeHasEngineAddresses
// returns false, so the generator and the FindInFileFast wrapper bail
// silently with a "no engine addresses for runtime 1.16.236" log line —
// install is harmless but inert until we fill these in.
// ✅ Verified via GhidrAssistMCP against the Steamless 1.16.236.0 binary at
//    C:/Games/Starfield 1.7/Starfield.exe. RTTI string `.?AVTESWorldSpace@@`
//    at 0x145994B58 → TypeDescriptor 0x145994B48 → primary COL 0x14503F4D8 →
//    primary vtable header 0x144B9DA10. Function entries below were not
//    reached via the (98-entry) vtable directly because Bethesda's 1.16.236
//    layout uses small tail-call thunks at vtable[12]/[13] (`mov rax,[rcx];
//    jmp [rax+0x68]`); the real Load_Impl / LoadPartial are byte-pattern
//    matched (NAM0 magic 0x304D414E + NAM9 magic 0x394D414E both in body)
//    and the GetOffsetData / GetOrCreateOffsetData / GetIndexForCellCoord
//    helpers were identified by their call signatures from inside Load_Impl
//    and FindCellInFile.
constexpr EngineOffsets kOffsetsSF_1_16_236{
    .findCellInFile        = 0x0BBA370,   // ✅ TESWorldSpace::FindCellInFile  — fast/slow paths verified (GetThreadSafeFile → IsMaster → GetOffsetData → GetIndexForCellCoord → SeekToFileOffset, then slow-path scanner with XCLC/CELL/TLODX magics)
    .getIndexForCellCoord  = 0x0BB8600,   // ✅ TESWorldSpace::GetIndexForCellCoord — called from FindCellInFile fast path
    .getOffsetData         = 0x0BC1C80,   // ✅ TESWorldSpace::GetOffsetData (lookup-only) — called from FindCellInFile + FindInFileFast
    .getOrCreateOffsetData = 0x0BC1D10,   // ✅ TESWorldSpace::GetOrCreateOffsetData — called from Load_Impl write path (Load.fileOffset + Load.NAM0/9 + LoadPartial.NAM0/9)
};

// 1.16.242 — derived from the 1.16.236 table by mapping each function through
// its address-library ID (versionlib-1-16-236-0.bin → versionlib-1-16-242-0.bin)
// and confirming identical function sizes in both bins (internal layout
// preserved). IDs: findCellInFile=64491, getIndexForCellCoord=64480,
// getOffsetData=64546, getOrCreateOffsetData=64547. The runtime byte-verify
// guard in InitHooks still protects against any unexpected body change.
constexpr EngineOffsets kOffsetsSF_1_16_242{
    .findCellInFile        = 0x0BBA530,
    .getIndexForCellCoord  = 0x0BB87C0,
    .getOffsetData         = 0x0BC1E40,
    .getOrCreateOffsetData = 0x0BC1ED0,
};

[[nodiscard]] const EngineOffsets& PickOffsets()
{
    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    if (ver == SFSE::RUNTIME_SF_1_14_70)  return kOffsetsSF_1_14_70;
    if (ver == SFSE::RUNTIME_SF_1_14_74)  return kOffsetsSF_1_14_74;
    if (ver == SFSE::RUNTIME_SF_1_16_236) return kOffsetsSF_1_16_236;
    if (ver == SFSE::RUNTIME_SF_1_16_242) return kOffsetsSF_1_16_242;
    static const EngineOffsets empty{};
    return empty;
}

using FindCellInFile_t        = bool          (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetIndexForCellCoord_t  = std::uint32_t (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetOffsetData_t         = OFFSET_DATA*  (*)(RE::TESWorldSpace*, RE::TESFile*);
using GetOrCreateOffsetData_t = OFFSET_DATA*  (*)(RE::TESWorldSpace*, RE::TESFile*);

}  // namespace

bool RuntimeHasEngineAddresses()
{
    // GetOrCreateOffsetData is the only address we strictly require — it
    // covers the lookup case via fallback, and both `findCellInFile` and
    // `getIndexForCellCoord` are nice-to-have for the slow-path scan.
    return PickOffsets().getOrCreateOffsetData != 0;
}

bool HasFindCellInFile()
{
    return PickOffsets().findCellInFile != 0;
}

bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                    std::int32_t a_x, std::int32_t a_y)
{
    static const auto offset = PickOffsets().findCellInFile;
    if (offset == 0) return false;
    static REL::Relocation<FindCellInFile_t> func{ REL::Offset(offset) };

    // Benchmark hook: time every call and accumulate into thread-local stats.
    // The cost is two clock reads + a handful of integer ops per call —
    // negligible relative to the engine's slow-path chunk scan, which reads
    // the file and walks variable-size records.
    const auto t0      = std::chrono::steady_clock::now();
    const bool result  = func(a_world, a_file, a_x, a_y);
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - t0).count();

    auto& s = t_findCellStats;
    ++s.calls;
    if (result) ++s.hits;
    s.totalNs += elapsed;
    if (s.calls == 1 || elapsed < s.minNs) s.minNs = elapsed;
    if (elapsed > s.maxNs) s.maxNs = elapsed;

    // Per-call line at debug level. With the default Info log level this is
    // filtered out — flip the SFSE InitInfo log level to Debug in main.cpp to
    // see one line per cell scan. Useful for hunting a specific pathological
    // cell; not useful in steady-state runs.
    logger::debug("[FindCellInFile] world={} file={} cell=({},{}) hit={} {}ns",
                  GetWorldEditorID(a_world),
                  GetFileName(a_file),
                  a_x, a_y, result, elapsed);

    return result;
}

FindCellStats GetFindCellStats()
{
    return t_findCellStats;
}

void ResetFindCellStats()
{
    t_findCellStats = {};
}

std::uint32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                   std::int32_t a_x, std::int32_t a_y)
{
    static const auto offset = PickOffsets().getIndexForCellCoord;
    if (offset == 0) return UINT32_MAX;
    static REL::Relocation<GetIndexForCellCoord_t> func{ REL::Offset(offset) };
    return func(a_world, a_file, a_x, a_y);
}

OFFSET_DATA* GetOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    // Lookup-only sibling not yet located on Starfield. Fall back to the
    // GetOrCreateOffsetData path: it does the same NiTMap::Find first, and
    // only creates a fresh empty record when nothing is mapped — semantically
    // equivalent for our generator (we treat newly-created entries as
    // "no offsets yet" and proceed to fill them).
    static const auto lookupOffset = PickOffsets().getOffsetData;
    if (lookupOffset != 0) {
        static REL::Relocation<GetOffsetData_t> func{ REL::Offset(lookupOffset) };
        return func(a_world, a_file);
    }
    return GetOrCreateOffsetData(a_world, a_file);
}

OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    static const auto offset = PickOffsets().getOrCreateOffsetData;
    if (offset == 0) return nullptr;
    static REL::Relocation<GetOrCreateOffsetData_t> func{ REL::Offset(offset) };
    return func(a_world, a_file);
}

const char* GetWorldEditorID(const RE::TESWorldSpace* a_world)
{
    if (!a_world) return "<null>";
    const auto* str = a_world->formEditorID.c_str();
    return (str && *str) ? str : "<unnamed>";
}

}  // namespace cog::sf
