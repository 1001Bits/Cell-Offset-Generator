#include "PCH.h"
#include "CellOffsetGenerator.hpp"

#include "FindCellInFileBench.hpp"
#include "PluginScanner.hpp"
#include "TESFileExt.hpp"
#include "TESWorldSpaceExt.hpp"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <format>
#include <string>
#include <unordered_set>

#define XXH_INLINE_ALL
#define XXH_ENABLE_AUTOVECTORIZE
#include <xxhash.h>

// ── Globals matching the NVSE original ─────────────────────────────────────
// The class layout, control flow, and progress counters all mirror
// CellOffsetGenerator.cpp 1:1 so the Starfield code base is grep-compatible
// with the NVSE source (and with the F4 port's `cog/` core).

namespace {

static const char OFFSETS_DIR[] = "Data\\CellOffsets";
std::uint32_t        uiTotalWorlds      = 0;
std::atomic<bool>    bGeneratingOffsets = false;
std::atomic<std::uint32_t> uiProcessedWorlds{ 0 };
std::uint32_t        uiLastValue        = 0;

// Sanity bound — a single worldspace shouldn't hold more than ~4M cell slots.
constexpr std::uint32_t kMaxReasonableTableSize = 4 * 1024 * 1024;

// Starfield (CE2) uses 100 world units per cell, NOT the 4096 inherited from
// CE1 (TES4/F3/FNV/TES5/F4). Verified empirically against the live binary's
// chunk-dispatcher constant DAT_14479ed14 (= 0.01f) and against 30 ground-
// truth WRLDs in Starfield.esm spanning 4x4 overlay POIs up through
// NewAtlantis (78x135). The reciprocal test against Skyrim.esm and
// Fallout4.esm confirmed they still use /4096. This is the first Bethesda
// game to change the cell-size convention since Oblivion.
//
// Floor-divide toward -inf so negative coords round correctly (e.g. -200.0
// must map to cell -2, not -1).
[[nodiscard]] std::int32_t WorldUnitsToCell(float a_value)
{
    return static_cast<std::int32_t>(std::floor(a_value / 100.0f));
}

// xxh3 — full plugin-file hash. Used to invalidate `.fco` caches when the
// plugin is re-cleaned by xEdit.
[[nodiscard]] XXH64_hash_t HashFile(const std::filesystem::path& a_path)
{
    std::ifstream file(a_path, std::ios::binary);
    if (!file) return 0;

    auto* state = XXH3_createState();
    if (!state) return 0;
    XXH3_64bits_reset(state);

    constexpr std::size_t kBuf = 64 * 1024;
    std::vector<char> buffer(kBuf);
    while (file.read(buffer.data(), kBuf) || file.gcount() > 0) {
        XXH3_64bits_update(state, buffer.data(),
                           static_cast<std::size_t>(file.gcount()));
    }
    const auto digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return digest;
}

[[nodiscard]] XXH64_hash_t HashOffsets(XXH3_state_t* a_state,
                                       const std::uint32_t* a_offsets,
                                       std::uint32_t a_count)
{
    XXH3_64bits_reset(a_state);
    XXH3_64bits_update(a_state, a_offsets,
                       static_cast<std::size_t>(a_count) * sizeof(std::uint32_t));
    return XXH3_64bits_digest(a_state);
}

// Engine memory wrapper for 1.16.236. The engine's OFST chunk handler at
// +BB8083 uses a two-stage allocator:
//
//   ctx = FUN_1402B81E0()                ; per-thread allocator context
//   ptr = FUN_1422CA0C0(ctx, size, 0, 0) ; allocate
//   FUN_1422C9B50(ptr)                   ; free (single-arg)
//
// RVAs verified by:
//   1. Computing CALL rel32 targets from the OFST handler bytes:
//        +0xBB80F3  e8 e8 00 70 ff  →  0x1402B81E0
//        +0xBB8104  e8 b7 1f 71 01  →  0x1422CA0C0
//        +0xBB80D5  e8 76 1a 71 01  →  0x1422C9B50
//   2. Reading the on-disk 1.16.236 Starfield.exe and confirming each target
//      has a proper function prologue:
//        GetAllocContext: 48 83 ec 28          (sub rsp, 0x28)
//        Alloc          : 44 88 4c 24 20 53 55 56 57 41 54 41 55
//                                              (push regs, set up args)
//        Free           : 48 89 5c 24 10 48 89 74 24 18 57 48 83 ec 20
//                                              (typical 1-arg helper prologue)
//
// Runtime-side: BethesdaAllocAvailable() does ANOTHER byte-check against the
// live process memory before enabling — protects against silent regressions
// if a future SF patch reshuffles function bodies.
namespace {

using GetAllocContext_t = void* (*)();
using AllocFn_t         = void* (*)(void* /*ctx*/, std::size_t /*size*/,
                                    std::size_t /*alignment*/, std::size_t /*flags*/);
using FreeFn_t          = void  (*)(void* /*ptr*/);

// Per-version allocator RVAs. 1.16.242 derived from 1.16.236 via address-
// library IDs (GetAllocContext=35721, Alloc=123792, Free=123786); each
// function is byte-identical in size between the two bins, so the prologue
// signatures below are shared.
struct AllocRVAs {
    std::uintptr_t allocContext;
    std::uintptr_t alloc;
    std::uintptr_t free;
};
constexpr AllocRVAs kAllocRVAs_1_16_236 = { 0x002B81E0, 0x022CA0C0, 0x022C9B50 };
constexpr AllocRVAs kAllocRVAs_1_16_242 = { 0x002B80C0, 0x022CA370, 0x022C9E00 };

// First 4 bytes of each function's prologue, used to detect address drift.
constexpr std::uint8_t kAllocContextProl[4] = { 0x48, 0x83, 0xEC, 0x28 };
constexpr std::uint8_t kAllocFnProl[4]      = { 0x44, 0x88, 0x4C, 0x24 };
constexpr std::uint8_t kFreeFnProl[4]       = { 0x48, 0x89, 0x5C, 0x24 };

[[nodiscard]] const AllocRVAs* PickAllocRVAs()
{
    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    if (ver == SFSE::RUNTIME_SF_1_16_236) return &kAllocRVAs_1_16_236;
    if (ver == SFSE::RUNTIME_SF_1_16_242) return &kAllocRVAs_1_16_242;
    return nullptr;
}

[[nodiscard]] bool BethesdaAllocAvailable()
{
    static const auto check = []() {
        const auto* rvas = PickAllocRVAs();
        if (!rvas) return false;
        // Byte-verify each function's prologue lives at the expected RVA.
        // If any check fails, fall back to malloc (safer than calling into
        // possibly-different code).
        auto check_bytes = [](std::uintptr_t rva, const std::uint8_t (&want)[4]) {
            const auto addr = REL::Offset(rva).address();
            const auto* p = reinterpret_cast<const std::uint8_t*>(addr);
            return std::memcmp(p, want, 4) == 0;
        };
        const bool ok =
            check_bytes(rvas->allocContext, kAllocContextProl) &&
            check_bytes(rvas->alloc,        kAllocFnProl) &&
            check_bytes(rvas->free,         kFreeFnProl);
        if (!ok) {
            logger::warn("BethesdaAlloc: prologue mismatch — falling back to malloc");
        }
        return ok;
    }();
    return check;
}

[[nodiscard]] void* BethesdaAlloc(std::size_t a_size)
{
    static const auto* rvas  = PickAllocRVAs();
    static const auto getCtx = reinterpret_cast<GetAllocContext_t>(
        REL::Offset(rvas->allocContext).address());
    static const auto alloc  = reinterpret_cast<AllocFn_t>(
        REL::Offset(rvas->alloc).address());
    auto* ctx = getCtx();
    return alloc(ctx, a_size, 0, 0);
}

void BethesdaFree(void* a_ptr)
{
    static const auto* rvas = PickAllocRVAs();
    static const auto freeFn = reinterpret_cast<FreeFn_t>(
        REL::Offset(rvas->free).address());
    freeFn(a_ptr);
}

}  // namespace

[[nodiscard]] void* EngineAlloc(std::size_t a_size)
{
    if (BethesdaAllocAvailable()) return BethesdaAlloc(a_size);
    return std::malloc(a_size);
}

void EngineFree(void* a_ptr)
{
    if (!a_ptr) return;
    if (BethesdaAllocAvailable()) BethesdaFree(a_ptr);
    else std::free(a_ptr);
}

[[nodiscard]] std::filesystem::path PluginPath(const RE::TESFile* a_file)
{
    return std::filesystem::path("Data") /
           std::string(cog::sf::GetFileName(a_file));
}

}  // namespace

// ── CellOffsetFile — .fco read/write ────────────────────────────────────────
// Header layout matches WallSoGB's NVSE format byte-for-byte; the offsets
// payload changed in v2 — see FILE_VERSION below for the off-by-one fix.
//
//   Header { u32 magic='FCOF'; u32 version=2; u64 fileHash; }
//   Data   { u64 offsetHash; u32 offsetCount; u32 offsets[offsetCount]; }
//
// offsetCount == UINT32_MAX is the "world is empty for this plugin" sentinel.
// Only v2 caches are accepted; v1 files (NVSE / F4 port at time of writing)
// are rejected by LoadHeader() since the count semantics differ.

class CellOffsetFile {
public:
    static constexpr std::uint32_t MAGIC_NUMBER = 'FCOF';
    // v1: NVSE / F4-port layout. `offsetCount = GetIndexForCellCoord(maxX,
    //     maxY)` — equal to (width * height - 1), one slot short of the
    //     full grid. The corner cell at (maxX, maxY) was silently dropped
    //     by the bounds check `uiKey < uiOffsetCount`.
    // v2: full grid. `offsetCount = (maxX-minX+1) * (maxY-minY+1)`. The
    //     bug also exists in F4 / NVSE; fixed here in line with the Skyrim
    //     port's v2/v3 fix.
    static constexpr std::uint32_t FILE_VERSION = 2;

    enum ErrorCode : std::uint32_t {
        SUCCESS         = 0,
        EMPTY_FILE,
        WRONG_FILE,
        HASH_MISMATCH,
        EMPTY_WORLD,
        READ_FAIL,
        UNKNOWN         = UINT32_MAX,
    };

    struct Header {
        std::uint32_t uiHeaderID  = MAGIC_NUMBER;
        std::uint32_t uiVersion   = FILE_VERSION;
        XXH64_hash_t  ullFileHash = 0;
    };

    struct Data {
        XXH64_hash_t   ullOffsetHash = 0;
        std::uint32_t  uiOffsetCount = 0;
        std::uint32_t* pOffsets      = nullptr;
    };

    CellOffsetFile(const char* a_name, std::uint32_t a_access, std::uint32_t a_open) {
        hFile = CreateFileA(a_name, a_access, FILE_SHARE_READ, nullptr, a_open,
                            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    }
    ~CellOffsetFile() {
        if (IsValid()) CloseHandle(hFile);
    }

    HANDLE hFile;
    Header kHeader;
    Data   kData;

    [[nodiscard]] bool IsValid() const { return hFile != INVALID_HANDLE_VALUE; }

    void FillData(const XXH64_hash_t& a_fileHash, std::uint32_t a_offsetCount,
                  std::uint32_t* a_offsets) {
        kHeader.ullFileHash = a_fileHash;
        kData.uiOffsetCount = a_offsetCount;
        kData.pOffsets      = a_offsets;
    }

    ErrorCode LoadHeader(XXH64_hash_t a_expectedHash) {
        std::uint64_t fileSize = 0;
        if (!GetSize(fileSize) || !fileSize) return EMPTY_FILE;

        std::uint32_t bytesRead = 0;
        if (!Read(&kHeader, sizeof(kHeader), bytesRead)) return UNKNOWN;
        if (bytesRead != sizeof(kHeader) || kHeader.uiHeaderID != MAGIC_NUMBER ||
            kHeader.uiVersion != FILE_VERSION) {
            return WRONG_FILE;
        }
        return (kHeader.ullFileHash == a_expectedHash) ? SUCCESS : HASH_MISMATCH;
    }

    ErrorCode LoadData(XXH3_state_t* a_state) {
        std::uint32_t bytesRead = 0;
        Read(&kData.ullOffsetHash, sizeof(kData.ullOffsetHash), bytesRead);
        Read(&kData.uiOffsetCount, sizeof(kData.uiOffsetCount), bytesRead);

        if (kData.uiOffsetCount == UINT32_MAX) [[unlikely]] return EMPTY_WORLD;
        if (kData.uiOffsetCount > kMaxReasonableTableSize) return READ_FAIL;

        const auto byteSize = static_cast<std::size_t>(kData.uiOffsetCount) *
                              sizeof(std::uint32_t);
        kData.pOffsets = static_cast<std::uint32_t*>(EngineAlloc(byteSize));
        if (!kData.pOffsets) return READ_FAIL;

        std::uint32_t payloadBytesRead = 0;
        if (!Read(kData.pOffsets, static_cast<std::uint32_t>(byteSize), payloadBytesRead) ||
            payloadBytesRead != byteSize) [[unlikely]] {
            EngineFree(kData.pOffsets);
            kData.pOffsets = nullptr;
            return READ_FAIL;
        }

        const auto computed = HashOffsets(a_state, kData.pOffsets, kData.uiOffsetCount);
        if (kData.ullOffsetHash != computed) [[unlikely]] {
            EngineFree(kData.pOffsets);
            kData.pOffsets = nullptr;
            return HASH_MISMATCH;
        }
        return SUCCESS;
    }

    void SaveHeader() {
        std::uint32_t written = 0;
        Write(&kHeader, sizeof(kHeader), written);
    }

    void SaveData(XXH3_state_t* a_state) {
        std::uint32_t written = 0;
        if (kData.uiOffsetCount != UINT32_MAX) {
            const std::uint32_t bytes =
                sizeof(std::uint32_t) * kData.uiOffsetCount;
            kData.ullOffsetHash =
                HashOffsets(a_state, kData.pOffsets, kData.uiOffsetCount);
            Write(&kData.ullOffsetHash, sizeof(kData.ullOffsetHash), written);
            Write(&kData.uiOffsetCount, sizeof(kData.uiOffsetCount), written);
            Write(kData.pOffsets, bytes, written);
        } else {
            Write(&kData.ullOffsetHash, sizeof(kData.ullOffsetHash), written);
            Write(&kData.uiOffsetCount, sizeof(kData.uiOffsetCount), written);
        }
    }

    static bool ReadOffsets(const char* a_filePath, XXH64_hash_t a_hash,
                            XXH3_state_t* a_state, RE::TESFile* a_file,
                            RE::TESWorldSpace* a_world,
                            cog::sf::OFFSET_DATA* a_data) {
        CellOffsetFile kFile(a_filePath, GENERIC_READ, OPEN_EXISTING);
        if (!kFile.IsValid()) return false;

        const auto status = kFile.LoadHeader(a_hash);
        if (status != SUCCESS) {
            if (status == EMPTY_FILE) {
                logger::warn("ReadOffsets - File {} is empty", a_filePath);
            } else if (status == HASH_MISMATCH) {
                logger::info(
                    "ReadOffsets - Hash mismatch for {}, expected {:016X}, got {:016X}",
                    a_filePath, a_hash, kFile.kHeader.ullFileHash);
            }
            return false;
        }

        const auto data = kFile.LoadData(a_state);
        if (data == SUCCESS) {
            a_data->pCellFileOffsets = kFile.kData.pOffsets;
            return true;
        }
        if (data == EMPTY_WORLD) {
            logger::info("ReadOffsets - World {} in file {} is empty",
                         cog::sf::GetWorldEditorID(a_world),
                         cog::sf::GetFileName(a_file));
            return true;
        }
        if (data == READ_FAIL) {
            logger::warn("ReadOffsets - Failed to read {} offsets from {}",
                         kFile.kData.uiOffsetCount, a_filePath);
        } else if (data == HASH_MISMATCH) {
            logger::info("ReadOffsets - Hash mismatch for {}! Plugin has changed cell data.",
                         a_filePath);
        }
        return false;
    }

    static void SaveOffsets(const char* a_folderPath, const char* a_filePath,
                            XXH64_hash_t a_hash, XXH3_state_t* a_state,
                            std::uint32_t* a_offsets, std::uint32_t a_count) {
        CreateDirectoryA(a_folderPath, nullptr);
        CellOffsetFile kFile(a_filePath, GENERIC_WRITE, CREATE_ALWAYS);
        if (!kFile.IsValid()) {
            logger::warn("SaveOffsets - Failed to create file {}", a_filePath);
            return;
        }
        kFile.FillData(a_hash, a_count, a_offsets);
        kFile.SaveHeader();
        kFile.SaveData(a_state);
    }

private:
    BOOL Read(void* a_buf, std::uint32_t a_size, std::uint32_t& a_read) {
        return ReadFile(hFile, a_buf, a_size,
                        reinterpret_cast<LPDWORD>(&a_read), nullptr);
    }

    BOOL Write(const void* a_buf, std::uint32_t a_size, std::uint32_t& a_written) {
        return WriteFile(hFile, a_buf, a_size,
                         reinterpret_cast<LPDWORD>(&a_written), nullptr);
    }

    BOOL GetSize(std::uint64_t& a_out) const {
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(hFile, &li)) return FALSE;
        a_out = static_cast<std::uint64_t>(li.QuadPart);
        return TRUE;
    }
};

namespace {
// Forward decl — defined later in this TU (top-level anonymous namespace, so
// it merges with the definition). The disk-scan generator producing byte-exact
// OFST+CLSZ, fed the real TESFiles from each worldspace's offsetDataMap.
// a_objectIdToWorld (optional): maps file-local objectID (formID & 0xFFFFFF) to
// the runtime worldspace, so mod formIDs (load-order remapped) match correctly.
void CreateOffsetsForFile(RE::TESFile* a_ownerFile, RE::TESFile* a_workerFile,
                          XXH3_state_t* a_state,
                          const std::unordered_map<std::uint32_t, RE::TESWorldSpace*>*
                              a_objectIdToWorld = nullptr);
}

void OffsetGenerator::GenerateAllOnMainThread()
{
    using namespace cog::sf;

    if (!RuntimeHasEngineAddresses()) {
        logger::warn("GenerateAllOnMainThread: no engine addresses for this runtime — skipping");
        return;
    }
    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) { logger::warn("GenerateAllOnMainThread: TESDataHandler null"); return; }

    const auto& worldArray = dh->formArrays[std::to_underlying(RE::FormType::kWRLD)];
    logger::info("GenerateAllOnMainThread: scanning {} worldspaces (main thread, engine calls)",
                 worldArray.formArray.size());

    // Each TESWorldSpace's offsetDataMap is a BSTScatterTable keyed by TESFile*:
    //   world+0x280 = entries base, world+0x288 = capacity (slot count).
    //   entry stride 0x18: {TESFile* key@0x00, OFFSET_DATA* val@0x08, i32 ctrl@0x10}
    //   ctrl == -1 marks an empty slot. (Verified via GetOffsetData decompile
    //   FUN_140bc1c80 + the scatter-table lookup FUN_140349f60.)
    constexpr std::uintptr_t kEntriesOff = 0x280;
    constexpr std::uintptr_t kCapacityOff = 0x288;
    constexpr std::size_t    kEntryStride = 0x18;

    // Pass 1: walk every worldspace's offsetDataMap. For each REAL TESFile,
    // build a map objectID(formID & 0xFFFFFF) → runtime worldspace covering ALL
    // worlds that file contributes to. The disk-scan reads file-LOCAL formIDs
    // (high byte = the plugin's own master-table index), but a plugin's own /
    // overridden worlds keep the same low-24 object index at runtime — only the
    // load-order high byte changes. So matching by objectID maps file-local →
    // runtime correctly, per-file (no cross-file collisions). These map keys
    // are genuine TESFile pointers (engine-inserted), so GetFileName resolves.
    std::uint32_t pairsSeen = 0, worldsWithFiles = 0, alreadyHad = 0, skippedEmpty = 0;
    std::unordered_map<RE::TESFile*,
                       std::unordered_map<std::uint32_t, RE::TESWorldSpace*>> fileWorlds;
    std::unordered_set<RE::TESFile*> filesNeedingGen;  // files with ≥1 world missing OFST
    for (auto& formPtr : worldArray.formArray) {
        auto* world = static_cast<RE::TESWorldSpace*>(formPtr.get());
        if (!world) continue;
        const auto* ws = reinterpret_cast<const std::uint8_t*>(world);
        const auto entries  = *reinterpret_cast<const std::uintptr_t*>(ws + kEntriesOff);
        const auto capacity = *reinterpret_cast<const std::uint64_t*>(ws + kCapacityOff);
        if (entries == 0 || capacity == 0 || capacity > 100000) continue;
        bool counted = false;
        for (std::uint64_t i = 0; i < capacity; ++i) {
            const auto* e = reinterpret_cast<const std::uint8_t*>(entries + i * kEntryStride);
            if (*reinterpret_cast<const std::int32_t*>(e + 0x10) == -1) continue;  // empty
            auto* file  = *reinterpret_cast<RE::TESFile* const*>(e + 0x00);
            auto* pData = *reinterpret_cast<OFFSET_DATA* const*>(e + 0x08);
            if (!file || !pData) continue;
            ++pairsSeen;
            if (!counted) { ++worldsWithFiles; counted = true; }
            fileWorlds[file].emplace(world->GetFormID() & 0x00FFFFFFu, world);
            // A file needs scanning only if it has a world WITHOUT OFST that is
            // also actually fast-pathable. The engine's GetIndexForCellCoord
            // reads pData's bounds (offsetMin/MaxCoords); a world with unset
            // (all-zero) or inverted bounds is an empty/no-NAM worldspace the
            // engine can never fast-path, so generating for it is pointless.
            // Skipping these stops a single spurious empty world from dragging
            // the intact 1.46 GB base master into a full scan that produces
            // nothing (generated=0).
            if (pData->pCellFileOffsets) { ++alreadyHad; continue; }
            const float minX = pData->offsetMinCoords.x, minY = pData->offsetMinCoords.y;
            const float maxX = pData->offsetMaxCoords.x, maxY = pData->offsetMaxCoords.y;
            const bool boundsUnset    = (minX == 0.0f && minY == 0.0f &&
                                         maxX == 0.0f && maxY == 0.0f);
            const bool boundsInverted = (maxX < minX) || (maxY < minY);
            if (boundsUnset || boundsInverted) { ++skippedEmpty; continue; }
            filesNeedingGen.insert(file);
        }
    }

    // Pass 2: disk-scan each file that needs it ONCE → byte-exact OFST+CLSZ for
    // its worlds, matched via the per-file objectID map. Files whose worlds all
    // already have engine-loaded OFST are skipped (not scanned).
    logger::info("GenerateAllOnMainThread: {} worldspaces, {} pairs, {} alreadyHad, "
                 "{} skippedEmpty, {} files need generation (of {} total contributing)",
                 worldArray.formArray.size(), pairsSeen, alreadyHad, skippedEmpty,
                 filesNeedingGen.size(), fileWorlds.size());
    for (auto* file : filesNeedingGen) {
        CreateOffsetsForFile(file, file, nullptr, &fileWorlds[file]);
    }
    logger::info("GenerateAllOnMainThread: done — worldsWithFiles={} pairs={} "
                 "alreadyHad={} filesScanned={}",
                 worldsWithFiles, pairsSeen, alreadyHad, filesNeedingGen.size());
}

void OffsetGenerator::InitHooks()
{
    // ── Verified patch sites for Starfield 1.14.70 / 1.14.74 ──────────────
    //
    // Each entry NOPs a JZ that follows a `TEST byte ptr [file+0x1B8], 1`
    // (the IsMaster check). Two categories:
    //
    // 1. Write-side gates inside Load_Impl / LoadPartial — ESPs need their
    //    NAM0/NAM9 (min/max cell coord) chunks to actually populate
    //    OFFSET_DATA. Without these patches, GetIndexForCellCoord
    //    degenerates to OOB on ESPs and the cache is unusable.
    //
    // 2. Read-side gate at the entry of TESWorldSpace::FindCellInFile —
    //    even after the writes succeed and our generator populates
    //    pCellFileOffsets, the engine's runtime cell resolver gates the
    //    fast path on IsMaster (line 141A4AAE3 below). Without this patch
    //    the engine slow-paths every cell access on ESPs, defeating the
    //    cache. NOP-safe because the function still null-checks the file
    //    (the previous JZ at 141A4AADA) and still checks GetOffsetData /
    //    pCellFileOffsets for null (falls back to slow path if our
    //    generator hasn't built the cache for this file).
    //
    // Starfield's OFST chunk handler itself is NOT IsMaster-gated — ESPs
    // already load saved OFST through the engine's normal path, so no patch
    // is needed there.

    struct PatchSite {
        std::uintptr_t address_abs;
        std::size_t    length;
        const char*    name;
        std::uint8_t   expected[6];
    };

    // Per-version patch tables. 1.14.70 is the verified-from-Ghidra reference;
    // 1.14.74 is derived by adding +0x90 to every address (the uniform shift
    // observed across the entire [0x1A48000, 0x1A50000] region between the
    // two versionlib bins — see _addrlib_extract). The byte verification
    // step below provides a safety net in case any function body in our
    // region differs between the two versions despite the consistent shift.
    constexpr PatchSite kSitesSF_1_14_70[] = {
        // Load_Impl (Unk_12 @ 0x141A4D65C) — write-side
        // .fileOffset gates the very first OFFSET_DATA write at function entry:
        //   pData->fileOffset = file_clone->cursor (file+0x390)
        // Without this, ESPs get pData->fileOffset = 0; per-cell deltas would
        // still seek to the right absolute offset (since delta = absolute - 0
        // = absolute, and seek = 0 + delta = absolute), but RebaseOffsetTable
        // and any other code that adds to pData->fileOffset would land in
        // the wrong place. Match the F4/Skyrim ports' coverage by NOPing it.
        { 0x141A4D6D6, 2, "Load.fileOffset",  { 0x74, 0x19 } },
        { 0x141A4D880, 6, "Load.NAM0",        { 0x0F, 0x84, 0x24, 0x09, 0x00, 0x00 } },
        { 0x141A4D910, 6, "Load.NAM9",        { 0x0F, 0x84, 0x94, 0x08, 0x00, 0x00 } },
        // LoadPartial (Unk_13 @ 0x141A4EEB4) — write-side
        { 0x141A4EF5B, 6, "LoadPartial.NAM0", { 0x0F, 0x84, 0xAD, 0x00, 0x00, 0x00 } },
        { 0x141A4EFE0, 2, "LoadPartial.NAM9", { 0x74, 0x2C } },
        // FindCellInFile (0x141A4AAA0) — read-side; this is the gate that
        // makes ESPs actually USE the cache we built.
        { 0x141A4AAE3, 2, "FindCellInFile.IsMaster", { 0x74, 0x59 } },
        // FindInFileFast (0x141A4ACD8) — separate per-file fast WRLD locator
        // that Ghidra RTTI auto-named "AddChange" but the body matches F4/
        // Skyrim's FindInFileFast: GetOffsetData → if IsMaster && fileOffset
        // != 0 && Seek+'V'-magic+formID-match → return true. NOPing the
        // IsMaster gate lets ESPs reach the rest of the checks; the formID
        // and 'V'-byte verifications make this safe even on bogus state.
        // Depends on Load.fileOffset above being applied (otherwise the
        // pData->fileOffset != 0 check fails for ESPs).
        { 0x141A4ACF4, 2, "FindInFileFast.IsMaster", { 0x74, 0x37 } },
    };

    constexpr PatchSite kSitesSF_1_14_74[] = {
        { 0x141A4D6D6 + 0x90, 2, "Load.fileOffset",  { 0x74, 0x19 } },
        { 0x141A4D880 + 0x90, 6, "Load.NAM0",        { 0x0F, 0x84, 0x24, 0x09, 0x00, 0x00 } },
        { 0x141A4D910 + 0x90, 6, "Load.NAM9",        { 0x0F, 0x84, 0x94, 0x08, 0x00, 0x00 } },
        { 0x141A4EF5B + 0x90, 6, "LoadPartial.NAM0", { 0x0F, 0x84, 0xAD, 0x00, 0x00, 0x00 } },
        { 0x141A4EFE0 + 0x90, 2, "LoadPartial.NAM9", { 0x74, 0x2C } },
        { 0x141A4AAE3 + 0x90, 2, "FindCellInFile.IsMaster", { 0x74, 0x59 } },
        { 0x141A4ACF4 + 0x90, 2, "FindInFileFast.IsMaster", { 0x74, 0x37 } },
    };

    // ── Starfield 1.16.236 — TBD, awaiting Ghidra ─────────────────────────
    // Each entry needs three pieces from the Ghidra session on the
    // 1.16.236 build of Starfield.exe:
    //
    //   • address_abs : the absolute VA of the JZ (short or near) that
    //     gates this site on the IsMaster bit (or, for Load.fileOffset,
    //     the short JZ over the .fileOffset write at function entry).
    //   • length      : 2 for `74 ??` short-JZ, 6 for `0F 84 ?? ?? ?? ??`
    //     near-JZ. Don't change this without re-decompiling the site.
    //   • expected    : the literal bytes currently at address_abs. Used
    //     by InitHooks as a safety check before NOPing — if the runtime
    //     bytes don't match what we recorded here, the patch is skipped
    //     and an error is logged.
    //
    // The names (Load.fileOffset, Load.NAM0, …) are stable across versions:
    // they describe which engine code path the gate sits in, not the byte
    // pattern. After 1.14.74 → 1.15.216 the function bodies were rewritten
    // enough that byte signatures from 1.14.x can't be expected to match;
    // every field needs independent verification on 1.16.236.
    //
    // Until populated, kSitesSF stays empty for 1.16.236 and InitHooks
    // logs "no NOP sites configured for runtime 1.16.236" then returns —
    // plugin loads, generator runs no-op.
    // ✅ Verified via GhidrAssistMCP against Starfield.exe 1.16.236.0
    //    (Steamless build at C:/Games/Starfield 1.7/Starfield.exe).
    //    Function entry points:
    //      • Load_Impl       = 0x140BB6740
    //      • LoadPartial     = 0x140BB6430
    //      • FindCellInFile  = 0x140BBA370
    //      • FindInFileFast  = 0x140BBA6D0  (the function Ghidra RTTI
    //        auto-names "AddChange" on F4/Skyrim; the body matches
    //        F4/Skyrim's FindInFileFast — GetOffsetData → IsMaster &&
    //        fileOffset!=0 && Seek + verify 'V' magic + formID match).
    //    Each IsMaster test instruction is `test byte ptr [reg+0x1B8], 1`
    //    (7 bytes, `F6 ?? B8 01 00 00 01`) followed immediately by the
    //    JZ patch site recorded here.
    constexpr PatchSite kSitesSF_1_16_236[] = {
        // Load_Impl.fileOffset: at function entry, gates the write of
        // file->cursorOffset (file+0x3A0 in 1.16.236, was file+0x390 in
        // 1.14.x) into OFFSET_DATA+0x20.
        { 0x140BB6827, 2, "Load.fileOffset",  { 0x74, 0x19 } },
        // Load_Impl NAM0 IsMaster gate — near JZ +0x3F8 over the
        // GetOrCreateOffsetData + min-coords write block.
        { 0x140BB6C08, 6, "Load.NAM0",        { 0x0F, 0x84, 0xF8, 0x03, 0x00, 0x00 } },
        // Load_Impl NAM9 IsMaster gate — near JZ with BACKWARD displacement
        // (-0x2A8) to a common loop-continuation label at 0x140BB7006.
        // Compiler put the OFFSET_DATA write inline after the gate, with
        // the "skip" target backward; semantically still "if !master, skip".
        { 0x140BB72A8, 6, "Load.NAM9",        { 0x0F, 0x84, 0x58, 0xFD, 0xFF, 0xFF } },
        // LoadPartial NAM0 IsMaster gate — short JZ +0x30 over the write block.
        { 0x140BB66BE, 2, "LoadPartial.NAM0", { 0x74, 0x30 } },
        // LoadPartial NAM9 IsMaster gate — near JZ +0x13B (NAM9 handler in
        // LoadPartial is laid out inline before the NAM0 handler block).
        { 0x140BB65AF, 6, "LoadPartial.NAM9", { 0x0F, 0x84, 0x3B, 0x01, 0x00, 0x00 } },
        // FindCellInFile fast-path IsMaster gate — short JZ +0x65 to the
        // slow-path scanner. NOPing lets ESPs use the cached cell offsets.
        { 0x140BBA3A5, 2, "FindCellInFile.IsMaster", { 0x74, 0x65 } },
        // FindInFileFast IsMaster gate — short JZ +0x40 to the
        // "return false" tail. Lets the rest of the checks (fileOffset!=0,
        // 'V' chunk magic, formID match) gate WRLD lookups for ESPs.
        { 0x140BBA6EC, 2, "FindInFileFast.IsMaster", { 0x74, 0x40 } },
    };

    // 1.16.242 — derived from the 1.16.236 table by remapping each site's
    // containing function through its address-library ID (each function is
    // byte-identical in size between versionlib-1-16-236-0.bin and
    // versionlib-1-16-242-0.bin, so the in-function offset of every gate is
    // unchanged and the expected bytes — including relative-JZ displacements —
    // are identical). Per-function shifts: Load_Impl/LoadPartial/FindCellInFile/
    // FindInFileFast all +0x1C0. Byte-verify guard below still applies.
    constexpr PatchSite kSitesSF_1_16_242[] = {
        { 0x140BB69E7, 2, "Load.fileOffset",  { 0x74, 0x19 } },
        { 0x140BB6DC8, 6, "Load.NAM0",        { 0x0F, 0x84, 0xF8, 0x03, 0x00, 0x00 } },
        { 0x140BB7468, 6, "Load.NAM9",        { 0x0F, 0x84, 0x58, 0xFD, 0xFF, 0xFF } },
        { 0x140BB687E, 2, "LoadPartial.NAM0", { 0x74, 0x30 } },
        { 0x140BB676F, 6, "LoadPartial.NAM9", { 0x0F, 0x84, 0x3B, 0x01, 0x00, 0x00 } },
        { 0x140BBA565, 2, "FindCellInFile.IsMaster", { 0x74, 0x65 } },
        { 0x140BBA8AC, 2, "FindInFileFast.IsMaster", { 0x74, 0x40 } },
    };

    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    std::span<const PatchSite> kSitesSF{};
    if      (ver == SFSE::RUNTIME_SF_1_14_70)  kSitesSF = kSitesSF_1_14_70;
    else if (ver == SFSE::RUNTIME_SF_1_14_74)  kSitesSF = kSitesSF_1_14_74;
    else if (ver == SFSE::RUNTIME_SF_1_16_236) kSitesSF = kSitesSF_1_16_236;
    else if (ver == SFSE::RUNTIME_SF_1_16_242) kSitesSF = kSitesSF_1_16_242;

    if (kSitesSF.empty() || kSitesSF.front().address_abs == 0) {
        logger::warn("Patches: no NOP sites configured for runtime {} — "
                     "supported: 1.14.70, 1.14.74, 1.16.236, 1.16.242.",
                     ver.string());
        return;
    }

    constexpr std::uintptr_t kExpectedImageBase = 0x140000000;
    const auto base = REX::FModule::GetExecutingModule().GetBaseAddress();

    int applied = 0;
    for (const auto& site : kSitesSF) {
        const auto offset = site.address_abs - kExpectedImageBase;
        const auto target = reinterpret_cast<std::uint8_t*>(base + offset);
        bool ok = true;
        for (std::size_t i = 0; i < site.length; ++i) {
            if (target[i] != site.expected[i]) {
                logger::error("[{}] expected byte {:02X} at +{:X}, got {:02X} — refusing to patch",
                              site.name, site.expected[i], offset + i, target[i]);
                ok = false;
                break;
            }
        }
        if (ok) {
            REL::WriteSafeFill(reinterpret_cast<std::uintptr_t>(target), 0x90, site.length);
            logger::info("[{}] NOPed {} byte(s) at +{:X}", site.name, site.length, offset);
            ++applied;
        }
    }

    logger::info("CellOffsetGenerator: {}/{} patch sites applied", applied, std::size(kSitesSF));
}

namespace {

void CreateOffsetsForFile(RE::TESFile* a_ownerFile,
                          RE::TESFile* a_workerFile,
                          XXH3_state_t* a_state,
                          const std::unordered_map<std::uint32_t, RE::TESWorldSpace*>*
                              a_objectIdToWorld)
{
    using namespace cog::sf;

    // Resolve the owning plugin's name. The file we scan must match the
    // TESFile key whose OFFSET_DATA we mutate; using a different fallback file
    // would install valid offsets into the wrong plugin table.
    auto ownerName = cog::sf::GetFileName(a_ownerFile);
    if (ownerName.empty()) {
        logger::warn("CreateOffsetsForFile: could not resolve plugin name for owner={} — skipping",
                     static_cast<const void*>(a_ownerFile));
        return;
    }
    logger::info("CreateOffsetsForFile: enter owner={} ({}) worker={}",
                 static_cast<const void*>(a_ownerFile),
                 std::string(ownerName),
                 static_cast<const void*>(a_workerFile));

    (void)a_state;

    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        logger::warn("CreateOffsetsForFile: TESDataHandler null");
        return;
    }
    (void)a_workerFile;

    // ── File-scan generation path ─────────────────────────────────────────
    // SF 1.16.236's engine functions (FindCellInFile, GetIndexForCellCoord)
    // crash when called from any thread that isn't the engine main thread —
    // their internal TESFile::vtable[1] dispatch returns a clone with a
    // NULL vtable slot, and the engine's chain-walk then dereferences it.
    // We side-step that entirely by parsing the plugin file ourselves to
    // discover exterior cell coords + record offsets, then writing the
    // resulting tables directly into OFFSET_DATA. GetOrCreateOffsetData is
    // safe (it has its own thread-context prelude).
    //
    const std::filesystem::path pluginPath =
        std::filesystem::path("Data") / std::string(ownerName);
    const std::filesystem::path cachePath =
        std::filesystem::path("Data") / "CellOffsets" /
        (std::string(ownerName) + ".psc");

    ScanResult scan;

    // Hash the plugin and try the cache first. Subsequent launches with the
    // same file skip the multi-second walk.
    const auto pluginHash = HashPluginFile(pluginPath);
    if (pluginHash != 0 && LoadScanCache(cachePath, pluginHash, scan)) {
        logger::info("Scan cache hit: {} cells across {} worldspaces (hash={:#x})",
                     scan.cells.size(), scan.worlds.size(), pluginHash);
    } else {
        scan.cells.clear();
        scan.worlds.clear();
        if (!ScanPluginFile(pluginPath, scan)) {
            logger::warn("CreateOffsetsForFile: scan failed for {}",
                         pluginPath.string());
            return;
        }
        logger::info("Scan: {} exterior cells across {} worldspaces (hash={:#x})",
                     scan.cells.size(), scan.worlds.size(), pluginHash);
        if (pluginHash != 0) {
            if (!SaveScanCache(cachePath, pluginHash, scan)) {
                logger::warn("Failed to write cache to {}", cachePath.string());
            }
        }
    }

    // Build formID → TESWorldSpace* map once.
    const auto& worldArray =
        dh->formArrays[std::to_underlying(RE::FormType::kWRLD)];
    std::unordered_map<std::uint32_t, RE::TESWorldSpace*> worldByFormID;
    worldByFormID.reserve(worldArray.formArray.size());
    for (auto& formPtr : worldArray.formArray) {
        auto* w = static_cast<RE::TESWorldSpace*>(formPtr.get());
        if (w) worldByFormID.emplace(w->GetFormID(), w);
    }

    // Group cells by worldspace for fast per-world iteration.
    std::unordered_map<std::uint32_t, std::vector<const ScannedCell*>> cellsByWorld;
    cellsByWorld.reserve(scan.worlds.size());
    for (const auto& c : scan.cells) {
        cellsByWorld[c.worldFormID].push_back(&c);
    }

    std::uint32_t dbgGenerated = 0, dbgNoWorld = 0, dbgNoData = 0;
    std::uint32_t dbgEmpty = 0, dbgAlreadyHas = 0;
    int           dbgLogged = 0;

    for (const auto& [formID, scannedWorld] : scan.worlds) {
        // The engine's GetIndexForCellCoord uses pData->offsetMin/MaxCoords
        // (set by NAM0/NAM9 handlers when the engine lazily walks the WRLD).
        // To match that index math, our table MUST be sized to NAM0/NAM9
        // bounds. XCLC-observed bounds are smaller (cells without records)
        // and using them produces a too-small table → engine reads OOB on
        // every fast-path hit → garbage offset → catastrophic slow recovery.
        std::int32_t boundsMinX, boundsMinY, boundsMaxX, boundsMaxY;
        if (scannedWorld.hasNam) {
            boundsMinX = scannedWorld.nam0CellX;
            boundsMinY = scannedWorld.nam0CellY;
            boundsMaxX = scannedWorld.nam9CellX;
            boundsMaxY = scannedWorld.nam9CellY;
        } else {
            // Fallback: WRLD record had no NAM0/NAM9 (or was compressed and
            // we couldn't read it). Use XCLC-observed bounds. Engine will
            // overwrite these via its NAM handlers if/when the record gets
            // walked, but at least we contribute something for ESPs that
            // don't carry NAM bounds.
            boundsMinX = scannedWorld.xclcMinX;
            boundsMinY = scannedWorld.xclcMinY;
            boundsMaxX = scannedWorld.xclcMaxX;
            boundsMaxY = scannedWorld.xclcMaxY;
        }

        if (boundsMinX > boundsMaxX || boundsMinY > boundsMaxY) {
            ++dbgEmpty;
            continue;
        }
        // Resolve the runtime worldspace. Prefer the per-file objectID map
        // (handles mod load-order formID remapping); fall back to exact formID.
        RE::TESWorldSpace* world = nullptr;
        if (a_objectIdToWorld) {
            auto oit = a_objectIdToWorld->find(formID & 0x00FFFFFFu);
            if (oit != a_objectIdToWorld->end()) world = oit->second;
        }
        if (!world) {
            auto it = worldByFormID.find(formID);
            if (it != worldByFormID.end()) world = it->second;
        }
        if (!world) { ++dbgNoWorld; continue; }

        auto* pData = GetOrCreateOffsetData(world, a_ownerFile);
        if (!pData) { ++dbgNoData; continue; }
        if (pData->pCellFileOffsets) { ++dbgAlreadyHas; continue; }

        const auto width  = static_cast<std::uint32_t>(boundsMaxX - boundsMinX + 1);
        const auto height = static_cast<std::uint32_t>(boundsMaxY - boundsMinY + 1);
        const auto cellCount = width * height;
        if (cellCount == 0 || cellCount > kMaxReasonableTableSize) {
            ++dbgEmpty;
            continue;
        }

        const auto byteSize = static_cast<std::size_t>(cellCount) * sizeof(std::uint32_t);
        const bool needClsz = (pData->unk08 == 0);
        auto* buf  = static_cast<std::uint32_t*>(EngineAlloc(byteSize));   // OFST
        auto* clsz = needClsz
                         ? static_cast<std::uint32_t*>(EngineAlloc(byteSize))
                         : nullptr;                                       // CLSZ
        if (!buf || (needClsz && !clsz)) {
            if (buf)  EngineFree(buf);
            if (clsz) EngineFree(clsz);
            ++dbgNoData; continue;
        }
        std::memset(buf,  0, byteSize);
        if (clsz) std::memset(clsz, 0, byteSize);

        // Anchor pData->fileOffset at the WRLD record so per-cell deltas
        // stay positive. Engine reads via:
        //   absolutePos = pCellFileOffsets[idx] + pData->fileOffset
        pData->fileOffset = scannedWorld.wrldFileOffset;
        pData->offsetMinCoords.x = static_cast<float>(boundsMinX * 100);
        pData->offsetMinCoords.y = static_cast<float>(boundsMinY * 100);
        pData->offsetMaxCoords.x = static_cast<float>(boundsMaxX * 100);
        pData->offsetMaxCoords.y = static_cast<float>(boundsMaxY * 100);

        const auto& cellList = cellsByWorld[formID];
        std::uint32_t filled = 0;
        std::uint32_t dropped = 0;
        // COG_ZERO_OFFSETS=1 leaves the buffer all zeros — engine fast path
        // returns false per cell, isolating the per-cell value as the bug.
        if (!cog::sf::bench::IsZeroOffsetsMode()) {
            for (const auto* cell : cellList) {
                // Cells outside the NAM0/NAM9-sized table are intentionally
                // dropped — the engine will fall back to slow scan for those
                // (idx out of range → fast path returns false). Vanilla
                // master plugins shouldn't have any, but being defensive.
                if (cell->x < boundsMinX || cell->x > boundsMaxX ||
                    cell->y < boundsMinY || cell->y > boundsMaxY) {
                    ++dropped;
                    continue;
                }
                const auto idxX = static_cast<std::uint32_t>(cell->x - boundsMinX);
                const auto idxY = static_cast<std::uint32_t>(cell->y - boundsMinY);
                const auto idx  = idxY * width + idxX;
                if (idx >= cellCount) { ++dropped; continue; }
                buf[idx] = cell->fileOffset >= scannedWorld.wrldFileOffset
                               ? cell->fileOffset - scannedWorld.wrldFileOffset
                               : 0;
                // CLSZ entry = total CELL record size (header + payload).
                // Verified against CK's FUN_141defd10 which stores
                // `cellRecord.size + 0x18` per slot. Engine reads this via
                // RE::TESWorldSpace::Unk_12's CLSZ branch into pData->unk08.
                if (clsz) clsz[idx] = cell->recordTotal;
                ++filled;
            }
        }

        // COG_NO_TABLE=1 keeps bounds/fileOffset on pData but never installs the
        // table — engine fast path bails on *plVar7!=0 and slow-scans instead.
        if (!cog::sf::bench::IsNoTableMode()) {
            pData->pCellFileOffsets = buf;
            // Install a synthesized CLSZ buffer only if the engine did not
            // already load one from the file's CLSZ chunk.
            if (clsz) pData->unk08 = reinterpret_cast<std::uint64_t>(clsz);
            // Engine's OFST handler stores the entry count at pData+0x24
            // (our `pad24`) — see disassembly at +0x1A4E1A1:
            //   MOV [R12+0x24], EBX     ; pad24 = count
            // The engine likely uses this for bounds checks against the
            // buffer. We've been leaving it 0 — set it to match.
            pData->pad24 = cellCount;
        } else {
            EngineFree(buf);
            EngineFree(clsz);
        }
        ++dbgGenerated;
        ++uiProcessedWorlds;

        if (dbgLogged++ < 8) {
            logger::info("  world=0x{:08x} bounds=({},{})-({},{}) [{}] cells={}/{} dropped={} "
                         "wrldFileOffset={:#x}",
                         formID, boundsMinX, boundsMinY, boundsMaxX, boundsMaxY,
                         scannedWorld.hasNam ? "NAM" : "XCLC",
                         filled, cellCount, dropped, scannedWorld.wrldFileOffset);
        }
    }

    logger::info("CreateOffsetsForFile: [{}] scanned={} generated={} alreadyHas={} "
                 "noWorld={} noData={} empty={}",
                 std::string(ownerName),
                 scan.worlds.size(), dbgGenerated, dbgAlreadyHas,
                 dbgNoWorld, dbgNoData, dbgEmpty);
}

}  // namespace
