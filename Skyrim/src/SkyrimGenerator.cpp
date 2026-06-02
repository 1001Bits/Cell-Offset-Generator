#include "PCH.h"
#include "SkyrimGenerator.h"

#include "EngineCalls.h"
#include "EngineTypes.h"
#include "Patches.h"
#include "ProgressWindow.h"

#define XXH_INLINE_ALL
#define XXH_ENABLE_AUTOVECTORIZE
#include <xxhash.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <optional>
#include <thread>
#include <unordered_map>
#include <utility>

namespace cog {

namespace {

// ── xxh3 hashing ────────────────────────────────────────────────────────────
//
// Wall keeps these inline at the top of CellOffsetGenerator.cpp; we follow the
// same pattern. Only used here, so no need for a separate translation unit.

[[nodiscard]] std::uint64_t HashBytes(const void* a_data, std::size_t a_size)
{
    return XXH3_64bits(a_data, a_size);
}

// Open a plugin file with the right share flags so we co-exist with
// MO2/USVFS handles, AV on-access scans, and any other process that has
// the .esp open. `std::ifstream` defaults to FILE_SHARE_READ only and
// intermittently failed under heavy concurrent IO on a 914-plugin VR
// Wabbajack. FILE_FLAG_SEQUENTIAL_SCAN matches WallSoGB's NVSE original
// (CellOffsetGenerator.cpp:79).
[[nodiscard]] HANDLE OpenPluginForHash(const std::filesystem::path& a_path)
{
    return CreateFileW(
        a_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
}

// Hash a plugin file. Tries the caller's path first; on
// ERROR_FILE_NOT_FOUND we retry with a relative `Data\<filename>` path,
// because MO2's Wabbajack "Stock Game" pattern uses USVFS to overlay
// mod files into the virtual Data dir and only redirects relative-path
// CreateFileW calls — absolute paths to the same logical target bypass
// the overlay and resolve to the real (mostly empty) Data folder. The
// engine itself uses relative paths so its loads succeed; without the
// fallback our absolute path missed every mod plugin (Mages & Vikings
// modlist reported err=2 for ~500 plugins). The exe-relative absolute
// path remains the primary attempt because Skyrim VR with MO2's USVFS
// leaves cwd as the MO2 profile dir, not the game folder, so a pure
// cwd-relative path fails there.
[[nodiscard]] std::uint64_t HashFile(const std::filesystem::path& a_path,
                                     std::uint32_t* a_winErrorOut = nullptr)
{
    HANDLE handle = OpenPluginForHash(a_path);
    if (handle == INVALID_HANDLE_VALUE) {
        const auto firstErr = GetLastError();
        if (firstErr == ERROR_FILE_NOT_FOUND || firstErr == ERROR_PATH_NOT_FOUND) {
            const auto fallback = std::filesystem::path(L"Data") / a_path.filename();
            handle = OpenPluginForHash(fallback);
        }
        if (handle == INVALID_HANDLE_VALUE) {
            if (a_winErrorOut) {
                *a_winErrorOut = firstErr;
            }
            return 0;
        }
    }

    auto* state = XXH3_createState();
    if (!state) {
        CloseHandle(handle);
        return 0;
    }
    XXH3_64bits_reset(state);

    constexpr DWORD kBufferSize = 64 * 1024;
    std::vector<char> buffer(kBufferSize);
    DWORD read = 0;
    while (ReadFile(handle, buffer.data(), kBufferSize, &read, nullptr) && read > 0) {
        XXH3_64bits_update(state, buffer.data(), read);
    }

    const auto digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    CloseHandle(handle);
    return digest;
}

}  // namespace

std::uint64_t LazyFileHash::Get()
{
    if (!computed) {
        std::uint32_t winError = 0;
        value    = HashFile(path, &winError);
        computed = true;
    }
    return value;
}

namespace {

// Fetch (size, mtime) with a single GetFileAttributesExW (no content read).
// Used as the cache fast-path key; the content xxh3 is the fallback when the
// stamp doesn't match. Tries the caller's path first, then the relative
// `Data\<name>` form for MO2's USVFS "Stock Game" overlay — same fallback
// rationale as HashFile.
[[nodiscard]] FileStamp StatPlugin(const std::filesystem::path& a_path)
{
    auto tryStat = [](const std::filesystem::path& a_p, FileStamp& a_out) {
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(a_p.c_str(), GetFileExInfoStandard, &fad)) {
            return false;
        }
        a_out.size  = (static_cast<std::uint64_t>(fad.nFileSizeHigh) << 32) |
                      fad.nFileSizeLow;
        a_out.mtime = (static_cast<std::uint64_t>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
                      fad.ftLastWriteTime.dwLowDateTime;
        a_out.valid = true;
        return true;
    };

    FileStamp stamp{};
    if (tryStat(a_path, stamp)) {
        return stamp;
    }
    const auto fallback = std::filesystem::path(L"Data") / a_path.filename();
    if (tryStat(fallback, stamp)) {
        return stamp;
    }
    return {};
}

// ── .fco cache file ─────────────────────────────────────────────────────────
//
// .fco — Fallout Cell Offset (we keep the magic for tooling familiarity; the
// layout matches WallSoGB's NVSE format so inspection scripts stay useful as
// a reference).
//
// Layout (all little-endian, no padding):
//   Header { u32 magic='FCOF'; u32 version; u64 fileSize; u64 mtime; u64 fileHash; }
//   Data   { u64 offsetHash; u32 offsetCount; u32 offsets[offsetCount]; }
//
// If offsetCount == UINT32_MAX, the worldspace is empty for this plugin and
// no offset array follows. We still write the record so we can short-circuit
// re-checks on subsequent loads.

constexpr std::uint32_t kCacheMagic    = 'FCOF';
// v1: original layout, offsetCount = (maxX-minX) * (maxY-minY+1) +
//     (maxX-minX) — one slot short of the full grid (corner cell at
//     (maxX, maxY) was silently dropped).
// v2: offsetCount = (maxX-minX+1) * (maxY-minY+1) — full grid. Bumped in
//     v1.4.3 alongside the SkyrimGenerator off-by-one fix.
// v3: bumped in v1.5.4. v1.5.0–v1.5.3 had a generator race in the
//     publish path (check-then-set without CAS, drift handler that
//     wrote stale snapshots back into shared OFFSET_DATA, and a
//     broken -0xC0 engine call on SE) that could persist subtly-wrong
//     offsets into the cache. Forcing a regen on first v1.5.4 launch
//     guarantees every cached table came from the corrected code.
// v4: header gained fileSize + mtime so cache validation can take a
//     fast path (stat-only, no content read) on unchanged plugins. The
//     content hash stays as the fallback when size/mtime don't match.
//     Header layout changed → old caches invalidated.
constexpr std::uint32_t kCacheVersion       = 4;
constexpr std::uint32_t kCacheEmptySentinel = UINT32_MAX;

struct CacheHeader
{
    std::uint32_t magic{ kCacheMagic };
    std::uint32_t version{ kCacheVersion };
    std::uint64_t fileSize{ 0 };
    std::uint64_t mtime{ 0 };
    std::uint64_t fileHash{ 0 };
};
static_assert(sizeof(CacheHeader) == 32);

enum class CacheLoadStatus
{
    kOk,
    kFileMissing,
    kEmptyFile,
    kBadMagic,
    kHashMismatch,
    kReadFail,
    kEmptyWorld,
};

template <typename T>
[[nodiscard]] bool ReadPod(std::ifstream& a_in, T& a_out)
{
    a_in.read(reinterpret_cast<char*>(&a_out), sizeof(T));
    return a_in.good() && a_in.gcount() == sizeof(T);
}

template <typename T>
[[nodiscard]] bool WritePod(std::ofstream& a_out, const T& a_value)
{
    a_out.write(reinterpret_cast<const char*>(&a_value), sizeof(T));
    return a_out.good();
}

[[nodiscard]] CacheLoadStatus LoadCache(
    const std::filesystem::path& a_path,
    const FileStamp&             a_stamp,
    LazyFileHash&                a_fileHash,
    std::vector<std::uint32_t>&  a_offsets)
{
    a_offsets.clear();

    std::error_code ec;
    if (!std::filesystem::exists(a_path, ec)) {
        return CacheLoadStatus::kFileMissing;
    }

    const auto size = std::filesystem::file_size(a_path, ec);
    if (ec || size == 0) {
        return CacheLoadStatus::kEmptyFile;
    }

    std::ifstream in(a_path, std::ios::binary);
    if (!in) {
        return CacheLoadStatus::kReadFail;
    }

    CacheHeader header{};
    if (!ReadPod(in, header) || header.magic != kCacheMagic ||
        header.version != kCacheVersion) {
        return CacheLoadStatus::kBadMagic;
    }

    // Fast path: if the plugin's size + mtime match what we cached, trust the
    // cache without reading a single byte of the (potentially tens-of-MB)
    // plugin. Only when the stamp differs do we fall back to the content hash
    // — which catches both real edits (regen) and re-timestamped-but-identical
    // files (stat changed, content same → hash still matches → cache valid).
    const bool stampMatch = a_stamp.valid &&
                            header.fileSize == a_stamp.size &&
                            header.mtime == a_stamp.mtime;
    if (!stampMatch && header.fileHash != a_fileHash.Get()) {
        return CacheLoadStatus::kHashMismatch;
    }

    std::uint64_t storedOffsetHash = 0;
    std::uint32_t offsetCount      = 0;
    if (!ReadPod(in, storedOffsetHash) || !ReadPod(in, offsetCount)) {
        return CacheLoadStatus::kReadFail;
    }

    if (offsetCount == kCacheEmptySentinel) {
        return CacheLoadStatus::kEmptyWorld;
    }

    constexpr std::uint32_t kReasonableMax = 4 * 1024 * 1024;
    if (offsetCount > kReasonableMax) {
        return CacheLoadStatus::kReadFail;
    }

    a_offsets.resize(offsetCount);
    in.read(reinterpret_cast<char*>(a_offsets.data()),
            static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t)));
    if (!in.good() ||
        in.gcount() != static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t))) {
        a_offsets.clear();
        return CacheLoadStatus::kReadFail;
    }

    const auto computedHash = HashBytes(a_offsets.data(), offsetCount * sizeof(std::uint32_t));
    if (computedHash != storedOffsetHash) {
        a_offsets.clear();
        return CacheLoadStatus::kHashMismatch;
    }

    return CacheLoadStatus::kOk;
}

[[nodiscard]] bool SaveCache(
    const std::filesystem::path&   a_path,
    std::uint64_t                  a_fileHash,
    const FileStamp&               a_stamp,
    std::span<const std::uint32_t> a_offsets)
{
    std::error_code ec;
    std::filesystem::create_directories(a_path.parent_path(), ec);

    // Direct write to the final path. We previously did a .tmp + rename for
    // atomicity, but the rename → MoveFileExW path crashes inside USVFS's
    // hook (lock-xadd on freed memory) under MO2 / Wabbajack. The hook is
    // non-thread-safe globally — even with our own writes serialized, MO2's
    // helper or any other USVFS-aware process can race with us, and the
    // crash happens before MoveFileExW returns so try/error_code can't
    // catch it. Direct write loses atomic-update — a process kill mid-write
    // leaves a partial file — but the LoadCache magic + dual-hash check
    // rejects partial/torn caches and regenerates next session. Trade-off:
    // rare crash on USVFS hits → 1.5s of regen on next launch.
    std::ofstream out(a_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    const CacheHeader header{ kCacheMagic, kCacheVersion,
                              a_stamp.size, a_stamp.mtime, a_fileHash };
    if (!WritePod(out, header)) {
        return false;
    }

    if (a_offsets.empty()) {
        const std::uint64_t zeroHash = 0;
        const std::uint32_t sentinel = kCacheEmptySentinel;
        if (!WritePod(out, zeroHash) || !WritePod(out, sentinel)) {
            return false;
        }
    } else {
        const auto byteSize    = a_offsets.size() * sizeof(std::uint32_t);
        const auto offsetHash  = HashBytes(a_offsets.data(), byteSize);
        const auto offsetCount = static_cast<std::uint32_t>(a_offsets.size());

        if (!WritePod(out, offsetHash) || !WritePod(out, offsetCount)) {
            return false;
        }
        out.write(reinterpret_cast<const char*>(a_offsets.data()),
                  static_cast<std::streamsize>(byteSize));
        if (!out.good()) {
            return false;
        }
    }
    return true;
}

// ── Generator helpers ───────────────────────────────────────────────────────

// Sanity cap on the offset table size. Anything bigger almost certainly
// indicates corrupt OFFSET_DATA bounds (e.g. uninitialized floats).
constexpr std::uint32_t kMaxReasonableTableSize = 4 * 1024 * 1024;

// Convert worldspace-unit float to cell coord with floor semantics matching
// the engine (see GetIndexForCellCoord decompile: integer-cast then >> 12).
[[nodiscard]] std::int32_t WorldUnitsToCell(float a_value)
{
    const auto truncated = static_cast<std::int32_t>(a_value);
    if (a_value - static_cast<float>(truncated) < 0.0f) {
        return (truncated - 1) >> 12;
    }
    return truncated >> 12;
}

// Resolve <game install>/Data via the running .exe location instead of cwd.
// Skyrim VR with MO2's USVFS (and some Steam VR launchers) leaves cwd as the
// MO2 profile dir, not the game folder — relative `Data/<plugin>.esp` then
// fails to open and the generator skips every plugin with "failed to hash".
[[nodiscard]] const std::filesystem::path& DataRoot()
{
    static const std::filesystem::path root = []() {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, buf, MAX_PATH);
        return std::filesystem::path(buf).parent_path() / L"Data";
    }();
    return root;
}

[[nodiscard]] std::filesystem::path PluginPath(const RE::TESFile* a_file)
{
    return DataRoot() / std::string_view(a_file->fileName);
}

[[nodiscard]] std::filesystem::path CacheFileFor(
    const std::filesystem::path& a_root,
    const RE::TESFile*           a_file,
    const RE::TESWorldSpace*     a_world)
{
    return a_root / std::string_view(a_file->fileName)
                  / (std::string(a_world->GetFormEditorID()) + ".fco");
}

// Mirrors Generate()'s bounds-validation. Returns the offsetCount (= number
// of slots in pCellFileOffsets), or 0 when bounds are invalid (no-cells
// sentinel, inverted/oversized ranges, or GetIndexForCellCoord rejecting
// the corner). Used to size the empty-world sentinel array installed below.
//
// v1.4.3: GetIndexForCellCoord uses 0-based indexing, returning [0, count-1]
// for valid (x, y) where count = (maxX-minX+1) * (maxY-minY+1). Pre-v1.4.3
// we used `offsetCount = maxIdx` which was off by one and silently dropped
// the (maxX, maxY) corner cell at the bounds check below. Fix:
// `offsetCount = maxIdx + 1`. Verified by Ghidra decompile of FUN_140306750:
//   return (width) * (y - minY) - minX + x;   // width = maxX-minX+1
// For (maxX, maxY): idx = width*height + (maxX-minX) = count - 1.
[[nodiscard]] std::uint32_t ComputeOffsetCount(
    RE::TESWorldSpace* a_world, RE::TESFile* a_file, const OFFSET_DATA* a_data)
{
    const auto minX = WorldUnitsToCell(a_data->offsetMinCoords.x);
    const auto minY = WorldUnitsToCell(a_data->offsetMinCoords.y);
    const auto maxX = WorldUnitsToCell(a_data->offsetMaxCoords.x);
    const auto maxY = WorldUnitsToCell(a_data->offsetMaxCoords.y);
    if (minX == -524288) {
        return 0;
    }
    if (maxX < minX || maxY < minY ||
        (maxX - minX + 1) >= 1000 || (maxY - minY + 1) >= 1000) {
        return 0;
    }
    const auto maxIdx = GetIndexForCellCoord(a_world, a_file, maxX, maxY);
    if (maxIdx < 0) {
        return 0;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx) + 1;
    if (offsetCount > kMaxReasonableTableSize) {
        return 0;
    }
    return offsetCount;
}

}  // namespace

std::filesystem::path SkyrimGenerator::GetCacheRoot() const
{
    return DataRoot() / kCacheDirName;
}

std::uint32_t* SkyrimGenerator::InstallEngineArray(std::span<const std::uint32_t> a_offsets)
{
    if (a_offsets.empty()) {
        return nullptr;
    }
    auto* mm = RE::MemoryManager::GetSingleton();
    if (!mm) {
        return nullptr;
    }
    const auto byteSize = a_offsets.size() * sizeof(std::uint32_t);
    auto* buf = static_cast<std::uint32_t*>(mm->Allocate(byteSize, 0, false));
    if (!buf) {
        return nullptr;
    }
    std::memcpy(buf, a_offsets.data(), byteSize);
    return buf;
}

std::uint32_t SkyrimGenerator::Generate(RE::TESFile* a_ownerFile,
                                        RE::TESFile* a_workerFile,
                                        RE::TESWorldSpace* a_world,
                                        OFFSET_DATA* a_data,
                                        std::vector<std::uint32_t>& a_offsets)
{
    const auto minX = WorldUnitsToCell(a_data->offsetMinCoords.x);
    const auto minY = WorldUnitsToCell(a_data->offsetMinCoords.y);
    const auto maxX = WorldUnitsToCell(a_data->offsetMaxCoords.x);
    const auto maxY = WorldUnitsToCell(a_data->offsetMaxCoords.y);

    // No-cells sentinel from the engine — when bounds aren't initialized.
    if (minX == -524288) {
        return UINT32_MAX;
    }

    if (maxX < minX || maxY < minY ||
        (maxX - minX + 1) >= 1000 || (maxY - minY + 1) >= 1000) {
        logger::warn("[{}/{}] invalid cell bounds ({}, {}) — ({}, {}), skipping",
                     a_ownerFile->fileName, a_world->GetFormEditorID(),
                     minX, minY, maxX, maxY);
        return UINT32_MAX;
    }

    const auto maxIdx = GetIndexForCellCoord(a_world, a_ownerFile, maxX, maxY);
    if (maxIdx < 0) {
        return UINT32_MAX;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx) + 1;
    if (offsetCount > kMaxReasonableTableSize) {
        logger::warn("[{}/{}] table size {} exceeds sanity cap, skipping",
                     a_ownerFile->fileName, a_world->GetFormEditorID(), offsetCount);
        return UINT32_MAX;
    }

    a_offsets.assign(offsetCount, 0);

    // We run synchronously inside the SKSE kDataLoaded handler — the main
    // thread is blocked until this returns and our worker threads each own a
    // unique TESFile via the atomic-index partition in Run(). Nothing else in
    // the engine can mutate `a_data->fileOffset` between this read and the end
    // of the loop. Subtracting from a fixed base also produces identical
    // entries to `a_workerFile->fileOffset - a_data->fileOffset` per-iteration,
    // but is one load cheaper.
    const auto baseFileOffset = a_data->fileOffset;

    std::uint32_t cellsFound = 0;
    for (std::int32_t y = minY; y <= maxY; ++y) {
        for (std::int32_t x = minX; x <= maxX; ++x) {
            const auto idx = GetIndexForCellCoord(a_world, a_ownerFile, x, y);
            if (idx < 0 || static_cast<std::uint32_t>(idx) >= offsetCount) {
                continue;
            }
            if (!FindCellInFile(a_world, a_workerFile, x, y)) {
                continue;
            }
            a_offsets[idx] = a_workerFile->fileOffset - baseFileOffset;
            ++cellsFound;
        }
    }

    return cellsFound;
}

bool SkyrimGenerator::ProcessWorld(RE::TESFile* a_ownerFile,
                                   RE::TESFile* a_workerFile,
                                   const FileStamp& a_stamp,
                                   LazyFileHash& a_fileHash,
                                   RE::TESWorldSpace* a_world)
{
    // Inline BSTHashMap::find at TESWorldSpace+0x1D0 — purely a read-only
    // lookup, no engine call. The engine's GetOffsetData (= GetOrCreate-0xC0)
    // is not at the same RVA across runtimes (verified Ghidra: SE 1.5.97 has
    // it at 0x1402B7AA0, not at REL_ID(20110)-0xC0), so the engine wrapper
    // is unsafe for the generator. The map at +0x1D0 has the same layout
    // across SE/AE/VR/GOG, so the inline lookup just works.
    auto* data = FindOffsetData(a_world, a_ownerFile);
    if (!data) {
        // Plugin doesn't contribute anything to this worldspace.
        return false;
    }
    if (data->pCellFileOffsets) {
        // Engine loaded OFST directly via our NOPed gates. This is the
        // common case for non-xEdit-cleaned plugins; our generator does no
        // work here, but the NOPs themselves are what unlocked the load.
        m_stats.ofstIntact.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Plain assignment, no CAS. We run synchronously inside the SKSE
    // kDataLoaded handler, which blocks the main thread until Run() returns
    // (jthreads join on scope exit). The OFST-load path that the engine
    // would use to write pCellFileOffsets only fires inside TESWorldSpace
    // ::Load during data-load — already finished by the time we get here.
    // Per-file partitioning in Run() guarantees that no two workers touch
    // the same (file, world) OFFSET_DATA slot either. So we are the sole
    // writer of `data->pCellFileOffsets` for as long as we hold it; same
    // single-writer invariant WallSoGB's NVSE original relies on.
    auto publish = [&](std::span<const std::uint32_t> a_values) -> bool {
        auto* buf = InstallEngineArray(a_values);
        if (!buf) {
            return false;
        }
        data->pCellFileOffsets = buf;
        return true;
    };

    const auto cachePath = CacheFileFor(GetCacheRoot(), a_ownerFile, a_world);

    std::vector<std::uint32_t> offsets;
    const auto status = LoadCache(cachePath, a_stamp, a_fileHash, offsets);
    switch (status) {
    case CacheLoadStatus::kOk:
        if (publish(offsets)) {
            m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        logger::warn("[{}/{}] cache load OK but engine alloc failed",
                     a_ownerFile->fileName, a_world->GetFormEditorID());
        break;
    case CacheLoadStatus::kEmptyWorld:
        if (!Patches::HasSafeLookupPatch()) {
            // Cached as empty, but our Load NOPs created OFFSET_DATA for this
            // ESP → pCellFileOffsets is null. Without the original-style safe
            // editor-ID lookup patch, we still need a zero-valued sentinel to
            // keep the engine from null-dereferencing on `coc <editorID>`.
            const auto offsetCount = ComputeOffsetCount(a_world, a_ownerFile, data);
            if (offsetCount > 0) {
                std::vector<std::uint32_t> zeros(offsetCount, 0);
                if (publish(zeros)) {
                    m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    default:
        // Cache miss / mismatch / corrupt — regenerate.
        break;
    }

    // Real generation work (slow). Reveal the progress window — a pure cache /
    // OFST-intact launch never reaches here, so the window never flashes.
    ProgressWindow::NotifyGenerating();

    const auto cellsFound = Generate(a_ownerFile, a_workerFile, a_world, data, offsets);
    if (cellsFound == UINT32_MAX) {
        // Bounds invalid — engine's GetIndexForCellCoord will reject all
        // (x, y) here too (or the slow path keeps working), so the unsafe
        // deref site can never fire.
        return false;
    }
    if (cellsFound == 0) {
        // Worldspace exists in this plugin but contributes no exterior cells.
        // With the original-style safe lookup patch installed, null
        // pCellFileOffsets is fine here; otherwise keep the older sentinel
        // fallback.
        if (!Patches::HasSafeLookupPatch() && publish(offsets)) {
            m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
        }
        std::ignore = SaveCache(cachePath, a_fileHash.Get(), a_stamp, {});
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (publish(offsets)) {
        std::ignore = SaveCache(cachePath, a_fileHash.Get(), a_stamp, offsets);
        m_stats.generatedTables.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    logger::warn("[{}/{}] generated {} cells but engine alloc failed",
                 a_ownerFile->fileName, a_world->GetFormEditorID(), cellsFound);
    return false;
}

void SkyrimGenerator::Run()
{
    using clock = std::chrono::steady_clock;
    const auto startedAt = clock::now();

    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        logger::error("Generator: TESDataHandler null");
        return;
    }

    auto& worlds = dh->GetFormArray<RE::TESWorldSpace>();
    if (worlds.empty()) {
        logger::info("Generator: no worldspaces loaded — nothing to do");
        return;
    }

    // Build the work set the way WallSoGB's NVSE original does (ThreadProc,
    // CellOffsetGenerator.cpp:423): walk each worldspace's OFFSET_DATA map —
    // the engine's per-world list of contributing files — and collect only
    // the (file, world) pairs whose pCellFileOffsets is still null. Files the
    // engine already populated via intact OFST, and the thousands of plugins
    // that touch no worldspace at all, never enter the set, so we never stat
    // or hash them. Earlier we iterated the entire load order and hashed every
    // plugin up front, which read the whole Data folder on every launch and
    // dominated cached-startup time on large modlists.
    std::unordered_map<RE::TESFile*, std::vector<RE::TESWorldSpace*>> work;
    std::uint32_t ofstIntact = 0;
    for (auto* world : worlds) {
        if (!world) {
            continue;
        }
        for (auto& entry : GetOffsetDataMap(world)) {
            auto* file = entry.first;
            auto* data = entry.second;
            if (!file || !data) {
                continue;
            }
            if (data->pCellFileOffsets) {
                ++ofstIntact;  // engine populated it during data-load; skip
                continue;
            }
            work[file].push_back(world);
        }
    }
    m_stats.ofstIntact.store(ofstIntact, std::memory_order_relaxed);

    // Flatten to a vector so workers can claim entries via a stable index.
    std::vector<std::pair<RE::TESFile*, std::vector<RE::TESWorldSpace*>>> targets;
    targets.reserve(work.size());
    for (auto& [file, list] : work) {
        targets.emplace_back(file, std::move(list));
    }
    m_stats.totalFiles.store(static_cast<std::uint32_t>(targets.size()),
                             std::memory_order_relaxed);

    // Parallel per-file loop. Each worker pulls a (file, worldspaces) entry
    // from a shared atomic index and processes that file's needy worldspaces
    // serially. Partitioning by file guarantees no two workers touch the same
    // (file, world) OFFSET_DATA slot, and post-kDataLoaded the engine isn't
    // seeking these files, so per-file state stays thread-local. We pass the
    // original file pointer for both seek and OFFSET_DATA ownership — no
    // TESFile::Duplicate (its master-chain walk + unlocked NiTPointerMap
    // insert crashed under contention; see git history).
    //
    // Cap matches WallSoGB's NVSE original (CellOffsetGenerator.cpp:494):
    // `min(32, dwNumberOfProcessors)` — but reserve one logical core for the
    // progress-window UI thread (and the OS). With every core saturated by
    // workers, the high-priority UI thread still gets preempt slices, but
    // leaving one core free keeps the bar repainting smoothly instead of
    // flickering in/out during a heavy regen. One fewer worker is a negligible
    // generation-time cost.
    const auto hw = std::max<unsigned>(1, std::thread::hardware_concurrency());
    const auto threadCount =
        std::min<unsigned>(32, hw > 1 ? hw - 1 : 1);

    std::atomic<std::size_t> nextIdx{ 0 };
    auto worker = [&]() {
        while (true) {
            const auto i = nextIdx.fetch_add(1, std::memory_order_relaxed);
            if (i >= targets.size()) {
                return;
            }
            auto* file       = targets[i].first;
            const auto& needy = targets[i].second;
            const auto pluginPath = PluginPath(file);

            // Cheap identity for the cache fast-path. The content hash is
            // computed lazily by LazyFileHash only if a cache stamp misses or
            // we generate a fresh table — so an all-cache-hit launch reads no
            // plugin bytes at all.
            const auto   stamp = StatPlugin(pluginPath);
            LazyFileHash fileHash{ pluginPath };
            if (!stamp.valid) {
                logger::warn("Generator: failed to stat {} (path='{}', err={}); "
                             "falling back to content hash",
                             file->fileName, pluginPath.string(), GetLastError());
            }

            for (auto* world : needy) {
                if (world) {
                    ProcessWorld(file, file, stamp, fileHash, world);
                }
                ProgressWindow::Tick();  // one (file, world) work unit done
            }
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
        }
    };

    // Total work units = every (file, world) pair that needs offsets. The
    // window stays hidden until the first real cache-miss generation
    // (NotifyGenerating in ProcessWorld), so all-cache-hit boots never flash
    // it — but the bar already reflects the cache-hit ticks when it appears.
    std::uint32_t totalWork = 0;
    for (const auto& entry : targets) {
        totalWork += static_cast<std::uint32_t>(entry.second.size());
    }
    ProgressWindow::Start("FasterCellLookup");
    ProgressWindow::SetTotal(totalWork);

    logger::info("Generator: {} plugin(s) needing work across {} worldspace(s), "
                 "{} already OFST-intact, {} thread(s)",
                 targets.size(), worlds.size(), ofstIntact, threadCount);

    {
        std::vector<std::jthread> workers;
        workers.reserve(threadCount);
        for (unsigned t = 0; t < threadCount; ++t) {
            workers.emplace_back(worker);
        }
    }  // jthreads join on destruction

    ProgressWindow::Stop();

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             clock::now() - startedAt)
                             .count();

    logger::info(
        "Generator: done in {} ms — files={}, generated={}, cache-hits={}, "
        "OFST-intact={}, empty-worlds={} (sentinels={})",
        elapsed,
        m_stats.processedFiles.load(),
        m_stats.generatedTables.load(),
        m_stats.cacheHits.load(),
        m_stats.ofstIntact.load(),
        m_stats.emptyWorlds.load(),
        m_stats.emptySentinels.load());
}

}  // namespace cog
