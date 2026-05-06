#include "PCH.h"
#include "SkyrimGenerator.h"

#include "EngineCalls.h"
#include "EngineTypes.h"

#define XXH_INLINE_ALL
#define XXH_ENABLE_AUTOVECTORIZE
#include <xxhash.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <fstream>
#include <optional>
#include <thread>

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

[[nodiscard]] std::uint64_t HashFile(const std::filesystem::path& a_path)
{
    std::ifstream file(a_path, std::ios::binary);
    if (!file) {
        return 0;
    }

    auto* state = XXH3_createState();
    if (!state) {
        return 0;
    }
    XXH3_64bits_reset(state);

    constexpr std::size_t kBufferSize = 64 * 1024;
    std::vector<char> buffer(kBufferSize);
    while (file.read(buffer.data(), kBufferSize) || file.gcount() > 0) {
        XXH3_64bits_update(state, buffer.data(), static_cast<std::size_t>(file.gcount()));
    }

    const auto digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return digest;
}

// ── .fco cache file ─────────────────────────────────────────────────────────
//
// .fco — Fallout Cell Offset (we keep the magic for tooling familiarity; the
// layout matches WallSoGB's NVSE format so inspection scripts stay useful as
// a reference).
//
// Layout (all little-endian, no padding):
//   Header { u32 magic='FCOF'; u32 version=2; u64 fileHash; }
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
constexpr std::uint32_t kCacheVersion       = 2;
constexpr std::uint32_t kCacheEmptySentinel = UINT32_MAX;

struct CacheHeader
{
    std::uint32_t magic{ kCacheMagic };
    std::uint32_t version{ kCacheVersion };
    std::uint64_t fileHash{ 0 };
};
static_assert(sizeof(CacheHeader) == 16);

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
    std::uint64_t                a_expectedFileHash,
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

    if (header.fileHash != a_expectedFileHash) {
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
    std::span<const std::uint32_t> a_offsets)
{
    std::error_code ec;
    std::filesystem::create_directories(a_path.parent_path(), ec);

    // Atomic write: stream into <path>.tmp, close, rename to <path>. A
    // process kill or short write only damages the tmp file, leaving any
    // previous valid cache intact. std::filesystem::rename uses MoveFileEx
    // (REPLACE_EXISTING) on Windows, atomic on the same volume.
    auto tmpPath = a_path;
    tmpPath += ".tmp";

    {
        std::ofstream out(tmpPath, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }

        const CacheHeader header{ kCacheMagic, kCacheVersion, a_fileHash };
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
    }  // close ofstream → flush + release handle before rename

    std::filesystem::rename(tmpPath, a_path, ec);
    if (ec) {
        std::filesystem::remove(tmpPath, ec);
        return false;
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

[[nodiscard]] std::filesystem::path PluginPath(const RE::TESFile* a_file)
{
    return std::filesystem::path("Data") / std::string_view(a_file->fileName);
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
    return std::filesystem::path("Data") / kCacheDirName;
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

std::uint32_t SkyrimGenerator::Generate(RE::TESFile* a_file, RE::TESWorldSpace* a_world,
                                         OFFSET_DATA* a_data, std::vector<std::uint32_t>& a_offsets)
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
                     a_file->fileName, a_world->GetFormEditorID(),
                     minX, minY, maxX, maxY);
        return UINT32_MAX;
    }

    const auto maxIdx = GetIndexForCellCoord(a_world, a_file, maxX, maxY);
    if (maxIdx < 0) {
        return UINT32_MAX;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx) + 1;
    if (offsetCount > kMaxReasonableTableSize) {
        logger::warn("[{}/{}] table size {} exceeds sanity cap, skipping",
                     a_file->fileName, a_world->GetFormEditorID(), offsetCount);
        return UINT32_MAX;
    }

    a_offsets.assign(offsetCount, 0);

    // Snapshot data->fileOffset at the start of generation. We use this fixed
    // value for all subtractions; if FindCellInFile (or anything else) mutates
    // a_data->fileOffset mid-loop, our entries stay consistent.
    const auto fileOffsetSnapshot = a_data->fileOffset;

    std::uint32_t cellsFound = 0;
    for (std::int32_t y = minY; y <= maxY; ++y) {
        for (std::int32_t x = minX; x <= maxX; ++x) {
            const auto idx = GetIndexForCellCoord(a_world, a_file, x, y);
            if (idx < 0 || static_cast<std::uint32_t>(idx) >= offsetCount) {
                continue;
            }
            if (!FindCellInFile(a_world, a_file, x, y)) {
                continue;
            }
            a_offsets[idx] = a_file->fileOffset - fileOffsetSnapshot;
            ++cellsFound;
        }
    }

    if (a_data->fileOffset != fileOffsetSnapshot) {
        logger::warn("[{}/{}] fileOffset drifted during Generate: was +{:X}, ended +{:X}",
                     a_file->fileName, a_world->GetFormEditorID(),
                     fileOffsetSnapshot, a_data->fileOffset);
        a_data->fileOffset = fileOffsetSnapshot;
    }

    return cellsFound;
}

bool SkyrimGenerator::ProcessWorld(RE::TESFile* a_file, std::uint64_t a_fileHash,
                                    RE::TESWorldSpace* a_world)
{
    auto* data = FindOffsetData(a_world, a_file);
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

    const auto cachePath = CacheFileFor(GetCacheRoot(), a_file, a_world);

    std::vector<std::uint32_t> offsets;
    const auto status = LoadCache(cachePath, a_fileHash, offsets);
    switch (status) {
    case CacheLoadStatus::kOk: {
        if (auto* buf = InstallEngineArray(offsets)) {
            data->pCellFileOffsets = buf;
            m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        logger::warn("[{}/{}] cache load OK but engine alloc failed",
                     a_file->fileName, a_world->GetFormEditorID());
        break;
    }
    case CacheLoadStatus::kEmptyWorld: {
        // Cached as empty, but our Load NOPs created OFFSET_DATA for this ESP
        // → pCellFileOffsets is null. The engine's editor-ID lookup path
        // (FUN_140306dc0 in AE, called from `coc <editorID>`) dereferences
        // pCellFileOffsets without a nullcheck, so install a zero-valued
        // sentinel sized to offsetCount. Reads return 0 = "no cell here",
        // which is the correct semantics for an empty worldspace.
        const auto offsetCount = ComputeOffsetCount(a_world, a_file, data);
        if (offsetCount > 0) {
            std::vector<std::uint32_t> zeros(offsetCount, 0);
            if (auto* buf = InstallEngineArray(zeros)) {
                data->pCellFileOffsets = buf;
                m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
            }
        }
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    default:
        // Cache miss / mismatch / corrupt — regenerate.
        break;
    }

    const auto cellsFound = Generate(a_file, a_world, data, offsets);
    if (cellsFound == UINT32_MAX) {
        // Bounds invalid — engine's GetIndexForCellCoord will reject all
        // (x, y) here too (or the slow path keeps working), so the unsafe
        // deref site can never fire.
        return false;
    }
    if (cellsFound == 0) {
        // Worldspace exists in this plugin but contributes no exterior cells.
        // Install a zero-valued sentinel — same reason as the kEmptyWorld
        // branch above. The offsets vector was already sized to offsetCount
        // and zero-initialized at the start of Generate.
        if (auto* buf = InstallEngineArray(offsets)) {
            data->pCellFileOffsets = buf;
            m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
        }
        std::ignore = SaveCache(cachePath, a_fileHash, {});
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (auto* buf = InstallEngineArray(offsets)) {
        data->pCellFileOffsets = buf;
        std::ignore = SaveCache(cachePath, a_fileHash, offsets);
        m_stats.generatedTables.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    logger::warn("[{}/{}] generated {} cells but engine alloc failed",
                 a_file->fileName, a_world->GetFormEditorID(), cellsFound);
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

    // Process every loaded plugin regardless of master flag. xEdit doesn't
    // preserve OFST records on save, so any plugin touched by xEdit (cleaned
    // masters via QAC, persistentified ESPs, etc.) ships without an offset
    // table even when flagged as master. Per-worldspace ProcessWorld() short-
    // circuits files whose OFST was already populated by the engine — that's
    // what filters out plugins that don't need our help. Matches WallSoGB's
    // original NVSE Cell-Offset-Generator behavior.
    std::vector<RE::TESFile*> targets;
    auto** regularMods = dh->GetLoadedMods();
    const auto regularCount = dh->GetLoadedModCount();
    for (std::uint32_t i = 0; i < regularCount; ++i) {
        if (auto* file = regularMods[i]) {
            targets.push_back(file);
        }
    }
    auto** lightMods = dh->GetLoadedLightMods();
    const auto lightCount = dh->GetLoadedLightModCount();
    if (lightMods) {
        for (std::uint32_t i = 0; i < lightCount; ++i) {
            if (auto* file = lightMods[i]) {
                targets.push_back(file);
            }
        }
    }

    m_stats.totalFiles.store(static_cast<std::uint32_t>(targets.size()),
                             std::memory_order_relaxed);

    // Parallel per-file loop. Each worker pulls files from a shared atomic
    // index and processes that file's full set of worldspaces serially. Two
    // threads never touch the same TESFile, so per-file engine state
    // (`a_file->fileOffset`, file stream position) doesn't race. Per-(world,
    // file) `OFFSET_DATA` structs were already created by the engine during
    // data-load, so `FindOffsetData` is a read-only lookup here. The
    // MemoryManager allocator is thread-safe; spdlog is thread-safe; m_stats
    // counters are atomic.
    //
    // Cap matches WallSoGB's NVSE original (Cell-Offset-Generator/internal/
    // CellOffsetGenerator.cpp:494): `min(32, dwNumberOfProcessors)`. NVSE
    // mints a per-thread TESFile clone via pThreadSafeFileMap so threads can
    // share files; we don't have that, so we partition by file instead —
    // bounded above by file count regardless of thread count.
    const auto threadCount = std::max<unsigned>(1,
        std::min<unsigned>(32, std::thread::hardware_concurrency()));

    std::atomic<std::size_t> nextIdx{ 0 };
    auto worker = [&]() {
        while (true) {
            const auto i = nextIdx.fetch_add(1, std::memory_order_relaxed);
            if (i >= targets.size()) {
                return;
            }
            auto* file = targets[i];
            const auto pluginPath = PluginPath(file);
            const auto fileHash = HashFile(pluginPath);
            if (fileHash == 0) {
                logger::warn("Generator: failed to hash {}, skipping", file->fileName);
                m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
                continue;
            }

            for (auto* world : worlds) {
                if (world) {
                    ProcessWorld(file, fileHash, world);
                }
            }
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
        }
    };

    logger::info("Generator: {} plugin(s) × {} worldspace(s) to consider, {} thread(s)",
                 targets.size(), worlds.size(), threadCount);

    {
        std::vector<std::jthread> workers;
        workers.reserve(threadCount);
        for (unsigned t = 0; t < threadCount; ++t) {
            workers.emplace_back(worker);
        }
    }  // jthreads join on destruction

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
