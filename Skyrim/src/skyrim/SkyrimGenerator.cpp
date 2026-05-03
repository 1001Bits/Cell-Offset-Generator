#include "PCH.h"
#include "skyrim/SkyrimGenerator.h"

#include "cog/CacheFile.h"
#include "cog/HashUtil.h"
#include "skyrim/EngineCalls.h"
#include "skyrim/EngineTypes.h"
#include "skyrim/GenerationLog.h"

#include <chrono>
#include <cmath>
#include <fstream>

namespace cog::sky {

namespace {

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
    const RE::TESFile* a_file,
    const RE::TESWorldSpace* a_world)
{
    return a_root / std::string_view(a_file->fileName)
                  / (std::string(a_world->GetFormEditorID()) + ".fco");
}

// Mirrors Generate()'s bounds-validation. Returns the offsetCount the engine
// would index against, or 0 when bounds are invalid (no-cells sentinel,
// inverted/oversized ranges, or GetIndexForCellCoord rejecting the corner).
// Used to size the empty-world sentinel array installed below.
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
    if (maxIdx <= 0) {
        return 0;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx);
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
    if (maxIdx <= 0) {
        return UINT32_MAX;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx);
    if (offsetCount > kMaxReasonableTableSize) {
        logger::warn("[{}/{}] table size {} exceeds sanity cap, skipping",
                     a_file->fileName, a_world->GetFormEditorID(), offsetCount);
        return UINT32_MAX;
    }

    a_offsets.assign(offsetCount, 0);

    // FindCellInFile occasionally returns true with a stale a_file->fileOffset
    // (caching artifact in the engine for cells that don't actually exist in
    // this plugin). We open the plugin file and verify each captured offset
    // points at a "CELL" record header before storing it. Failures are dropped.
    const auto pluginPath = std::filesystem::path("Data") /
                            std::string_view(a_file->fileName);
    std::ifstream pluginStream(pluginPath, std::ios::binary);
    const bool canVerify = pluginStream.is_open();
    if (!canVerify) {
        logger::warn("[{}/{}] can't open plugin file for verification — accepting all entries",
                     a_file->fileName, a_world->GetFormEditorID());
    }

    // Snapshot data->fileOffset at the start of generation. We use this fixed
    // value for all subtractions; if FindCellInFile (or anything else) mutates
    // a_data->fileOffset mid-loop, our entries stay consistent with the value
    // we'll stash via GenerationLog::RecordWrite below.
    const auto fileOffsetSnapshot = a_data->fileOffset;

    std::uint32_t cellsFound = 0;
    std::uint32_t cellsRejected = 0;
    std::uint32_t verifyAttempts = 0;
    char magic[4]{};
    for (std::int32_t y = minY; y <= maxY; ++y) {
        for (std::int32_t x = minX; x <= maxX; ++x) {
            const auto idx = GetIndexForCellCoord(a_world, a_file, x, y);
            if (idx < 0 || static_cast<std::uint32_t>(idx) >= offsetCount) {
                continue;
            }
            if (!FindCellInFile(a_world, a_file, x, y)) {
                continue;
            }
            const auto absolute = a_file->fileOffset;

            if (canVerify) {
                ++verifyAttempts;
                pluginStream.clear();
                pluginStream.seekg(static_cast<std::streamoff>(absolute), std::ios::beg);
                pluginStream.read(magic, 4);
                const auto streamGood = pluginStream.good();
                const auto bytesRead  = pluginStream.gcount();
                if (!streamGood || std::memcmp(magic, "CELL", 4) != 0) {
                    ++cellsRejected;
                    continue;
                }

                // Targeted diagnostic: log the first 3 successful verifies for
                // a known-failing tuple so we can see what we're actually
                // reading at write-time.
                static thread_local int diagLogged = 0;
                std::string_view fname(a_file->fileName);
                if (diagLogged < 3 &&
                    fname.find("EnhancedLightsandFX") != std::string_view::npos) {
                    logger::info("[verify-trace] {}/{} ({},{}) idx={} abs=+{:X} "
                                 "bytes={:02X}{:02X}{:02X}{:02X} good={} gcount={}",
                                 a_file->fileName, a_world->GetFormEditorID(),
                                 x, y, idx, absolute,
                                 static_cast<unsigned char>(magic[0]),
                                 static_cast<unsigned char>(magic[1]),
                                 static_cast<unsigned char>(magic[2]),
                                 static_cast<unsigned char>(magic[3]),
                                 streamGood, bytesRead);
                    ++diagLogged;
                }
            }

            a_offsets[idx] = absolute - fileOffsetSnapshot;
            ++cellsFound;
        }
    }

    if (canVerify && verifyAttempts > 0) {
        std::string_view fname(a_file->fileName);
        if (fname.find("EnhancedLightsandFX") != std::string_view::npos) {
            logger::info("[{}/{}] verify ran {}× — rejected {}, accepted {}",
                         a_file->fileName, a_world->GetFormEditorID(),
                         verifyAttempts, cellsRejected, cellsFound);
        }
    }
    if (cellsRejected > 0) {
        logger::info("[{}/{}] dropped {} false-positive(s) from FindCellInFile",
                     a_file->fileName, a_world->GetFormEditorID(), cellsRejected);
    }

    if (a_data->fileOffset != fileOffsetSnapshot) {
        logger::warn("[{}/{}] fileOffset drifted during Generate: was +{:X}, ended +{:X}",
                     a_file->fileName, a_world->GetFormEditorID(),
                     fileOffsetSnapshot, a_data->fileOffset);
        a_data->fileOffset = fileOffsetSnapshot;
    }

    // Self-check: round-trip every stored entry through the same arithmetic
    // the post-pass validator uses, reading from our LOCAL vector (not the
    // engine's pCellFileOffsets) and using fileOffsetSnapshot. If this finds
    // mismatches, the bug is purely in our generation logic — not engine
    // mutation, not arithmetic disagreement.
    if (canVerify) {
        std::uint32_t selfFails = 0;
        for (std::uint32_t i = 0; i < offsetCount; ++i) {
            if (a_offsets[i] == 0) {
                continue;
            }
            const auto absoluteCheck = static_cast<std::uint32_t>(
                fileOffsetSnapshot + a_offsets[i]);
            pluginStream.clear();
            pluginStream.seekg(static_cast<std::streamoff>(absoluteCheck),
                               std::ios::beg);
            char check[4]{};
            pluginStream.read(check, 4);
            if (!pluginStream.good() || std::memcmp(check, "CELL", 4) != 0) {
                if (selfFails < 3) {
                    logger::warn("[{}/{}] self-check FAIL idx={} entry=+{:X} abs=+{:X} "
                                 "bytes={:02X}{:02X}{:02X}{:02X}",
                                 a_file->fileName, a_world->GetFormEditorID(),
                                 i, a_offsets[i], absoluteCheck,
                                 static_cast<unsigned char>(check[0]),
                                 static_cast<unsigned char>(check[1]),
                                 static_cast<unsigned char>(check[2]),
                                 static_cast<unsigned char>(check[3]));
                }
                ++selfFails;
            }
        }
        if (selfFails > 0) {
            logger::warn("[{}/{}] self-check: {} of {} entries fail round-trip",
                         a_file->fileName, a_world->GetFormEditorID(),
                         selfFails, cellsFound);
        }
    }

    // Snapshot the fileOffset and full table we just wrote.
    GenerationLog::RecordWrite(a_file, a_world, fileOffsetSnapshot, a_offsets);

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
    const auto status = CacheFile::Load(cachePath, a_fileHash, offsets);
    switch (status) {
    case CacheFile::LoadStatus::kOk: {
        if (auto* buf = InstallEngineArray(offsets)) {
            data->pCellFileOffsets = buf;
            m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            GenerationLog::RecordWrite(a_file, a_world, data->fileOffset, offsets);
            return true;
        }
        logger::warn("[{}/{}] cache load OK but engine alloc failed",
                     a_file->fileName, a_world->GetFormEditorID());
        break;
    }
    case CacheFile::LoadStatus::kEmptyWorld: {
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
        // (x, y) here too, so the unsafe deref site can never fire. No
        // sentinel needed.
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
        std::ignore = CacheFile::Save(cachePath, a_fileHash, {});
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (auto* buf = InstallEngineArray(offsets)) {
        data->pCellFileOffsets = buf;
        std::ignore = CacheFile::Save(cachePath, a_fileHash, offsets);
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

    logger::info("Generator: {} plugin(s) × {} worldspace(s) to consider",
                 targets.size(), worlds.size());

    for (auto* file : targets) {
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

}  // namespace cog::sky
