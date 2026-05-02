#include "PCH.h"
#include "fallout4/Fo4Generator.h"

#include "cog/CacheFile.h"
#include "cog/HashUtil.h"
#include "fallout4/EngineCalls.h"

namespace cog::fo4 {

namespace {

// Sanity cap on the offset table size. Anything bigger almost certainly
// indicates corrupt OFFSET_DATA bounds (e.g. uninitialized floats).
constexpr std::uint32_t kMaxReasonableTableSize = 4 * 1024 * 1024;

// Convert worldspace-unit float to cell coord with floor semantics matching
// the engine: integer-cast then >> 12. Mirrors the FNV decompile.
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
    return std::filesystem::path("Data") / std::string_view(a_file->filename);
}

[[nodiscard]] std::filesystem::path CacheFileFor(
    const std::filesystem::path& a_root,
    const RE::TESFile* a_file,
    const RE::TESWorldSpace* a_world)
{
    return a_root / std::string_view(a_file->filename)
                  / (std::string(a_world->GetFormEditorID()) + ".fco");
}

}  // namespace

std::filesystem::path Fo4Generator::GetCacheRoot() const
{
    return std::filesystem::path("Data") / kCacheDirName;
}

std::uint32_t* Fo4Generator::InstallEngineArray(std::span<const std::uint32_t> a_offsets)
{
    if (a_offsets.empty()) {
        return nullptr;
    }
    const auto byteSize = a_offsets.size() * sizeof(std::uint32_t);
    // CommonLibF4 exposes the engine's MemoryManager via RE::malloc/calloc.
    // Falling back to plain operator new would leak on game shutdown but
    // wouldn't corrupt anything; using the engine allocator keeps ownership
    // semantics aligned with how the OFST-load path normally fills this field.
    auto* buf = static_cast<std::uint32_t*>(RE::malloc(byteSize));
    if (!buf) {
        return nullptr;
    }
    std::memcpy(buf, a_offsets.data(), byteSize);
    return buf;
}

std::uint32_t Fo4Generator::Generate(RE::TESFile* a_file, RE::TESWorldSpace* a_world,
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
                     a_file->filename, a_world->GetFormEditorID(),
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
                     a_file->filename, a_world->GetFormEditorID(), offsetCount);
        return UINT32_MAX;
    }

    a_offsets.assign(offsetCount, 0);

    // Open the plugin file for verification. FindCellInFile occasionally
    // returns true with a stale fileOffset (caching artifact in the engine
    // for cells that don't actually exist in this plugin). We verify each
    // captured offset points at a "CELL" record header before storing it.
    const auto pluginPath = PluginPath(a_file);
    std::ifstream pluginStream(pluginPath, std::ios::binary);
    const bool canVerify = pluginStream.is_open();
    if (!canVerify) {
        logger::warn("[{}/{}] can't open plugin file for verification — accepting all entries",
                     a_file->filename, a_world->GetFormEditorID());
    }

    // Snapshot data->fileOffset at the start of generation. We use this
    // fixed value for all subtractions; if FindCellInFile mutates it
    // mid-loop, our entries stay consistent.
    const auto fileOffsetSnapshot = a_data->fileOffset;

    std::uint32_t cellsFound = 0;
    std::uint32_t cellsRejected = 0;
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
            const auto absolute = a_file->fileoffset;

            if (canVerify) {
                pluginStream.clear();
                pluginStream.seekg(static_cast<std::streamoff>(absolute), std::ios::beg);
                pluginStream.read(magic, 4);
                if (!pluginStream.good() || std::memcmp(magic, "CELL", 4) != 0) {
                    ++cellsRejected;
                    continue;
                }
            }

            a_offsets[idx] = absolute - fileOffsetSnapshot;
            ++cellsFound;
        }
    }

    if (cellsRejected > 0) {
        logger::info("[{}/{}] dropped {} false-positive(s) from FindCellInFile",
                     a_file->filename, a_world->GetFormEditorID(), cellsRejected);
    }

    if (a_data->fileOffset != fileOffsetSnapshot) {
        logger::warn("[{}/{}] fileOffset drifted during Generate: was +{:X}, ended +{:X}",
                     a_file->filename, a_world->GetFormEditorID(),
                     fileOffsetSnapshot, a_data->fileOffset);
        a_data->fileOffset = fileOffsetSnapshot;
    }

    return cellsFound;
}

bool Fo4Generator::ProcessWorld(RE::TESFile* a_file, std::uint64_t a_fileHash,
                                 RE::TESWorldSpace* a_world)
{
    // GetOffsetData (lookup-only) returns nullptr when the plugin doesn't
    // contribute anything to this worldspace. We use the lookup variant here
    // — only escalate to GetOrCreateOffsetData on the install path below
    // when we've actually generated cells worth recording.
    auto* data = GetOffsetData(a_world, a_file);
    if (!data) {
        return false;
    }
    if (data->pCellFileOffsets) {
        // Engine loaded OFST directly. For ESMs that's the normal master
        // path; for ESPs it's the NOPed-gate path our patches unlock.
        // Either way, we don't need to do anything for this (file, world).
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
            return true;
        }
        logger::warn("[{}/{}] cache load OK but engine alloc failed",
                     a_file->filename, a_world->GetFormEditorID());
        break;
    }
    case CacheFile::LoadStatus::kEmptyWorld:
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    default:
        // Cache miss / mismatch / corrupt — regenerate.
        break;
    }

    const auto cellsFound = Generate(a_file, a_world, data, offsets);
    if (cellsFound == UINT32_MAX) {
        return false;
    }
    if (cellsFound == 0) {
        // Worldspace exists in this plugin but contributes no exterior cells.
        // Persist a sentinel so we can short-circuit next launch.
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
                 a_file->filename, a_world->GetFormEditorID(), cellsFound);
    return false;
}

// CommonLibF4-NG's `REL::RelocationID` for the TESDataHandler singleton
// resolves to a wrong offset on AE 1.11.191 (the Address-Library v2 .bin
// doesn't carry a correct mapping for that ID on the AE build). Use verified
// absolute addresses for the desktop runtimes; fall back to the library
// helper for VR (where AddressLibrary works fine).
//
// Singleton VAs (verified in Ghidra via BSTSingletonSDM<TESDataHandler>::InitSDM
// which writes the constructed pointer to a known static):
//   OG 1.10.163:  0x1458CF080 (image-relative 0x58CF080)
//   AE 1.11.191:  0x1430DC000 (image-relative 0x30DC000)
// NG isn't covered separately yet — its AddressLibrary mapping has worked
// historically; if a future build breaks, repeat the InitSDM trick.
[[nodiscard]] RE::TESDataHandler* GetTESDataHandlerSafe()
{
    if (REL::Module::IsVR()) {
        return RE::TESDataHandler::GetSingleton();
    }
    const auto ver = REL::Module::get().version();
    constexpr REL::Version kFirstAE{ 1, 11, 0, 0 };
    if (ver == F4SE::RUNTIME_1_10_163) {
        constexpr std::uintptr_t kOGSingletonOffset = 0x58CF080;
        const REL::Relocation<RE::TESDataHandler**> reloc{ REL::Offset(kOGSingletonOffset) };
        return *reloc;
    }
    if (ver >= kFirstAE) {
        constexpr std::uintptr_t kAESingletonOffset = 0x30DC000;
        const REL::Relocation<RE::TESDataHandler**> reloc{ REL::Offset(kAESingletonOffset) };
        return *reloc;
    }
    return RE::TESDataHandler::GetSingleton();
}

void Fo4Generator::Run()
{
    using clock = std::chrono::steady_clock;
    const auto startedAt = clock::now();

    auto* dh = GetTESDataHandlerSafe();
    if (!dh) {
        logger::error("Generator: TESDataHandler null");
        return;
    }

    const auto& worlds = dh->GetFormArray<RE::TESWorldSpace>();
    if (worlds.empty()) {
        logger::info("Generator: no worldspaces loaded — nothing to do");
        return;
    }

    // Include EVERY loaded plugin, master or not. ProcessWorld decides per
    // (file, worldspace) whether the engine already populated pCellFileOffsets
    // (counted as ofstIntact) or whether we need to regenerate (cleaned OFST).
    // Cleaned ESMs are just as broken as cleaned ESPs — both need our help.
    auto* fileColl = dh->GetCompiledFileCollection();
    std::vector<RE::TESFile*> targets;
    if (fileColl) {
        for (auto* file : fileColl->files) {
            if (file) targets.push_back(file);
        }
        for (auto* file : fileColl->smallFiles) {
            if (file) targets.push_back(file);
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
            logger::warn("Generator: failed to hash {}, skipping", file->filename);
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
            continue;
        }

        for (auto* world : worlds) {
            // GetFormArray<TESWorldSpace>() already returns TESWorldSpace*
            // — no As<> cast needed.
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
        "OFST-intact={}, empty-worlds={}",
        elapsed,
        m_stats.processedFiles.load(),
        m_stats.generatedTables.load(),
        m_stats.cacheHits.load(),
        m_stats.ofstIntact.load(),
        m_stats.emptyWorlds.load());
}

}  // namespace cog::fo4
