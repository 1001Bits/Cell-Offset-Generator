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

// xxh3 hashes are pure file I/O — independent across files, no engine state.
// We parallelise hashing because for a stable load order it dominates Run()
// wall-time (every plugin file is read end-to-end whether or not anything
// needs regenerating).
[[nodiscard]] std::vector<HashedFile> HashFilesParallel(
    std::span<RE::TESFile* const> a_files)
{
    std::vector<HashedFile> out(a_files.size());
    if (a_files.empty()) {
        return out;
    }

    const auto hw = std::thread::hardware_concurrency();
    const auto threadCount = std::clamp<std::size_t>(
        hw == 0 ? 4 : hw, 1, std::min<std::size_t>(32, a_files.size()));

    std::atomic<std::size_t> next{ 0 };
    auto worker = [&]() {
        while (true) {
            const auto i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= a_files.size()) return;
            out[i].file = a_files[i];
            out[i].hash = HashFile(PluginPath(a_files[i]));
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(threadCount);
    for (std::size_t i = 0; i < threadCount; ++i) {
        workers.emplace_back(worker);
    }
    for (auto& w : workers) {
        w.join();
    }
    return out;
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

void Fo4Generator::RunParallel(std::span<const HashedFile> a_hashed,
                                std::span<RE::TESWorldSpace* const> a_worlds)
{
    // Build the work list: every (file, world) pair where the file hash is OK
    // and the world pointer is non-null. We dispatch one of these per
    // ProcessWorld call.
    struct Unit
    {
        std::size_t        fileIdx;
        RE::TESWorldSpace* world;
    };
    std::vector<Unit> units;
    units.reserve(a_hashed.size() * a_worlds.size());
    for (std::size_t i = 0; i < a_hashed.size(); ++i) {
        if (a_hashed[i].hash == 0) continue;
        for (auto* world : a_worlds) {
            if (world) units.push_back({ i, world });
        }
    }

    if (units.empty()) {
        for (const auto& hf : a_hashed) {
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
            (void)hf;
        }
        return;
    }

    const auto hw = std::thread::hardware_concurrency();
    const auto threadCount = std::clamp<std::size_t>(
        hw == 0 ? 4 : hw, 1, std::min<std::size_t>(32, units.size()));

    logger::info("Generator: parallel × {} thread(s) over {} (file × world) unit(s)",
                 threadCount, units.size());

    std::atomic<std::size_t> next{ 0 };
    std::atomic<std::size_t> filesProcessed{ 0 };
    std::vector<std::atomic<std::uint32_t>> perFileRemaining(a_hashed.size());
    for (std::size_t i = 0; i < a_hashed.size(); ++i) {
        perFileRemaining[i].store(0, std::memory_order_relaxed);
    }
    for (const auto& u : units) {
        perFileRemaining[u.fileIdx].fetch_add(1, std::memory_order_relaxed);
    }
    const std::size_t totalFiles = a_hashed.size();

    auto worker = [&]() {
        try {
            while (true) {
                const auto idx = next.fetch_add(1, std::memory_order_relaxed);
                if (idx >= units.size()) return;
                const auto& u = units[idx];
                auto* orig = a_hashed[u.fileIdx].file;
                auto* clone = GetThreadSafeFile(orig);
                if (!clone) clone = orig;  // engine refused; degrade gracefully
                ProcessWorld(clone, a_hashed[u.fileIdx].hash, u.world);
                // Last unit for this file? Bump the per-file counter + log.
                if (perFileRemaining[u.fileIdx].fetch_sub(1, std::memory_order_acq_rel) == 1) {
                    const auto fileNum = filesProcessed.fetch_add(1, std::memory_order_relaxed) + 1;
                    logger::info("[{}/{}] {} done",
                                 fileNum, totalFiles, orig->filename);
                    m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
                }
            }
        } catch (const std::exception& e) {
            logger::error("Generator worker exception: {}", e.what());
        } catch (...) {
            logger::error("Generator worker: unknown exception");
        }
    };

    std::vector<std::thread> workers;
    workers.reserve(threadCount);
    for (std::size_t i = 0; i < threadCount; ++i) {
        workers.emplace_back(worker);
    }
    for (auto& w : workers) w.join();

    // Account for files that had no work (hash==0). They never decrement the
    // per-file counter, so their processed counter never advances inside the
    // worker. Bump processedFiles to match totalFiles for the summary line.
    for (const auto& hf : a_hashed) {
        if (hf.hash == 0) {
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Tear down all per-thread file clones. Must happen on the main thread
    // after every worker has joined; the call walks the file's
    // thread→clone scatter map and frees each entry.
    for (const auto& hf : a_hashed) {
        ClearThreadSafeFiles(hf.file);
    }
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

    // Phase 1: hash every plugin file in parallel. This is pure disk I/O on
    // independent paths, no engine state involved.
    const auto hashStart = clock::now();
    auto hashed = HashFilesParallel(targets);
    const auto hashMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                           clock::now() - hashStart).count();

    logger::info("Generator: hashed {} plugin(s) in {} ms (parallel) — "
                 "now scanning × {} worldspace(s)",
                 hashed.size(), hashMs, worlds.size());

    // Phase 2: generation. Parallel when the engine's TESFile::GetThreadSafeFile
    // primitive is available (each worker pulls a per-thread file clone with
    // its own BSFile cursor; GetOffsetData/FindCellInFile/etc. walk
    // GetThreadSafeParent up to the root before keying into the worldspace
    // map, so passing a clone returns the same OFFSET_DATA as the original).
    // Falls back to serial when the runtime's address isn't filled in.
    const std::size_t totalFiles = hashed.size();
    if (HasThreadSafeFilePrimitives()) {
        // RunParallel takes std::span — flatten the engine's container.
        std::vector<RE::TESWorldSpace*> worldsVec;
        worldsVec.reserve(worlds.size());
        for (auto* w : worlds) worldsVec.push_back(w);
        RunParallel(hashed, worldsVec);
    } else {
        logger::info("Generator: ThreadSafeFile primitives unavailable for this "
                     "runtime — falling back to serial generation");
        std::size_t fileIdx = 0;
        for (const auto& hf : hashed) {
            ++fileIdx;
            if (hf.hash == 0) {
                logger::warn("[{}/{}] {} — hash failed, skipping",
                             fileIdx, totalFiles, hf.file->filename);
                m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            logger::info("[{}/{}] {} — scanning {} worldspace(s)",
                         fileIdx, totalFiles, hf.file->filename, worlds.size());
            for (auto* world : worlds) {
                if (world) ProcessWorld(hf.file, hf.hash, world);
            }
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
        }
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
