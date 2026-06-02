#pragma once

#include "PCH.h"
#include "EngineTypes.h"

#include <atomic>

namespace cog {

// Cheap plugin identity for the cache fast-path: size + last-write time,
// fetched with one GetFileAttributesExW (no content read).
struct FileStamp
{
    std::uint64_t size{ 0 };
    std::uint64_t mtime{ 0 };
    bool          valid{ false };
};

// Computes a plugin's content xxh3 at most once, lazily. Only touched when
// the (size, mtime) stamp doesn't match the cached header, or when a fresh
// table is generated and needs a hash written into the new cache header.
struct LazyFileHash
{
    const std::filesystem::path& path;
    std::uint64_t                value{ 0 };
    bool                         computed{ false };

    std::uint64_t Get();  // defined in SkyrimGenerator.cpp (needs HashFile)
};

// Drives the cell-offset regeneration pass: per (file × worldspace) it tries
// the .fco cache first, then runs FindCellInFile across the worldspace bounds
// to fill `pCellFileOffsets` and persist the result. Owns its own thread pool;
// `Run()` blocks until all files are processed.
class SkyrimGenerator
{
public:
    SkyrimGenerator() = default;

    static constexpr const char* kCacheDirName = "CellOffsets";

    struct Stats
    {
        std::atomic<std::uint32_t> processedFiles{ 0 };
        std::atomic<std::uint32_t> totalFiles{ 0 };
        std::atomic<std::uint32_t> generatedTables{ 0 };
        // Engine populated pCellFileOffsets via the OFST-load path our NOPs
        // unlocked — i.e. the plugin shipped intact OFST subrecords.
        std::atomic<std::uint32_t> ofstIntact{ 0 };
        // Loaded from our .fco cache (plugin had stripped OFST, we generated
        // it on a prior run).
        std::atomic<std::uint32_t> cacheHits{ 0 };
        std::atomic<std::uint32_t> emptyWorlds{ 0 };
        // Fallback path for runtimes where we could not install the original-
        // style safe editor-ID lookup patch: install a zero-valued
        // pCellFileOffsets so the engine doesn't null-deref on empty worlds.
        // Subset of emptyWorlds.
        std::atomic<std::uint32_t> emptySentinels{ 0 };
    };

    void Run();

    [[nodiscard]] const Stats& GetStats() const noexcept { return m_stats; }
    [[nodiscard]] std::filesystem::path GetCacheRoot() const;

private:
    bool ProcessWorld(RE::TESFile* a_ownerFile, RE::TESFile* a_workerFile,
                      const FileStamp& a_stamp, LazyFileHash& a_fileHash,
                      RE::TESWorldSpace* a_world);

    std::uint32_t Generate(RE::TESFile* a_ownerFile, RE::TESFile* a_workerFile,
                           RE::TESWorldSpace* a_world,
                           OFFSET_DATA* a_data, std::vector<std::uint32_t>& a_offsets);

    [[nodiscard]] std::uint32_t* InstallEngineArray(std::span<const std::uint32_t> a_offsets);

    Stats m_stats{};
};

}  // namespace cog
