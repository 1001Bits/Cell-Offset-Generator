#pragma once

#include "PCH.h"
#include "EngineTypes.h"

#include <atomic>
#include <optional>
#include <unordered_map>
#include <unordered_set>

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

// Ground truth about a plugin's exterior cells, read straight from the file's
// GRUP structure (record headers only — compressed record bodies are skipped,
// never inflated). Keyed by the in-file WRLD record's objectID (low 24 bits).
// Used to verify generated tables before they are published or cached: the
// engine treats a zero table entry as "this file does not contain this cell"
// with NO slow-path fallback, so an unverified table converts any generation
// miss (transient IO failure, closed stream, bounds narrower than content)
// into permanently missing cell content.
struct WorldCellCounts
{
    // Exterior CELL records the engine's slow-scan probe can DEFINITELY
    // match: carrying data, no skip-relevant flags.
    std::uint32_t clean{ 0 };
    // Records whose probe-matchability depends on unverified engine flag
    // semantics: deleted (0x20) or 0x400-flagged records with data, and
    // zero-size (data-stripped) records. They extend only the UPPER bound
    // of the verification band, so the gate is correct regardless of
    // whether the engine matches them.
    std::uint32_t uncertain{ 0 };
    // A persistent CELL directly in the world-children group (XCLC
    // conventionally 0,0) can satisfy one probe without being a block cell.
    bool persistent{ false };
};

struct PluginScan
{
    std::unordered_map<std::uint32_t, WorldCellCounts> worlds;
    std::unordered_set<std::uint32_t>                  ambiguousWorlds;
};

// Scans a plugin at most once, lazily; only runs on the generation path
// (cache hits via the stamp fast-path never touch the file).
struct LazyPluginScan
{
    const std::filesystem::path&    path;
    std::optional<PluginScan>       value;
    bool                            computed{ false };

    // nullptr = file could not be parsed (unreadable / malformed structure).
    const PluginScan* Get();  // defined in SkyrimGenerator.cpp
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
        // Generated tables whose cell count did NOT match the plugin's actual
        // records (transient IO failure, closed stream, or NAM0/NAM9 bounds
        // narrower than the file's content). Not published, not cached — the
        // engine keeps its (correct) slow path for these.
        std::atomic<std::uint32_t> mismatched{ 0 };
        // Plugins whose GRUP structure could not be parsed for verification.
        // Their tables are not published or cached either.
        std::atomic<std::uint32_t> scanFailed{ 0 };
    };

    void Run();

    [[nodiscard]] const Stats& GetStats() const noexcept { return m_stats; }
    [[nodiscard]] std::filesystem::path GetCacheRoot() const;

private:
    bool ProcessWorld(RE::TESFile* a_file, const FileStamp& a_stamp,
                      LazyFileHash& a_fileHash, LazyPluginScan& a_scan,
                      RE::TESWorldSpace* a_world);

    std::uint32_t Generate(RE::TESFile* a_file, RE::TESWorldSpace* a_world,
                           OFFSET_DATA* a_data, std::vector<std::uint32_t>& a_offsets);

    [[nodiscard]] std::uint32_t* InstallEngineArray(std::span<const std::uint32_t> a_offsets);

    Stats m_stats{};
};

}  // namespace cog
