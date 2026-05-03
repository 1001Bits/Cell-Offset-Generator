#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>

namespace cog {

// Engine-agnostic offset generator orchestration. The actual per-plugin
// scanning logic that knows how to read TES4 plugin files lives in the
// engine-specific layer (skyrim/, fnv/, fo4/...).
class Generator
{
public:
    virtual ~Generator() = default;

    // Folder for cache files (relative to the game's Data directory).
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
        // Worldspace had no cells but valid bounds; we installed a zero-valued
        // pCellFileOffsets so the engine's editor-ID lookup path doesn't crash
        // on null-deref. Subset of emptyWorlds.
        std::atomic<std::uint32_t> emptySentinels{ 0 };
    };

    // Run the generation pass synchronously. Spawns its own thread pool.
    // Returns when all files are processed and offsets are applied.
    virtual void Run() = 0;

    [[nodiscard]] const Stats& GetStats() const noexcept { return m_stats; }

    // Where the cache lives — typically <DataDir>/CellOffsets/.
    [[nodiscard]] virtual std::filesystem::path GetCacheRoot() const = 0;

protected:
    Stats m_stats{};
};

}  // namespace cog
