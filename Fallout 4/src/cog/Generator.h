#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>

namespace cog {

// Engine-agnostic generator orchestration. Per-engine subclasses live in their
// own subfolder (fallout4/) and know how to walk plugin files and call into
// engine internals.
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
    };

    // Run the generation pass synchronously. Returns when all files are
    // processed and offsets are applied.
    virtual void Run() = 0;

    [[nodiscard]] const Stats& GetStats() const noexcept { return m_stats; }

    // Where the cache lives — typically <DataDir>/CellOffsets/.
    [[nodiscard]] virtual std::filesystem::path GetCacheRoot() const = 0;

protected:
    Stats m_stats{};
};

}  // namespace cog
