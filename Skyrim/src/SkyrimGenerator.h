#pragma once

#include "PCH.h"
#include "EngineTypes.h"

#include <atomic>

namespace cog {

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
        // Worldspace had no cells but valid bounds; we installed a zero-valued
        // pCellFileOffsets so the engine's editor-ID lookup path doesn't crash
        // on null-deref. Subset of emptyWorlds.
        std::atomic<std::uint32_t> emptySentinels{ 0 };
    };

    void Run();

    [[nodiscard]] const Stats& GetStats() const noexcept { return m_stats; }
    [[nodiscard]] std::filesystem::path GetCacheRoot() const;

private:
    bool ProcessWorld(RE::TESFile* a_file, std::uint64_t a_fileHash, RE::TESWorldSpace* a_world);

    std::uint32_t Generate(RE::TESFile* a_file, RE::TESWorldSpace* a_world,
                           OFFSET_DATA* a_data, std::vector<std::uint32_t>& a_offsets);

    [[nodiscard]] std::uint32_t* InstallEngineArray(std::span<const std::uint32_t> a_offsets);

    Stats m_stats{};
};

}  // namespace cog
