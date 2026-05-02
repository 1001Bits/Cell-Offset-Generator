#pragma once

#include "PCH.h"
#include "cog/Generator.h"
#include "skyrim/EngineTypes.h"

namespace cog::sky {

class SkyrimGenerator final : public cog::Generator
{
public:
    SkyrimGenerator() = default;
    ~SkyrimGenerator() override = default;

    void Run() override;

    [[nodiscard]] std::filesystem::path GetCacheRoot() const override;

private:
    // Process one (file × worldspace) pair: cache lookup → FindCellInFile loop →
    // engine memory install + .fco persist. Returns true if pCellFileOffsets
    // was populated (either from cache or freshly generated).
    bool ProcessWorld(RE::TESFile* a_file, std::uint64_t a_fileHash, RE::TESWorldSpace* a_world);

    // Run FindCellInFile across the worldspace bounds, fill `a_offsets` with
    // per-cell relative offsets. Returns the count of cells found (or
    // UINT32_MAX if bounds were invalid for this plugin).
    std::uint32_t Generate(RE::TESFile* a_file, RE::TESWorldSpace* a_world,
                           OFFSET_DATA* a_data, std::vector<std::uint32_t>& a_offsets);

    // Allocate via the engine's MemoryManager so the engine can free it
    // normally on shutdown. Copies `a_offsets` into the returned buffer.
    [[nodiscard]] std::uint32_t* InstallEngineArray(std::span<const std::uint32_t> a_offsets);
};

}  // namespace cog::sky
