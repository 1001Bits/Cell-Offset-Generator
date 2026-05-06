#include "PCH.h"
#include "EngineCalls.h"

namespace cog {

namespace {

// Engine-function lookups. SE+AE resolve via Address Library IDs (resilient
// to minor patch revisions). VR's sparse CSV (~13.8k of ~778k entries)
// doesn't include 2 of our 4 IDs, so VR keeps an image-relative fallback.
// GOG 1.6.1179 may have no Address Library versionlib bin available, so it
// also uses image-relative offsets (verified via Ghidra against the GOG
// SkyrimSE.exe — see ../../docs/skyrim-engine-map.md and Patches.cpp).
struct EngineFunc
{
    std::uint64_t  seID;
    std::uint64_t  aeID;
    std::uintptr_t vrOffset;   // image-relative; 0 disables on VR
    std::uintptr_t gogOffset;  // image-relative; 0 disables on GOG 1.6.1179
};

// IDs verified against versionlib-1-6-1170-0.bin (AE) and version-1-5-97-0.bin
// (SE); VR + GOG offsets verified via Ghidra.
constexpr EngineFunc kFindCellInFile       { 20022, 20456, 0x2C32D0, 0x3062F0 };
constexpr EngineFunc kGetIndexForCellCoord { 20023, 20457, 0x2C3560, 0x306580 };
constexpr EngineFunc kGetOrCreateOffsetData{ 20110, 20560, 0x2C9210, 0x30C8B0 };

[[nodiscard]] std::uintptr_t Resolve(const EngineFunc& a_func)
{
    if (REL::Module::IsVR()) {
        return a_func.vrOffset == 0
                 ? 0
                 : REL::Offset(a_func.vrOffset).address();
    }
    if (IsGOG()) {
        return a_func.gogOffset == 0
                 ? 0
                 : REL::Offset(a_func.gogOffset).address();
    }
    return REL::RelocationID(a_func.seID, a_func.aeID).address();
}

using FindCellInFile_t        = bool (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetIndexForCellCoord_t  = std::int32_t (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetOrCreateOffsetData_t = OFFSET_DATA* (*)(RE::TESWorldSpace*, RE::TESFile*);

}  // namespace

bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                    std::int32_t a_x, std::int32_t a_y)
{
    static const auto addr = Resolve(kFindCellInFile);
    if (addr == 0) {
        return false;
    }
    return reinterpret_cast<FindCellInFile_t>(addr)(a_world, a_file, a_x, a_y);
}

std::int32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                  std::int32_t a_x, std::int32_t a_y)
{
    static const auto addr = Resolve(kGetIndexForCellCoord);
    if (addr == 0) {
        return -1;
    }
    return reinterpret_cast<GetIndexForCellCoord_t>(addr)(a_world, a_file, a_x, a_y);
}

OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    static const auto addr = Resolve(kGetOrCreateOffsetData);
    if (addr == 0) {
        return nullptr;
    }
    return reinterpret_cast<GetOrCreateOffsetData_t>(addr)(a_world, a_file);
}

bool RuntimeHasEngineAddresses()
{
    return Resolve(kFindCellInFile) != 0 && Resolve(kGetIndexForCellCoord) != 0;
}

}  // namespace cog
