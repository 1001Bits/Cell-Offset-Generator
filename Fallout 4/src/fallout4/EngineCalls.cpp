#include "PCH.h"
#include "fallout4/EngineCalls.h"

namespace cog::fo4 {

namespace {

// Per-runtime IMAGE-RELATIVE offsets (subtract image base 0x140000000).
// Verified via Ghidra against four binaries:
//   OG 1.10.163  — user-installed Fallout4.exe (~65 MB, 189870 functions)
//   NG 1.10.984  — Fallout4.exe.unpacked.exe (depot_377162)
//   AE 1.11.x    — current Steam Fallout4.exe (verified at 1.11.191)
//   VR 1.2.72    — Fallout4VR.exe
struct EngineOffsets
{
    std::uintptr_t findCellInFile;
    std::uintptr_t getIndexForCellCoord;
    std::uintptr_t getOffsetData;
    std::uintptr_t getOrCreateOffsetData;
    // 0 means "not yet derived" — runtime falls back to serial generation.
    std::uintptr_t getThreadSafeFile;
    std::uintptr_t clearThreadSafeFiles;
};

constexpr EngineOffsets kOffsetsOG_1_10_163{
    .findCellInFile        = 0x491EF0,
    .getIndexForCellCoord  = 0x492270,
    .getOffsetData         = 0x4981F0,
    .getOrCreateOffsetData = 0x4982B0,
    .getThreadSafeFile     = 0x1322B0,
    .clearThreadSafeFiles  = 0x132430,
};

constexpr EngineOffsets kOffsetsNG_1_10_984{
    .findCellInFile        = 0x51E8E0,
    .getIndexForCellCoord  = 0x51EC60,
    .getOffsetData         = 0x525590,
    .getOrCreateOffsetData = 0x525670,
    .getThreadSafeFile     = 0x2A4ED0,
    .clearThreadSafeFiles  = 0x2A5050,
};

constexpr EngineOffsets kOffsetsAE{
    .findCellInFile        = 0x572860,
    .getIndexForCellCoord  = 0x572BE0,
    .getOffsetData         = 0x579510,
    .getOrCreateOffsetData = 0x5795F0,
    .getThreadSafeFile     = 0x2F91B0,
    .clearThreadSafeFiles  = 0x2F9330,
};

constexpr EngineOffsets kOffsetsVR_1_2_72{
    .findCellInFile        = 0x47B030,
    .getIndexForCellCoord  = 0x47B3B0,
    .getOffsetData         = 0x481330,
    .getOrCreateOffsetData = 0x4813F0,
    .getThreadSafeFile     = 0x138EB0,
    .clearThreadSafeFiles  = 0x139030,
};

[[nodiscard]] const EngineOffsets& PickOffsets()
{
    const auto ver = REL::Module::get().version();
    if (ver == F4SE::RUNTIME_1_10_163)  return kOffsetsOG_1_10_163;
    if (ver == F4SE::RUNTIME_VR_1_2_72) return kOffsetsVR_1_2_72;
    // 1.11+ is AE; 1.10.980/984 is NG. Bethesda has shipped several AE
    // sub-versions — addresses MAY drift between them. Verify in Ghidra if a
    // future patch lands and the byte-verifier in Patches.cpp starts rejecting.
    constexpr REL::Version kFirstAE{ 1, 11, 0, 0 };
    if (ver >= kFirstAE)                return kOffsetsAE;
    if (ver >= F4SE::RUNTIME_1_10_984)  return kOffsetsNG_1_10_984;
    static const EngineOffsets empty{};
    return empty;
}

using FindCellInFile_t        = bool (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetIndexForCellCoord_t  = std::int32_t (*)(RE::TESWorldSpace*, RE::TESFile*, std::int32_t, std::int32_t);
using GetOffsetData_t         = OFFSET_DATA* (*)(RE::TESWorldSpace*, RE::TESFile*);
using GetOrCreateOffsetData_t = OFFSET_DATA* (*)(RE::TESWorldSpace*, RE::TESFile*);
using GetThreadSafeFile_t     = RE::TESFile* (*)(RE::TESFile*, std::uint32_t);
using ClearThreadSafeFiles_t  = void (*)(RE::TESFile*);

}  // namespace

bool FindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                    std::int32_t a_x, std::int32_t a_y)
{
    static const auto offset = PickOffsets().findCellInFile;
    if (offset == 0) return false;
    static REL::Relocation<FindCellInFile_t> func{ REL::Offset(offset) };
    return func(a_world, a_file, a_x, a_y);
}

std::int32_t GetIndexForCellCoord(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                  std::int32_t a_x, std::int32_t a_y)
{
    static const auto offset = PickOffsets().getIndexForCellCoord;
    if (offset == 0) return -1;
    static REL::Relocation<GetIndexForCellCoord_t> func{ REL::Offset(offset) };
    return func(a_world, a_file, a_x, a_y);
}

OFFSET_DATA* GetOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    static const auto offset = PickOffsets().getOffsetData;
    if (offset == 0) return nullptr;
    static REL::Relocation<GetOffsetData_t> func{ REL::Offset(offset) };
    return func(a_world, a_file);
}

OFFSET_DATA* GetOrCreateOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    static const auto offset = PickOffsets().getOrCreateOffsetData;
    if (offset == 0) return nullptr;
    static REL::Relocation<GetOrCreateOffsetData_t> func{ REL::Offset(offset) };
    return func(a_world, a_file);
}

bool RuntimeHasEngineAddresses()
{
    const auto& o = PickOffsets();
    return o.findCellInFile != 0 && o.getIndexForCellCoord != 0 && o.getOffsetData != 0;
}

bool HasThreadSafeFilePrimitives()
{
    const auto& o = PickOffsets();
    return o.getThreadSafeFile != 0 && o.clearThreadSafeFiles != 0;
}

RE::TESFile* GetThreadSafeFile(RE::TESFile* a_file, std::uint32_t a_bufSize)
{
    static const auto offset = PickOffsets().getThreadSafeFile;
    if (offset == 0) return a_file;  // no clone available — caller must serialise
    static REL::Relocation<GetThreadSafeFile_t> func{ REL::Offset(offset) };
    return func(a_file, a_bufSize);
}

void ClearThreadSafeFiles(RE::TESFile* a_file)
{
    static const auto offset = PickOffsets().clearThreadSafeFiles;
    if (offset == 0) return;
    static REL::Relocation<ClearThreadSafeFiles_t> func{ REL::Offset(offset) };
    func(a_file);
}

}  // namespace cog::fo4
