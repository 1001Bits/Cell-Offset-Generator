#pragma once

#include "PCH.h"

namespace cog::sky {

// Per-(file × worldspace) offset record. Layout assumed identical to FNV.
// VERIFY: confirm size and field order in Ghidra against Skyrim AE 1.6.1170
// before relying on this in production. The most likely failure mode is
// Bethesda having added/reordered fields in the 16-year gap.
struct OFFSET_DATA
{
    std::uint32_t* pCellFileOffsets;  // 0x00 — table indexed by GetIndexForCellCoord
    RE::NiPoint2   offsetMinCoords;   // 0x08
    RE::NiPoint2   offsetMaxCoords;   // 0x10
    std::uint32_t  fileOffset;        // 0x18
    std::uint32_t  pad1C;             // 0x1C
};
static_assert(sizeof(OFFSET_DATA) == 0x20);

// CommonLibSSE-NG places this at TESWorldSpace+0x1D0 with the speculative
// comment "BSTHashMap<TESFile*, OFFSET_DATA*> offsetDataMap?". We treat that
// as confirmed for now — see docs/skyrim-engine-map.md.
//
// BSTHashMap<TESFile*, OFFSET_DATA*> matches RE::BSTHashMap<RE::TESFile*, OFFSET_DATA*>.
using OffsetDataMap = RE::BSTHashMap<RE::TESFile*, OFFSET_DATA*>;

[[nodiscard]] inline OffsetDataMap& GetOffsetDataMap(RE::TESWorldSpace* a_world)
{
    constexpr std::ptrdiff_t kOffsetMapByteOffset = 0x1D0;
    auto* base = reinterpret_cast<std::byte*>(a_world);
    return *reinterpret_cast<OffsetDataMap*>(base + kOffsetMapByteOffset);
}

[[nodiscard]] inline const OffsetDataMap& GetOffsetDataMap(const RE::TESWorldSpace* a_world)
{
    constexpr std::ptrdiff_t kOffsetMapByteOffset = 0x1D0;
    auto* base = reinterpret_cast<const std::byte*>(a_world);
    return *reinterpret_cast<const OffsetDataMap*>(base + kOffsetMapByteOffset);
}

[[nodiscard]] inline OFFSET_DATA* FindOffsetData(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    auto& map = GetOffsetDataMap(a_world);
    if (auto it = map.find(a_file); it != map.end()) {
        return it->second;
    }
    return nullptr;
}

}  // namespace cog::sky
