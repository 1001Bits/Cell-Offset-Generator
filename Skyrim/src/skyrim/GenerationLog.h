#pragma once

#include "PCH.h"

#include <unordered_map>
#include <utility>

namespace cog::sky {

// Cross-pass diagnostic store: records, per (file × world), the value of
// data->fileOffset at the moment the generator wrote relative-offset entries
// into pCellFileOffsets. The validator can compare this to the current value
// at validation time to detect engine-side mutation.
class GenerationLog
{
public:
    struct Key
    {
        const RE::TESFile*       file;
        const RE::TESWorldSpace* world;
        bool operator==(const Key& o) const noexcept
        { return file == o.file && world == o.world; }
    };
    struct Hash
    {
        std::size_t operator()(const Key& k) const noexcept
        {
            return std::hash<const void*>{}(k.file) ^
                   (std::hash<const void*>{}(k.world) << 1);
        }
    };

    static void RecordWrite(const RE::TESFile* a_file, const RE::TESWorldSpace* a_world,
                            std::uint32_t a_fileOffsetAtWrite,
                            std::vector<std::uint32_t> a_tableSnapshot);
    static std::uint32_t GetRecordedFileOffset(const RE::TESFile* a_file,
                                                const RE::TESWorldSpace* a_world,
                                                bool& a_found);
    static const std::vector<std::uint32_t>* GetRecordedTable(
        const RE::TESFile* a_file, const RE::TESWorldSpace* a_world);
    static void Clear();

private:
    struct Entry
    {
        std::uint32_t fileOffsetAtWrite;
        std::vector<std::uint32_t> table;
    };
    static inline std::unordered_map<Key, Entry, Hash> s_map;
};

}  // namespace cog::sky
