#include "PCH.h"
#include "skyrim/GenerationLog.h"

namespace cog::sky {

void GenerationLog::RecordWrite(const RE::TESFile* a_file, const RE::TESWorldSpace* a_world,
                                std::uint32_t a_fileOffsetAtWrite,
                                std::vector<std::uint32_t> a_tableSnapshot)
{
    s_map[{a_file, a_world}] = Entry{ a_fileOffsetAtWrite, std::move(a_tableSnapshot) };
}

std::uint32_t GenerationLog::GetRecordedFileOffset(const RE::TESFile* a_file,
                                                    const RE::TESWorldSpace* a_world,
                                                    bool& a_found)
{
    auto it = s_map.find({a_file, a_world});
    if (it == s_map.end()) {
        a_found = false;
        return 0;
    }
    a_found = true;
    return it->second.fileOffsetAtWrite;
}

const std::vector<std::uint32_t>* GenerationLog::GetRecordedTable(
    const RE::TESFile* a_file, const RE::TESWorldSpace* a_world)
{
    auto it = s_map.find({a_file, a_world});
    if (it == s_map.end()) {
        return nullptr;
    }
    return &it->second.table;
}

void GenerationLog::Clear()
{
    s_map.clear();
}

}  // namespace cog::sky
