#include "PCH.h"
#include "skyrim/InteriorOffsets.h"

#include <mutex>
#include <unordered_map>

namespace cog::sky::interior {

namespace {

using FormIDOffsetMap = std::unordered_map<std::uint32_t, std::uint32_t>;
using PerFileMap      = std::unordered_map<RE::TESFile*, FormIDOffsetMap>;

PerFileMap g_perFile;
std::mutex g_mutex;

// NVSE uses a thread_local because cell loading dispatches per-thread; the
// engine's parse state is one-file-at-a-time per thread. Cheaper than a
// global atomic and correct under the actual access pattern.
thread_local RE::TESFile* tl_currentFile = nullptr;

}  // namespace

void AddOffsetForFile(RE::TESFile* a_file, std::uint32_t a_formID,
                      std::uint32_t a_offset)
{
    if (!a_file || a_offset == 0) {
        return;
    }
    std::lock_guard lock(g_mutex);
    g_perFile[a_file][a_formID] = a_offset;
}

std::uint32_t GetOffsetForFile(const RE::TESFile* a_file, std::uint32_t a_formID)
{
    if (!a_file) {
        return 0;
    }
    std::lock_guard lock(g_mutex);
    auto fileIt = g_perFile.find(const_cast<RE::TESFile*>(a_file));
    if (fileIt == g_perFile.end()) {
        return 0;
    }
    auto formIt = fileIt->second.find(a_formID);
    return (formIt != fileIt->second.end()) ? formIt->second : 0;
}

std::size_t CountOffsetsForFile(const RE::TESFile* a_file)
{
    if (!a_file) {
        return 0;
    }
    std::lock_guard lock(g_mutex);
    auto it = g_perFile.find(const_cast<RE::TESFile*>(a_file));
    return (it != g_perFile.end()) ? it->second.size() : 0;
}

std::size_t CountFiles()
{
    std::lock_guard lock(g_mutex);
    return g_perFile.size();
}

void ForEach(const TupleVisitor& a_visitor)
{
    if (!a_visitor) {
        return;
    }
    std::lock_guard lock(g_mutex);
    for (auto& [file, formMap] : g_perFile) {
        for (auto& [formID, offset] : formMap) {
            if (!a_visitor(file, formID, offset)) {
                return;
            }
        }
    }
}

void SetCurrentFile(RE::TESFile* a_file)
{
    tl_currentFile = a_file;
}

RE::TESFile* GetCurrentFile()
{
    return tl_currentFile;
}

void Reset()
{
    std::lock_guard lock(g_mutex);
    g_perFile.clear();
    tl_currentFile = nullptr;
}

}  // namespace cog::sky::interior
