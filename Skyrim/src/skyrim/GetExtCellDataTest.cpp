#include "PCH.h"
#include "skyrim/GetExtCellDataTest.h"

#include <unordered_map>

namespace cog::sky {

namespace {

// Address Library IDs for TESDataHandler::GetExtCellDataFromFileByEditorID.
// VR resolves via SE id 13618 (offset 0x17C000 in VR CSV).
constexpr std::uint64_t kSeID_GetExtCellData = 13618;
constexpr std::uint64_t kAeID_GetExtCellData = 13716;

// Best-guess signature derived from the SE disassembly:
//   RCX = TESDataHandler* (this)
//   RDX = const char*     editorID
//   R8  = TESFile*        file
//   R9  = void*           output buffer (function writes coords / cell ptr here)
// Returns: bool in AL.
//
// We pass a 32-byte zero-filled output buffer to be defensive about layout.
using GetExtCellDataFn =
    bool(__fastcall*)(RE::TESDataHandler*, const char*, RE::TESFile*, void*);

struct PerFileTally
{
    std::uint64_t calls   = 0;
    std::uint64_t hits    = 0;
    bool          isLight = false;
};

}  // namespace

void RunGetExtCellDataTest()
{
    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        return;
    }

    static REL::Relocation<GetExtCellDataFn> func{
        REL::RelocationID(kSeID_GetExtCellData, kAeID_GetExtCellData)
    };

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    std::unordered_map<RE::TESFile*, PerFileTally> perFile;
    std::uint64_t totalCalls = 0;
    std::uint64_t totalHits  = 0;
    std::uint64_t skippedNoEdid = 0;
    std::uint64_t skippedNoFile = 0;

    // Walk every loaded form, filter to exterior TESObjectCELL entries that
    // have a non-empty editor ID. This is the population we'd want
    // GetExtCellData to find.
    // Collect candidates under the form-table read lock, then release it
    // before calling GetExtCellData — that function may itself take the
    // same lock internally and deadlock with us.
    struct Candidate
    {
        std::string  edid;
        RE::TESFile* file;
    };
    std::vector<Candidate> candidates;
    {
        auto [map, lockRef] = RE::TESForm::GetAllForms();
        if (!map) {
            logger::warn("GetExtCellDataTest: GetAllForms returned null map");
            return;
        }
        const RE::BSReadWriteLock l{ lockRef };
        candidates.reserve(map->size() / 16);
        for (auto& [formID, form] : *map) {
            if (!form || form->GetFormType() != RE::FormType::Cell) {
                continue;
            }
            auto* cell = form->As<RE::TESObjectCELL>();
            if (!cell || cell->IsInteriorCell()) {
                continue;
            }
            const auto edid = cell->GetFormEditorID();
            if (!edid || !*edid) {
                ++skippedNoEdid;
                continue;
            }
            auto* file = cell->GetFile(0);
            if (!file) {
                ++skippedNoFile;
                continue;
            }
            candidates.push_back({ std::string(edid), file });
        }
    }

    // Sample at most 4 cells per file. The function does an O(M) scan over
    // loaded files internally; iterating thousands of cells × hundreds of
    // files will hang the title-screen for minutes. A small sample is
    // enough to detect a master-vs-ESP hit-rate disparity.
    constexpr std::size_t kPerFileSampleCap = 4;
    std::unordered_map<RE::TESFile*, std::size_t> sampledByFile;
    std::size_t sampleSize = 0;

    for (const auto& c : candidates) {
        if (sampledByFile[c.file] >= kPerFileSampleCap) {
            continue;
        }
        ++sampledByFile[c.file];
        ++sampleSize;

        std::array<std::uint8_t, 32> outBuf{};
        const bool ok = func(dh, c.edid.c_str(), c.file, outBuf.data());

        auto& tally = perFile[c.file];
        ++tally.calls;
        ++totalCalls;
        if (ok) {
            ++tally.hits;
            ++totalHits;
        }
    }
    logger::info("GetExtCellDataTest: sampled {} of {} candidate cell(s) "
                 "(cap {}/file)", sampleSize, candidates.size(), kPerFileSampleCap);

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        clock::now() - t0).count();

    // Bucket by master/ESP — the headline question.
    std::uint64_t masterCalls = 0, masterHits = 0;
    std::uint64_t espCalls    = 0, espHits    = 0;
    std::vector<std::pair<RE::TESFile*, PerFileTally>> filesSorted;
    filesSorted.reserve(perFile.size());
    for (auto& kv : perFile) {
        filesSorted.push_back(kv);
        if (kv.first->recordFlags.all(RE::TESFile::RecordFlag::kMaster)) {
            masterCalls += kv.second.calls;
            masterHits  += kv.second.hits;
        } else {
            espCalls    += kv.second.calls;
            espHits     += kv.second.hits;
        }
    }

    auto pct = [](std::uint64_t hits, std::uint64_t calls) {
        return calls == 0 ? 0.0 : 100.0 * static_cast<double>(hits) / static_cast<double>(calls);
    };

    logger::info("GetExtCellDataTest: {} ms — total {}/{} ({:.1f}%), "
                 "masters {}/{} ({:.1f}%), ESPs {}/{} ({:.1f}%), "
                 "files-tested={}, skipped(no-edid={}, no-file={})",
                 ms, totalHits, totalCalls, pct(totalHits, totalCalls),
                 masterHits, masterCalls, pct(masterHits, masterCalls),
                 espHits, espCalls, pct(espHits, espCalls),
                 perFile.size(), skippedNoEdid, skippedNoFile);

    // Log the worst-performing files (lowest hit rate) — those are the
    // candidates that would benefit from a NOP patch.
    std::sort(filesSorted.begin(), filesSorted.end(),
              [](const auto& a, const auto& b) {
                  const auto pa = a.second.calls == 0 ? 1.0
                                : static_cast<double>(a.second.hits) /
                                  static_cast<double>(a.second.calls);
                  const auto pb = b.second.calls == 0 ? 1.0
                                : static_cast<double>(b.second.hits) /
                                  static_cast<double>(b.second.calls);
                  return pa < pb;
              });
    std::size_t printed = 0;
    for (auto& [file, tally] : filesSorted) {
        if (printed >= 10) break;
        if (tally.calls == 0) continue;
        if (pct(tally.hits, tally.calls) >= 99.999) continue;  // skip clean files
        logger::info("  bottom: {} {}/{} ({:.1f}%) — master={}",
                     file->fileName, tally.hits, tally.calls,
                     pct(tally.hits, tally.calls), file->recordFlags.all(RE::TESFile::RecordFlag::kMaster));
        ++printed;
    }
    if (printed == 0) {
        logger::info("  all files at 100% hit rate");
    }
}

}  // namespace cog::sky
