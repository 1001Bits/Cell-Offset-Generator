#include "PCH.h"
#include "skyrim/Validator.h"

#include "skyrim/EngineCalls.h"
#include "skyrim/EngineTypes.h"
#include "skyrim/GenerationLog.h"

#include <fstream>

namespace cog::sky {

namespace {

[[nodiscard]] std::int32_t WorldUnitsToCellFloor(float a_v)
{
    const auto t = static_cast<std::int32_t>(a_v);
    if (a_v - static_cast<float>(t) < 0.0f) {
        return (t - 1) >> 12;
    }
    return t >> 12;
}

[[nodiscard]] bool ReadCellMagicAt(std::ifstream& a_stream, std::uint64_t a_absoluteOffset)
{
    a_stream.clear();
    a_stream.seekg(static_cast<std::streamoff>(a_absoluteOffset), std::ios::beg);
    char magic[4]{};
    a_stream.read(magic, 4);
    return a_stream.good() && std::memcmp(magic, "CELL", 4) == 0;
}

struct Tally
{
    std::uint64_t checked = 0;
    std::uint64_t valid   = 0;
    std::uint64_t openFailed = 0;
    std::uint64_t worldsScanned = 0;
    std::uint64_t fileOffsetMutated = 0;
    std::uint64_t entryMutated = 0;
    // Same data, different traversal: iterate raw indices instead of (x,y).
    std::uint64_t rawChecked = 0;
    std::uint64_t rawValid   = 0;
};

void ValidateFile(RE::TESFile* a_file, RE::TESDataHandler* a_dh,
                  Tally& a_tally, std::vector<std::string>& a_failures)
{
    if (!a_file || !a_dh) {
        return;
    }
    const auto pluginPath = std::filesystem::path("Data") /
                            std::string_view(a_file->fileName);
    std::ifstream stream(pluginPath, std::ios::binary);
    if (!stream) {
        ++a_tally.openFailed;
        logger::warn("Validator: can't open {}", a_file->fileName);
        return;
    }

    for (auto* world : a_dh->GetFormArray<RE::TESWorldSpace>()) {
        if (!world) {
            continue;
        }
        auto* data = FindOffsetData(world, a_file);
        if (!data || !data->pCellFileOffsets) {
            continue;
        }
        const auto minX = WorldUnitsToCellFloor(data->offsetMinCoords.x);
        const auto minY = WorldUnitsToCellFloor(data->offsetMinCoords.y);
        const auto maxX = WorldUnitsToCellFloor(data->offsetMaxCoords.x);
        const auto maxY = WorldUnitsToCellFloor(data->offsetMaxCoords.y);
        if (minX == -524288 || maxX < minX || maxY < minY) {
            continue;
        }
        ++a_tally.worldsScanned;

        bool hasRecorded = false;
        const auto recordedFileOffset =
            GenerationLog::GetRecordedFileOffset(a_file, world, hasRecorded);
        if (hasRecorded && recordedFileOffset != data->fileOffset) {
            ++a_tally.fileOffsetMutated;
            if (a_tally.fileOffsetMutated <= 5) {
                logger::warn("[{}/{}] fileOffset mutated: was +{:X} at write, now +{:X}",
                             a_file->fileName, world->GetFormEditorID(),
                             recordedFileOffset, data->fileOffset);
            }
        }
        const auto* recordedTable = GenerationLog::GetRecordedTable(a_file, world);

        // Raw-index pass: iterate the recorded table by index, verify each
        // non-zero entry. If this passes but the (x,y) pass fails, the
        // difference must be in GetIndexForCellCoord's mapping changing.
        if (recordedTable) {
            for (std::uint32_t i = 0; i < recordedTable->size(); ++i) {
                const auto entry = (*recordedTable)[i];
                if (entry == 0) {
                    continue;
                }
                ++a_tally.rawChecked;
                const auto absolute32 = static_cast<std::uint32_t>(
                    data->fileOffset + entry);
                stream.clear();
                stream.seekg(static_cast<std::streamoff>(absolute32),
                             std::ios::beg);
                char rawMagic[4]{};
                stream.read(rawMagic, 4);
                if (stream.good() && std::memcmp(rawMagic, "CELL", 4) == 0) {
                    ++a_tally.rawValid;
                }
            }
        }

        const auto tableSize = recordedTable ? recordedTable->size() : 0;
        for (std::int32_t y = minY; y <= maxY; ++y) {
            for (std::int32_t x = minX; x <= maxX; ++x) {
                const auto idx = GetIndexForCellCoord(world, a_file, x, y);
                if (idx <= 0) {
                    continue;
                }
                if (recordedTable && static_cast<std::uint32_t>(idx) >= tableSize) {
                    // idx is out of the bounds we allocated for the table.
                    // Reading data->pCellFileOffsets[idx] would be a buffer
                    // overrun. Skip — these are the "false positive" cases.
                    continue;
                }
                const auto entry = data->pCellFileOffsets[idx];
                if (entry == 0) {
                    continue;
                }
                if (recordedTable && static_cast<std::uint32_t>(idx) < recordedTable->size()) {
                    const auto recordedEntry = (*recordedTable)[idx];
                    if (recordedEntry != entry) {
                        ++a_tally.entryMutated;
                        if (a_tally.entryMutated <= 5) {
                            logger::warn("[{}/{}] entry mutated idx={}: was +{:X}, now +{:X}",
                                         a_file->fileName, world->GetFormEditorID(),
                                         idx, recordedEntry, entry);
                        }
                    }
                }
                const auto absolute32 = static_cast<std::uint32_t>(
                    data->fileOffset + entry);
                const auto absolute = static_cast<std::uint64_t>(absolute32);
                ++a_tally.checked;
                if (ReadCellMagicAt(stream, absolute)) {
                    ++a_tally.valid;
                } else if (a_failures.size() < 20) {
                    a_failures.push_back(fmt::format(
                        "{}/{} ({},{}) idx={} entry=+{:X} abs=+{:X} — no CELL magic",
                        a_file->fileName, world->GetFormEditorID(), x, y, idx,
                        entry, absolute));
                }
            }
        }
    }
}

}  // namespace

void RunValidator()
{
    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        return;
    }

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    Tally tally{};
    std::vector<std::string> failures;
    failures.reserve(20);

    if (auto** mods = dh->GetLoadedMods()) {
        const auto n = dh->GetLoadedModCount();
        for (std::uint32_t i = 0; i < n; ++i) {
            ValidateFile(mods[i], dh, tally, failures);
        }
    }
    if (auto** mods = dh->GetLoadedLightMods()) {
        const auto n = dh->GetLoadedLightModCount();
        for (std::uint32_t i = 0; i < n; ++i) {
            ValidateFile(mods[i], dh, tally, failures);
        }
    }

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        clock::now() - t0).count();

    const auto invalid = tally.checked - tally.valid;
    logger::info("Validator: {} ms — worlds={}, (x,y)-pass: checked={} valid={} invalid={}, "
                 "raw-pass: checked={} valid={} invalid={}, "
                 "files-failed-open={}, fileOffset-mutated={}, entry-mutated={}",
                 ms, tally.worldsScanned, tally.checked, tally.valid, invalid,
                 tally.rawChecked, tally.rawValid, tally.rawChecked - tally.rawValid,
                 tally.openFailed, tally.fileOffsetMutated, tally.entryMutated);
    for (const auto& f : failures) {
        logger::error("  {}", f);
    }
    if (invalid > failures.size()) {
        logger::error("  ... ({} more invalid entries omitted)",
                      invalid - failures.size());
    }
}

}  // namespace cog::sky
