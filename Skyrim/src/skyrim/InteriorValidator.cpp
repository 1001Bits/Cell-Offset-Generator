#include "PCH.h"
#include "skyrim/InteriorValidator.h"

#include "skyrim/InteriorOffsets.h"

#include <fstream>
#include <unordered_map>

namespace cog::sky {

namespace {

struct Tally
{
    std::uint64_t checked = 0;
    std::uint64_t valid   = 0;
    std::uint64_t openFailed = 0;
    std::uint64_t filesScanned = 0;
};

[[nodiscard]] bool ReadCellMagicAt(std::ifstream& a_stream, std::uint32_t a_offset)
{
    a_stream.clear();
    a_stream.seekg(static_cast<std::streamoff>(a_offset), std::ios::beg);
    char magic[4]{};
    a_stream.read(magic, 4);
    return a_stream.good() && std::memcmp(magic, "CELL", 4) == 0;
}

}  // namespace

void RunInteriorValidator()
{
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    const auto fileCount  = interior::CountFiles();
    if (fileCount == 0) {
        logger::info("InteriorValidator: 0 files captured — interior hooks not "
                     "installed or not yet run, skipping");
        return;
    }

    // Group entries by file so we open each plugin once.
    std::unordered_map<RE::TESFile*, std::vector<std::pair<std::uint32_t, std::uint32_t>>> byFile;
    interior::ForEach([&](RE::TESFile* a_file, std::uint32_t a_formID,
                          std::uint32_t a_offset) {
        byFile[a_file].emplace_back(a_formID, a_offset);
        return true;
    });

    Tally tally{};
    std::vector<std::string> failures;
    failures.reserve(20);

    for (auto& [file, entries] : byFile) {
        if (!file) {
            continue;
        }
        const auto pluginPath = std::filesystem::path("Data") /
                                std::string_view(file->fileName);
        std::ifstream stream(pluginPath, std::ios::binary);
        if (!stream) {
            ++tally.openFailed;
            logger::warn("InteriorValidator: can't open {}", file->fileName);
            continue;
        }
        ++tally.filesScanned;

        for (const auto& [formID, offset] : entries) {
            ++tally.checked;
            if (ReadCellMagicAt(stream, offset)) {
                ++tally.valid;
            } else if (failures.size() < 20) {
                failures.push_back(fmt::format(
                    "{} formID=+{:06X} offset=+{:X} — no CELL magic",
                    file->fileName, formID, offset));
            }
        }
    }

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        clock::now() - t0).count();
    const auto invalid = tally.checked - tally.valid;
    logger::info("InteriorValidator: {} ms — files-scanned={}, checked={}, valid={}, "
                 "invalid={}, open-failed={}",
                 ms, tally.filesScanned, tally.checked, tally.valid, invalid,
                 tally.openFailed);
    for (const auto& f : failures) {
        logger::error("  {}", f);
    }
    if (invalid > failures.size()) {
        logger::error("  ... ({} more invalid entries omitted)",
                      invalid - failures.size());
    }
}

}  // namespace cog::sky
