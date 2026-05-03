#include "PCH.h"
#include "skyrim/InteriorHooks.h"

#include "cog/Settings.h"
#include "skyrim/InteriorOffsets.h"

namespace cog::sky {

namespace {

// =============================================================================
// Strategy — master-only interior offset repair
// =============================================================================
//
// Mirrors WallSoGB's NVSE Cell-Offset-Generator design (InteriorOffsets.hpp):
// "ESP makes cell contents always loaded ... only master files have offsets."
// We capture and repair offsets ONLY for cells whose primary file is a master
// (.esm, .esl, ESM-flagged ESP). ESP interior cells are left on the vanilla
// path entirely — never touched, never written, never read.
//
// Earlier versions of this code applied the optimization to all plugins and
// caused interior→exterior CTDs that baked into save state. Restricting to
// masters matches the original NVSE author's explicit IsMaster check and
// closes the failure mode.
//
// Why we still need this for masters: xEdit doesn't preserve OFST records on
// save, so any master cleaned via QAC, ESM-flagged ESP saved through xEdit,
// or plugin processed by Persistentify ships with INTERIOR_DATA+0x5C
// uninitialized. Engine writes 0 to the field, FindInFileFast finds 0 and
// falls through to the slow path. We capture the file offset at Load time
// (when the engine has the right value in file->fileOffset) and write it
// back into INTERIOR_DATA+0x5C in the post-kDataLoaded scrape.

// Hook strategy: vtable swap on TESObjectCELL slot 6 (Load). Safer than a
// 5-byte function-entry splice — it doesn't require knowing the runtime's
// prologue byte layout, and CommonLibSSE's REL::Relocation::write_vfunc
// handles memory protection for us.

// TESFile::fileOffset — the file's "current parse position", set by the
// engine before each record's Load is invoked.
constexpr std::ptrdiff_t kTESFileFileOffsetField = 0x2A8;

[[nodiscard]] std::uint32_t ReadFileOffset(const RE::TESFile* a_file)
{
    if (!a_file) {
        return 0;
    }
    auto* base = reinterpret_cast<const std::byte*>(a_file);
    return *reinterpret_cast<const std::uint32_t*>(base + kTESFileFileOffsetField);
}

// CellData lives at TESObjectCELL+0x68 on AE 1.6.1170, +0x60 on SE/VR.
// The union holds either EXTERIOR_DATA* or INTERIOR_DATA*; for interior
// cells it's INTERIOR_DATA*, and INTERIOR_DATA+0x5C is the file offset.
[[nodiscard]] std::ptrdiff_t CellDataOffset()
{
    return REL::Module::IsAE() ? 0x68 : 0x60;
}

[[nodiscard]] void* GetCellDataPointer(const RE::TESObjectCELL* a_cell)
{
    if (!a_cell) {
        return nullptr;
    }
    auto* base = reinterpret_cast<const std::byte*>(a_cell);
    return *reinterpret_cast<void* const*>(base + CellDataOffset());
}

// Scoped raw read of cellData->interiorOffset (INTERIOR_DATA+0x5C). Returns:
//   {0, false}  — cellData pointer is null (DATA opcode never populated it)
//   {n, true}   — cellData populated; n is the file offset (may be 0)
struct CellOffsetRead
{
    std::uint32_t offset;
    bool          cellDataPresent;
};
[[nodiscard]] CellOffsetRead ReadCellOffsetField(const RE::TESObjectCELL* a_cell)
{
    auto* ptr = GetCellDataPointer(a_cell);
    if (!ptr) {
        return { 0, false };
    }
    const auto offset = *reinterpret_cast<const std::uint32_t*>(
        static_cast<std::byte*>(ptr) + 0x5C);
    return { offset, true };
}

bool WriteCellOffsetField(RE::TESObjectCELL* a_cell, std::uint32_t a_offset)
{
    auto* ptr = GetCellDataPointer(a_cell);
    if (!ptr) {
        return false;
    }
    *reinterpret_cast<std::uint32_t*>(
        static_cast<std::byte*>(ptr) + 0x5C) = a_offset;
    return true;
}

// =============================================================================
// TESObjectCELL::Load entry hook
// =============================================================================

using LoadFn = bool(__fastcall*)(RE::TESObjectCELL*, RE::TESFile*);
LoadFn g_origLoad = nullptr;

bool __fastcall LoadHook(RE::TESObjectCELL* a_cell, RE::TESFile* a_file)
{
    // Master-only capture, mirrors NVSE InteriorOffsets.hpp's IsMaster guard.
    // ESP interior cells stay on the vanilla code path (never reach our map,
    // never get +0x5C touched).
    if (a_cell && a_file &&
        a_file->recordFlags.all(RE::TESFile::RecordFlag::kMaster)) {
        const auto offset = ReadFileOffset(a_file);
        if (offset != 0) {
            const auto formID = a_cell->GetFormID() & 0x00FFFFFFu;
            interior::AddOffsetForFile(a_file, formID, offset);
        }
    }
    return g_origLoad(a_cell, a_file);
}

}  // namespace

bool InstallInteriorHooks(const cog::Settings& /*a_settings*/)
{
    // VTABLE[0] is the primary vtable for TESObjectCELL. Slot 0x06 is
    // TESForm::Load (overridden by TESObjectCELL::Load). Swap the slot,
    // remember the original for chaining.
    REL::Relocation<std::uintptr_t> vtbl{ RE::TESObjectCELL::VTABLE[0] };
    const auto orig = vtbl.write_vfunc(0x06, &LoadHook);
    if (orig == 0) {
        logger::error("InteriorHooks: vtable swap at slot 6 returned 0");
        return false;
    }
    g_origLoad = reinterpret_cast<LoadFn>(orig);
    logger::info("InteriorHooks: TESObjectCELL::Load vtable[6] swapped (orig +{:X})",
                 orig - REL::Module::get().base());
    return true;
}

void ScrapeInteriorCellsFromLoadedForms()
{
    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        return;
    }

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    std::uint64_t scanned             = 0;
    std::uint64_t alreadyHadOffset    = 0;
    std::uint64_t skippedNoFile       = 0;
    std::uint64_t skippedNullCellData = 0;
    std::uint64_t skippedNonInterior  = 0;
    std::uint64_t repairTried         = 0;
    std::uint64_t repairWritten       = 0;
    std::uint64_t repairNoEntry       = 0;

    for (auto* cell : dh->interiorCells) {
        if (!cell) {
            continue;
        }
        ++scanned;

        if (!cell->IsInteriorCell()) {
            ++skippedNonInterior;
            continue;
        }

        auto* file = cell->GetFile(0);
        if (!file) {
            ++skippedNoFile;
            continue;
        }

        // Master-only repair, matching the LoadHook filter above. ESP-defined
        // interior cells are left on the vanilla path.
        if (!file->recordFlags.all(RE::TESFile::RecordFlag::kMaster)) {
            continue;
        }

        const auto read = ReadCellOffsetField(cell);
        if (!read.cellDataPresent) {
            ++skippedNullCellData;
            continue;
        }

        const auto formID = cell->GetFormID() & 0x00FFFFFFu;

        if (read.offset != 0) {
            // Engine wrote a valid offset; ensure our map has the entry too
            // (LoadHook may have already captured this, but pre-hook cells are
            // still candidates for capture).
            interior::AddOffsetForFile(file, formID, read.offset);
            ++alreadyHadOffset;
            continue;
        }

        // Repair: cell has cellData but +0x5C == 0 (typical xEdit-cleaned
        // master). Walk the cell's sourceFiles array — TESForm::GetFile(i)
        // for out-of-range i returns array->back() rather than nullptr, so a
        // `until null` loop never terminates.
        //
        // Prefer the LATEST file's offset (overrides sit later in the list)
        // since cellData itself was last reallocated by that file's load,
        // making its offset most likely the one FindInFileFast will need.
        // Multi-source masters are the normal state in real modlists (USSEP,
        // cleaning tools, Persistentify all touch cells); filtering them out
        // disables the optimization entirely. The hot lookup path queries
        // the latest override file, so writing the latest's offset matches
        // vanilla engine behavior.
        ++repairTried;
        std::uint32_t patched = 0;
        if (auto* arr = cell->sourceFiles.array) {
            for (auto* candidate : *arr) {
                if (!candidate) {
                    continue;
                }
                const auto mapped = interior::GetOffsetForFile(candidate, formID);
                if (mapped != 0) {
                    patched = mapped;
                }
            }
        }
        if (patched == 0) {
            ++repairNoEntry;
            continue;
        }
        if (WriteCellOffsetField(cell, patched)) {
            ++repairWritten;
        }
    }

    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        clock::now() - t0).count();
    logger::info("InteriorHooks: scrape+repair in {} ms — scanned={}, "
                 "already-had-offset={}, repaired={}, repair-no-entry={}, "
                 "repair-tried={}, no-file={}, non-interior={}, null-cellData={}, "
                 "files-in-map={}",
                 ms, scanned, alreadyHadOffset, repairWritten, repairNoEntry,
                 repairTried, skippedNoFile, skippedNonInterior,
                 skippedNullCellData, interior::CountFiles());
}

}  // namespace cog::sky
