#include "PCH.h"
#include "skyrim/InteriorHooks.h"

#include "cog/Settings.h"
#include "skyrim/InteriorOffsets.h"

namespace cog::sky {

namespace {

// =============================================================================
// Strategy
// =============================================================================
//
// The Load.interiorFileOffset NOP (in Patches.cpp) lets ESP cells flow through
// the engine's own SetInteriorOffset CALL inside TESObjectCELL::Load — but
// only when the DATA opcode handler runs. Override-only ESP records (changing
// FULL/LCTN without redefining DATA) skip that path entirely, so the master's
// previously-written +0x5C gets clobbered when cellData.interior is
// reallocated, and FindInFileFast falls back to slow scan.
//
// To close that gap we hook TESObjectCELL::Load at the function entry. Every
// cell load — master, ESP-with-DATA, override-only — captures
// (file, formID, file->fileOffset) into our interior map. Then in the
// post-kDataLoaded scrape we run a repair pass: any cell still showing
// +0x5C == 0 gets the captured offset written back into INTERIOR_DATA.
//
// All offsets are validated by InteriorValidator against the source plugins.

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
    // Capture (file, formID, fileOffset) on EVERY cell-load entry — covers
    // override-only records that never reach the engine's own SetInteriorOffset
    // CALL. fileOffset is the cell record's start offset in the source file.
    if (a_cell && a_file) {
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

        // Repair: cell has cellData but +0x5C == 0. Walk the cell's
        // sourceFiles array directly — TESForm::GetFile(i) for out-of-range
        // i returns array->back() rather than nullptr, so a `until null`
        // loop never terminates.
        //
        // Prefer the LATEST file's offset (overrides sit later in the list)
        // since cellData itself was last reallocated by that file's load,
        // making its offset most likely the one FindInFileFast will need.
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
