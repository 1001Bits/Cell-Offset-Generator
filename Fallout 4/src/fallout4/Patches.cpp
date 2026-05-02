#include "PCH.h"
#include "fallout4/Patches.h"

#include "cog/Settings.h"

namespace cog::fo4 {

namespace {

enum class Group : std::uint8_t
{
    Load,    // OFST-load path: ESPs get pCellFileOffsets populated
    Lookup,  // FindCellInFile / FindInFileFast: ESP cells reach the lookup
};

struct PatchSite
{
    std::uintptr_t address_abs;  // absolute address (image base 0x140000000)
    std::size_t    length;       // bytes to NOP
    const char*    name;
    Group          group;
    std::uint8_t   expected[6];  // verification bytes (unused tail = 0)
};

// ── Per-runtime patch tables ────────────────────────────────────────────────
// Each entry's `address_abs` is the absolute VA of an IsMaster() gate at the
// start of `if (!file->IsMaster()) goto skip`. The expected bytes are the
// disassembled jump — verified before NOPing so a Bethesda patch that shifts
// code can never silently corrupt the binary.
//
// F4 has four distinct runtimes; addresses drift between every one:
//   OG  = 1.10.163         (pre-Next-Gen, original Steam build)
//   NG  = 1.10.980/984     (Next-Gen update; short-lived)
//   AE  = 1.11.x           (Anniversary Edition; later release)
//   VR  = 1.2.72           (Fallout 4 VR)
//
// Verified in Ghidra:
//   OG  ↔ user-installed Fallout4.exe (1.10.163, ~65 MB, 189870 functions)
//   NG  ↔ Fallout4.exe.unpacked.exe (depot_377162, 1.10.984)
//   AE  ↔ current Steam Fallout4.exe (1.11.191)
//   VR  ↔ Fallout4VR.exe (1.2.72)

constexpr PatchSite kPatchSitesOG_1_10_163[] = {
    { 0x140490DAE, 2, "Load.fileOffset",       Group::Load,   { 0x74, 0x15 } },
    { 0x140490F06, 6, "Load.offsetMinCoords",  Group::Load,   { 0x0F, 0x84, 0x81, 0x07, 0x00, 0x00 } },
    { 0x140491024, 6, "Load.offsetMaxCoords",  Group::Load,   { 0x0F, 0x84, 0x63, 0x06, 0x00, 0x00 } },
    { 0x14049183F, 6, "LoadPartial.gateMax",   Group::Load,   { 0x0F, 0x84, 0x85, 0x00, 0x00, 0x00 } },
    { 0x1404918B4, 2, "LoadPartial.gateMin",   Group::Load,   { 0x74, 0x14 } },
    { 0x140491F16, 2, "FindCellInFile",        Group::Lookup, { 0x74, 0x63 } },
    { 0x1404924FC, 2, "FindInFileFast",        Group::Lookup, { 0x74, 0x48 } },
    { 0x1403BD60F, 2, "Cell::FindInFileFast",  Group::Lookup, { 0x74, 0x72 } },
    // ── INTENTIONALLY OMITTED: CellLoader.intCapture (was 0x1403AD165) ──────
    // Mirrors NVSE intent: ESMs get interior optimization, ESPs don't.
    //
    // Vanilla F4 already maintains a per-file formID→offset array for interior
    // cells at TESFile+0x3B8 — but the write site is IsMaster-gated. Masters
    // pass the check unconditionally (so vanilla F4 already optimizes ESM
    // interiors); ESPs are blocked. We previously NOPed this gate to extend
    // the optimization to ESPs, but that path mirrors the Skyrim port bug
    // WallSoGB explicitly avoided in InteriorOffsets.hpp:
    //   "ESP makes cell contents always loaded ... only master files have
    //    offsets" — writing offsets into ESP interior cells triggers engine
    // teardown paths vanilla never exercises, corrupting reference state in
    // a way that's baked into the save (uninstalling doesn't unpoison).
    //
    // The Lookup-group `Cell::FindInFileFast` NOP above is safe even for ESPs
    // because it's read-only — without entries written by intCapture, the
    // ESP-interior read returns 0 and falls through to the slow path.
};

constexpr PatchSite kPatchSitesNG_1_10_984[] = {
    { 0x14051D6FE, 2, "Load.fileOffset",       Group::Load,   { 0x74, 0x15 } },
    { 0x14051D844, 6, "Load.offsetMinCoords",  Group::Load,   { 0x0F, 0x84, 0xA6, 0x00, 0x00, 0x00 } },
    { 0x14051D9F1, 6, "Load.offsetMaxCoords",  Group::Load,   { 0x0F, 0x84, 0xF9, 0xFE, 0xFF, 0xFF } },
    { 0x14051E12B, 2, "LoadPartial.gateMax",   Group::Load,   { 0x74, 0x79 } },
    { 0x14051E18E, 2, "LoadPartial.gateMin",   Group::Load,   { 0x74, 0x16 } },
    { 0x14051E906, 2, "FindCellInFile",        Group::Lookup, { 0x74, 0x63 } },
    { 0x14051EEFC, 2, "FindInFileFast",        Group::Lookup, { 0x74, 0x48 } },
    { 0x140480353, 6, "Cell::FindInFileFast",  Group::Lookup, { 0x0F, 0x84, 0xB7, 0x00, 0x00, 0x00 } },
    // CellLoader.intCapture intentionally omitted — see OG comment above.
};

constexpr PatchSite kPatchSitesAE[] = {
    { 0x14057167E, 2, "Load.fileOffset",       Group::Load,   { 0x74, 0x15 } },
    { 0x1405717C4, 6, "Load.offsetMinCoords",  Group::Load,   { 0x0F, 0x84, 0xA6, 0x00, 0x00, 0x00 } },
    { 0x140571971, 6, "Load.offsetMaxCoords",  Group::Load,   { 0x0F, 0x84, 0xF9, 0xFE, 0xFF, 0xFF } },
    { 0x1405720AB, 2, "LoadPartial.gateMax",   Group::Load,   { 0x74, 0x79 } },
    { 0x14057210E, 2, "LoadPartial.gateMin",   Group::Load,   { 0x74, 0x16 } },
    { 0x140572886, 2, "FindCellInFile",        Group::Lookup, { 0x74, 0x63 } },
    { 0x140572E7C, 2, "FindInFileFast",        Group::Lookup, { 0x74, 0x48 } },
    { 0x1404D41C3, 6, "Cell::FindInFileFast",  Group::Lookup, { 0x0F, 0x84, 0xB7, 0x00, 0x00, 0x00 } },
    // CellLoader.intCapture intentionally omitted — see OG comment above.
};

constexpr PatchSite kPatchSitesVR_1_2_72[] = {
    { 0x140479EEE, 2, "Load.fileOffset",       Group::Load,   { 0x74, 0x15 } },
    { 0x14047A046, 6, "Load.offsetMinCoords",  Group::Load,   { 0x0F, 0x84, 0x81, 0x07, 0x00, 0x00 } },
    { 0x14047A164, 6, "Load.offsetMaxCoords",  Group::Load,   { 0x0F, 0x84, 0x63, 0x06, 0x00, 0x00 } },
    { 0x14047A97F, 6, "LoadPartial.gateMax",   Group::Load,   { 0x0F, 0x84, 0x85, 0x00, 0x00, 0x00 } },
    { 0x14047A9F4, 2, "LoadPartial.gateMin",   Group::Load,   { 0x74, 0x14 } },
    { 0x14047B056, 2, "FindCellInFile",        Group::Lookup, { 0x74, 0x63 } },
    { 0x14047B63C, 2, "FindInFileFast",        Group::Lookup, { 0x74, 0x48 } },
    { 0x1403A3CDF, 2, "Cell::FindInFileFast",  Group::Lookup, { 0x74, 0x72 } },
    // CellLoader.intCapture intentionally omitted — see OG comment above.
};

[[nodiscard]] std::span<const PatchSite> PickPatchSites()
{
    const auto ver = REL::Module::get().version();
    if (ver == F4SE::RUNTIME_1_10_163)  return { kPatchSitesOG_1_10_163 };
    if (ver == F4SE::RUNTIME_VR_1_2_72) return { kPatchSitesVR_1_2_72 };
    // Split the post-OG desktop range at 1.11: 1.10.980/1.10.984 are NG
    // (Next-Gen update), 1.11.x is AE (Anniversary Edition). The two share
    // similar layouts but offsets drift, so we keep separate tables.
    constexpr REL::Version kFirstAE{ 1, 11, 0, 0 };
    if (ver >= kFirstAE)                return { kPatchSitesAE };
    if (ver >= F4SE::RUNTIME_1_10_984)  return { kPatchSitesNG_1_10_984 };
    return {};
}

[[nodiscard]] bool VerifyAndPatch(const PatchSite& a_site)
{
    const auto& mod = REL::Module::get();
    const auto base = mod.base();

    constexpr std::uintptr_t kExpectedBase = 0x140000000;
    const auto offset = a_site.address_abs - kExpectedBase;
    const auto target = reinterpret_cast<std::uint8_t*>(base + offset);

    for (std::size_t i = 0; i < a_site.length; ++i) {
        if (target[i] != a_site.expected[i]) {
            logger::error("[{}] expected byte {:02X} at +{:X}, got {:02X} — refusing to patch",
                          a_site.name, a_site.expected[i], offset + i, target[i]);
            return false;
        }
    }

    REL::safe_fill(reinterpret_cast<std::uintptr_t>(target), 0x90, a_site.length);
    logger::info("[{}] NOPed {} byte(s) at +{:X}", a_site.name, a_site.length, offset);
    return true;
}

}  // namespace

bool InstallEsmGateNops(const cog::Settings& a_settings)
{
    const auto& mod = REL::Module::get();
    const auto ver = mod.version();
    const auto sites = PickPatchSites();

    if (sites.empty()) {
        logger::warn("Patches: no NOP sites configured for runtime {} — "
                     "supported: OG 1.10.163, NG 1.10.980/984, AE 1.11.x, VR 1.2.72.",
                     ver.string());
        return false;
    }

    if (!a_settings.enablePatches) {
        logger::info("Patches: disabled via Settings.enablePatches=false");
        return true;
    }

    logger::info("Patches: load-gates={}, lookup-gates={}, runtime={}",
                 a_settings.enableLoadGates ? "on" : "OFF",
                 a_settings.enableLookupGates ? "on" : "OFF",
                 ver.string());

    bool allOk = true;
    std::size_t applied = 0;
    for (const auto& site : sites) {
        const bool enabled =
            (site.group == Group::Load   && a_settings.enableLoadGates) ||
            (site.group == Group::Lookup && a_settings.enableLookupGates);
        if (!enabled) {
            logger::info("[{}] skipped (group disabled in settings)", site.name);
            continue;
        }
        if (VerifyAndPatch(site)) {
            ++applied;
        } else {
            allOk = false;
        }
    }

    logger::info("Patches: {}/{} site(s) applied{}",
                 applied, sites.size(),
                 allOk ? "" : " — one or more failed verification");
    return allOk;
}

}  // namespace cog::fo4
