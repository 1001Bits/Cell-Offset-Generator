#include "PCH.h"
#include "Patches.h"

#include "Settings.h"

namespace cog {

namespace {

enum class Group : std::uint8_t
{
    Load,    // OFST-load path: ESPs get pCellFileOffsets populated
    Lookup,  // FindCellInFile / FindInFileFast: ESP cells reach the lookup
};

struct PatchSite
{
    std::uintptr_t address_abs;  // absolute address in this runtime's image (image base 0x140000000)
    std::size_t    length;       // bytes to NOP
    const char*    name;
    Group          group;
    std::uint8_t   expected[6];  // verification bytes (unused tail = 0)
};

// Patch sites cover EXTERIOR cell paths only. ESP interior cells stay on the
// vanilla path: ESPs make cell contents perma-resident after the initial
// data-load parse, so the engine never re-streams interiors and never calls
// FindInFileFast on them. Earlier versions of this port NOPed two extra
// interior gates (Load.interiorFileOffset, CELL.FindInFileFast) and eagerly
// wrote INTERIOR_DATA+0x5C; that caused interior→exterior CTDs that baked
// into save state.

// AE 1.6.1170 — verified working.
constexpr PatchSite kPatchSitesAE_1_6_1170[] = {
    { 0x1403053F2, 2, "Load.fileOffset",            Group::Load,   { 0x74, 0x15 } },
    { 0x140305566, 6, "Load.offsetMinCoords",       Group::Load,   { 0x0F, 0x84, 0x91, 0x05, 0x00, 0x00 } },
    { 0x1403056DF, 6, "Load.offsetMaxCoords",       Group::Load,   { 0x0F, 0x84, 0x18, 0x04, 0x00, 0x00 } },
    { 0x140305F6E, 6, "LoadPartial.gate1",          Group::Load,   { 0x0F, 0x84, 0x99, 0x00, 0x00, 0x00 } },
    { 0x140305FF5, 2, "LoadPartial.gate2",          Group::Load,   { 0x74, 0x16 } },
    { 0x1403069EC, 2, "FindInFileFast",             Group::Lookup, { 0x74, 0x48 } },
    { 0x1403064E6, 2, "FindCellInFile",             Group::Lookup, { 0x74, 0x63 } },
};

// SE 1.5.97 — verified via Ghidra (SkyrimSE.gpr).
constexpr PatchSite kPatchSitesSE_1_5_97[] = {
    { 0x1402B0B63, 2, "Load.fileOffset",            Group::Load,   { 0x74, 0x14 } },
    { 0x1402B0CDF, 6, "Load.offsetMinCoords",       Group::Load,   { 0x0F, 0x84, 0xEC, 0x07, 0x00, 0x00 } },
    { 0x1402B0E5D, 6, "Load.offsetMaxCoords",       Group::Load,   { 0x0F, 0x84, 0x6E, 0x06, 0x00, 0x00 } },
    { 0x1402B165E, 6, "LoadPartial.gate1",          Group::Load,   { 0x0F, 0x84, 0xA9, 0x00, 0x00, 0x00 } },
    { 0x1402B16F5, 2, "LoadPartial.gate2",          Group::Load,   { 0x74, 0x16 } },
    { 0x1402B207C, 2, "FindInFileFast",             Group::Lookup, { 0x74, 0x48 } },
    { 0x1402B1B86, 2, "FindCellInFile",             Group::Lookup, { 0x74, 0x63 } },
};

// VR 1.4.15 — verified via Ghidra (skyrimvr.gpr). Function bodies are byte-
// identical to SE; entry points shifted by +0x11770.
constexpr PatchSite kPatchSitesVR_1_4_15[] = {
    { 0x1402C22D3, 2, "Load.fileOffset",            Group::Load,   { 0x74, 0x14 } },
    { 0x1402C244F, 6, "Load.offsetMinCoords",       Group::Load,   { 0x0F, 0x84, 0xEC, 0x07, 0x00, 0x00 } },
    { 0x1402C25CD, 6, "Load.offsetMaxCoords",       Group::Load,   { 0x0F, 0x84, 0x6E, 0x06, 0x00, 0x00 } },
    { 0x1402C2DCE, 6, "LoadPartial.gate1",          Group::Load,   { 0x0F, 0x84, 0xA9, 0x00, 0x00, 0x00 } },
    { 0x1402C2E65, 2, "LoadPartial.gate2",          Group::Load,   { 0x74, 0x16 } },
    { 0x1402C37EC, 2, "FindInFileFast",             Group::Lookup, { 0x74, 0x48 } },
    { 0x1402C32F6, 2, "FindCellInFile",             Group::Lookup, { 0x74, 0x63 } },
};

// GOG 1.6.1179 — verified via Ghidra (SkyrimSE GOG). Each site shifted -0x1D0
// from its AE 1.6.1170 counterpart; expected bytes are byte-identical to AE.
constexpr PatchSite kPatchSitesGOG_1_6_1179[] = {
    { 0x140305222, 2, "Load.fileOffset",            Group::Load,   { 0x74, 0x15 } },
    { 0x140305396, 6, "Load.offsetMinCoords",       Group::Load,   { 0x0F, 0x84, 0x91, 0x05, 0x00, 0x00 } },
    { 0x14030550F, 6, "Load.offsetMaxCoords",       Group::Load,   { 0x0F, 0x84, 0x18, 0x04, 0x00, 0x00 } },
    { 0x140305D9E, 6, "LoadPartial.gate1",          Group::Load,   { 0x0F, 0x84, 0x99, 0x00, 0x00, 0x00 } },
    { 0x140305E25, 2, "LoadPartial.gate2",          Group::Load,   { 0x74, 0x16 } },
    { 0x14030681C, 2, "FindInFileFast",             Group::Lookup, { 0x74, 0x48 } },
    { 0x140306316, 2, "FindCellInFile",             Group::Lookup, { 0x74, 0x63 } },
};

[[nodiscard]] std::span<const PatchSite> PickPatchSites()
{
    const auto ver = REL::Module::get().version();
    constexpr REL::Version kAE{ 1, 6, 1170, 0 };
    constexpr REL::Version kSE{ 1, 5, 97, 0 };
    constexpr REL::Version kVR{ 1, 4, 15, 0 };
    constexpr REL::Version kGOG{ 1, 6, 1179, 0 };
    if (ver == kAE)  return { kPatchSitesAE_1_6_1170 };
    if (ver == kSE)  return { kPatchSitesSE_1_5_97 };
    if (ver == kVR)  return { kPatchSitesVR_1_4_15 };
    if (ver == kGOG) return { kPatchSitesGOG_1_6_1179 };
    return {};
}

[[nodiscard]] bool VerifyAndPatch(const PatchSite& a_site)
{
    const auto& mod = REL::Module::get();
    const auto base = mod.base();

    // Sites are recorded against the binary's stated image base 0x140000000.
    // Translate to the actual loaded base via the image-relative offset.
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

bool Patches::InitHooks(const Settings& a_settings)
{
    const auto& mod = REL::Module::get();
    const auto ver = mod.version();
    const auto sites = PickPatchSites();

    if (sites.empty()) {
        logger::warn("Patches: no NOP sites configured for runtime {} — "
                     "supported: AE 1.6.1170, SE 1.5.97, VR 1.4.15, GOG 1.6.1179.",
                     ver.string());
        return false;
    }

    if (!a_settings.enablePatches) {
        logger::info("Patches: disabled via INI [Patches] EnablePatches=0");
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
            logger::info("[{}] skipped (group disabled in INI)", site.name);
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

}  // namespace cog
