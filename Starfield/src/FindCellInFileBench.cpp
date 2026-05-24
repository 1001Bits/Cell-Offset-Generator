#include "PCH.h"
#include "FindCellInFileBench.hpp"
#include "TESWorldSpaceExt.hpp"   // GetOffsetData / GetIndexForCellCoord / OFFSET_DATA

#include "REL/ASM.h"
#include "REL/Relocation.h"
#include "REL/Utility.h"
#include "REL/Trampoline.h"
#include "REX/W32/KERNEL32.h"

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace cog::sf::bench {

namespace {

// ── Per-runtime address + prologue table ──────────────────────────────────
// Each detour writes E9 rel32 over the first 5 bytes of the target. We
// require those 5 bytes to span a SINGLE x86-64 instruction with no RIP-
// relative addressing, so the trampoline can re-execute them verbatim.
// Both target functions have a clean 5-byte register-spill instruction at
// their entry, verified by byte-dump of the 1.16.236 binary.

struct PrologueRecord
{
    std::uintptr_t offset;            // image-relative entry offset
    std::uint8_t   firstFive[5];      // exact bytes overwritten by E9 rel32
    const char*    name;              // for log messages
};

struct RuntimePrologues
{
    PrologueRecord findCellInFile;
    PrologueRecord findInFileFast;
    PrologueRecord getIndexForCellCoord;
    PrologueRecord seekFile;
};

// 1.16.236 — both verified by dumping the .text section directly from
// C:/Games/Starfield 1.16.236/Starfield.exe.
//
// FindCellInFile @ 0x140BBA370:
//     44 89 44 24 18    mov dword ptr [rsp+18h], r8d
//
// FindInFileFast @ 0x140BBA6D0  (entry of the function whose IsMaster gate
// at +0xBBA6EC is patch site #7; 0xBBA6EC - 0x1C confirms the entry):
//     48 89 5c 24 08    mov qword ptr [rsp+8], rbx
constexpr RuntimePrologues kProls_1_16_236 = {
    .findCellInFile = {
        .offset    = 0x0BBA370,
        .firstFive = { 0x44, 0x89, 0x44, 0x24, 0x18 },
        .name      = "FindCellInFile",
    },
    .findInFileFast = {
        .offset    = 0x0BBA6D0,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x08 },
        .name      = "FindInFileFast",
    },
    // FUN_140bb8600 — TESWorldSpace::GetIndexForCellCoord.
    // Prologue: 48 89 5C 24 08 = mov [rsp+0x8], rbx
    .getIndexForCellCoord = {
        .offset    = 0x0BB8600,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x08 },
        .name      = "GetIndexForCellCoord",
    },
    // FUN_1405bb360 — file seek used by FCF's fast-path (sets file->fileOffset,
    // calls buffer seek, refetches group header).
    // Prologue: 48 89 5C 24 10 = mov [rsp+0x10], rbx
    .seekFile = {
        .offset    = 0x05BB360,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x10 },
        .name      = "SeekFile",
    },
};

// 1.16.242 — same prologue bytes as 1.16.236 (each function is byte-identical
// in size between the two versionlib bins, so the entry instructions are
// unchanged); only the entry RVAs shifted. IDs: findCellInFile=64491,
// findInFileFast=64492, getIndexForCellCoord=64480, seekFile=46887.
constexpr RuntimePrologues kProls_1_16_242 = {
    .findCellInFile = {
        .offset    = 0x0BBA530,
        .firstFive = { 0x44, 0x89, 0x44, 0x24, 0x18 },
        .name      = "FindCellInFile",
    },
    .findInFileFast = {
        .offset    = 0x0BBA890,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x08 },
        .name      = "FindInFileFast",
    },
    .getIndexForCellCoord = {
        .offset    = 0x0BB87C0,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x08 },
        .name      = "GetIndexForCellCoord",
    },
    .seekFile = {
        .offset    = 0x05BB3D0,
        .firstFive = { 0x48, 0x89, 0x5C, 0x24, 0x10 },
        .name      = "SeekFile",
    },
};

[[nodiscard]] const RuntimePrologues* PickPrologues()
{
    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    if (ver == SFSE::RUNTIME_SF_1_16_236) return &kProls_1_16_236;
    if (ver == SFSE::RUNTIME_SF_1_16_242) return &kProls_1_16_242;
    return nullptr;
}

// ── Atomic counter set — one instance per instrumented function ──────────
// fetch_add for totals/counts; CAS for min/max. Workers updating these in
// parallel cannot starve the reader: GetEngineCallStats snapshots with
// relaxed loads, and at most reads slightly-out-of-date values, which is
// fine for periodic logging.
struct AtomicStats
{
    std::atomic<std::uint64_t> calls{ 0 };
    std::atomic<std::uint64_t> hits{ 0 };
    std::atomic<std::int64_t>  totalNs{ 0 };
    std::atomic<std::int64_t>  minNs{ (std::numeric_limits<std::int64_t>::max)() };
    std::atomic<std::int64_t>  maxNs{ 0 };
};

AtomicStats g_stats[static_cast<std::size_t>(HookId::Count)];

// ── Per-(world, x, y) FCF tally (ported from the Skyrim port) ─────────────
// Mutex-protected map; mutated on every FCF call. Key count = unique cells
// touched, which is small (~hundreds) so map memory is bounded. Lock cost
// is dwarfed by the engine call we're measuring.
struct PerCellKey
{
    std::uint32_t world;   // worldspace formID
    std::int32_t  x;
    std::int32_t  y;
    bool operator==(const PerCellKey& o) const noexcept
    { return world == o.world && x == o.x && y == o.y; }
};
struct PerCellKeyHash
{
    std::size_t operator()(const PerCellKey& k) const noexcept
    {
        std::uint64_t h = k.world;
        h = h * 0x9E3779B97F4A7C15ull ^ static_cast<std::uint32_t>(k.x);
        h = h * 0x9E3779B97F4A7C15ull ^ static_cast<std::uint32_t>(k.y);
        return static_cast<std::size_t>(h);
    }
};
struct PerCellTally
{
    std::uint64_t calls   = 0;
    std::uint64_t totalNs = 0;
    std::uint64_t maxNs   = 0;
};

std::mutex                                                       g_perCellMutex;
std::unordered_map<PerCellKey, PerCellTally, PerCellKeyHash>     g_perCell;

inline void RecordCall(AtomicStats& s, bool a_hit, std::int64_t a_elapsedNs)
{
    s.calls.fetch_add(1, std::memory_order_relaxed);
    if (a_hit) s.hits.fetch_add(1, std::memory_order_relaxed);
    s.totalNs.fetch_add(a_elapsedNs, std::memory_order_relaxed);

    auto curMin = s.minNs.load(std::memory_order_relaxed);
    while (a_elapsedNs < curMin &&
           !s.minNs.compare_exchange_weak(curMin, a_elapsedNs,
                                          std::memory_order_relaxed)) {
    }
    auto curMax = s.maxNs.load(std::memory_order_relaxed);
    while (a_elapsedNs > curMax &&
           !s.maxNs.compare_exchange_weak(curMax, a_elapsedNs,
                                          std::memory_order_relaxed)) {
    }
}

// Trampoline gadget: saved 5-byte prologue + 14-byte absolute JMP back.
#pragma pack(push, 1)
struct PrologueTrampoline
{
    std::uint8_t  origPrologue[5];
    REL::ASM::JMP14 jmpBack;

    PrologueTrampoline(const std::uint8_t (&a_orig)[5], std::uintptr_t a_returnTo)
        : jmpBack(a_returnTo)
    {
        std::memcpy(origPrologue, a_orig, 5);
    }
};
#pragma pack(pop)
static_assert(sizeof(PrologueTrampoline) == 19);

using FindCellInFile_t = bool (*)(RE::TESWorldSpace*, RE::TESFile*,
                                  std::int32_t, std::int32_t);
using FindInFileFast_t = bool (*)(RE::TESWorldSpace*, RE::TESFile*);
using GetIndexForCellCoord_t = std::int32_t (*)(RE::TESWorldSpace*, RE::TESFile*,
                                                std::int32_t, std::int32_t);
using SeekFile_t = std::uint8_t (*)(void* /*file*/, std::uint32_t /*absoluteOffset*/);

FindCellInFile_t       g_origFindCellInFile       = nullptr;
FindInFileFast_t       g_origFindInFileFast       = nullptr;
GetIndexForCellCoord_t g_origGetIndexForCellCoord = nullptr;
SeekFile_t             g_origSeekFile             = nullptr;

bool DetourFindCellInFile(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                          std::int32_t a_x, std::int32_t a_y)
{
    const auto t0 = std::chrono::steady_clock::now();
    const bool result = g_origFindCellInFile(a_world, a_file, a_x, a_y);
    const auto elapsedNs = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - t0).count();
    RecordCall(g_stats[static_cast<std::size_t>(HookId::FindCellInFile)],
               result, elapsedNs);

    // Per-(world, x, y) tally — used by FormatPerCellComparison() to print a
    // cell-by-cell speedup table against the baseline snapshot.
    {
        const std::uint32_t wfid = a_world ? a_world->GetFormID() : 0u;
        const std::uint64_t ns   = static_cast<std::uint64_t>(elapsedNs);
        std::lock_guard lock(g_perCellMutex);
        auto& t = g_perCell[PerCellKey{ wfid, a_x, a_y }];
        ++t.calls;
        t.totalNs += ns;
        if (ns > t.maxNs) t.maxNs = ns;
    }

    // Fast-path diagnostic: for SLOW calls (which shouldn't happen on the
    // fast path), log the OFST offset OUR table holds for this cell. Done
    // OUTSIDE the timed region so it doesn't perturb the measurement.
    //   ofst == 0  → empty/unfilled slot (engine seeks to base, fails verify,
    //                slow-scans) — the suspected bug for cells with no record.
    //   ofst != 0 but slow → wrong offset / bad index.
    //   table=NO   → generation never installed pCellFileOffsets for this pair.
    const double elapsedMs = static_cast<double>(elapsedNs) / 1e6;
    if (elapsedMs > 20.0 && a_world && a_file) {
        auto*              pData = cog::sf::GetOffsetData(a_world, a_file);
        const std::uint32_t idx  = cog::sf::GetIndexForCellCoord(a_world, a_file, a_x, a_y);
        std::uint32_t       ofst = 0, count = 0;
        const bool          haveTable = pData && pData->pCellFileOffsets;
        if (haveTable) {
            count = pData->pad24;
            if (idx != UINT32_MAX && idx < count) ofst = pData->pCellFileOffsets[idx];
        }
        logger::info("[FastPath] world={:#x} cell=({},{}) idx={} ofst={:#x} "
                     "table={} count={} -> {:.1f} ms (found={})",
                     a_world->GetFormID(), a_x, a_y,
                     (idx == UINT32_MAX ? -1 : static_cast<int>(idx)), ofst,
                     haveTable ? "yes" : "NO", count, elapsedMs, result);
    }
    return result;
}

bool DetourFindInFileFast(RE::TESWorldSpace* a_world, RE::TESFile* a_file)
{
    const auto t0 = std::chrono::steady_clock::now();
    const bool result = g_origFindInFileFast(a_world, a_file);
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - t0).count();
    RecordCall(g_stats[static_cast<std::size_t>(HookId::FindInFileFast)],
               result, elapsed);
    return result;
}

std::int32_t DetourGetIndexForCellCoord(RE::TESWorldSpace* a_world, RE::TESFile* a_file,
                                        std::int32_t a_x, std::int32_t a_y)
{
    const auto t0 = std::chrono::steady_clock::now();
    const auto result = g_origGetIndexForCellCoord(a_world, a_file, a_x, a_y);
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - t0).count();
    RecordCall(g_stats[static_cast<std::size_t>(HookId::GetIndexForCellCoord)],
               result != -1, elapsed);
    return result;
}

std::uint8_t DetourSeekFile(void* a_file, std::uint32_t a_offset)
{
    const auto t0 = std::chrono::steady_clock::now();
    const auto result = g_origSeekFile(a_file, a_offset);
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - t0).count();
    RecordCall(g_stats[static_cast<std::size_t>(HookId::SeekFile)],
               result != 0, elapsed);
    return result;
}

// Install one detour. Returns the trampoline gadget pointer (typed by the
// caller via reinterpret_cast) on success, nullptr on prologue mismatch.
void* InstallOne(const PrologueRecord& a_prol, void* a_hookFn)
{
    const std::uintptr_t target = REL::Offset(a_prol.offset).address();
    const auto* targetBytes = reinterpret_cast<const std::uint8_t*>(target);
    if (std::memcmp(targetBytes, a_prol.firstFive, 5) != 0) {
        logger::warn("[Bench] {} detour aborted — prologue mismatch at 0x{:X}. "
                     "Expected {:02X} {:02X} {:02X} {:02X} {:02X}, got "
                     "{:02X} {:02X} {:02X} {:02X} {:02X}",
                     a_prol.name, target,
                     a_prol.firstFive[0], a_prol.firstFive[1], a_prol.firstFive[2],
                     a_prol.firstFive[3], a_prol.firstFive[4],
                     targetBytes[0], targetBytes[1], targetBytes[2],
                     targetBytes[3], targetBytes[4]);
        return nullptr;
    }

    auto& trampoline = REL::GetTrampoline();
    auto* gadget = trampoline.allocate<PrologueTrampoline>(a_prol.firstFive,
                                                            target + 5);
    trampoline.write_jmp<5>(target, reinterpret_cast<std::uintptr_t>(a_hookFn));

    logger::info("[Bench] {} detour installed at 0x{:X} -> hook 0x{:X}, "
                 "trampoline 0x{:X}",
                 a_prol.name, target,
                 reinterpret_cast<std::uintptr_t>(a_hookFn),
                 reinterpret_cast<std::uintptr_t>(gadget));
    return gadget;
}

bool                g_installed{ false };
bool                g_ofstStripped{ false };
std::optional<bool> g_baselineCache{};
std::optional<bool> g_diagnosticsCache{};
std::optional<bool> g_stripOfstCache{};
std::optional<bool> g_zeroOffsetsCache{};
std::optional<bool> g_noTableCache{};
std::optional<bool> g_noGenerateCache{};

constexpr std::array<const char*, static_cast<std::size_t>(HookId::Count)>
    kHookNames = { "FindCellInFile", "FindInFileFast",
                   "GetIndexForCellCoord", "SeekFile" };

// Resolve the settings INI sitting next to our DLL:
//   Data/SFSE/Plugins/CellOffsetGeneratorSF.ini
// Falls back to that relative path if the module path can't be resolved.
const std::string& IniPath()
{
    static const std::string path = [] {
        char        buf[260] = {};
        const auto  hmod = REX::W32::GetModuleHandleA("CellOffsetGeneratorSF.dll");
        const auto  n    = REX::W32::GetModuleFileNameA(hmod, buf, sizeof(buf));
        if (n > 0 && n < sizeof(buf)) {
            std::filesystem::path p(buf);
            p.replace_extension(".ini");
            return p.string();
        }
        return std::string("Data/SFSE/Plugins/CellOffsetGeneratorSF.ini");
    }();
    return path;
}

}  // namespace

bool IsBaselineMode()
{
    if (!g_baselineCache.has_value()) {
        // Precedence: COG_BASELINE env var (if set) overrides the INI; otherwise
        // read [Benchmark] BaselineMode from CellOffsetGeneratorSF.ini (default 0).
        char       buf[8] = {};
        const auto n = REX::W32::GetEnvironmentVariableA("COG_BASELINE", buf, sizeof(buf));
        if (n == 1 && (buf[0] == '0' || buf[0] == '1')) {
            g_baselineCache = (buf[0] == '1');
        } else {
            const auto v = REX::W32::GetPrivateProfileIntA(
                "Benchmark", "BaselineMode", 0, IniPath().c_str());
            g_baselineCache = (v != 0);
        }
    }
    return *g_baselineCache;
}

bool IsDiagnosticsMode()
{
    if (!g_diagnosticsCache.has_value()) {
        // Baseline benchmarking needs the detours, so it implies diagnostics.
        if (IsBaselineMode()) {
            g_diagnosticsCache = true;
        } else {
            char       buf[8] = {};
            const auto n = REX::W32::GetEnvironmentVariableA("COG_DIAGNOSTICS", buf, sizeof(buf));
            if (n == 1 && (buf[0] == '0' || buf[0] == '1')) {
                g_diagnosticsCache = (buf[0] == '1');
            } else {
                const auto v = REX::W32::GetPrivateProfileIntA(
                    "Benchmark", "Diagnostics", 0, IniPath().c_str());
                g_diagnosticsCache = (v != 0);
            }
        }
    }
    return *g_diagnosticsCache;
}

bool IsStripOfstMode()
{
    if (!g_stripOfstCache.has_value()) {
        char       buf[8] = {};
        const auto n = REX::W32::GetEnvironmentVariableA("COG_STRIP_OFST", buf, sizeof(buf));
        g_stripOfstCache = (n == 1 && buf[0] == '1');
    }
    return *g_stripOfstCache;
}

bool IsZeroOffsetsMode()
{
    if (!g_zeroOffsetsCache.has_value()) {
        char       buf[8] = {};
        const auto n = REX::W32::GetEnvironmentVariableA("COG_ZERO_OFFSETS", buf, sizeof(buf));
        g_zeroOffsetsCache = (n == 1 && buf[0] == '1');
    }
    return *g_zeroOffsetsCache;
}

bool IsNoTableMode()
{
    if (!g_noTableCache.has_value()) {
        char       buf[8] = {};
        const auto n = REX::W32::GetEnvironmentVariableA("COG_NO_TABLE", buf, sizeof(buf));
        g_noTableCache = (n == 1 && buf[0] == '1');
    }
    return *g_noTableCache;
}

bool IsNoGenerateMode()
{
    if (!g_noGenerateCache.has_value()) {
        char       buf[8] = {};
        const auto n = REX::W32::GetEnvironmentVariableA("COG_NO_GENERATE", buf, sizeof(buf));
        g_noGenerateCache = (n == 1 && buf[0] == '1');
    }
    return *g_noGenerateCache;
}

bool InstallOfstStripper()
{
    if (g_ofstStripped) return true;
    if (!IsStripOfstMode()) return false;

    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    if (ver != SFSE::RUNTIME_SF_1_16_236) {
        logger::info("[StripOFST] skipped — patch site only known for 1.16.236");
        return false;
    }

    // The chunk dispatcher at +0xBB8083 is:
    //     3d 4f 46 53 54    cmp eax, 'OFST' (0x5453464F)
    //     0f 85 ...         jne <next dispatch case>
    //     <OFST handler body>
    // Replacing the 4-byte magic literal with 0xFFFFFFFF makes the cmp
    // never match a real chunk magic, so the engine always takes the jne
    // and skips the OFST handler. From the engine's perspective every
    // WRLD's OFST subrecord is silently absent — exactly the state xEdit's
    // Clean-Masters leaves an ESP in.
    constexpr std::uintptr_t kOfstMagicOffset = 0x0BB8084;
    constexpr std::uint32_t  kExpectedMagic   = 0x5453464F;   // 'OFST' LE
    constexpr std::uint32_t  kPatchMagic      = 0xFFFFFFFF;

    const std::uintptr_t target = REL::Offset(kOfstMagicOffset).address();
    const auto*          atTarget = reinterpret_cast<const std::uint32_t*>(target);
    if (*atTarget != kExpectedMagic) {
        const auto* b = reinterpret_cast<const std::uint8_t*>(target);
        logger::warn("[StripOFST] aborted — expected 4f 46 53 54 at 0x{:X}, "
                     "got {:02X} {:02X} {:02X} {:02X}",
                     target, b[0], b[1], b[2], b[3]);
        return false;
    }

    REL::WriteSafeData(target, kPatchMagic);
    g_ofstStripped = true;
    logger::info("[StripOFST] OFST magic at 0x{:X} replaced with 0xFFFFFFFF — "
                 "engine chunk dispatcher will skip all OFST subrecords this run",
                 target);
    return true;
}

bool InstallEngineHooks()
{
    if (g_installed) return true;

    const auto* prols = PickPrologues();
    if (!prols) {
        logger::info("[Bench] detours skipped — no prologue table for this runtime");
        return false;
    }

    logger::info("[Bench] installing detours (baseline mode = {})",
                 IsBaselineMode() ? "ON" : "OFF");

    if (auto* g = InstallOne(prols->findCellInFile, &DetourFindCellInFile)) {
        g_origFindCellInFile = reinterpret_cast<FindCellInFile_t>(g);
    }
    if (auto* g = InstallOne(prols->findInFileFast, &DetourFindInFileFast)) {
        g_origFindInFileFast = reinterpret_cast<FindInFileFast_t>(g);
    }
    if (auto* g = InstallOne(prols->getIndexForCellCoord, &DetourGetIndexForCellCoord)) {
        g_origGetIndexForCellCoord = reinterpret_cast<GetIndexForCellCoord_t>(g);
    }
    if (auto* g = InstallOne(prols->seekFile, &DetourSeekFile)) {
        g_origSeekFile = reinterpret_cast<SeekFile_t>(g);
    }

    g_installed = true;
    return true;
}

EngineCallStats GetEngineCallStats(HookId a_id)
{
    const auto idx = static_cast<std::size_t>(a_id);
    auto&      s   = g_stats[idx];
    EngineCallStats out;
    out.calls   = s.calls.load(std::memory_order_relaxed);
    out.hits    = s.hits.load(std::memory_order_relaxed);
    out.totalNs = s.totalNs.load(std::memory_order_relaxed);
    if (out.calls == 0) {
        out.minNs = 0;
        out.maxNs = 0;
    } else {
        out.minNs = s.minNs.load(std::memory_order_relaxed);
        out.maxNs = s.maxNs.load(std::memory_order_relaxed);
    }
    return out;
}

std::string FormatAllStatsLines(std::string_view a_label)
{
    std::string out;
    out.reserve(256);
    for (std::size_t i = 0; i < static_cast<std::size_t>(HookId::Count); ++i) {
        const auto s = GetEngineCallStats(static_cast<HookId>(i));
        const auto avg = s.calls
                             ? (s.totalNs / static_cast<std::int64_t>(s.calls))
                             : 0;
        fmt::format_to(std::back_inserter(out),
                       "[Bench] {} {} mode={} calls={} hits={} total={}ns "
                       "min/avg/max={}/{}/{}ns\n",
                       a_label, kHookNames[i],
                       IsBaselineMode() ? "BASELINE" : "ACTIVE",
                       s.calls, s.hits, s.totalNs, s.minNs, avg, s.maxNs);
    }
    if (!out.empty() && out.back() == '\n') out.pop_back();
    return out;
}

// ── Cross-run savings comparison ──────────────────────────────────────────
// Per-mode snapshot file: { uint64 calls, int64 totalNs } for
// FindCellInFile only. Written every heartbeat. When both files exist (i.e.
// the user has already run baseline and is now in active), the heartbeat
// logs the time-saved comparison.

namespace {

struct BenchSnapshot
{
    std::uint64_t magic;     // 'COGB'
    std::uint64_t version;   // 1
    std::uint64_t calls;
    std::int64_t  totalNs;
};
constexpr std::uint64_t kBenchMagic   = 0x42474F43u;  // 'COGB'
constexpr std::uint64_t kBenchVersion = 1u;

std::filesystem::path BenchPath(bool a_baseline)
{
    return std::filesystem::path("Data") / "CellOffsets"
         / (a_baseline ? "bench-baseline.bin" : "bench-active.bin");
}

bool ReadSnapshot(const std::filesystem::path& a_path, BenchSnapshot& a_out)
{
    std::ifstream is(a_path, std::ios::binary);
    if (!is) return false;
    is.read(reinterpret_cast<char*>(&a_out), sizeof(a_out));
    if (!is) return false;
    return a_out.magic == kBenchMagic && a_out.version == kBenchVersion;
}

void WriteSnapshot(const std::filesystem::path& a_path, std::uint64_t a_calls,
                   std::int64_t a_totalNs)
{
    std::error_code ec;
    std::filesystem::create_directories(a_path.parent_path(), ec);
    std::ofstream os(a_path, std::ios::binary | std::ios::trunc);
    if (!os) return;
    BenchSnapshot snap{ kBenchMagic, kBenchVersion, a_calls, a_totalNs };
    os.write(reinterpret_cast<const char*>(&snap), sizeof(snap));
}

}  // namespace

std::string FormatSavingsLine()
{
    const auto active = GetEngineCallStats(HookId::FindCellInFile);
    const bool baselineMode = IsBaselineMode();

    // Always persist the current mode's running totals; subsequent runs
    // (whichever mode) will diff against this snapshot.
    WriteSnapshot(BenchPath(baselineMode), active.calls, active.totalNs);

    BenchSnapshot other{};
    if (!ReadSnapshot(BenchPath(!baselineMode), other) || other.calls == 0) {
        return {};
    }

    // `this` = current mode's stats; `other` = the saved snapshot from the
    // opposite mode. Compute always-positive savings (baseline - active).
    const auto baseline = baselineMode ? BenchSnapshot{ 0,0, active.calls,
                                                        static_cast<std::int64_t>(active.totalNs) }
                                       : other;
    const auto activeSnap = baselineMode ? other
                                         : BenchSnapshot{ 0,0, active.calls,
                                                          static_cast<std::int64_t>(active.totalNs) };

    if (baseline.calls == 0 || activeSnap.calls == 0) return {};

    const auto totalSavedNs = baseline.totalNs - activeSnap.totalNs;
    const double totalSavedSec = static_cast<double>(totalSavedNs) / 1e9;

    const double baselineAvgMs = static_cast<double>(baseline.totalNs)
                                     / static_cast<double>(baseline.calls) / 1e6;
    const double activeAvgMs = static_cast<double>(activeSnap.totalNs)
                                     / static_cast<double>(activeSnap.calls) / 1e6;
    const double perCallSavedMs = baselineAvgMs - activeAvgMs;

    return fmt::format(
        "[Savings] total saved={:.3f}s, per-cell saved={:.3f}ms "
        "(baseline {} calls, {:.3f}s | active {} calls, {:.3f}s)",
        totalSavedSec, perCallSavedMs,
        baseline.calls, static_cast<double>(baseline.totalNs) / 1e9,
        activeSnap.calls, static_cast<double>(activeSnap.totalNs) / 1e9);
}

// ── Per-cell snapshot persistence + comparison report ─────────────────────

namespace {

#pragma pack(push, 1)
struct PerCellRecord
{
    std::uint32_t world;
    std::int32_t  x;
    std::int32_t  y;
    std::uint64_t calls;
    std::uint64_t totalNs;
    std::uint64_t maxNs;
};
#pragma pack(pop)
static_assert(sizeof(PerCellRecord) == 36);

constexpr std::uint64_t kPerCellMagic   = 0x4C434350u;  // 'PCCL'
constexpr std::uint64_t kPerCellVersion = 1u;

std::filesystem::path PerCellPath(bool a_baseline)
{
    return std::filesystem::path("Data") / "CellOffsets"
         / (a_baseline ? "percell-baseline.bin" : "percell-active.bin");
}

void WritePerCellSnapshot(bool a_baseline)
{
    std::vector<PerCellRecord> records;
    {
        std::lock_guard lock(g_perCellMutex);
        records.reserve(g_perCell.size());
        for (const auto& [k, v] : g_perCell) {
            records.push_back({ k.world, k.x, k.y, v.calls, v.totalNs, v.maxNs });
        }
    }

    const auto path = PerCellPath(a_baseline);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ofstream os(path, std::ios::binary | std::ios::trunc);
    if (!os) return;

    const std::uint64_t header[3] = {
        kPerCellMagic, kPerCellVersion, static_cast<std::uint64_t>(records.size())
    };
    os.write(reinterpret_cast<const char*>(header), sizeof(header));
    if (!records.empty()) {
        os.write(reinterpret_cast<const char*>(records.data()),
                 static_cast<std::streamsize>(records.size() * sizeof(PerCellRecord)));
    }
}

bool ReadPerCellSnapshot(bool a_baseline, std::vector<PerCellRecord>& a_out)
{
    std::ifstream is(PerCellPath(a_baseline), std::ios::binary);
    if (!is) return false;
    std::uint64_t header[3]{};
    is.read(reinterpret_cast<char*>(header), sizeof(header));
    if (!is) return false;
    if (header[0] != kPerCellMagic || header[1] != kPerCellVersion) return false;

    a_out.resize(header[2]);
    if (header[2] > 0) {
        is.read(reinterpret_cast<char*>(a_out.data()),
                static_cast<std::streamsize>(header[2] * sizeof(PerCellRecord)));
        if (!is) return false;
    }
    return true;
}

}  // namespace

std::string FormatPerCellSingleRun()
{
    // Snapshot the current run's per-cell tally without requiring an opposite-
    // mode snapshot to compare against. Useful for absolute-timing reports.
    std::vector<PerCellRecord> rows;
    {
        std::lock_guard lock(g_perCellMutex);
        rows.reserve(g_perCell.size());
        for (const auto& [k, v] : g_perCell) {
            rows.push_back({ k.world, k.x, k.y, v.calls, v.totalNs, v.maxNs });
        }
    }
    if (rows.empty()) return {};

    // Persist this run's per-cell tally so it survives the next launch (SFSE
    // truncates the log each launch). Lets a later opposite-mode run diff
    // against it. (Re-added after the ratio-table removal dropped this.)
    WritePerCellSnapshot(IsBaselineMode());

    std::sort(rows.begin(), rows.end(),
              [](const PerCellRecord& l, const PerCellRecord& r) {
                  return l.totalNs > r.totalNs;
              });

    std::uint64_t totalCalls = 0;
    std::uint64_t totalNs    = 0;
    for (const auto& r : rows) {
        totalCalls += r.calls;
        totalNs    += r.totalNs;
    }

    std::string out;
    out.reserve(64 + rows.size() * 48);
    fmt::format_to(std::back_inserter(out),
        "\n[PerCell-{}] {:.3f} ms total across {} cells / {} reads\n",
        IsBaselineMode() ? "BASELINE" : "ACTIVE",
        static_cast<double>(totalNs) / 1e6,
        rows.size(), totalCalls);
    fmt::format_to(std::back_inserter(out),
        "           world  |       cell |   reads |    total ms\n");
    fmt::format_to(std::back_inserter(out),
        "  --------------------------------------------------------\n");

    // Every cell — total time for all reads of that cell combined, in ms.
    for (const auto& r : rows) {
        const double tMs = static_cast<double>(r.totalNs) / 1e6;
        fmt::format_to(std::back_inserter(out),
            "  0x{:08x} | ({:4},{:4}) | {:7} | {:11.3f}\n",
            r.world, r.x, r.y, r.calls, tMs);
    }
    return out;
}

std::string FormatPerCellComparison()
{
    // Always persist the current run's snapshot first.
    const bool baselineMode = IsBaselineMode();
    WritePerCellSnapshot(baselineMode);

    std::vector<PerCellRecord> baselineVec, activeVec;
    if (!ReadPerCellSnapshot(true,  baselineVec)) return {};
    if (!ReadPerCellSnapshot(false, activeVec))   return {};
    if (baselineVec.empty() || activeVec.empty()) return {};

    // Index active by (world, x, y) for O(1) lookup against baseline entries.
    std::unordered_map<PerCellKey, PerCellTally, PerCellKeyHash> activeIdx;
    activeIdx.reserve(activeVec.size());
    for (const auto& r : activeVec) {
        activeIdx[PerCellKey{ r.world, r.x, r.y }] =
            PerCellTally{ r.calls, r.totalNs, r.maxNs };
    }

    struct Row { PerCellRecord b; PerCellTally a; bool hasActive; };
    std::vector<Row> rows;
    rows.reserve(baselineVec.size());
    for (const auto& b : baselineVec) {
        auto it = activeIdx.find(PerCellKey{ b.world, b.x, b.y });
        rows.push_back({ b,
                         it != activeIdx.end() ? it->second : PerCellTally{},
                         it != activeIdx.end() });
    }
    // Hottest cells first.
    std::sort(rows.begin(), rows.end(),
              [](const Row& l, const Row& r) { return l.b.totalNs > r.b.totalNs; });

    std::uint64_t baselineTotal = 0, activeTotal = 0;
    for (const auto& r : rows) {
        baselineTotal += r.b.totalNs;
        activeTotal   += r.a.totalNs;
    }
    const double deltaMs = (static_cast<double>(baselineTotal) -
                            static_cast<double>(activeTotal)) / 1e6;
    const double speedup = activeTotal > 0
        ? static_cast<double>(baselineTotal) / static_cast<double>(activeTotal)
        : 0.0;

    std::string out;
    out.reserve(64 + rows.size() * 80);

    fmt::format_to(std::back_inserter(out),
        "\n[PerCell] vanilla total: {:.3f} ms, optimized total: {:.3f} ms, "
        "unique cells: {}, total saved: {:.3f} ms, speedup: {:.2f}x\n",
        static_cast<double>(baselineTotal) / 1e6,
        static_cast<double>(activeTotal)   / 1e6,
        rows.size(), deltaMs, speedup);

    fmt::format_to(std::back_inserter(out),
        "           world  |       cell |  vanilla ms | optimized ms |  delta ms |  speedup\n");
    fmt::format_to(std::back_inserter(out),
        "  --------------------------------------------------------------------------------\n");

    // Top 30 by baseline cost.
    const auto limit = (std::min)(rows.size(), static_cast<std::size_t>(30));
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& r = rows[i];
        const double vMs = static_cast<double>(r.b.totalNs) / 1e6;
        const double oMs = static_cast<double>(r.a.totalNs) / 1e6;
        const double dMs = vMs - oMs;
        const double su  = r.a.totalNs > 0
            ? static_cast<double>(r.b.totalNs) / static_cast<double>(r.a.totalNs)
            : 0.0;
        fmt::format_to(std::back_inserter(out),
            "  0x{:08x} | ({:4},{:4}) | {:11.3f} | {:12.3f} | {:9.3f} | {:6.2f}x\n",
            r.b.world, r.b.x, r.b.y, vMs, oMs, dMs, su);
    }
    return out;
}

}  // namespace cog::sf::bench
