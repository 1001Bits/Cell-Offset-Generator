#include "PCH.h"
#include "TESFileExt.hpp"

namespace cog::sf {

namespace {

// Address-library RVAs to fill in once located in Ghidra. While zero, the
// matching wrapper returns a safe-no-op value. (IsMaster used to live here
// too; it's now a direct bit-read at file+0x1B8 — see IsMaster() below.)
struct FileOffsets
{
    std::uintptr_t getThreadSafeFileForThread;
};

constexpr FileOffsets kFileOffsetsSF{
    .getThreadSafeFileForThread  = 0,  // TODO: TESFile::GetThreadSafeFileForThread
                                       //   The engine uses TESFile::vtable[1]
                                       //   for the per-thread clone; a vtable
                                       //   call may be cheaper than chasing a
                                       //   fixed RVA.
};

// Byte-offset of the per-file `fileoffset` field (the absolute file cursor
// the engine maintains as it walks records). Located via the engine seek
// wrapper FUN_1414b9340 (Starfield 1.7.x):
//
//   *(uint *)(file + offset) = absoluteOffset;          // new cursor
//   if (absoluteOffset < *(uint *)(file + offset+4)) {  // < total size
//       file->buffer->Seek(absoluteOffset, 0);
//   }
//
// Position is +0x390 on 1.14.x and **+0x3A0 on 1.15.216 onward** — the
// shift was confirmed in Load_Impl on 1.16.236 (`mov ecx, [rbx+0x3A0]; mov
// [rax+0x20], ecx` writes the cursor into OFFSET_DATA+0x20). After a
// successful FindCellInFile slow-path match the engine clears +0x174
// (current chunk magic) and +0x178 (chunk bytes remaining) then refetches
// the next chunk header — so this offset ends up pointing JUST AFTER the
// matched XCLC chunk, not at the CELL record start. Matches F4 semantics.
//
// Other TESFile fields located along the way (kept for reference, not used
// directly by the generator): +0x15c group magic, +0x164 group flags
// (&0x1000 = is-group, &0x400 = interior), +0x174 chunk magic,
// +0x178 chunk bytes remaining, +0x18 file-chain head (overlay/patch chain;
// null for normal plugins), +0x1B8 flags byte (bit 0 = IsMaster).
[[nodiscard]] std::uintptr_t PickFileOffsetField()
{
    const auto ver = REX::FModule::GetExecutingModule().GetFileVersion();
    if (ver == SFSE::RUNTIME_SF_1_14_70)  return 0x390;
    if (ver == SFSE::RUNTIME_SF_1_14_74)  return 0x390;
    if (ver == SFSE::RUNTIME_SF_1_15_216) return 0x3A0;
    if (ver == SFSE::RUNTIME_SF_1_15_222) return 0x3A0;
    if (ver == SFSE::RUNTIME_SF_1_16_236) return 0x3A0;
    if (ver == SFSE::RUNTIME_SF_1_16_242) return 0x3A0;  // struct layout unchanged from 1.16.236 (minor patch)
    return 0;  // unsupported runtime — GetFileOffset() returns 0 (safe no-op)
}

[[nodiscard]] const FileOffsets& Pick()
{
    return kFileOffsetsSF;
}

using GetThreadSafeFile_t = RE::TESFile* (*)(RE::TESFile*, std::uint32_t, std::uint32_t);

// Default thread-safe buffer size. F4 uses 0x10000 (64 KB) — we mirror that
// pending Ghidra confirmation of the parameter shape on Starfield.
constexpr std::uint32_t kDefaultThreadSafeBufferSize = 0x10000;

}  // namespace

bool IsMaster(const RE::TESFile* a_file)
{
    if (!a_file) return false;
    // Verified via TESWorldSpace::FindCellInFile (0x141A4AAA0) decompile:
    //   `(*(byte *)(file + 0x1b8) & 1) == 0`  → not master
    // Direct bit read avoids the cost of a vtable dispatch and the dependency
    // on locating a stripped engine function.
    const auto* base = reinterpret_cast<const std::uint8_t*>(a_file);
    return (base[0x1B8] & 1u) != 0u;
}

namespace {

// Is `c` a plausible plugin-filename character?
[[nodiscard]] constexpr bool IsNameChar(std::uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') ||
           c == ' ' || c == '_' || c == '-' || c == '.' ||
           c == '(' || c == ')' || c == '\'' || c == '!' || c == '+' || c == '&';
}

// Does the NUL-terminated run starting at `p` (max `max` chars) look like a
// plugin filename (ends in .esm/.esp/.esl, case-insensitive)?
[[nodiscard]] const char* MatchPluginName(const std::uint8_t* p, std::size_t max)
{
    std::size_t n = 0;
    while (n < max && p[n] != 0) {
        if (!IsNameChar(p[n])) return nullptr;
        ++n;
    }
    if (n < 5 || n >= max) return nullptr;          // need "x.esX" min, and a NUL
    auto lower = [](std::uint8_t c) -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c);
    };
    if (p[n - 4] != '.') return nullptr;
    const char e1 = lower(p[n - 3]), e2 = lower(p[n - 2]), e3 = lower(p[n - 1]);
    const bool ok = (e1 == 'e' && e2 == 's' && (e3 == 'm' || e3 == 'p' || e3 == 'l'));
    return ok ? reinterpret_cast<const char*>(p) : nullptr;
}

[[nodiscard]] bool Readable(const void* p, std::size_t bytes);

[[nodiscard]] std::string_view FindPluginNameInRange(const std::uint8_t* p, std::size_t max)
{
    if (!p || !Readable(p, max)) return {};

    for (std::size_t off = 0; off + 5 < max; ++off) {
        if (const char* m = MatchPluginName(p + off, max - off)) {
            return std::string_view(m);
        }
    }
    return {};
}

[[nodiscard]] bool Readable(const void* p, std::size_t bytes)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const auto prot = mbi.Protect & 0xFF;
    if (prot == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) return false;
    const auto start = reinterpret_cast<std::uintptr_t>(p);
    const auto end   = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return start + bytes <= end;
}

}  // namespace

// Resolve a TESFile's plugin name without depending on a hardcoded field
// offset (which drifts across SF versions — CommonLibSF's +0x38 holds floats
// on 1.16.x, not the name). Strategy: scan the object's own bytes for an
// inline ".esm/.esp/.esl" run; if absent, follow each aligned pointer in the
// header region and scan its target. Returns "" if nothing plausible found.
std::string_view GetFileName(const RE::TESFile* a_file)
{
    if (!a_file) return {};
    const auto* base = reinterpret_cast<const std::uint8_t*>(a_file);

    // 1) Inline scan of the object header. Older layouts expose
    // TESFile::fileName directly here.
    constexpr std::size_t kInlineWindow = 0x800;
    if (auto name = FindPluginNameInRange(base, kInlineWindow); !name.empty()) {
        return name;
    }

    // 2) Follow aligned pointer slots in the header — the name may be stored
    //    out-of-line, or as a full Data\Plugin.esm path. Scan within each
    //    target instead of assuming the string starts at target+0.
    for (std::size_t slot = 0x18; slot <= 0x400; slot += 8) {
        if (!Readable(base + slot, 8)) continue;
        const auto cand = *reinterpret_cast<const std::uintptr_t*>(base + slot);
        const auto* target = reinterpret_cast<const std::uint8_t*>(cand);
        if (cand < 0x10000) continue;
        if (auto name = FindPluginNameInRange(target, 0x300); !name.empty()) {
            return name;
        }
    }

    // 3) 1.16.x keeps an opened BSFile pointer around file+0x378; that object
    // often carries the resolved path even when TESFile's header no longer
    // has a direct name field.
    constexpr std::size_t kBSFilePtrOffset = 0x378;
    if (Readable(base + kBSFilePtrOffset, 8)) {
        const auto bsFilePtr = *reinterpret_cast<const std::uintptr_t*>(base + kBSFilePtrOffset);
        const auto* bsFile = reinterpret_cast<const std::uint8_t*>(bsFilePtr);
        if (bsFilePtr >= 0x10000) {
            if (auto name = FindPluginNameInRange(bsFile, 0x400); !name.empty()) {
                return name;
            }
            for (std::size_t slot = 0; slot <= 0x200; slot += 8) {
                if (!Readable(bsFile + slot, 8)) continue;
                const auto cand = *reinterpret_cast<const std::uintptr_t*>(bsFile + slot);
                const auto* target = reinterpret_cast<const std::uint8_t*>(cand);
                if (cand < 0x10000) continue;
                if (auto name = FindPluginNameInRange(target, 0x300); !name.empty()) {
                    return name;
                }
            }
        }
    }
    return {};
}

RE::TESFile* AcquireThreadSafeFile(RE::TESFile* a_file)
{
    if (!a_file) return nullptr;
    static const auto offset = Pick().getThreadSafeFileForThread;
    if (offset == 0) return nullptr;
    static REL::Relocation<GetThreadSafeFile_t> func{ REL::Offset(offset) };
    const auto threadId = REX::W32::GetCurrentThreadId();
    auto* clone = func(a_file, threadId, kDefaultThreadSafeBufferSize);
    return (clone == a_file) ? nullptr : clone;
}

std::uint32_t GetFileOffset(const RE::TESFile* a_file)
{
    const auto fileOffsetField = PickFileOffsetField();
    if (!a_file || fileOffsetField == 0) return 0;

    // The engine routes all file I/O through TESFile::vtable[1] — verified at
    // the top of TESWorldSpace::FindCellInFile (0x141A4AAA0):
    //   lVar7 = (*(*param_2 + 8))(param_2);   // vtable[1]
    //   ... lVar7+0x1B8 IsMaster check ...
    //   FUN_1414b9340(lVar7, ...)              // seek writes lVar7+0x390
    // vtable[1] (located at FUN_1414B83F8) returns the original on the main
    // thread but returns a per-thread clone via FUN_1414B8458 when called
    // from worker threads. The cursor at +0x390 lives on whatever vtable[1]
    // returned, NOT necessarily on a_file. Dispatching vtable[1] from this
    // wrapper guarantees we read the same cursor the engine just wrote to.
    using GetActiveT = RE::TESFile* (*)(RE::TESFile*);
    auto* vtbl = *reinterpret_cast<void* const* const*>(a_file);
    auto* fn   = reinterpret_cast<GetActiveT>(const_cast<void*>(vtbl[1]));
    auto* eff  = fn(const_cast<RE::TESFile*>(a_file));
    const auto* base = reinterpret_cast<const std::uint8_t*>(eff ? eff : a_file);
    return *reinterpret_cast<const std::uint32_t*>(base + fileOffsetField);
}

void ReleaseThreadSafeFile(RE::TESFile* a_file)
{
    // Intentional no-op — see Cell Offset Generator F4 EngineCalls.cpp for
    // the rationale (engine background loaders mutate threadSafeFileMap on
    // their own threads, racing our erase walk; leak is the safer trade).
    (void)a_file;
}

}  // namespace cog::sf
