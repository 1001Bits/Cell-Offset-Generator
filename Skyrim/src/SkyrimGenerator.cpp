#include "PCH.h"
#include "SkyrimGenerator.h"

#include "EngineCalls.h"
#include "EngineTypes.h"
#include "Patches.h"
#include "ProgressWindow.h"

#define XXH_INLINE_ALL
#define XXH_ENABLE_AUTOVECTORIZE
#include <xxhash.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <fstream>
#include <optional>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace cog {

namespace {

// ── xxh3 hashing ────────────────────────────────────────────────────────────
//
// Wall keeps these inline at the top of CellOffsetGenerator.cpp; we follow the
// same pattern. Only used here, so no need for a separate translation unit.

[[nodiscard]] std::uint64_t HashBytes(const void* a_data, std::size_t a_size)
{
    return XXH3_64bits(a_data, a_size);
}

// Open a plugin file with the right share flags so we co-exist with
// MO2/USVFS handles, AV on-access scans, and any other process that has
// the .esp open. `std::ifstream` defaults to FILE_SHARE_READ only and
// intermittently failed under heavy concurrent IO on a 914-plugin VR
// Wabbajack. FILE_FLAG_SEQUENTIAL_SCAN matches WallSoGB's NVSE original
// (CellOffsetGenerator.cpp:79).
[[nodiscard]] HANDLE OpenPluginForHash(const std::filesystem::path& a_path)
{
    return CreateFileW(
        a_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
}

// Hash a plugin file at an already-resolved path (see ResolvePluginPath —
// the resolution happens ONCE per file so the stamp, the content hash, and
// the verification scan all describe the SAME physical file). Returns 0 on
// failure; callers must treat 0 as "identity unknown" and never persist or
// trust a cache entry keyed to it (0 is not a usable hash value — a second
// failing read would also produce 0 and vacuously "match").
[[nodiscard]] std::uint64_t HashFile(const std::filesystem::path& a_path,
                                     std::uint32_t* a_winErrorOut = nullptr)
{
    HANDLE handle = OpenPluginForHash(a_path);
    if (handle == INVALID_HANDLE_VALUE) {
        if (a_winErrorOut) {
            *a_winErrorOut = GetLastError();
        }
        return 0;
    }

    auto* state = XXH3_createState();
    if (!state) {
        CloseHandle(handle);
        return 0;
    }
    XXH3_64bits_reset(state);

    // Distinguish EOF from a mid-file read error: hashing a silently
    // truncated read would produce an "authoritative" hash of content the
    // engine never saw. Capture the error code IMMEDIATELY — FreeState /
    // CloseHandle below would overwrite GetLastError.
    std::uint32_t readError = 0;
    constexpr DWORD kBufferSize = 64 * 1024;
    std::vector<char> buffer(kBufferSize);
    for (;;) {
        DWORD read = 0;
        if (!ReadFile(handle, buffer.data(), kBufferSize, &read, nullptr)) {
            readError = GetLastError();
            if (readError == 0) {
                readError = ERROR_READ_FAULT;
            }
            break;
        }
        if (read == 0) {
            break;  // EOF
        }
        XXH3_64bits_update(state, buffer.data(), read);
    }

    const auto digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    CloseHandle(handle);
    if (readError != 0) {
        if (a_winErrorOut) {
            *a_winErrorOut = readError;
        }
        return 0;
    }
    return digest;
}

}  // namespace

std::uint64_t LazyFileHash::Get()
{
    if (!computed) {
        std::uint32_t winError = 0;
        value    = HashFile(path, &winError);
        computed = true;
        if (value == 0) {
            // Surface this loudly: a zero hash means the plugin's tables are
            // never cached (regenerated every boot) — without this line the
            // log gives support no way to see why the .fco never appears.
            logger::warn("Generator: failed to hash '{}' (err={}) — results "
                         "for this plugin will not be cached",
                         path.string(), winError);
        }
    }
    return value;
}

namespace {

// Fetch (size, mtime) with a single GetFileAttributesExW (no content read)
// at the already-resolved path — the SAME path HashFile and the verification
// scan use, so the v4+ header's stamp and hash always describe one physical
// file. On failure a_winErrorOut receives the error for THIS path (not a
// fallback's).
[[nodiscard]] FileStamp StatPlugin(const std::filesystem::path& a_path,
                                   std::uint32_t* a_winErrorOut = nullptr)
{
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(a_path.c_str(), GetFileExInfoStandard, &fad)) {
        if (a_winErrorOut) {
            *a_winErrorOut = GetLastError();
        }
        return {};
    }
    FileStamp stamp{};
    stamp.size  = (static_cast<std::uint64_t>(fad.nFileSizeHigh) << 32) |
                  fad.nFileSizeLow;
    stamp.mtime = (static_cast<std::uint64_t>(fad.ftLastWriteTime.dwHighDateTime) << 32) |
                  fad.ftLastWriteTime.dwLowDateTime;
    stamp.valid = true;
    return stamp;
}

// ── Raw plugin scan (verification ground truth) ─────────────────────────────
//
// Walks the plugin's GRUP structure reading record/group HEADERS only (24
// bytes each; record bodies — including zlib-compressed CELLs — are seeked
// over, never inflated) and counts the exterior CELL records per worldspace,
// keyed by the in-file WRLD record's objectID (low 24 bits).
//
// Why this exists: the engine treats a zero entry in pCellFileOffsets as
// "this file does not contain this cell" with NO slow-path fallback. So a
// generated table may only be published/cached if the number of cells the
// FindCellInFile probes located EXACTLY matches the number of exterior CELL
// records the file actually contains. A mismatch means either a transient
// probe failure (closed stream, IO error — would otherwise permanently bake
// missing content into the cache) or NAM0/NAM9 bounds narrower than the
// file's real content (tool-generated plugins, e.g. DynDOLOD — cells outside
// the stated bounds are unreachable by the fast path). Either way the safe
// answer is: leave the engine's slow path alone for that (file, world).
//
// SE plugin format (both record and group headers are 24 bytes):
//   Record: char sig[4]; u32 dataSize; u32 flags; u32 formID; u32 vc;
//           u16 version; u16 unk;   → followed by dataSize bytes
//   Group:  "GRUP"; u32 groupSize (INCLUDES this 24-byte header); u8 label[4];
//           s32 groupType; u16 stamp; u16 unk; u16 version; u16 unk2;
//   groupType: 0=top(label=fourcc) 1=world children(label=WRLD formID)
//              4=exterior block 5=exterior sub-block 6..9=cell/topic children
//
// Parsing is lenient about CONTENT (unknown records/groups are skipped) but
// strict about STRUCTURE (any size that escapes its parent bounds aborts the
// scan) — a failed scan disables publish/cache for the file, never content.

constexpr std::uint32_t kSigGRUP = 0x50555247;  // "GRUP"
constexpr std::uint32_t kSigWRLD = 0x444C5257;  // "WRLD"
constexpr std::uint32_t kSigCELL = 0x4C4C4543;  // "CELL"
constexpr std::uint32_t kSigTES4 = 0x34534554;  // "TES4"

struct RawHeader
{
    std::uint32_t sig;
    std::uint32_t sizeField;   // record: dataSize (excl. header); GRUP: total (incl. header)
    std::uint32_t labelOrFlags;
    std::uint32_t typeOrFormID;
};

class PluginReader
{
public:
    explicit PluginReader(HANDLE a_handle) : m_handle(a_handle) {}

    [[nodiscard]] bool ReadHeader(std::uint64_t a_at, RawHeader& a_out)
    {
        std::uint8_t raw[24];
        if (!ReadAt(a_at, raw, sizeof(raw))) {
            return false;
        }
        std::memcpy(&a_out.sig,         raw + 0,  4);
        std::memcpy(&a_out.sizeField,   raw + 4,  4);
        std::memcpy(&a_out.labelOrFlags, raw + 8, 4);
        std::memcpy(&a_out.typeOrFormID, raw + 12, 4);
        return true;
    }

private:
    [[nodiscard]] bool ReadAt(std::uint64_t a_at, void* a_buf, DWORD a_size)
    {
        LARGE_INTEGER li;
        li.QuadPart = static_cast<LONGLONG>(a_at);
        if (!SetFilePointerEx(m_handle, li, nullptr, FILE_BEGIN)) {
            return false;
        }
        DWORD read = 0;
        return ReadFile(m_handle, a_buf, a_size, &read, nullptr) && read == a_size;
    }

    HANDLE m_handle;
};

// Flag semantics for probe-matchability, from the engine's FindCellInFile
// slow scan (AE 1.6.1170, TESWorldSpace::FindCellInFile @ 0x1403064C0,
// verified by disassembly):
//   - The ONLY header flag the scan checks is 0x400. A CELL with 0x400 set
//     is assigned coordinate INT_MAX (0x7FFFFFFF), which can never equal a
//     target coord, so the engine NEVER matches a 0x400 CELL. Because our
//     generation probe calls that same engine function, cellsFound never
//     counts a 0x400 CELL either — so a 0x400 CELL belongs in NEITHER
//     verification bound (excluded entirely).
//   - The scan does NOT check 0x20 (deleted): a deleted CELL that still
//     carries an XCLC subrecord IS matched by coordinate. We can't cheaply
//     confirm the XCLC survived a deletion, and a zero-size CELL has no
//     XCLC to match, so deleted-or-zero-size CELLs count as UNCERTAIN,
//     widening only the upper bound of the band.
constexpr std::uint32_t kRecFlagDeleted = 0x00000020;
constexpr std::uint32_t kRecFlag400     = 0x00000400;

// Counts CELL record headers inside exterior block/sub-block groups (type 4
// and 5), recursing through nested groups; cell-children groups (type >= 6)
// are skipped. A CELL directly inside the type-1 world-children group is the
// world's PERSISTENT cell — tracked as a flag because the engine's slow-scan
// probe at its XCLC (typically 0,0) can match it. a_depth caps recursion so
// a crafted/corrupt plugin can't exhaust the game's stack. Returns false
// only on structural corruption.
[[nodiscard]] bool CountCellsInGroup(PluginReader& a_reader, std::uint64_t a_begin,
                                     std::uint64_t a_end, std::int32_t a_groupType,
                                     WorldCellCounts& a_out, int a_depth)
{
    if (a_depth > 8) {
        return false;  // legit nesting is 2 (block → sub-block)
    }
    std::uint64_t pos = a_begin;
    while (pos + 24 <= a_end) {
        RawHeader h{};
        if (!a_reader.ReadHeader(pos, h)) {
            return false;
        }
        if (h.sig == kSigGRUP) {
            if (h.sizeField < 24 || pos + h.sizeField > a_end) {
                return false;
            }
            const auto childType = static_cast<std::int32_t>(h.typeOrFormID);
            // Recurse only into exterior block levels; skip cell-children etc.
            if (childType == 4 || childType == 5) {
                if (!CountCellsInGroup(a_reader, pos + 24, pos + h.sizeField,
                                       childType, a_out, a_depth + 1)) {
                    return false;
                }
            }
            pos += h.sizeField;
        } else {
            const std::uint64_t recEnd = pos + 24 + h.sizeField;
            if (recEnd > a_end) {
                return false;
            }
            if (h.sig == kSigCELL) {
                if (a_groupType == 4 || a_groupType == 5) {
                    if ((h.labelOrFlags & kRecFlag400) != 0) {
                        // Engine never matches this cell — count in neither
                        // bound (see flag-semantics note above).
                    } else if (h.sizeField > 0 &&
                               (h.labelOrFlags & kRecFlagDeleted) == 0) {
                        ++a_out.clean;
                    } else {
                        ++a_out.uncertain;  // deleted-with-data or zero-size
                    }
                } else if (a_groupType == 1 && h.sizeField > 0 &&
                           (h.labelOrFlags & kRecFlag400) == 0) {
                    a_out.persistent = true;
                }
            }
            pos = recEnd;
        }
    }
    return pos == a_end || pos + 24 > a_end;  // tolerate trailing padding < one header
}

[[nodiscard]] std::optional<PluginScan> ScanPlugin(const std::filesystem::path& a_path)
{
    HANDLE handle = CreateFileW(a_path.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }
    LARGE_INTEGER sizeLi{};
    if (!GetFileSizeEx(handle, &sizeLi) || sizeLi.QuadPart <= 24) {
        CloseHandle(handle);
        return std::nullopt;
    }
    const auto fileEnd = static_cast<std::uint64_t>(sizeLi.QuadPart);

    PluginReader reader(handle);
    PluginScan   scan{};
    std::unordered_set<std::uint32_t> seenChildren;
    bool         ok = true;

    RawHeader tes4{};
    if (!reader.ReadHeader(0, tes4) || tes4.sig != kSigTES4 ||
        24ull + tes4.sizeField > fileEnd) {
        // A TES4 dataSize overrunning the file must be a parse FAILURE, not a
        // silently-successful empty scan.
        CloseHandle(handle);
        return std::nullopt;
    }
    std::uint64_t pos = 24ull + tes4.sizeField;

    while (ok && pos + 24 <= fileEnd) {
        RawHeader top{};
        if (!reader.ReadHeader(pos, top)) {
            ok = false;
            break;
        }
        if (top.sig != kSigGRUP) {
            // Stray top-level record (non-standard but harmless) — skip it.
            const std::uint64_t recEnd = pos + 24 + top.sizeField;
            if (recEnd > fileEnd) {
                ok = false;
                break;
            }
            pos = recEnd;
            continue;
        }
        if (top.sizeField < 24 || pos + top.sizeField > fileEnd) {
            ok = false;
            break;
        }
        const std::uint64_t grpEnd = pos + top.sizeField;
        if (top.labelOrFlags == kSigWRLD &&
            static_cast<std::int32_t>(top.typeOrFormID) == 0) {
            // Inside the WRLD top group: WRLD records interleaved with their
            // type-1 world-children groups. Attribution is by the children
            // group's own LABEL (which per the format IS the parent WRLD's
            // formID) — NOT by adjacency to the last-seen WRLD record, so an
            // orphaned or reordered children group (merge-tool output) can
            // never be counted into the wrong world.
            std::uint64_t p = pos + 24;
            while (ok && p + 24 <= grpEnd) {
                RawHeader h{};
                if (!reader.ReadHeader(p, h)) {
                    ok = false;
                    break;
                }
                if (h.sig == kSigGRUP) {
                    if (h.sizeField < 24 || p + h.sizeField > grpEnd) {
                        ok = false;
                        break;
                    }
                    if (static_cast<std::int32_t>(h.typeOrFormID) == 1) {
                        const auto labelKey = h.labelOrFlags & 0x00FFFFFFu;
                        WorldCellCounts counts{};
                        if (!CountCellsInGroup(reader, p + 24, p + h.sizeField,
                                               1, counts, 0)) {
                            ok = false;
                            break;
                        }
                        // Two children groups resolving to one key means two
                        // WRLD entries collided on objectID (or a malformed
                        // duplicate) — counts can't be attributed, flag it.
                        if (!seenChildren.insert(labelKey).second) {
                            scan.ambiguousWorlds.insert(labelKey);
                        }
                        auto& w = scan.worlds[labelKey];
                        w.clean      += counts.clean;
                        w.uncertain  += counts.uncertain;
                        w.persistent  = w.persistent || counts.persistent;
                    }
                    p += h.sizeField;
                } else {
                    const std::uint64_t recEnd = p + 24 + h.sizeField;
                    if (recEnd > grpEnd) {
                        ok = false;
                        break;
                    }
                    if (h.sig == kSigWRLD) {
                        // Seed so a WRLD with no children group is a known
                        // world with 0 cells (vs. "not in scan").
                        (void)scan.worlds[h.typeOrFormID & 0x00FFFFFFu];
                    }
                    p = recEnd;
                }
            }
        }
        pos = grpEnd;
    }

    CloseHandle(handle);
    if (!ok) {
        return std::nullopt;
    }
    return scan;
}

// ── .fco cache file ─────────────────────────────────────────────────────────
//
// .fco — Fallout Cell Offset (we keep the magic for tooling familiarity; the
// layout matches WallSoGB's NVSE format so inspection scripts stay useful as
// a reference).
//
// Layout (all little-endian, no padding):
//   Header { u32 magic='FCOF'; u32 version; u64 fileSize; u64 mtime; u64 fileHash; }
//   Data   { u64 offsetHash; u32 offsetCount; u32 offsets[offsetCount]; }
//
// If offsetCount == UINT32_MAX, the worldspace is empty for this plugin and
// no offset array follows. We still write the record so we can short-circuit
// re-checks on subsequent loads.

constexpr std::uint32_t kCacheMagic    = 'FCOF';
// v1: original layout, offsetCount = (maxX-minX) * (maxY-minY+1) +
//     (maxX-minX) — one slot short of the full grid (corner cell at
//     (maxX, maxY) was silently dropped).
// v2: offsetCount = (maxX-minX+1) * (maxY-minY+1) — full grid. Bumped in
//     v1.4.3 alongside the SkyrimGenerator off-by-one fix.
// v3: bumped in v1.5.4. v1.5.0–v1.5.3 had a generator race in the
//     publish path (check-then-set without CAS, drift handler that
//     wrote stale snapshots back into shared OFFSET_DATA, and a
//     broken -0xC0 engine call on SE) that could persist subtly-wrong
//     offsets into the cache. Forcing a regen on first v1.5.4 launch
//     guarantees every cached table came from the corrected code.
// v4: header gained fileSize + mtime so cache validation can take a
//     fast path (stat-only, no content read) on unchanged plugins. The
//     content hash stays as the fallback when size/mtime don't match.
//     Header layout changed → old caches invalidated.
// v5: bumped for three correctness fixes that can all change (or should
//     invalidate) previously-cached tables: (1) WorldUnitsToCell now
//     matches the engine's truncate semantics — v4 tables could be sized
//     one row/column short of the engine's runtime grid; (2) tables are
//     now verified against a raw scan of the plugin's exterior CELL
//     records before caching — v4 caches may contain unverified partial
//     or false-empty tables; (3) plugin identity is now resolved to a
//     single physical path shared by stamp+hash — v4 headers could
//     describe a different file than the engine loaded (USVFS duality).
constexpr std::uint32_t kCacheVersion       = 5;
constexpr std::uint32_t kCacheEmptySentinel = UINT32_MAX;

struct CacheHeader
{
    std::uint32_t magic{ kCacheMagic };
    std::uint32_t version{ kCacheVersion };
    std::uint64_t fileSize{ 0 };
    std::uint64_t mtime{ 0 };
    std::uint64_t fileHash{ 0 };
};
static_assert(sizeof(CacheHeader) == 32);

enum class CacheLoadStatus
{
    kOk,
    kFileMissing,
    kEmptyFile,
    kBadMagic,
    kHashMismatch,
    kReadFail,
    kEmptyWorld,
};

template <typename T>
[[nodiscard]] bool ReadPod(std::ifstream& a_in, T& a_out)
{
    a_in.read(reinterpret_cast<char*>(&a_out), sizeof(T));
    return a_in.good() && a_in.gcount() == sizeof(T);
}

template <typename T>
[[nodiscard]] bool WritePod(std::ofstream& a_out, const T& a_value)
{
    a_out.write(reinterpret_cast<const char*>(&a_value), sizeof(T));
    return a_out.good();
}

[[nodiscard]] CacheLoadStatus LoadCache(
    const std::filesystem::path& a_path,
    const FileStamp&             a_stamp,
    LazyFileHash&                a_fileHash,
    std::vector<std::uint32_t>&  a_offsets)
{
    a_offsets.clear();

    std::error_code ec;
    if (!std::filesystem::exists(a_path, ec)) {
        return CacheLoadStatus::kFileMissing;
    }

    const auto size = std::filesystem::file_size(a_path, ec);
    if (ec || size == 0) {
        return CacheLoadStatus::kEmptyFile;
    }

    std::ifstream in(a_path, std::ios::binary);
    if (!in) {
        return CacheLoadStatus::kReadFail;
    }

    CacheHeader header{};
    if (!ReadPod(in, header) || header.magic != kCacheMagic ||
        header.version != kCacheVersion) {
        return CacheLoadStatus::kBadMagic;
    }

    // fileHash == 0 is HashFile's failure sentinel, never a real digest. A
    // header carrying it can't be validated (and a failing re-hash would also
    // produce 0, vacuously "matching"), so treat it as invalid outright.
    if (header.fileHash == 0) {
        return CacheLoadStatus::kBadMagic;
    }

    // Fast path: if the plugin's size + mtime match what we cached, trust the
    // cache without reading a single byte of the (potentially tens-of-MB)
    // plugin. Only when the stamp differs do we fall back to the content hash
    // — which catches both real edits (regen) and re-timestamped-but-identical
    // files (stat changed, content same → hash still matches → cache valid).
    const bool stampMatch = a_stamp.valid &&
                            header.fileSize == a_stamp.size &&
                            header.mtime == a_stamp.mtime;
    if (!stampMatch && header.fileHash != a_fileHash.Get()) {
        return CacheLoadStatus::kHashMismatch;
    }

    std::uint64_t storedOffsetHash = 0;
    std::uint32_t offsetCount      = 0;
    if (!ReadPod(in, storedOffsetHash) || !ReadPod(in, offsetCount)) {
        return CacheLoadStatus::kReadFail;
    }

    if (offsetCount == kCacheEmptySentinel) {
        return CacheLoadStatus::kEmptyWorld;
    }

    constexpr std::uint32_t kReasonableMax = 4 * 1024 * 1024;
    if (offsetCount > kReasonableMax) {
        return CacheLoadStatus::kReadFail;
    }

    a_offsets.resize(offsetCount);
    in.read(reinterpret_cast<char*>(a_offsets.data()),
            static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t)));
    if (!in.good() ||
        in.gcount() != static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t))) {
        a_offsets.clear();
        return CacheLoadStatus::kReadFail;
    }

    const auto computedHash = HashBytes(a_offsets.data(), offsetCount * sizeof(std::uint32_t));
    if (computedHash != storedOffsetHash) {
        a_offsets.clear();
        return CacheLoadStatus::kHashMismatch;
    }

    return CacheLoadStatus::kOk;
}

[[nodiscard]] bool SaveCache(
    const std::filesystem::path&   a_path,
    std::uint64_t                  a_fileHash,
    const FileStamp&               a_stamp,
    std::span<const std::uint32_t> a_offsets)
{
    std::error_code ec;
    std::filesystem::create_directories(a_path.parent_path(), ec);

    // Direct write to the final path. We previously did a .tmp + rename for
    // atomicity, but the rename → MoveFileExW path crashes inside USVFS's
    // hook (lock-xadd on freed memory) under MO2 / Wabbajack. The hook is
    // non-thread-safe globally — even with our own writes serialized, MO2's
    // helper or any other USVFS-aware process can race with us, and the
    // crash happens before MoveFileExW returns so try/error_code can't
    // catch it. Direct write loses atomic-update — a process kill mid-write
    // leaves a partial file — but the LoadCache magic + dual-hash check
    // rejects partial/torn caches and regenerates next session. Trade-off:
    // rare crash on USVFS hits → 1.5s of regen on next launch.
    std::ofstream out(a_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    const CacheHeader header{ kCacheMagic, kCacheVersion,
                              a_stamp.size, a_stamp.mtime, a_fileHash };
    if (!WritePod(out, header)) {
        return false;
    }

    if (a_offsets.empty()) {
        const std::uint64_t zeroHash = 0;
        const std::uint32_t sentinel = kCacheEmptySentinel;
        if (!WritePod(out, zeroHash) || !WritePod(out, sentinel)) {
            return false;
        }
    } else {
        const auto byteSize    = a_offsets.size() * sizeof(std::uint32_t);
        const auto offsetHash  = HashBytes(a_offsets.data(), byteSize);
        const auto offsetCount = static_cast<std::uint32_t>(a_offsets.size());

        if (!WritePod(out, offsetHash) || !WritePod(out, offsetCount)) {
            return false;
        }
        out.write(reinterpret_cast<const char*>(a_offsets.data()),
                  static_cast<std::streamsize>(byteSize));
        if (!out.good()) {
            return false;
        }
    }
    return true;
}

// ── Generator helpers ───────────────────────────────────────────────────────

// Sanity cap on the offset table size. Anything bigger almost certainly
// indicates corrupt OFFSET_DATA bounds (e.g. uninitialized floats).
constexpr std::uint32_t kMaxReasonableTableSize = 4 * 1024 * 1024;

// Convert worldspace-unit float to cell coord EXACTLY like the engine does
// (GetIndexForCellCoord decompile: integer-cast then arithmetic >> 12 — i.e.
// truncate toward zero, then shift). We previously applied a floor correction
// for negative fractional values; that made our grid differ from the engine's
// by one row/column whenever a bound was negative, non-integral, and its
// truncation was a multiple of 4096 (including everything in (-1, 0)) —
// undersizing the table the engine later indexes WITHOUT a bounds check.
// The clamp guards the (int) cast against garbage float bounds, which is UB
// for values outside int range and could bypass the -524288 sentinel check.
[[nodiscard]] std::int32_t WorldUnitsToCell(float a_value)
{
    if (std::isnan(a_value)) {
        // NaN passes straight through std::clamp (all comparisons false) and
        // the (int) cast of NaN is UB. Map it to the engine's own "no cells"
        // sentinel so the caller's bounds checks reject it.
        return INT32_MIN >> 12;  // == -524288
    }
    constexpr float kMaxExact = 2147483520.0f;  // largest float <= INT32_MAX
    const float clamped = std::clamp(a_value, -kMaxExact, kMaxExact);
    return static_cast<std::int32_t>(clamped) >> 12;
}

// Resolve <game install>/Data via the running .exe location instead of cwd.
// Skyrim VR with MO2's USVFS (and some Steam VR launchers) leaves cwd as the
// MO2 profile dir, not the game folder — relative `Data/<plugin>.esp` then
// fails to open and the generator skips every plugin with "failed to hash".
[[nodiscard]] const std::filesystem::path& DataRoot()
{
    static const std::filesystem::path root = []() {
        wchar_t buf[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, buf, MAX_PATH);
        return std::filesystem::path(buf).parent_path() / L"Data";
    }();
    return root;
}

// Resolve the plugin's physical path ONCE per file; the stamp, the content
// hash, and the verification scan must all describe the SAME file the ENGINE
// parsed. The engine opens plugins via cwd-relative "Data\<name>", which is
// what MO2/USVFS overlays virtualize — under Wabbajack "Stock Game" the
// exe-relative ABSOLUTE form can resolve to a different (stock) file or
// nothing (err=2 for ~500 plugins on one tester's setup). So: cwd-relative
// first (engine truth), exe-relative absolute as the fallback for Skyrim VR
// where MO2 leaves cwd pointing at the profile dir and the relative form
// fails entirely.
[[nodiscard]] std::filesystem::path PluginPath(const RE::TESFile* a_file)
{
    const auto rel = std::filesystem::path(L"Data") / std::string_view(a_file->fileName);
    std::error_code ec;
    if (std::filesystem::exists(rel, ec)) {
        auto abs = std::filesystem::absolute(rel, ec);
        return ec ? rel : abs;
    }
    return DataRoot() / std::string_view(a_file->fileName);
}

// Cache file name: sanitized editor ID for human readability + the world's
// objectID (low 24 bits — load-order independent for non-ESL-origin worlds)
// for uniqueness. Guards GetFormEditorID() returning null/empty, and keeps
// two same-named (or unnamed) worldspaces from colliding onto one .fco and
// cross-loading each other's tables.
[[nodiscard]] std::string SanitizeForFilename(const char* a_text)
{
    std::string out;
    if (a_text) {
        for (const char c : std::string_view(a_text)) {
            const auto uc = static_cast<unsigned char>(c);
            out += (std::isalnum(uc) || c == '_' || c == '-') ? c : '_';
            if (out.size() >= 64) {
                break;
            }
        }
    }
    if (out.empty()) {
        out = "WORLD";
    }
    return out;
}

[[nodiscard]] std::filesystem::path CacheFileFor(
    const std::filesystem::path& a_root,
    const RE::TESFile*           a_file,
    const RE::TESWorldSpace*     a_world)
{
    // ESL-origin worlds: use only the load-order-stable low 12 bits (the
    // low-24 form of an ESL runtime ID embeds the ESL slot index, which
    // changes whenever light plugins are added/removed — that would orphan
    // and regenerate every ESL-origin cache on any load-order change).
    const auto fid = a_world->GetFormID();
    const auto id  = ((fid >> 24) == 0xFEu) ? (fid & 0x00000FFFu)
                                            : (fid & 0x00FFFFFFu);
    return a_root / std::string_view(a_file->fileName)
                  / fmt::format("{}_{:06X}.fco",
                                SanitizeForFilename(a_world->GetFormEditorID()), id);
}

// Mirrors Generate()'s bounds-validation. Returns the offsetCount (= number
// of slots in pCellFileOffsets), or 0 when bounds are invalid (no-cells
// sentinel, inverted/oversized ranges, or GetIndexForCellCoord rejecting
// the corner). Used to size the empty-world sentinel array installed below.
//
// v1.4.3: GetIndexForCellCoord uses 0-based indexing, returning [0, count-1]
// for valid (x, y) where count = (maxX-minX+1) * (maxY-minY+1). Pre-v1.4.3
// we used `offsetCount = maxIdx` which was off by one and silently dropped
// the (maxX, maxY) corner cell at the bounds check below. Fix:
// `offsetCount = maxIdx + 1`. Verified by Ghidra decompile of FUN_140306750:
//   return (width) * (y - minY) - minX + x;   // width = maxX-minX+1
// For (maxX, maxY): idx = width*height + (maxX-minX) = count - 1.
[[nodiscard]] std::uint32_t ComputeOffsetCount(
    RE::TESWorldSpace* a_world, RE::TESFile* a_file, const OFFSET_DATA* a_data)
{
    const auto minX = WorldUnitsToCell(a_data->offsetMinCoords.x);
    const auto minY = WorldUnitsToCell(a_data->offsetMinCoords.y);
    const auto maxX = WorldUnitsToCell(a_data->offsetMaxCoords.x);
    const auto maxY = WorldUnitsToCell(a_data->offsetMaxCoords.y);
    if (minX == -524288) {
        return 0;
    }
    if (maxX < minX || maxY < minY ||
        (maxX - minX + 1) >= 1000 || (maxY - minY + 1) >= 1000) {
        return 0;
    }
    const auto maxIdx = GetIndexForCellCoord(a_world, a_file, maxX, maxY);
    if (maxIdx < 0) {
        return 0;
    }
    const auto offsetCount = static_cast<std::uint32_t>(maxIdx) + 1;
    if (offsetCount > kMaxReasonableTableSize) {
        return 0;
    }
    return offsetCount;
}

}  // namespace

const PluginScan* LazyPluginScan::Get()
{
    if (!computed) {
        value    = ScanPlugin(path);
        computed = true;
    }
    return value.has_value() ? &*value : nullptr;
}

std::filesystem::path SkyrimGenerator::GetCacheRoot() const
{
    // Resolve with the SAME cwd-relative-first / exe-relative-fallback order
    // as PluginPath, so under MO2/USVFS the cache is written into the
    // virtualized (writable) Data overlay rather than possibly the read-only
    // real game Data dir. Reads and writes both go through here, so it stays
    // self-consistent regardless.
    const auto rel = std::filesystem::path(L"Data") / kCacheDirName;
    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::path(L"Data"), ec)) {
        auto abs = std::filesystem::absolute(rel, ec);
        return ec ? rel : abs;
    }
    return DataRoot() / kCacheDirName;
}

std::uint32_t* SkyrimGenerator::InstallEngineArray(std::span<const std::uint32_t> a_offsets)
{
    if (a_offsets.empty()) {
        return nullptr;
    }
    auto* mm = RE::MemoryManager::GetSingleton();
    if (!mm) {
        return nullptr;
    }
    const auto byteSize = a_offsets.size() * sizeof(std::uint32_t);
    auto* buf = static_cast<std::uint32_t*>(mm->Allocate(byteSize, 0, false));
    if (!buf) {
        return nullptr;
    }
    std::memcpy(buf, a_offsets.data(), byteSize);
    return buf;
}

std::uint32_t SkyrimGenerator::Generate(RE::TESFile* a_file,
                                        RE::TESWorldSpace* a_world,
                                        OFFSET_DATA* a_data,
                                        std::vector<std::uint32_t>& a_offsets)
{
    // Single source of truth for grid sizing (ComputeOffsetCount applies the
    // exact same sentinel / inverted / >=1000 / GetIndexForCellCoord / sanity-
    // cap checks); returns 0 on any rejection.
    const auto offsetCount = ComputeOffsetCount(a_world, a_file, a_data);
    if (offsetCount == 0) {
        logger::warn("[{}/{}] invalid or unusable cell bounds — skipping "
                     "(vanilla slow path keeps working)",
                     a_file->fileName, a_world->GetFormEditorID());
        return UINT32_MAX;
    }

    const auto minX = WorldUnitsToCell(a_data->offsetMinCoords.x);
    const auto minY = WorldUnitsToCell(a_data->offsetMinCoords.y);
    const auto maxX = WorldUnitsToCell(a_data->offsetMaxCoords.x);
    const auto maxY = WorldUnitsToCell(a_data->offsetMaxCoords.y);

    a_offsets.assign(offsetCount, 0);

    // We run synchronously inside the SKSE kDataLoaded handler — the main
    // thread is blocked until this returns and our worker threads each own a
    // unique TESFile via the atomic-index partition in Run(). Nothing else in
    // the engine can mutate `a_data->fileOffset` between this read and the end
    // of the loop.
    const auto baseFileOffset = a_data->fileOffset;

    std::uint32_t cellsFound = 0;
    for (std::int32_t y = minY; y <= maxY; ++y) {
        for (std::int32_t x = minX; x <= maxX; ++x) {
            const auto idx = GetIndexForCellCoord(a_world, a_file, x, y);
            if (idx < 0 || static_cast<std::uint32_t>(idx) >= offsetCount) {
                continue;
            }
            if (!FindCellInFile(a_world, a_file, x, y)) {
                continue;
            }
            a_offsets[idx] = a_file->fileOffset - baseFileOffset;
            ++cellsFound;
        }
    }

    return cellsFound;
}

bool SkyrimGenerator::ProcessWorld(RE::TESFile* a_file,
                                   const FileStamp& a_stamp,
                                   LazyFileHash& a_fileHash,
                                   LazyPluginScan& a_scan,
                                   RE::TESWorldSpace* a_world)
{
    // Inline BSTHashMap::find at TESWorldSpace+0x1D0 — purely a read-only
    // lookup, no engine call. The engine's GetOffsetData (= GetOrCreate-0xC0)
    // is not at the same RVA across runtimes (verified Ghidra: SE 1.5.97 has
    // it at 0x1402B7AA0, not at REL_ID(20110)-0xC0), so the engine wrapper
    // is unsafe for the generator. The map at +0x1D0 has the same layout
    // across SE/AE/VR/GOG, so the inline lookup just works.
    auto* data = FindOffsetData(a_world, a_file);
    if (!data) {
        // Plugin doesn't contribute anything to this worldspace.
        return false;
    }
    if (data->pCellFileOffsets) {
        // Engine loaded OFST directly via our NOPed gates. This is the
        // common case for non-xEdit-cleaned plugins; our generator does no
        // work here, but the NOPs themselves are what unlocked the load.
        m_stats.ofstIntact.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Plain assignment, no CAS. We run synchronously inside the SKSE
    // kDataLoaded handler, which blocks the main thread until Run() returns
    // (jthreads join on scope exit). The OFST-load path that the engine
    // would use to write pCellFileOffsets only fires inside TESWorldSpace
    // ::Load during data-load — already finished by the time we get here.
    // Per-file partitioning in Run() guarantees that no two workers touch
    // the same (file, world) OFFSET_DATA slot either. So we are the sole
    // writer of `data->pCellFileOffsets` for as long as we hold it; same
    // single-writer invariant WallSoGB's NVSE original relies on.
    auto publish = [&](std::span<const std::uint32_t> a_values) -> bool {
        auto* buf = InstallEngineArray(a_values);
        if (!buf) {
            return false;
        }
        data->pCellFileOffsets = buf;
        return true;
    };

    const auto cachePath = CacheFileFor(GetCacheRoot(), a_file, a_world);

    std::vector<std::uint32_t> offsets;
    const auto status = LoadCache(cachePath, a_stamp, a_fileHash, offsets);
    if (status == CacheLoadStatus::kOk) {
        // A cached table was verified at WRITE time, but its size must still
        // fit the engine's CURRENT grid for this (file, world): the engine
        // indexes pCellFileOffsets without a bounds check, so a stale or
        // cross-linked cache of the wrong size becomes an out-of-bounds read.
        const auto expected = ComputeOffsetCount(a_world, a_file, data);
        if (expected != 0 && offsets.size() == expected) {
            if (publish(offsets)) {
                m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            logger::warn("[{}/{}] cache load OK but engine alloc failed",
                         a_file->fileName, a_world->GetFormEditorID());
        } else {
            logger::warn("[{}/{}] cached table size {} != engine grid {} — "
                         "discarding cache and regenerating",
                         a_file->fileName, a_world->GetFormEditorID(),
                         offsets.size(), expected);
        }
        // fall through to regeneration
    } else if (status == CacheLoadStatus::kEmptyWorld) {
        // Verified-empty at write time (raw scan found zero exterior CELL
        // records for this world in this plugin).
        if (!Patches::HasSafeLookupPatch()) {
            // Without the original-style safe editor-ID lookup patch we still
            // need a zero-valued sentinel so `coc <editorID>` can't null-deref
            // the OFFSET_DATA our Load NOPs created.
            const auto offsetCount = ComputeOffsetCount(a_world, a_file, data);
            if (offsetCount > 0) {
                std::vector<std::uint32_t> zeros(offsetCount, 0);
                if (publish(zeros)) {
                    m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    // Cache miss / mismatch / corrupt / wrong-size — regenerate.

    // Real generation work (slow). Reveal the progress window — a pure cache /
    // OFST-intact launch never reaches here, so the window never flashes.
    ProgressWindow::NotifyGenerating();

    const auto cellsFound = Generate(a_file, a_world, data, offsets);
    if (cellsFound == UINT32_MAX) {
        // Bounds invalid — engine's GetIndexForCellCoord will reject all
        // (x, y) here too (or the slow path keeps working), so the unsafe
        // deref site can never fire.
        return false;
    }

    // ── Verification gate ───────────────────────────────────────────────────
    // The engine treats a zero table entry as "cell not in this file" with NO
    // slow-path fallback, so publishing (or caching) a table with gaps turns
    // any generation miss into permanently missing cell content. Before
    // trusting the probe results, compare cellsFound against the number of
    // exterior CELL records the plugin ACTUALLY contains for this world (raw
    // header-only scan of the file's GRUP structure). Mismatch or unparsable
    // file ⇒ leave pCellFileOffsets null: the engine's slow path stays intact
    // (correct, just unaccelerated) and NOTHING is cached, so a transient IO
    // failure can never be baked in.
    const auto* scan = a_scan.Get();
    if (!scan) {
        logger::warn("[{}/{}] plugin structure scan failed — table not "
                     "published or cached (engine slow path preserved)",
                     a_file->fileName, a_world->GetFormEditorID());
        m_stats.scanFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Map the runtime worldspace to its in-file objectID. Non-ESL-origin
    // worlds keep their low 24 bits in every override record; ESL-origin
    // worlds (runtime 0xFExxxxxx) store only the low 12 bits in-file — for
    // those the low-24 runtime key contains ESL slot bits and would only
    // ever match a DIFFERENT world's key by collision, so use low-12 alone.
    const auto runtimeID = a_world->GetFormID();
    const auto key       = ((runtimeID >> 24) == 0xFEu) ? (runtimeID & 0x00000FFFu)
                                                        : (runtimeID & 0x00FFFFFFu);
    const auto it        = scan->worlds.find(key);

    if (it == scan->worlds.end()) {
        // The engine says this file contributes OFFSET_DATA to this world,
        // but the scan found no WRLD record for it — the two views disagree,
        // so the scan can't vouch for anything (treating this as rawCount==0
        // could cache a FALSE empty). Inconclusive ⇒ no publish, no cache.
        logger::warn("[{}/{}] world not found in plugin scan (key {:06X}) — "
                     "table not published or cached",
                     a_file->fileName, a_world->GetFormEditorID(), key);
        m_stats.scanFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    const auto& raw = it->second;

    if (scan->ambiguousWorlds.contains(key)) {
        logger::warn("[{}/{}] plugin contains duplicate WRLD groups for this "
                     "world — table not published or cached",
                     a_file->fileName, a_world->GetFormEditorID());
        m_stats.scanFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Verification band. Lower bound: cells the engine's probe definitely
    // matches (clean records with data). Upper bound additionally allows
    // records whose matchability depends on unverified engine flag
    // semantics (deleted/0x400/zero-size — 'uncertain'), plus one hit for
    // the persistent CELL when the probed grid contains the origin. The
    // generation probe itself defines runtime semantics, so any count
    // inside the band is explainable by static file content; a count
    // outside it means something non-static (transient IO failure,
    // bounds narrower than content) happened — keep the slow path.
    const bool originInBounds =
        WorldUnitsToCell(data->offsetMinCoords.x) <= 0 &&
        WorldUnitsToCell(data->offsetMinCoords.y) <= 0 &&
        WorldUnitsToCell(data->offsetMaxCoords.x) >= 0 &&
        WorldUnitsToCell(data->offsetMaxCoords.y) >= 0;
    const auto slack = (originInBounds && raw.persistent) ? 1u : 0u;
    const auto lower = raw.clean;
    const auto upper = raw.clean + raw.uncertain + slack;

    if (cellsFound < lower || cellsFound > upper) {
        logger::warn("[{}/{}] verification mismatch: probes found {} cells, "
                     "file contains {} (+{} uncertain, +{} slack) — table "
                     "not published or cached (engine slow path preserved)",
                     a_file->fileName, a_world->GetFormEditorID(),
                     cellsFound, raw.clean, raw.uncertain, slack);
        m_stats.mismatched.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Never persist a cache entry we can't key: fileHash 0 means the plugin
    // could not be (fully) read for hashing, so the entry would be
    // unverifiable on later boots (0 == 0 vacuous match).
    const auto fileHash  = a_fileHash.Get();
    const bool cacheable = fileHash != 0;

    if (cellsFound == 0) {
        // VERIFIED empty: the raw scan agrees this plugin contributes no
        // exterior cells to this worldspace.
        if (!Patches::HasSafeLookupPatch() && publish(offsets)) {
            m_stats.emptySentinels.fetch_add(1, std::memory_order_relaxed);
        }
        if (cacheable && !SaveCache(cachePath, fileHash, a_stamp, {})) {
            logger::warn("[{}/{}] failed to write cache file '{}'",
                         a_file->fileName, a_world->GetFormEditorID(),
                         cachePath.string());
        }
        m_stats.emptyWorlds.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (publish(offsets)) {
        if (cacheable && !SaveCache(cachePath, fileHash, a_stamp, offsets)) {
            logger::warn("[{}/{}] failed to write cache file '{}'",
                         a_file->fileName, a_world->GetFormEditorID(),
                         cachePath.string());
        }
        m_stats.generatedTables.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    logger::warn("[{}/{}] generated {} cells but engine alloc failed",
                 a_file->fileName, a_world->GetFormEditorID(), cellsFound);
    return false;
}

void SkyrimGenerator::Run()
{
    using clock = std::chrono::steady_clock;
    const auto startedAt = clock::now();

    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        logger::error("Generator: TESDataHandler null");
        return;
    }

    auto& worlds = dh->GetFormArray<RE::TESWorldSpace>();
    if (worlds.empty()) {
        logger::info("Generator: no worldspaces loaded — nothing to do");
        return;
    }

    // Build the work set the way WallSoGB's NVSE original does (ThreadProc,
    // CellOffsetGenerator.cpp:423): walk each worldspace's OFFSET_DATA map —
    // the engine's per-world list of contributing files — and collect only
    // the (file, world) pairs whose pCellFileOffsets is still null. Files the
    // engine already populated via intact OFST, and the thousands of plugins
    // that touch no worldspace at all, never enter the set, so we never stat
    // or hash them. Earlier we iterated the entire load order and hashed every
    // plugin up front, which read the whole Data folder on every launch and
    // dominated cached-startup time on large modlists.
    std::unordered_map<RE::TESFile*, std::vector<RE::TESWorldSpace*>> work;
    std::uint32_t ofstIntact = 0;
    for (auto* world : worlds) {
        if (!world) {
            continue;
        }
        for (auto& entry : GetOffsetDataMap(world)) {
            auto* file = entry.first;
            auto* data = entry.second;
            if (!file || !data) {
                continue;
            }
            if (data->pCellFileOffsets) {
                ++ofstIntact;  // engine populated it during data-load; skip
                continue;
            }
            work[file].push_back(world);
        }
    }
    m_stats.ofstIntact.store(ofstIntact, std::memory_order_relaxed);

    // Flatten to a vector so workers can claim entries via a stable index.
    std::vector<std::pair<RE::TESFile*, std::vector<RE::TESWorldSpace*>>> targets;
    targets.reserve(work.size());
    for (auto& [file, list] : work) {
        targets.emplace_back(file, std::move(list));
    }
    // Largest-file-first, matching WallSoGB's NVSE original
    // (CellOffsetGenerator.cpp:445-448) and the Starfield port: with the
    // work-stealing atomic index, handing out the biggest plugins first keeps
    // a slow file from becoming the lone straggler while every other worker
    // idles. TESFile::filesize (+0x2A4) is the engine's own size field — the
    // same one Wall sorts on — so no filesystem stat is needed.
    std::sort(targets.begin(), targets.end(),
              [](const auto& a, const auto& b) {
                  return a.first->filesize > b.first->filesize;
              });
    m_stats.totalFiles.store(static_cast<std::uint32_t>(targets.size()),
                             std::memory_order_relaxed);

    // Parallel per-file loop. Each worker pulls a (file, worldspaces) entry
    // from a shared atomic index and processes that file's needy worldspaces
    // serially. Partitioning by file guarantees no two workers touch the same
    // (file, world) OFFSET_DATA slot, and post-kDataLoaded the engine isn't
    // seeking these files, so per-file state stays thread-local. We pass the
    // original file pointer for both seek and OFFSET_DATA ownership — no
    // TESFile::Duplicate (its master-chain walk + unlocked NiTPointerMap
    // insert crashed under contention; see git history).
    //
    // Cap matches WallSoGB's NVSE original (CellOffsetGenerator.cpp:494):
    // `min(32, dwNumberOfProcessors)` — but reserve one logical core for the
    // progress-window UI thread (and the OS). With every core saturated by
    // workers, the high-priority UI thread still gets preempt slices, but
    // leaving one core free keeps the bar repainting smoothly instead of
    // flickering in/out during a heavy regen. One fewer worker is a negligible
    // generation-time cost.
    const auto hw = std::max<unsigned>(1, std::thread::hardware_concurrency());
    const auto threadCount =
        std::min<unsigned>(32, hw > 1 ? hw - 1 : 1);

    std::atomic<std::size_t> nextIdx{ 0 };
    auto worker = [&]() {
        SetThreadDescription(GetCurrentThread(), L"FCL Generator Worker");
        while (true) {
            const auto i = nextIdx.fetch_add(1, std::memory_order_relaxed);
            if (i >= targets.size()) {
                return;
            }
            auto* file       = targets[i].first;
            const auto& needy = targets[i].second;

            // Exception barrier: a throw escaping a jthread calls
            // std::terminate → CTD during the loading screen. Anything below
            // (filesystem paths from plugin-controlled names, allocation,
            // logging) may throw; contain it to this file and move on — the
            // affected plugin just keeps the engine's slow path.
            try {
                // One resolved path per file: stamp, hash, and verification
                // scan all describe the same physical file (see PluginPath).
                const auto pluginPath = PluginPath(file);

                // Cheap identity for the cache fast-path. Content hash and
                // structure scan are lazy — an all-cache-hit launch reads no
                // plugin bytes at all.
                std::uint32_t statError = 0;
                const auto    stamp     = StatPlugin(pluginPath, &statError);
                LazyFileHash   fileHash{ pluginPath };
                LazyPluginScan scan{ pluginPath };
                if (!stamp.valid) {
                    logger::warn("Generator: failed to stat {} (path='{}', err={}); "
                                 "falling back to content hash",
                                 file->fileName, pluginPath.string(), statError);
                }

                for (auto* world : needy) {
                    if (world) {
                        ProcessWorld(file, stamp, fileHash, scan, world);
                    }
                    ProgressWindow::Tick();  // one (file, world) work unit done
                }
            } catch (const std::exception& e) {
                logger::error("Generator: worker exception on '{}': {}",
                              file ? file->fileName : "<null>", e.what());
            } catch (...) {
                logger::error("Generator: unknown worker exception on '{}'",
                              file ? file->fileName : "<null>");
            }
            m_stats.processedFiles.fetch_add(1, std::memory_order_relaxed);
        }
    };

    // Total work units = every (file, world) pair that needs offsets. The
    // window stays hidden until the first real cache-miss generation
    // (NotifyGenerating in ProcessWorld), so all-cache-hit boots never flash
    // it — but the bar already reflects the cache-hit ticks when it appears.
    std::uint32_t totalWork = 0;
    for (const auto& entry : targets) {
        totalWork += static_cast<std::uint32_t>(entry.second.size());
    }
    // RAII pairing: if anything below throws, the window thread must not be
    // orphaned re-asserting topmost over the game for the whole session.
    struct ProgressScope
    {
        ~ProgressScope() { ProgressWindow::Stop(); }
    } progressScope;
    ProgressWindow::Start("FasterCellLookup");
    ProgressWindow::SetTotal(totalWork);

    logger::info("Generator: {} plugin(s) needing work across {} worldspace(s), "
                 "{} already OFST-intact, {} thread(s)",
                 targets.size(), worlds.size(), ofstIntact, threadCount);

    {
        std::vector<std::jthread> workers;
        workers.reserve(threadCount);
        for (unsigned t = 0; t < threadCount; ++t) {
            workers.emplace_back(worker);
        }
    }  // jthreads join on destruction

    ProgressWindow::Stop();

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             clock::now() - startedAt)
                             .count();

    logger::info(
        "Generator: done in {} ms — files={}/{}, generated={}, "
        "cache-hits={}, OFST-intact={}, empty-worlds={} (sentinels={}), "
        "verify-mismatch={}, scan-failed={}",
        elapsed,
        m_stats.processedFiles.load(),
        m_stats.totalFiles.load(),
        m_stats.generatedTables.load(),
        m_stats.cacheHits.load(),
        m_stats.ofstIntact.load(),
        m_stats.emptyWorlds.load(),
        m_stats.emptySentinels.load(),
        m_stats.mismatched.load(),
        m_stats.scanFailed.load());
    if (m_stats.mismatched.load() > 0 || m_stats.scanFailed.load() > 0) {
        logger::warn(
            "Generator: {} worldspace table(s) were NOT accelerated because "
            "the plugin's actual cell records did not match the probe results "
            "(or the plugin could not be parsed). Those plugins keep the "
            "vanilla slow path — content is safe, just not sped up. See "
            "warnings above for the specific plugins.",
            m_stats.mismatched.load() + m_stats.scanFailed.load());
    }
}

}  // namespace cog
