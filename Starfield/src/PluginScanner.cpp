#include "PCH.h"
#include "PluginScanner.hpp"

#include <cmath>
#include <cstring>
#include <fstream>
#include <memory>

#define XXH_INLINE_ALL
#include <xxhash.h>
#include <zlib.h>

namespace cog::sf {

namespace {

constexpr std::size_t kRecordHeaderSize = 24;
constexpr std::size_t kGrupHeaderSize   = 24;

// Record flag indicating zlib-compressed data — we skip those for now.
constexpr std::uint32_t kFlagCompressed = 0x00040000u;

constexpr std::uint32_t kSigGRUP = 0x50555247u;  // "GRUP"
constexpr std::uint32_t kSigTES4 = 0x34534554u;  // "TES4"
constexpr std::uint32_t kSigWRLD = 0x444C5257u;  // "WRLD"
constexpr std::uint32_t kSigCELL = 0x4C4C4543u;  // "CELL"
constexpr std::uint32_t kSigXCLC = 0x434C4358u;  // "XCLC"
constexpr std::uint32_t kSigXXXX = 0x58585858u;  // "XXXX"
constexpr std::uint32_t kSigNAM0 = 0x304D414Eu;  // "NAM0" (min corner, 2x float, world units)
constexpr std::uint32_t kSigNAM9 = 0x394D414Eu;  // "NAM9" (max corner, 2x float, world units)

// World-unit -> cell-coord scale. MUST be bit-identical to the engine's
// GetIndexForCellCoord (FUN_140BB8600), which computes the cell index from
// pData's NAM0/NAM9 floats as `floor(0.01f * worldUnits)` in SINGLE precision,
// using the constant at 0x144F07F7C = 0x3C23D70A = 0.01f (≈0.00999999978).
// We MUST replicate this exactly: dividing by 100.0 (exact) instead of
// multiplying by 0.01f (imprecise) floors a different integer at exact cell
// boundaries (e.g. 4200.0 -> ours 42 vs engine 41), which mis-sizes/mis-indexes
// the OFST table for any worldspace whose NAM bounds land on a boundary —
// loading wrong cell data for a whole region of that world.
constexpr float kCellScale = 0.01f;  // == engine's 0x144F07F7C

struct XclcData
{
    std::int32_t  x;
    std::int32_t  y;
    std::uint32_t flags;
};

struct Reader
{
    std::ifstream is;
    std::uint64_t fileSize = 0;

    [[nodiscard]] bool open(const std::filesystem::path& a_path)
    {
        is.open(a_path, std::ios::binary);
        if (!is) return false;
        is.seekg(0, std::ios::end);
        fileSize = static_cast<std::uint64_t>(is.tellg());
        is.seekg(0, std::ios::beg);
        return true;
    }

    [[nodiscard]] std::uint64_t pos() { return static_cast<std::uint64_t>(is.tellg()); }
    void seek(std::uint64_t a_off) { is.seekg(static_cast<std::streamoff>(a_off), std::ios::beg); }
    void skip(std::uint64_t a_n)   { is.seekg(static_cast<std::streamoff>(a_n), std::ios::cur); }

    [[nodiscard]] bool read(void* a_buf, std::size_t a_n)
    {
        is.read(static_cast<char*>(a_buf), static_cast<std::streamsize>(a_n));
        return is.good();
    }
};

// Pull XCLC out of an in-memory buffer of subrecord bytes. Handles the
// XXXX big-size prefix Bethesda uses for subrecords exceeding 0xFFFF.
[[nodiscard]] bool ReadXclcFromBuffer(const std::uint8_t* a_data, std::size_t a_len,
                                      XclcData& a_out)
{
    std::size_t off = 0;
    std::uint32_t nextBigSize = 0;
    while (off + 6 <= a_len) {
        std::uint32_t type;
        std::uint16_t size16;
        std::memcpy(&type, a_data + off, 4);
        std::memcpy(&size16, a_data + off + 4, 2);
        off += 6;

        std::uint32_t size = nextBigSize ? nextBigSize : static_cast<std::uint32_t>(size16);
        nextBigSize = 0;

        if (off + size > a_len) return false;

        if (type == kSigXXXX) {
            if (size != 4) { off += size; continue; }
            std::memcpy(&nextBigSize, a_data + off, 4);
            off += 4;
            continue;
        }
        if (type == kSigXCLC) {
            if (size < sizeof(XclcData)) { off += size; continue; }
            std::memcpy(&a_out, a_data + off, sizeof(XclcData));
            return true;
        }
        off += size;
    }
    return false;
}

// File-backed variant: read the CELL data block from the stream, then walk
// it in-memory. We use a buffer either way because the compressed path
// also needs to materialize the decompressed bytes.
[[nodiscard]] bool ReadXclcFromCellData(Reader& r, std::uint64_t a_dataStart,
                                        std::uint32_t a_dataSize, bool a_compressed,
                                        XclcData& a_out)
{
    r.seek(a_dataStart);

    if (a_compressed) {
        // First 4 bytes of the data block = decompressed size; rest = zlib.
        if (a_dataSize < 4) return false;
        std::uint32_t decompSize = 0;
        if (!r.read(&decompSize, 4)) return false;
        if (decompSize == 0 || decompSize > 64u * 1024u * 1024u) return false;

        const auto compSize = a_dataSize - 4;
        std::unique_ptr<std::uint8_t[]> comp(new (std::nothrow) std::uint8_t[compSize]);
        std::unique_ptr<std::uint8_t[]> decomp(new (std::nothrow) std::uint8_t[decompSize]);
        if (!comp || !decomp) return false;
        if (!r.read(comp.get(), compSize)) return false;

        uLongf dstLen = decompSize;
        const auto zr = uncompress(decomp.get(), &dstLen, comp.get(),
                                   static_cast<uLong>(compSize));
        if (zr != Z_OK || dstLen != decompSize) return false;
        return ReadXclcFromBuffer(decomp.get(), decompSize, a_out);
    }

    if (a_dataSize == 0) return false;
    std::unique_ptr<std::uint8_t[]> buf(new (std::nothrow) std::uint8_t[a_dataSize]);
    if (!buf) return false;
    if (!r.read(buf.get(), a_dataSize)) return false;
    return ReadXclcFromBuffer(buf.get(), a_dataSize, a_out);
}

bool WalkContainer(Reader& r, std::uint64_t a_end,
                   std::uint32_t a_currentWorldFormID, ScanResult& a_out)
{
    while (r.pos() < a_end) {
        const auto recordStart = r.pos();

        std::uint32_t type;
        std::uint32_t size;
        if (!r.read(&type, 4)) return false;
        if (!r.read(&size, 4)) return false;

        if (type == kSigGRUP) {
            std::uint32_t label;
            std::int32_t  groupType;
            std::uint32_t tail[2];
            if (!r.read(&label, 4)) return false;
            if (!r.read(&groupType, 4)) return false;
            if (!r.read(tail, 8)) return false;

            if (size < kGrupHeaderSize || recordStart + size > r.fileSize) return false;

            const auto childEnd = recordStart + size;
            const std::uint32_t childWorld =
                (groupType == 1) ? label : a_currentWorldFormID;

            if (!WalkContainer(r, childEnd, childWorld, a_out)) return false;
            r.seek(childEnd);
            continue;
        }

        std::uint32_t flags, formID, versionControl, internalVersion;
        if (!r.read(&flags, 4)) return false;
        if (!r.read(&formID, 4)) return false;
        if (!r.read(&versionControl, 4)) return false;
        if (!r.read(&internalVersion, 4)) return false;

        const auto dataStart = r.pos();
        const auto dataEnd   = dataStart + size;
        if (dataEnd > r.fileSize) return false;

        if (type == kSigWRLD) {
            auto& w = a_out.worlds[formID];
            w.wrldFileOffset = static_cast<std::uint32_t>(recordStart);

            // Walk WRLD subrecords looking for NAM0/NAM9 — these set the
            // engine's coordinate bounds (and therefore the size of
            // pCellFileOffsets). Decompression: WRLD records can be compressed
            // too, but in vanilla Starfield.esm the WRLD records we care about
            // aren't, and our scanner currently doesn't decompress them. If
            // we hit one, we fall back to XCLC-observed bounds via hasNam=false.
            if ((flags & kFlagCompressed) == 0) {
                auto sub = dataStart;
                std::uint32_t nextBigSize = 0;
                bool sawNam0 = false;
                bool sawNam9 = false;
                while (sub + 6 <= dataEnd) {
                    r.seek(sub);
                    std::uint32_t subType;
                    std::uint16_t subSize16;
                    if (!r.read(&subType, 4)) break;
                    if (!r.read(&subSize16, 2)) break;
                    const std::uint32_t subSize = nextBigSize
                                                      ? nextBigSize
                                                      : static_cast<std::uint32_t>(subSize16);
                    nextBigSize = 0;
                    const auto subData = sub + 6;
                    if (subData + subSize > dataEnd) break;

                    if (subType == kSigXXXX) {
                        if (subSize >= 4) (void)r.read(&nextBigSize, 4);
                    } else if ((subType == kSigNAM0 || subType == kSigNAM9) && subSize == 8) {
                        float fx, fy;
                        if (r.read(&fx, 4) && r.read(&fy, 4)) {
                            // Single-precision multiply by 0.01f then floor —
                            // bit-identical to the engine's GetIndexForCellCoord.
                            const auto cellX = static_cast<std::int32_t>(std::floor(kCellScale * fx));
                            const auto cellY = static_cast<std::int32_t>(std::floor(kCellScale * fy));
                            if (subType == kSigNAM0) {
                                w.nam0CellX = cellX;
                                w.nam0CellY = cellY;
                                sawNam0 = true;
                            } else {
                                w.nam9CellX = cellX;
                                w.nam9CellY = cellY;
                                sawNam9 = true;
                            }
                        }
                    }
                    sub = subData + subSize;
                }
                // hasNam is set conservatively: only true if both NAM0 and
                // NAM9 produced sensible (min<=max) bounds.
                w.hasNam = sawNam0 && sawNam9 &&
                           (w.nam0CellX <= w.nam9CellX) &&
                           (w.nam0CellY <= w.nam9CellY);
            }

            r.seek(dataEnd);
            continue;
        }

        if (type == kSigCELL && a_currentWorldFormID != 0) {
            XclcData xclc{};
            const bool compressed = (flags & kFlagCompressed) != 0;
            if (ReadXclcFromCellData(r, dataStart, size, compressed, xclc)) {
                // Sanity: reject absurd coords. Real Starfield cells live
                // well under ±10,000 cells; anything outside that came from
                // a decompression/format misread.
                constexpr std::int32_t kCoordLimit = 100000;
                if (xclc.x < -kCoordLimit || xclc.x > kCoordLimit ||
                    xclc.y < -kCoordLimit || xclc.y > kCoordLimit) {
                    r.seek(dataEnd);
                    continue;
                }
                // CLSZ semantic — verified against CK FUN_141defd10 +
                // with-OFST.esm byte-identical compare on Akila + akilacity:
                //
                //   CLSZ = on-disk_record_total
                //          + (children_grup_size + 24  if cell has a
                //             CELL CHILDREN GRUP immediately following)
                //
                // The trailing +24 covers the next sub-block/transition
                // header the engine pre-reads after the cell's children.
                // Compression doesn't affect this — CLSZ tracks ON-DISK
                // extent, not in-memory decompressed size.
                std::uint32_t recordTotal =
                    size + static_cast<std::uint32_t>(kRecordHeaderSize);

                // Peek at the next 8 bytes for a GRUP header (uncompressed
                // records always end on a record boundary; we just resumed
                // the file at dataEnd via the read above so seek there).
                const auto savedPos = r.pos();
                r.seek(dataEnd);
                std::uint32_t nextType = 0;
                std::uint32_t nextSize = 0;
                std::int32_t  nextGrupType = 0;
                if (r.read(&nextType, 4) && r.read(&nextSize, 4)) {
                    if (nextType == kSigGRUP &&
                        dataEnd + nextSize <= r.fileSize) {
                        // Read the label + groupType to confirm CELL CHILDREN (type 6).
                        std::uint32_t label = 0;
                        if (r.read(&label, 4) && r.read(&nextGrupType, 4) &&
                            nextGrupType == 6) {
                            recordTotal += nextSize +
                                static_cast<std::uint32_t>(kRecordHeaderSize);
                        }
                    }
                }
                r.seek(savedPos);

                ScannedCell entry{
                    a_currentWorldFormID, xclc.x, xclc.y,
                    static_cast<std::uint32_t>(recordStart),
                    recordTotal,
                };
                a_out.cells.push_back(entry);

                auto& w = a_out.worlds[a_currentWorldFormID];
                if (xclc.x < w.xclcMinX) w.xclcMinX = xclc.x;
                if (xclc.y < w.xclcMinY) w.xclcMinY = xclc.y;
                if (xclc.x > w.xclcMaxX) w.xclcMaxX = xclc.x;
                if (xclc.y > w.xclcMaxY) w.xclcMaxY = xclc.y;
            }
            r.seek(dataEnd);
            continue;
        }

        r.seek(dataEnd);
    }
    return true;
}

}  // namespace

bool ScanPluginFile(const std::filesystem::path& a_path, ScanResult& a_out)
{
    Reader r;
    if (!r.open(a_path)) return false;

    std::uint32_t type;
    std::uint32_t size;
    if (!r.read(&type, 4)) return false;
    if (!r.read(&size, 4)) return false;
    if (type != kSigTES4) return false;
    r.skip(16);
    r.skip(size);

    return WalkContainer(r, r.fileSize, 0, a_out);
}

// ── On-disk scan cache ────────────────────────────────────────────────────
namespace {

constexpr std::uint32_t kCacheMagic   = 0x46435350u;  // 'PSCF' = "Plugin Scan Cache File"
constexpr std::uint32_t kCacheVersion = 7u;            // v7: NAM cell bounds now use engine-exact floor(0.01f*x) (was floor(x/100))

struct CacheHeader
{
    std::uint32_t magic;
    std::uint32_t version;
    std::uint64_t pluginHash;
    std::uint32_t worldCount;
    std::uint32_t cellCount;
};

#pragma pack(push, 1)
struct CachedWorldEntry
{
    std::uint32_t formID;
    std::uint32_t wrldFileOffset;
    std::int32_t  xclcMinX;
    std::int32_t  xclcMinY;
    std::int32_t  xclcMaxX;
    std::int32_t  xclcMaxY;
    std::uint8_t  hasNam;
    std::uint8_t  pad[3];
    std::int32_t  nam0CellX;
    std::int32_t  nam0CellY;
    std::int32_t  nam9CellX;
    std::int32_t  nam9CellY;
};
#pragma pack(pop)
static_assert(sizeof(CachedWorldEntry) == 44);

}  // namespace

// Cache validation signature — size + mtime, NOT a content hash.
//
// Hashing a 1.46 GB Starfield.esm cost ~23 s on every launch (even on a cache
// HIT) just to confirm the .psc was still valid — the dominant load-time cost.
// A plugin that changed will essentially always change its size and/or
// last-write time, so a size+mtime signature invalidates the cache just as
// reliably for the only scenario that matters (the user replaced/edited the
// plugin), at near-zero cost. The pathological case (an in-place edit that
// preserves both byte-count AND mtime) doesn't occur for distributed mods; if
// it ever did, the user can delete Data/CellOffsets to force a rescan.
std::uint64_t HashPluginFile(const std::filesystem::path& a_path)
{
    std::error_code ec;
    const auto size = std::filesystem::file_size(a_path, ec);
    if (ec) return 0;
    const auto mtime = std::filesystem::last_write_time(a_path, ec);
    if (ec) return 0;

    const auto ticks = static_cast<std::uint64_t>(mtime.time_since_epoch().count());
    // Mix size and mtime ticks into one 64-bit signature (boost::hash_combine-style).
    std::uint64_t sig = static_cast<std::uint64_t>(size);
    sig ^= ticks + 0x9e3779b97f4a7c15ULL + (sig << 6) + (sig >> 2);
    return sig != 0 ? sig : 1;  // never 0 — 0 is the "couldn't compute" sentinel
}

bool SaveScanCache(const std::filesystem::path& a_cachePath,
                   std::uint64_t a_pluginHash,
                   const ScanResult& a_scan)
{
    std::error_code ec;
    std::filesystem::create_directories(a_cachePath.parent_path(), ec);

    std::ofstream os(a_cachePath, std::ios::binary | std::ios::trunc);
    if (!os) return false;

    CacheHeader hdr{
        kCacheMagic,
        kCacheVersion,
        a_pluginHash,
        static_cast<std::uint32_t>(a_scan.worlds.size()),
        static_cast<std::uint32_t>(a_scan.cells.size()),
    };
    os.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));

    for (const auto& [formID, w] : a_scan.worlds) {
        CachedWorldEntry e{};
        e.formID         = formID;
        e.wrldFileOffset = w.wrldFileOffset;
        e.xclcMinX       = w.xclcMinX;
        e.xclcMinY       = w.xclcMinY;
        e.xclcMaxX       = w.xclcMaxX;
        e.xclcMaxY       = w.xclcMaxY;
        e.hasNam         = w.hasNam ? 1u : 0u;
        e.nam0CellX      = w.nam0CellX;
        e.nam0CellY      = w.nam0CellY;
        e.nam9CellX      = w.nam9CellX;
        e.nam9CellY      = w.nam9CellY;
        os.write(reinterpret_cast<const char*>(&e), sizeof(e));
    }

    if (!a_scan.cells.empty()) {
        os.write(reinterpret_cast<const char*>(a_scan.cells.data()),
                 static_cast<std::streamsize>(a_scan.cells.size() * sizeof(ScannedCell)));
    }
    return os.good();
}

bool LoadScanCache(const std::filesystem::path& a_cachePath,
                   std::uint64_t a_pluginHash,
                   ScanResult& a_scan)
{
    std::ifstream is(a_cachePath, std::ios::binary);
    if (!is) return false;

    CacheHeader hdr{};
    is.read(reinterpret_cast<char*>(&hdr), sizeof(hdr));
    if (!is) return false;
    if (hdr.magic != kCacheMagic || hdr.version != kCacheVersion) return false;
    if (hdr.pluginHash != a_pluginHash) return false;

    a_scan.worlds.clear();
    a_scan.worlds.reserve(hdr.worldCount);
    for (std::uint32_t i = 0; i < hdr.worldCount; ++i) {
        CachedWorldEntry e{};
        is.read(reinterpret_cast<char*>(&e), sizeof(e));
        if (!is) return false;
        ScannedWorld w{};
        w.wrldFileOffset = e.wrldFileOffset;
        w.xclcMinX       = e.xclcMinX;
        w.xclcMinY       = e.xclcMinY;
        w.xclcMaxX       = e.xclcMaxX;
        w.xclcMaxY       = e.xclcMaxY;
        w.hasNam         = (e.hasNam != 0);
        w.nam0CellX      = e.nam0CellX;
        w.nam0CellY      = e.nam0CellY;
        w.nam9CellX      = e.nam9CellX;
        w.nam9CellY      = e.nam9CellY;
        a_scan.worlds.emplace(e.formID, w);
    }

    a_scan.cells.clear();
    if (hdr.cellCount > 0) {
        a_scan.cells.resize(hdr.cellCount);
        is.read(reinterpret_cast<char*>(a_scan.cells.data()),
                static_cast<std::streamsize>(hdr.cellCount * sizeof(ScannedCell)));
        if (!is) return false;
    }
    return true;
}

}  // namespace cog::sf
