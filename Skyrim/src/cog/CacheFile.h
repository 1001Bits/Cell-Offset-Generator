#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>

namespace cog {

// .fco — Fallout Cell Offset (we keep the magic for tooling familiarity even
// though this is the Skyrim port; the layout matches WallSoGB's format so
// inspection scripts and the FNV mod's tooling stay useful as a reference).
//
// Layout (all little-endian, no padding):
//   Header { u32 magic='FCOF'; u32 version=1; u64 fileHash; }
//   Data   { u64 offsetHash; u32 offsetCount; u32 offsets[offsetCount]; }
//
// If offsetCount == UINT32_MAX, the worldspace is empty for this plugin and
// no offset array follows. We still write the record so we can short-circuit
// re-checks on subsequent loads.
class CacheFile
{
public:
    static constexpr std::uint32_t kMagic = 'FCOF';
    static constexpr std::uint32_t kVersion = 1;
    static constexpr std::uint32_t kEmptySentinel = UINT32_MAX;

    struct Header
    {
        std::uint32_t magic{ kMagic };
        std::uint32_t version{ kVersion };
        std::uint64_t fileHash{ 0 };
    };
    static_assert(sizeof(Header) == 16);

    enum class LoadStatus
    {
        kOk,
        kFileMissing,
        kEmptyFile,
        kBadMagic,
        kHashMismatch,
        kReadFail,
        kEmptyWorld,  // sentinel record — not an error, but no offsets to apply
    };

    // Load. On kOk, `offsets` is filled. On kEmptyWorld, `offsets` is empty
    // and the caller should treat the worldspace as "no offsets".
    [[nodiscard]] static LoadStatus Load(
        const std::filesystem::path& a_path,
        std::uint64_t a_expectedFileHash,
        std::vector<std::uint32_t>& a_offsets);

    // Save. Pass an empty span to write the empty-world sentinel.
    [[nodiscard]] static bool Save(
        const std::filesystem::path& a_path,
        std::uint64_t a_fileHash,
        std::span<const std::uint32_t> a_offsets);
};

}  // namespace cog
