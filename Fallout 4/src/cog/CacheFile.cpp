#include "PCH.h"
#include "cog/CacheFile.h"
#include "cog/HashUtil.h"

namespace cog {

namespace {

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

}  // namespace

CacheFile::LoadStatus CacheFile::Load(
    const std::filesystem::path& a_path,
    std::uint64_t a_expectedFileHash,
    std::vector<std::uint32_t>& a_offsets)
{
    a_offsets.clear();

    std::error_code ec;
    if (!std::filesystem::exists(a_path, ec)) {
        return LoadStatus::kFileMissing;
    }

    const auto size = std::filesystem::file_size(a_path, ec);
    if (ec || size == 0) {
        return LoadStatus::kEmptyFile;
    }

    std::ifstream in(a_path, std::ios::binary);
    if (!in) {
        return LoadStatus::kReadFail;
    }

    Header header{};
    if (!ReadPod(in, header) || header.magic != kMagic) {
        return LoadStatus::kBadMagic;
    }

    if (header.fileHash != a_expectedFileHash) {
        return LoadStatus::kHashMismatch;
    }

    std::uint64_t storedOffsetHash = 0;
    std::uint32_t offsetCount = 0;
    if (!ReadPod(in, storedOffsetHash) || !ReadPod(in, offsetCount)) {
        return LoadStatus::kReadFail;
    }

    if (offsetCount == kEmptySentinel) {
        return LoadStatus::kEmptyWorld;
    }

    // Sanity bound — a single worldspace shouldn't exceed ~4M cell slots.
    constexpr std::uint32_t kReasonableMax = 4 * 1024 * 1024;
    if (offsetCount > kReasonableMax) {
        return LoadStatus::kReadFail;
    }

    a_offsets.resize(offsetCount);
    in.read(reinterpret_cast<char*>(a_offsets.data()),
            static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t)));
    if (!in.good() || in.gcount() != static_cast<std::streamsize>(offsetCount * sizeof(std::uint32_t))) {
        a_offsets.clear();
        return LoadStatus::kReadFail;
    }

    const auto computedHash = HashBytes(a_offsets.data(), offsetCount * sizeof(std::uint32_t));
    if (computedHash != storedOffsetHash) {
        a_offsets.clear();
        return LoadStatus::kHashMismatch;
    }

    return LoadStatus::kOk;
}

bool CacheFile::Save(
    const std::filesystem::path& a_path,
    std::uint64_t a_fileHash,
    std::span<const std::uint32_t> a_offsets)
{
    std::error_code ec;
    std::filesystem::create_directories(a_path.parent_path(), ec);

    std::ofstream out(a_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }

    const Header header{ kMagic, kVersion, a_fileHash };
    if (!WritePod(out, header)) {
        return false;
    }

    if (a_offsets.empty()) {
        const std::uint64_t zeroHash = 0;
        const std::uint32_t sentinel = kEmptySentinel;
        return WritePod(out, zeroHash) && WritePod(out, sentinel);
    }

    const auto byteSize = a_offsets.size() * sizeof(std::uint32_t);
    const auto offsetHash = HashBytes(a_offsets.data(), byteSize);
    const auto offsetCount = static_cast<std::uint32_t>(a_offsets.size());

    if (!WritePod(out, offsetHash) || !WritePod(out, offsetCount)) {
        return false;
    }

    out.write(reinterpret_cast<const char*>(a_offsets.data()),
              static_cast<std::streamsize>(byteSize));
    return out.good();
}

}  // namespace cog
