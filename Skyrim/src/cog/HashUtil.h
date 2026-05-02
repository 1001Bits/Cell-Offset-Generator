#pragma once

#include <cstdint>
#include <filesystem>

namespace cog {

// xxh3 64-bit hash of an entire file. Returns 0 on failure (which we treat as
// a "won't match anything cached" sentinel — the caller will regenerate).
[[nodiscard]] std::uint64_t HashFile(const std::filesystem::path& a_path);

// xxh3 64-bit hash of a buffer.
[[nodiscard]] std::uint64_t HashBytes(const void* a_data, std::size_t a_size);

}  // namespace cog
