#include "PCH.h"
#include "cog/HashUtil.h"

#define XXH_INLINE_ALL
#define XXH_ENABLE_AUTOVECTORIZE
#include <xxhash.h>

namespace cog {

std::uint64_t HashBytes(const void* a_data, std::size_t a_size)
{
    return XXH3_64bits(a_data, a_size);
}

std::uint64_t HashFile(const std::filesystem::path& a_path)
{
    std::ifstream file(a_path, std::ios::binary);
    if (!file) {
        return 0;
    }

    auto* state = XXH3_createState();
    if (!state) {
        return 0;
    }
    XXH3_64bits_reset(state);

    constexpr std::size_t kBufferSize = 64 * 1024;
    std::vector<char> buffer(kBufferSize);
    while (file.read(buffer.data(), kBufferSize) || file.gcount() > 0) {
        XXH3_64bits_update(state, buffer.data(), static_cast<std::size_t>(file.gcount()));
    }

    const auto digest = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return digest;
}

}  // namespace cog
