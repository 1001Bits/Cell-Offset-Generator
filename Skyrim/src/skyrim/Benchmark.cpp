#include "PCH.h"
#include "skyrim/Benchmark.h"

#include "cog/Settings.h"
#include "skyrim/EngineCalls.h"
#include "skyrim/EngineTypes.h"

#include <algorithm>
#include <chrono>
#include <random>

namespace cog::sky {

namespace {

enum class Bucket : std::uint8_t
{
    MasterFast = 0,    // ESM/master, table populated → engine fast path
    NonMasterFast,     // ESP/ESL, table populated → our optimization
    NonMasterNoTable,  // ESP/ESL, table null → bails at gate or hits slow scan
    Count
};

constexpr const char* kBucketNames[] = {
    "Master/fast",
    "ESP/fast",
    "ESP/no-table",
};

struct BucketStats
{
    std::uint64_t calls   = 0;
    std::uint64_t totalNs = 0;
    std::uint64_t maxNs   = 0;
    std::uint64_t hits    = 0;  // FindCellInFile returned true
};

[[nodiscard]] Bucket Classify(const RE::TESFile* a_file, const OFFSET_DATA* a_data)
{
    const bool isMaster = a_file->recordFlags.all(RE::TESFile::RecordFlag::kMaster);
    if (a_data->pCellFileOffsets) {
        return isMaster ? Bucket::MasterFast : Bucket::NonMasterFast;
    }
    return Bucket::NonMasterNoTable;
}

[[nodiscard]] std::int32_t WorldUnitsToCellFloor(float a_v)
{
    const auto t = static_cast<std::int32_t>(a_v);
    if (a_v - static_cast<float>(t) < 0.0f) {
        return (t - 1) >> 12;
    }
    return t >> 12;
}

}  // namespace

void RunFindCellBenchmark(const cog::Settings& a_settings)
{
    if (!a_settings.runBenchmark) {
        return;
    }

    auto* dh = RE::TESDataHandler::GetSingleton();
    if (!dh) {
        return;
    }

    const auto samplesPerWorld = (std::max)(1, a_settings.benchmarkSamplesPerWorld);
    BucketStats stats[static_cast<std::size_t>(Bucket::Count)] = {};
    std::mt19937 rng{ 0xC0FFEE };  // deterministic across runs

    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();

    auto sampleFile = [&](RE::TESFile* file) {
        if (!file) {
            return;
        }
        for (auto* world : dh->GetFormArray<RE::TESWorldSpace>()) {
            if (!world) {
                continue;
            }
            auto* data = FindOffsetData(world, file);
            if (!data) {
                continue;
            }
            const auto minX = WorldUnitsToCellFloor(data->offsetMinCoords.x);
            const auto minY = WorldUnitsToCellFloor(data->offsetMinCoords.y);
            const auto maxX = WorldUnitsToCellFloor(data->offsetMaxCoords.x);
            const auto maxY = WorldUnitsToCellFloor(data->offsetMaxCoords.y);
            if (minX == -524288 || maxX < minX || maxY < minY) {
                continue;
            }
            const auto bucket = Classify(file, data);
            auto& s = stats[static_cast<std::size_t>(bucket)];

            std::uniform_int_distribution<std::int32_t> dx(minX, maxX);
            std::uniform_int_distribution<std::int32_t> dy(minY, maxY);
            for (int i = 0; i < samplesPerWorld; ++i) {
                const auto x = dx(rng);
                const auto y = dy(rng);
                const auto a = clock::now();
                const bool hit = FindCellInFile(world, file, x, y);
                const auto b = clock::now();
                const auto ns = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count());
                ++s.calls;
                s.totalNs += ns;
                s.maxNs = (std::max)(s.maxNs, ns);
                if (hit) ++s.hits;
            }
        }
    };

    if (auto** mods = dh->GetLoadedMods()) {
        const auto n = dh->GetLoadedModCount();
        for (std::uint32_t i = 0; i < n; ++i) {
            sampleFile(mods[i]);
        }
    }
    if (auto** mods = dh->GetLoadedLightMods()) {
        const auto n = dh->GetLoadedLightModCount();
        for (std::uint32_t i = 0; i < n; ++i) {
            sampleFile(mods[i]);
        }
    }

    const auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                             clock::now() - t0).count();

    logger::info("Benchmark: completed in {} ms ({} samples/world)",
                 totalMs, samplesPerWorld);
    for (std::size_t i = 0; i < static_cast<std::size_t>(Bucket::Count); ++i) {
        const auto& s = stats[i];
        if (s.calls == 0) {
            logger::info("  [{}] (no samples)", kBucketNames[i]);
            continue;
        }
        const auto avgNs = s.totalNs / s.calls;
        logger::info("  [{}] calls={}, avg={} ns, max={} ns, hits={} ({}%), total={} us",
                     kBucketNames[i],
                     s.calls, avgNs, s.maxNs, s.hits,
                     (s.hits * 100) / s.calls,
                     s.totalNs / 1000);
    }
}

}  // namespace cog::sky
