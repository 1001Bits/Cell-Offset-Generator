#include "PCH.h"
#include "cog/Settings.h"

#include <Windows.h>

namespace cog {

namespace {

bool ReadBool(const wchar_t* a_section, const wchar_t* a_key, bool a_default,
              const std::wstring& a_path)
{
    return GetPrivateProfileIntW(a_section, a_key, a_default ? 1 : 0, a_path.c_str()) != 0;
}

int ReadInt(const wchar_t* a_section, const wchar_t* a_key, int a_default,
            const std::wstring& a_path)
{
    return GetPrivateProfileIntW(a_section, a_key, a_default, a_path.c_str());
}

}  // namespace

Settings Settings::Load(const std::filesystem::path& a_iniPath)
{
    Settings s{};
    if (!std::filesystem::exists(a_iniPath)) {
        return s;
    }
    const auto path = a_iniPath.wstring();
    s.enablePatches            = ReadBool(L"Patches",   L"EnablePatches",      s.enablePatches,            path);
    s.enableLoadGates          = ReadBool(L"Patches",   L"EnableLoadGates",    s.enableLoadGates,          path);
    s.enableLookupGates        = ReadBool(L"Patches",   L"EnableLookupGates",  s.enableLookupGates,        path);
    s.runBenchmark             = ReadBool(L"Benchmark",  L"Run",               s.runBenchmark,             path);
    s.benchmarkSamplesPerWorld = ReadInt (L"Benchmark",  L"SamplesPerWorld",   s.benchmarkSamplesPerWorld, path);
    s.runValidator             = ReadBool(L"Validation", L"Run",               s.runValidator,             path);
    return s;
}

}  // namespace cog
