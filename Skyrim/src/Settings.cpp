#include "PCH.h"
#include "Settings.h"

#include <Windows.h>

namespace cog {

namespace {

bool ReadBool(const wchar_t* a_section, const wchar_t* a_key, bool a_default,
              const std::wstring& a_path)
{
    return GetPrivateProfileIntW(a_section, a_key, a_default ? 1 : 0, a_path.c_str()) != 0;
}

}  // namespace

Settings Settings::Load(const std::filesystem::path& a_iniPath)
{
    Settings s{};
    if (!std::filesystem::exists(a_iniPath)) {
        return s;
    }
    const auto path = a_iniPath.wstring();
    s.enablePatches         = ReadBool(L"Patches", L"EnablePatches",         s.enablePatches,         path);
    s.findCellInFileLogging = ReadBool(L"Logging", L"FindCellInFileLogging", s.findCellInFileLogging, path);
    return s;
}

}  // namespace cog
