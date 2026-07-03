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
    // GetPrivateProfileIntW resolves non-fully-qualified paths against the
    // WINDOWS directory, not the cwd — always hand it an absolute path.
    std::error_code ec;
    auto abs = std::filesystem::absolute(a_iniPath, ec);
    const auto path = (ec ? a_iniPath : abs).wstring();
    s.enablePatches         = ReadBool(L"Patches",  L"EnablePatches",         s.enablePatches,         path);
    s.findCellInFileLogging = ReadBool(L"Logging",  L"FindCellInFileLogging", s.findCellInFileLogging, path);
    s.showProgressWindow    = ReadBool(L"Progress", L"ShowProgressWindow",    s.showProgressWindow,    path);
    return s;
}

}  // namespace cog
