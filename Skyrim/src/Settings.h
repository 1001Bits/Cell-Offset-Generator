#pragma once

#include <filesystem>

namespace cog {

// Minimal user-facing config. Two flags:
//   enablePatches          — master on/off for the optimization itself.
//   findCellInFileLogging  — verbose per-cell log dump (off by default).
//
// Internal gate-group switches (load-side / lookup-side) are always on when
// enablePatches=1; they're not exposed in the INI to keep the user surface
// simple. They live as fields here for completeness in case finer-grained
// debugging is needed at the code level.
struct Settings
{
    bool enablePatches{ true };
    bool findCellInFileLogging{ false };

    // Internal — always true when enablePatches=true. Kept as fields so the
    // patch-install code can reference them; not exposed in the INI.
    bool enableLoadGates{ true };
    bool enableLookupGates{ true };

    static Settings Load(const std::filesystem::path& a_iniPath);
};

}  // namespace cog
