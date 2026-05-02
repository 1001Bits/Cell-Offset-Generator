#pragma once

namespace cog::sky {

// Round-trip every (file, formID, offset) tuple captured by the interior
// hooks: open the source plugin, seek to the recorded offset, verify the
// bytes there are a "CELL" record header. Counterpart to RunValidator()
// (which checks exterior OFST tables).
//
// Reports zero entries when the interior hooks are disabled or haven't run
// yet — that's expected, not an error.
void RunInteriorValidator();

}  // namespace cog::sky
