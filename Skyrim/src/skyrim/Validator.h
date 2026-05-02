#pragma once

namespace cog::sky {

// One-shot correctness check: for each populated (file × world × x,y), seek to
// data->fileOffset + table[idx] in the plugin file and verify the bytes there
// are a "CELL" record header. Logs a summary of valid/invalid entries.
//
// This is a dev-time tool — gate it via [Validation] Run=1 in the INI.
void RunValidator();

}  // namespace cog::sky
