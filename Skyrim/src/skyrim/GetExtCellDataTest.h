#pragma once

namespace cog::sky {

// Verify whether ESP-defined exterior cells can be looked up by editor ID
// via TESDataHandler::GetExtCellDataFromFileByEditorID. NVSE's port of this
// fix was needed in F4/NV because that function had an IsESM gate that
// rejected ESPs. We don't know if Skyrim has the same gate — this test
// calls the function directly for cells from both masters and ESPs and
// reports the hit rates.
//
// If ESP hit rate is materially below master hit rate, we need a Skyrim
// equivalent of NVSE's PatchMemoryNop. If parity, the patch isn't needed.
void RunGetExtCellDataTest();

}  // namespace cog::sky
