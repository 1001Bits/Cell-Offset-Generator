#pragma once

namespace cog {
struct Settings;
}

namespace cog::sky {

// Install the interior-cell offset hooks for the running runtime. Returns
// true if all chosen hooks were installed, false if any failed verification
// or the runtime isn't supported.
//
// Per-runtime decision tree (see InteriorHooks.cpp for full reasoning):
//
// - AE 1.6.1170: GetInteriorOffset and SetInteriorOffset are INLINED as
//   `MOV EAX,[RAX+0x5C]` and `MOV [RAX+0x5C],reg`. NVSE's 4-CALL-replace
//   pattern can't apply directly. Strategy: replace the CALL to
//   TESFile::SetOffset inside FindInFileFast (5-byte instruction at
//   0x1402bf4c5) with our wrapper that does map-lookup-then-passthrough.
//   Capture during cell load via a TESObjectCELL::Load function-entry
//   trampoline (saves arg2=pFile into our thread-local).
//
// - SE 1.5.97 / VR 1.4.15: The IsESM-gated path inside FindInFileFast still
//   has a CALL to TESFile::SetOffset (verified at +0x1402b1f15 / +0x1402c3685
//   to be confirmed). Same strategy as AE.
//
// All variations preserve the original NVSE semantics: ESP cells with
// recorded (formID → real-offset) entries get redirected; ESM cells and
// uncaptured ESPs pass through unchanged.
[[nodiscard]] bool InstallInteriorHooks(const cog::Settings& a_settings);

// Walk every currently-loaded interior cell and record its (formID, +0x5C)
// pair into the InteriorOffsets map. Catches the "ESP authored normally,
// not xEdit-stripped" case without needing load-time parse capture.
//
// Run during kDataLoaded after generation. Reports counts to log.
void ScrapeInteriorCellsFromLoadedForms();

}  // namespace cog::sky
