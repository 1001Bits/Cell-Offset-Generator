#pragma once

#include <cstdint>

// A tiny Win32 progress window that renders on its OWN thread, so it stays
// alive and animating while the game's main thread is locked inside the
// generator (we run synchronously in the SKSE kDataLoaded handler). Ported
// from the Starfield port's ProgressWindow, which in turn mirrors NVSE's
// progress-meter intent — but as an OS-level window, because Skyrim's
// Scaleform loading menu can't repaint while the main thread blocks.
//
// Lifecycle from the (blocked) main thread:
//   Start("title"); SetTotal(N);
//   ... per unit of work: Tick();  (and NotifyGenerating() on the first real
//       cache-miss generation, so a pure-cache load never flashes a window) ...
//   Stop();
//
// All calls are thread-safe and no-ops if the window couldn't be created.
namespace cog {

class ProgressWindow
{
public:
    static void Start(const char* a_title);
    static void SetTotal(std::uint32_t a_total);
    static void NotifyGenerating();  // first real (cache-miss) generation → reveal
    static void Tick();              // +1 processed unit
    static void SetStatus(const char* a_text);
    static void Stop();
};

}  // namespace cog
