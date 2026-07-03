#include "PCH.h"
#include "ProgressWindow.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>

#include <windows.h>
#include <commctrl.h>

// PROGRESS_CLASS lives in the common-controls DLL; pull the import lib in
// here rather than touching CMake so the dependency stays local to this file.
#pragma comment(lib, "comctl32.lib")

namespace cog {
namespace {

std::thread                g_thread;
std::atomic<bool>          g_enabled{ true };      // [Progress] ShowProgressWindow
std::atomic<bool>          g_running{ false };     // window thread alive
std::atomic<bool>          g_generating{ false };  // a real cache-miss happened → reveal
std::atomic<std::uint32_t> g_done{ 0 };
std::atomic<std::uint32_t> g_total{ 1 };
std::mutex                 g_statusMutex;
std::string                g_status;
std::string                g_title;

constexpr char kClassName[] = "FCL_ProgressWnd";

LRESULT CALLBACK WndProc(HWND a_h, UINT a_msg, WPARAM a_w, LPARAM a_l)
{
    if (a_msg == WM_CLOSE) {
        return 0;  // ignore user close — we own the lifecycle
    }
    return DefWindowProcA(a_h, a_msg, a_w, a_l);
}

void ThreadMain()
{
    // Don't show anything until a real generation starts. A pure-cache load
    // sets g_running=false (Stop) before g_generating ever flips, so we exit
    // without ever creating a window — no flash on fast launches.
    while (g_running.load(std::memory_order_relaxed) &&
           !g_generating.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
    if (!g_running.load(std::memory_order_relaxed)) {
        return;
    }

    // Generation saturates every logical core with worker threads, so this UI
    // thread would otherwise be starved — the window then flickers in/out
    // every few seconds (covered by the game while starved, popping back when
    // the re-assert finally runs). HIGHEST priority lets it preempt a worker
    // for the ~1ms it needs every 40ms to re-assert topmost and repaint; the
    // thread sleeps the rest of the time so the workers lose almost nothing.
    // The generator also reserves one core for us (see SkyrimGenerator::Run).
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    const HINSTANCE inst = GetModuleHandleA(nullptr);
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WNDCLASSA wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.lpszClassName = kClassName;
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.hCursor       = LoadCursorW(nullptr, IDC_WAIT);
    RegisterClassA(&wc);

    constexpr int kW = 440, kH = 120;
    const int sx = GetSystemMetrics(SM_CXSCREEN);
    const int sy = GetSystemMetrics(SM_CYSCREEN);
    // WS_EX_NOACTIVATE: never take the foreground/focus. Skyrim minimizes the
    // moment another window steals foreground (fullscreen and borderless
    // both), so the window must be show-on-top-but-never-activate. Paired with
    // SW_SHOWNOACTIVATE below and NO SetForegroundWindow call.
    HWND hwnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, kClassName, g_title.c_str(),
        WS_POPUP | WS_CAPTION,
        (sx - kW) / 2, (sy - kH) / 2, kW, kH, nullptr, nullptr, inst, nullptr);
    if (!hwnd) {
        UnregisterClassA(kClassName, inst);
        return;
    }

    HWND text = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                14, 12, kW - 30, 34, hwnd, nullptr, inst, nullptr);
    HWND bar  = CreateWindowExA(0, PROGRESS_CLASSA, "",
                                WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                14, 50, kW - 48, 20, hwnd, nullptr, inst, nullptr);

    SendMessageA(bar, PBM_SETRANGE32, 0,
                 static_cast<LPARAM>((std::max)(1u, g_total.load())));
    // SW_SHOWNOACTIVATE: display without stealing focus, so the game stays
    // foregrounded and doesn't minimize. (No SetForegroundWindow — that's
    // exactly what minimized Skyrim.)
    ShowWindow(hwnd, SW_SHOWNOACTIVATE);

    MSG msg;
    std::uint32_t lastDone = UINT32_MAX;
    while (g_running.load(std::memory_order_relaxed)) {
        // Re-assert top-of-z-order without taking focus, so the game's
        // borderless window doesn't bury us once it starts presenting.
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        const auto done  = g_done.load(std::memory_order_relaxed);
        const auto total = (std::max)(1u, g_total.load(std::memory_order_relaxed));
        if (done != lastDone) {
            SendMessageA(bar, PBM_SETRANGE32, 0, static_cast<LPARAM>(total));
            SendMessageA(bar, PBM_SETPOS, static_cast<WPARAM>((std::min)(done, total)), 0);
            std::string status;
            {
                std::lock_guard lk(g_statusMutex);
                status = g_status;
            }
            char buf[256];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s   (%u / %u)",
                        status.c_str(), done, total);
            SetWindowTextA(text, buf);
            lastDone = done;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }

    // Generation finished. Snap the bar to 100% and hold briefly — generation
    // can complete between render ticks (or faster than the bar filled under
    // CPU load), so without this the window vanishes mid-fill and the user
    // never sees it complete.
    {
        const auto total = (std::max)(1u, g_total.load(std::memory_order_relaxed));
        SendMessageA(bar, PBM_SETRANGE32, 0, static_cast<LPARAM>(total));
        SendMessageA(bar, PBM_SETPOS, static_cast<WPARAM>(total), 0);
        SetWindowTextA(text, "Cell offset cache complete");
        const auto holdUntil =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(600);
        while (std::chrono::steady_clock::now() < holdUntil) {
            while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageA(&msg);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    DestroyWindow(hwnd);
    while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    UnregisterClassA(kClassName, inst);
}

}  // namespace

void ProgressWindow::SetEnabled(bool a_enabled)
{
    g_enabled.store(a_enabled, std::memory_order_relaxed);
}

void ProgressWindow::Start(const char* a_title)
{
    if (!g_enabled.load(std::memory_order_relaxed)) {
        return;  // user disabled the window; all other calls are no-ops
    }
    if (g_running.exchange(true)) {
        return;  // already running
    }
    g_generating.store(false);
    g_done.store(0);
    g_total.store(1);
    {
        std::lock_guard lk(g_statusMutex);
        g_status = "Generating cell offset cache... (first run)";
    }
    g_title  = a_title ? a_title : "FasterCellLookup";
    g_thread = std::thread(ThreadMain);
}

void ProgressWindow::SetTotal(std::uint32_t a_total) { g_total.store((std::max)(1u, a_total)); }
void ProgressWindow::NotifyGenerating()              { g_generating.store(true); }
void ProgressWindow::Tick()                          { g_done.fetch_add(1, std::memory_order_relaxed); }

void ProgressWindow::SetStatus(const char* a_text)
{
    if (!a_text) {
        return;
    }
    std::lock_guard lk(g_statusMutex);
    g_status = a_text;
}

void ProgressWindow::Stop()
{
    if (!g_running.exchange(false)) {
        return;
    }
    if (g_thread.joinable()) {
        g_thread.join();
    }
}

}  // namespace cog
