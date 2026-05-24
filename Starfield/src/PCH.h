#pragma once

#include "RE/Starfield.h"
#include "SFSE/SFSE.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/msvc_sink.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

// libxse's SFSE::log namespace only exposes log_directory() — the leveled
// helpers (info/warn/error/critical) live on spdlog directly now.
// SFSE::Init({.log=true,...}) wires up the default spdlog logger for us.
namespace logger = spdlog;

using namespace std::literals;

#define DLLEXPORT __declspec(dllexport)
