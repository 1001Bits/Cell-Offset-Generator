cmake_minimum_required(VERSION 3.23)

set(NAME "FasterCellLookup")
set(VERSION 1.3.0)

message(">>> Start build for '${NAME}' v${VERSION}")

set(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(SOURCE_DIR "${ROOT_DIR}/src")
set(BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}")

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
  message(FATAL_ERROR ">> In-source builds not allowed.")
endif()

# ── vcpkg setup (BEFORE project()) ──────────────────────────────────────────
macro(set_from_environment VARIABLE)
  if(NOT DEFINED ${VARIABLE} AND DEFINED ENV{${VARIABLE}})
    set(${VARIABLE} $ENV{${VARIABLE}})
  endif()
endmacro()

set_from_environment(VCPKG_ROOT)
if(DEFINED VCPKG_ROOT)
  set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
  set(VCPKG_TARGET_TRIPLET "x64-windows-static-md" CACHE STRING "")
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL" CACHE STRING "")
else()
  message(FATAL_ERROR ">> Variable VCPKG_ROOT is not set!")
endif()

project(${NAME} VERSION ${VERSION} LANGUAGES CXX)
message(">>> Building project '${PROJECT_NAME}' v${PROJECT_VERSION}")

# ── Compiler settings ────────────────────────────────────────────────────────
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_DEBUG OFF)

# ── CommonLibSSE-NG (alandtse/CommonLibVR ng branch, source build) ──────────
# Pulled in as a git checkout under extern/CommonLibVR. This is the actively
# maintained NG fork that tracks po3 upstream patches — distinct from the
# colorglass vcpkg port (CharmedBaryon/CommonLibSSE-NG, last updated 2023).
set(BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SKSE_SUPPORT_XBYAK ON CACHE BOOL "" FORCE)
add_subdirectory(extern/CommonLibVR)

# ── Additional dependencies ─────────────────────────────────────────────────
find_package(spdlog REQUIRED CONFIG)
find_package(xxHash CONFIG REQUIRED)

# ── Sources ──────────────────────────────────────────────────────────────────
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    "${SOURCE_DIR}/*.cpp"
    "${SOURCE_DIR}/*.h"
)

# Multi-runtime build: SE 1.5.97, AE 1.6.1170, VR 1.4.15. Patch sites and
# engine-function addresses are picked at runtime in src/skyrim/. Runtimes
# without filled-in address tables silently skip patching with a log entry.
add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_23)
target_precompile_headers(${PROJECT_NAME} PRIVATE "${SOURCE_DIR}/PCH.h")

target_include_directories(${PROJECT_NAME} PRIVATE
    "${SOURCE_DIR}"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    CommonLibSSE::CommonLibSSE
    spdlog::spdlog
    xxHash::xxhash
)

target_compile_definitions(${PROJECT_NAME} PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
)

# ── MSVC-specific options ────────────────────────────────────────────────────
if(CMAKE_GENERATOR MATCHES "Visual Studio")
    target_compile_options(${PROJECT_NAME} PRIVATE
        /MP4
        /W3
        /permissive-
        /Zc:preprocessor
        /Zc:__cplusplus
        /Zi
    )
    target_link_options(${PROJECT_NAME} PRIVATE
        /DEBUG
        /OPT:REF
        /OPT:ICF
    )
endif()

# ── SKSE plugin metadata generator ───────────────────────────────────────────
# The colorglass port shipped an `add_commonlibsse_plugin` macro that wrote
# out the PluginDeclaration boilerplate. With the source build we synthesize
# the same file ourselves so SKSE recognises the DLL as a plugin.
configure_file(
    "${ROOT_DIR}/cmake/plugin.cpp.in"
    "${BUILD_DIR}/plugin.cpp"
    @ONLY
)
target_sources(${PROJECT_NAME} PRIVATE "${BUILD_DIR}/plugin.cpp")

message(">>> ${PROJECT_NAME} configured successfully")
