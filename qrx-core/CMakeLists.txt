cmake_minimum_required(VERSION 3.16)
project(qrx C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


# -----------------------------
# macOS architecture
# -----------------------------
# On Apple Silicon, CMake may still produce x86_64 binaries if the shell,
# compiler, Homebrew/OpenSSL, or an old CMake cache is running under Rosetta.
# Default to the native host architecture unless the user explicitly set
# CMAKE_OSX_ARCHITECTURES.
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Build architecture for macOS" FORCE)
    elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
        set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "Build architecture for macOS" FORCE)
    endif()
endif()


option(QRX_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(QRX_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(QRX_ENABLE_HARDENING "Enable basic hardening flags" ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# -----------------------------
# Core Library
# -----------------------------
add_library(qrxcore STATIC
    src/qrx.c
    src/core_frontend.c
    src/chain_params.c
    src/qrxdb.c
)

target_include_directories(qrxcore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(qrxcore PUBLIC
    OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(qrxcore PUBLIC ws2_32)
    target_compile_definitions(qrxcore PUBLIC
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()

# -----------------------------
# Compiler warnings
# -----------------------------
if(MSVC)
    target_compile_options(qrxcore PRIVATE /W4)
else()
    target_compile_options(qrxcore PRIVATE -Wall -Wextra -Wpedantic)
endif()

# -----------------------------
# Hardening compile flags
# -----------------------------
if(QRX_ENABLE_HARDENING)

    if(MSVC)
        target_compile_options(qrxcore PRIVATE /GS)

    elseif(APPLE)
        target_compile_definitions(qrxcore PRIVATE _FORTIFY_SOURCE=2)
        target_compile_options(qrxcore PRIVATE -fstack-protector)

    elseif(UNIX)
        target_compile_definitions(qrxcore PRIVATE _FORTIFY_SOURCE=2)
        target_compile_options(qrxcore PRIVATE -fstack-protector-strong -fPIE)
    endif()

endif()

# -----------------------------
# Sanitizers
# MSVC support is intentionally not enabled here.
# Use Clang/GCC for sanitizer builds.
# -----------------------------
if(NOT MSVC)
    if(QRX_ENABLE_ASAN)
        target_compile_options(qrxcore PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(qrxcore PRIVATE -fsanitize=address)
    endif()

    if(QRX_ENABLE_UBSAN)
        target_compile_options(qrxcore PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(qrxcore PRIVATE -fsanitize=undefined)
    endif()
endif()

# -----------------------------
# Executables
# -----------------------------
add_executable(qrx src/qrx_main.c)
target_link_libraries(qrx PRIVATE qrxcore)

add_executable(qrxd src/qrxd.c)
target_link_libraries(qrxd PRIVATE qrxcore Threads::Threads)

add_executable(qrx-cli src/qrx_cli.c)
target_link_libraries(qrx-cli PRIVATE qrxcore)

add_executable(qrxdb_verify src/qrxdb_verify_tool.c)
target_link_libraries(qrxdb_verify PRIVATE qrxcore)

add_executable(qrxdb_salvage src/qrxdb_salvage_tool.c)
target_link_libraries(qrxdb_salvage PRIVATE qrxcore)

add_executable(qrxdb_compact src/qrxdb_compact_tool.c)
target_link_libraries(qrxdb_compact PRIVATE qrxcore)

add_executable(qrxdb_snapshot src/qrxdb_snapshot_tool.c)
target_link_libraries(qrxdb_snapshot PRIVATE qrxcore)

if(WIN32)
    target_link_libraries(qrx PRIVATE ws2_32)
    target_link_libraries(qrxd PRIVATE ws2_32)
    target_link_libraries(qrx-cli PRIVATE ws2_32)
    target_link_libraries(qrxdb_verify PRIVATE ws2_32)
    target_link_libraries(qrxdb_salvage PRIVATE ws2_32)
    target_link_libraries(qrxdb_compact PRIVATE ws2_32)
    target_link_libraries(qrxdb_snapshot PRIVATE ws2_32)
endif()

# -----------------------------
# Linker options
# -----------------------------
foreach(tgt qrx qrxd qrx-cli qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot)

    if(QRX_ENABLE_HARDENING)

        if(MSVC)
            target_link_options(${tgt} PRIVATE
                /DYNAMICBASE
                /NXCOMPAT
            )

        elseif(APPLE)
            target_link_options(${tgt} PRIVATE
                -Wl,-dead_strip
            )

        elseif(UNIX)
            target_link_options(${tgt} PRIVATE
                -pie
                -Wl,-z,relro
                -Wl,-z,now
            )
        endif()

    endif()

    if(NOT MSVC)
        if(QRX_ENABLE_ASAN)
            target_link_options(${tgt} PRIVATE -fsanitize=address)
        endif()

        if(QRX_ENABLE_UBSAN)
            target_link_options(${tgt} PRIVATE -fsanitize=undefined)
        endif()
    endif()

endforeach()