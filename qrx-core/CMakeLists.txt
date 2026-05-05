cmake_minimum_required(VERSION 3.16)
project(qrx C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
)

target_include_directories(qrxcore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(qrxcore PUBLIC
    OpenSSL::Crypto
)

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

# -----------------------------
# Linker options
# -----------------------------
foreach(tgt qrx qrxd qrx-cli)

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