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

target_include_directories(qrxcore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_options(qrxcore PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# -----------------------------
# Hardening (Cross Platform)
# -----------------------------
if(QRX_ENABLE_HARDENING)

    # Common
    target_compile_definitions(qrxcore PRIVATE _FORTIFY_SOURCE=2)

    if(UNIX AND NOT APPLE)
        # Linux
        target_compile_options(qrxcore PRIVATE -fstack-protector-strong -fPIE)
    elseif(APPLE)
        # macOS (kein -fstack-protector-strong nötig, aber safe)
        target_compile_options(qrxcore PRIVATE -fstack-protector)
    elseif(WIN32)
        # Windows MSVC Hardening
        target_compile_options(qrxcore PRIVATE /GS)
    endif()

endif()

# -----------------------------
# Sanitizer
# -----------------------------
if(QRX_ENABLE_ASAN)
    target_compile_options(qrxcore PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(qrxcore PRIVATE -fsanitize=address)
endif()

if(QRX_ENABLE_UBSAN)
    target_compile_options(qrxcore PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options(qrxcore PRIVATE -fsanitize=undefined)
endif()

target_link_libraries(qrxcore PUBLIC OpenSSL::Crypto)

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
# Linker Hardening (Platform Specific)
# -----------------------------
foreach(tgt qrx qrxd qrx-cli)

    if(QRX_ENABLE_HARDENING)

        if(UNIX AND NOT APPLE)
            # Linux
            target_link_options(${tgt} PRIVATE
                -pie
                -Wl,-z,relro
                -Wl,-z,now
            )

        elseif(APPLE)
            # macOS (KEINE -z Flags!)
            target_link_options(${tgt} PRIVATE
                -Wl,-dead_strip
            )

        elseif(WIN32)
            # Windows MSVC
            target_link_options(${tgt} PRIVATE
                /DYNAMICBASE
                /NXCOMPAT
            )
        endif()

    endif()

    if(QRX_ENABLE_ASAN)
        target_link_options(${tgt} PRIVATE -fsanitize=address)
    endif()

    if(QRX_ENABLE_UBSAN)
        target_link_options(${tgt} PRIVATE -fsanitize=undefined)
    endif()

endforeach()