cmake_minimum_required(VERSION 3.16)

# Root wrapper. The actual QRX Core project lives in qrx-core/.
# This allows both:
#   cmake -S . -B build
# and:
#   cd qrx-core && cmake -S . -B build
project(qrx_root C)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/qrx-core/CMakeLists.txt")
    add_subdirectory(qrx-core)
else()
    message(FATAL_ERROR "qrx-core/CMakeLists.txt not found. Please keep the qrx-core directory in the repository root.")
endif()
