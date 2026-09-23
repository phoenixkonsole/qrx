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
option(QRX_REQUIRE_PQC "Require OpenSSL with ML-DSA / post-quantum support" ON)
option(QRX_BUILD_TESTS "Build QRX internal test executables" OFF)
option(QRX_BUILD_LLAMA_RUNTIME_PLUGIN "Build the production QRX AURA llama.cpp runtime plugin" OFF)
option(QRX_REQUIRE_BUNDLED_DEPS "Reject release builds that resolve native third-party libraries outside QRX_DEPS_PREFIX" OFF)
set(QRX_DEPS_PREFIX "" CACHE PATH "Hermetic QRX native dependency prefix")
set(QRX_LLAMA_CPP_ROOT "" CACHE PATH "Path to a pinned llama.cpp checkout when building the AURA runtime plugin")
set(QRX_AURA_LLAMA_PLUGIN_KIND "CPU" CACHE STRING "AURA llama.cpp plugin kind: CPU, CUDA or METAL")
if(QRX_BUILD_LLAMA_RUNTIME_PLUGIN)
    enable_language(CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# Prefer caller-supplied OpenSSL root/library paths.
# Recommended static build:
#   -DOPENSSL_USE_STATIC_LIBS=TRUE
#   -DOPENSSL_ROOT_DIR=/opt/qrx-openssl-static
#   -DOPENSSL_INCLUDE_DIR=/opt/qrx-openssl-static/include
#   -DOPENSSL_CRYPTO_LIBRARY=/opt/qrx-openssl-static/lib64/libcrypto.a
if(DEFINED OPENSSL_ROOT_DIR AND OPENSSL_ROOT_DIR)
    list(PREPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
endif()

if(QRX_REQUIRE_BUNDLED_DEPS)
    if(NOT QRX_DEPS_PREFIX OR NOT IS_DIRECTORY "${QRX_DEPS_PREFIX}")
        message(FATAL_ERROR "QRX_REQUIRE_BUNDLED_DEPS requires -DQRX_DEPS_PREFIX=<verified prefix>")
    endif()
    list(PREPEND CMAKE_PREFIX_PATH "${QRX_DEPS_PREFIX}")
    set(OPENSSL_ROOT_DIR "${QRX_DEPS_PREFIX}" CACHE PATH "" FORCE)
    set(CURL_ROOT "${QRX_DEPS_PREFIX}" CACHE PATH "" FORCE)
    set(ZLIB_ROOT "${QRX_DEPS_PREFIX}" CACHE PATH "" FORCE)
    set(CURL_USE_STATIC_LIBS TRUE CACHE BOOL "" FORCE)
endif()
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB QUIET)
if(QRX_REQUIRE_BUNDLED_DEPS)
    # Prefer curl's installed CMake package from the hermetic prefix so the
    # static target carries its own transitive requirements.
    find_package(CURL CONFIG QUIET PATHS
        "${QRX_DEPS_PREFIX}/lib/cmake/CURL"
        "${QRX_DEPS_PREFIX}/lib64/cmake/CURL"
        NO_DEFAULT_PATH)
    if(NOT CURL_FOUND)
        find_package(CURL QUIET)
    endif()
else()
    find_package(CURL QUIET)
endif()

# Different CMake/OpenSSL versions expose the version string under
# different variable names. Normalize it first.
if(DEFINED OPENSSL_VERSION)
    set(QRX_OPENSSL_VERSION "${OPENSSL_VERSION}")
elseif(DEFINED OPENSSL_VERSION_STRING)
    set(QRX_OPENSSL_VERSION "${OPENSSL_VERSION_STRING}")
elseif(DEFINED OpenSSL_VERSION)
    set(QRX_OPENSSL_VERSION "${OpenSSL_VERSION}")
else()
    set(QRX_OPENSSL_VERSION "0.0.0")
endif()

message(STATUS "Detected OpenSSL version: ${QRX_OPENSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto lib : ${OPENSSL_CRYPTO_LIBRARY}")

if(QRX_REQUIRE_PQC AND QRX_OPENSSL_VERSION VERSION_LESS "3.5.0")
    message(FATAL_ERROR
        "QRX hybrid consensus requires OpenSSL >= 3.5.0 with ML-DSA support. "
        "Detected: ${QRX_OPENSSL_VERSION}. "
        "Please build OpenSSL 3.6.x and configure with "
        "-DOPENSSL_ROOT_DIR=/opt/qrx-openssl-static, "
        "or use -DQRX_REQUIRE_PQC=OFF for developer-only builds."
    )
endif()

# -----------------------------
# Core Library
# -----------------------------
set(QRX_CORE_SOURCES
    src/qrx.c
    src/core_frontend.c
    src/chain_params.c
    src/qrxdb.c
    src/mempool/qrx_velocity_mempool.c
    src/mempool/qrx_velocity_scheduler.c
    src/mempool/qrx_velocity_mvcc.c
    src/bitcoin/qrx_btc_spv.c
    src/consensus/qrx_finality.c
    src/consensus/qrx_finality_state.c
    src/consensus/qrx_slashing.c
    src/economics/qrx_economics.c
    src/treasury/qrx_dev_addresses.c
    src/resource/qrx_resource.c
    src/resource/qrx_activation_readiness.c
    src/compute/qrx_compute.c
    src/compute/qrx_os_compute.c
    src/compute/qrx_compute_adversarial.c
    src/compute/qrx_pouc_mainnet.c
    src/compute/qrx_pouc_journal.c
    src/compute/qrx_pouc_consensus.c
    src/compute/qrx_pouc_pipeline.c
    src/compute/qrx_pouc_verifier.c
    src/compute/qrx_pouc_liveness.c
    src/compute/qrx_pouc_reorg.c
    src/compute/qrx_pouc_undo.c
    src/compute/qrx_aura_model_fabric.c
    src/compute/qrx_aura_fabric_gossip.c
    src/compute/qrx_compute_provider_identity.c
    src/compute/qrx_aura_live_dispatch.c
    src/compute/qrx_aura_remote_dispatch.c
    src/compute/qrx_aura_provider_service.c
    src/compute/qrx_aura_runtime_plugin.c
    src/compute/qrx_aura_moe_aggregate.c
    src/compute/qrx_aura_provider_bootstrap.c
    src/compute/qrx_aura_runtime_adapters.c
    src/compute/qrx_aura_runtime_packages.c
    src/compute/qrx_aura_runtime_delivery.c
    src/compute/qrx_aura_job_journal.c
    src/compute/qrx_aura_relay.c
    src/compute/qrx_aura_provider_host.c
    src/compute/qrx_aura_model_distribution.c
    src/compute/qrx_aura_model_origin.c
    src/compute/qrx_aura_model_governance.c
    src/compute/qrx_aura_production_routing.c
    src/compute/qrx_aura_release.c
    src/compute/qrx_aura_model_autoplacement.c
    src/compute/qrx_aura_provider_supervisor.c
    src/resource/qrx_storage_capacity.c
    src/resource/qrx_capacity_proof.c
    src/resource/qrx_storage_placement.c
    src/resource/qrx_storage_market.c
    src/resource/qrx_storage_repair.c
    src/resource/qrx_storage_atlas.c
    src/resource/qrx_resource_globe.c
    src/resource/qrx_resource_provider.c
    src/resource/qrx_resource_provider_runtime.c
    src/resource/qrx_compute_opportunity.c
    src/resource/qrx_task_globe.c
    src/resource/qrx_resource_dashboard.c
    src/resource/qrx_resource_live.c
    src/resource/qrx_drive_live.c
    src/resource/qrx_storage_consensus.c
    src/storage/qrx_storage_fs.c
    src/storage/qrx_merkle.c
    src/storage/qrx_drive_crypto.c
    src/storage/qrx_drive_manifest.c
    src/storage/qrx_drive_object.c
    src/storage/qrx_erasure.c
    src/storage/qrx_postor.c
    src/storage/qrx_storage_transport.c
    src/storage/qrx_storage_network.c
    src/storage/qrx_transfer_journal.c
    src/storage/qrx_drive_runtime.c
    src/storage/qrx_drive_private_pq.c
    src/storage/qrx_drive_prepare.c
    src/storage/qrx_drive_contract.c
    src/storage/qrx_storage_p2p.c
    src/storage/qrx_storage_activation.c
    src/storage/qrx_storage_postor_runtime.c
    src/storage/qrx_storage_repair_runtime.c
    src/storage/qrx_storage_discovery.c
    src/net/qrx_net_name.c
    src/net/qrx_net_consensus.c
    src/net/qrx_net_resolver.c
    src/net/qrx_net_registry.c
    src/net/qrx_net_site.c
    src/net/qrx_net_publisher.c
    src/net/qrx_net_browser.c
    src/net/qrx_net_sandbox.c
    src/net/qrx_net_permissions.c
    src/net/qrx_net_dapp_bridge.c
    src/net/qrx_net_ads.c
    src/net/qrx_net_youth.c
    src/genesis/qrx_bootstrap_validators.c
    src/genesis/qrx_genesis_governance.c
)

add_library(qrxcore STATIC ${QRX_CORE_SOURCES})

target_include_directories(qrxcore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

if(CURL_FOUND)
  target_link_libraries(qrxcore PUBLIC CURL::libcurl)
  target_compile_definitions(qrxcore PRIVATE QRX_HAVE_CURL=1)
  if(QRX_REQUIRE_BUNDLED_DEPS)
    target_compile_definitions(qrxcore PRIVATE CURL_STATICLIB=1)
    if(TARGET ZLIB::ZLIB)
      target_link_libraries(qrxcore PUBLIC ZLIB::ZLIB)
    endif()
    if(TARGET OpenSSL::SSL)
      target_link_libraries(qrxcore PUBLIC OpenSSL::SSL)
    endif()
  endif()
  message(STATUS "AURA external model origins: libcurl enabled")
else()
  if(QRX_REQUIRE_BUNDLED_DEPS)
    message(FATAL_ERROR "Hermetic release build requires bundled static libcurl")
  endif()
  message(WARNING "libcurl not found: AURA Hugging Face/external-origin bootstrap will be unavailable in this build")
endif()

# OpenSSL is a required part of the QRX ABI.  Always link through CMake's
# imported OpenSSL::Crypto target so include paths, architecture selection and
# transitive link requirements stay attached to every consumer of qrxcore.
# The release builder pins OPENSSL_ROOT_DIR on macOS to prevent CMake from
# accidentally selecting an Intel/Rosetta Homebrew installation for arm64.
if(NOT TARGET OpenSSL::Crypto)
    message(FATAL_ERROR "CMake OpenSSL package did not provide OpenSSL::Crypto")
endif()

add_library(qrx_crypto_deps INTERFACE)
target_link_libraries(qrx_crypto_deps INTERFACE OpenSSL::Crypto Threads::Threads)
if(UNIX AND NOT APPLE)
    target_link_libraries(qrx_crypto_deps INTERFACE ${CMAKE_DL_LIBS})
endif()

set(QRX_OPENSSL_LINK_LIBS qrx_crypto_deps)
target_link_libraries(qrxcore PUBLIC qrx_crypto_deps)

if(WIN32)
    target_link_libraries(qrxcore PUBLIC ws2_32)
    target_compile_definitions(qrxcore PUBLIC
        _CRT_SECURE_NO_WARNINGS
        strtok_r=strtok_s
        strdup=_strdup
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
        # qrxcore is a static library; sanitizer runtimes must also be linked by
        # every executable/test that consumes it. Directory-level options apply
        # to targets declared below this point and make sanitizer builds complete.
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()

    if(QRX_ENABLE_UBSAN)
        target_compile_options(qrxcore PRIVATE -fsanitize=undefined -fno-omit-frame-pointer)
        target_link_options(qrxcore PRIVATE -fsanitize=undefined)
        add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=undefined)
    endif()
endif()

# -----------------------------
# Optional production llama.cpp AURA runtime plugin
# -----------------------------
if(QRX_BUILD_LLAMA_RUNTIME_PLUGIN)
    if(NOT QRX_LLAMA_CPP_ROOT OR NOT EXISTS "${QRX_LLAMA_CPP_ROOT}/CMakeLists.txt")
        message(FATAL_ERROR "QRX_BUILD_LLAMA_RUNTIME_PLUGIN requires -DQRX_LLAMA_CPP_ROOT=/path/to/pinned/llama.cpp")
    endif()
    string(TOUPPER "${QRX_AURA_LLAMA_PLUGIN_KIND}" QRX_AURA_LLAMA_PLUGIN_KIND_UPPER)
    if(NOT QRX_AURA_LLAMA_PLUGIN_KIND_UPPER MATCHES "^(CPU|CUDA|METAL)$")
        message(FATAL_ERROR "QRX_AURA_LLAMA_PLUGIN_KIND must be CPU, CUDA or METAL")
    endif()
    set(LLAMA_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_SERVER OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(GGML_NATIVE OFF CACHE BOOL "" FORCE)
    if(QRX_AURA_LLAMA_PLUGIN_KIND_UPPER STREQUAL "CUDA")
        set(GGML_CUDA ON CACHE BOOL "" FORCE)
        set(GGML_METAL OFF CACHE BOOL "" FORCE)
        set(QRX_LLAMA_PLUGIN_DEFINE 1)
        set(QRX_LLAMA_PLUGIN_OUTPUT "qrx-aura-llama-cuda")
    elseif(QRX_AURA_LLAMA_PLUGIN_KIND_UPPER STREQUAL "METAL")
        if(NOT APPLE)
            message(FATAL_ERROR "METAL runtime plugin can only be built on macOS")
        endif()
        set(GGML_CUDA OFF CACHE BOOL "" FORCE)
        set(GGML_METAL ON CACHE BOOL "" FORCE)
        set(QRX_LLAMA_PLUGIN_DEFINE 2)
        set(QRX_LLAMA_PLUGIN_OUTPUT "qrx-aura-llama-metal")
    else()
        set(GGML_CUDA OFF CACHE BOOL "" FORCE)
        if(APPLE)
            set(GGML_METAL OFF CACHE BOOL "" FORCE)
        endif()
        set(QRX_LLAMA_PLUGIN_DEFINE 0)
        set(QRX_LLAMA_PLUGIN_OUTPUT "qrx-aura-llama-cpu")
    endif()
    add_subdirectory("${QRX_LLAMA_CPP_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/llama-cpp" EXCLUDE_FROM_ALL)
    add_library(qrx-aura-llama-runtime SHARED runtime/llama/qrx_aura_llama_plugin.cpp)
    target_include_directories(qrx-aura-llama-runtime PRIVATE "${QRX_LLAMA_CPP_ROOT}/include")
    target_compile_definitions(qrx-aura-llama-runtime PRIVATE QRX_LLAMA_PLUGIN_KIND=${QRX_LLAMA_PLUGIN_DEFINE})
    target_link_libraries(qrx-aura-llama-runtime PRIVATE qrxcore llama ${QRX_OPENSSL_LINK_LIBS})
    set_target_properties(qrx-aura-llama-runtime PROPERTIES PREFIX "" OUTPUT_NAME "${QRX_LLAMA_PLUGIN_OUTPUT}")
endif()

# -----------------------------
# Executables
# -----------------------------
set(QRX_OPENSSL_APPLINK_SRC "")
if(WIN32)
    set(QRX_OPENSSL_APPLINK_SRC src/openssl_applink.c)
endif()

add_executable(qrx src/qrx_main.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrx PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrxd src/qrxd.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrxd PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrx-cli src/qrx_cli.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrx-cli PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrx-aura-model-seed src/qrx_aura_model_seed.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrx-aura-model-seed PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

# Keep the extended command-line wallet in the build output beside qrx-cli.
# It is the shared non-shell frontend for Phase 4F.2 arbitrage, secure Kraken
# startup and the State-Root-verified complete ledger exporter.
add_custom_target(qrx-wallet-cli ALL
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/qrx-wallet-cli.py
        ${CMAKE_CURRENT_BINARY_DIR}/qrx-wallet-cli.py
    COMMAND ${CMAKE_COMMAND} -E make_directory
        ${CMAKE_CURRENT_BINARY_DIR}/qrx-wallet-resources
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/qrx-complete-ledger-export.py
        ${CMAKE_CURRENT_BINARY_DIR}/qrx-wallet-resources/qrx-complete-ledger-export.py
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/gateways/qrx-arbitrage-engine.py
        ${CMAKE_CURRENT_BINARY_DIR}/qrx-wallet-resources/qrx-arbitrage-engine.py
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/gateways/qrx-gateway-kraken.py
        ${CMAKE_CURRENT_BINARY_DIR}/qrx-wallet-resources/qrx-gateway-kraken.py
)

add_executable(qrxdb_verify src/qrxdb_verify_tool.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrxdb_verify PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrxdb_salvage src/qrxdb_salvage_tool.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrxdb_salvage PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrxdb_compact src/qrxdb_compact_tool.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrxdb_compact PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

add_executable(qrxdb_snapshot src/qrxdb_snapshot_tool.c ${QRX_OPENSSL_APPLINK_SRC})
target_link_libraries(qrxdb_snapshot PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})

if(WIN32)
    target_link_libraries(qrx PRIVATE ws2_32)
    target_link_libraries(qrxd PRIVATE ws2_32)
    target_link_libraries(qrx-cli PRIVATE ws2_32)
    target_link_libraries(qrx-aura-model-seed PRIVATE ws2_32)
    target_link_libraries(qrxdb_verify PRIVATE ws2_32)
    target_link_libraries(qrxdb_salvage PRIVATE ws2_32)
    target_link_libraries(qrxdb_compact PRIVATE ws2_32)
    target_link_libraries(qrxdb_snapshot PRIVATE ws2_32)
endif()

# -----------------------------
# Linker options
# -----------------------------
foreach(tgt qrx qrxd qrx-cli qrx-aura-model-seed qrxdb_verify qrxdb_salvage qrxdb_compact qrxdb_snapshot)

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
# QRX economics/bootstrap sources
# qrx-core/src/economics/qrx_economics.c
# qrx-core/src/treasury/qrx_dev_addresses.c
# qrx-core/src/genesis/qrx_bootstrap_validators.c

# QRX P2P seed/maxconnection/peer persistence sources:
# src/network/qrx_p2p_config.c
# src/network/qrx_peer_store.c
# src/network/qrx_peer_relay.c

# src/consensus/qrx_deterministic_rotation.c

# Finality voting layer sources
# src/consensus/qrx_finality.c
# src/consensus/qrx_finality_state.c

# Slashing/signature enforcement
# src/consensus/qrx_slashing.c

# -----------------------------
# Internal tests (off for normal release builds)
# -----------------------------
# ---------------------------------------------------------------------------
# QRX Upscaler (Apps). Permissive dependencies only: the core is MIT and PNG
# support uses libpng/zlib. No GPL/LGPL component is linked or bundled; video
# demux/mux is delegated to an external tool the operator supplies at runtime.
# ---------------------------------------------------------------------------
find_package(PNG QUIET)
if(QRX_REQUIRE_BUNDLED_DEPS)
  foreach(_qrx_dep_path IN ITEMS "${OPENSSL_INCLUDE_DIR}" "${OPENSSL_CRYPTO_LIBRARY}" "${CURL_INCLUDE_DIRS}" "${CURL_LIBRARIES}" "${PNG_PNG_INCLUDE_DIR}" "${PNG_LIBRARY}")
    if(_qrx_dep_path AND IS_ABSOLUTE "${_qrx_dep_path}" AND NOT "${_qrx_dep_path}" MATCHES "^${QRX_DEPS_PREFIX}(/|$)")
      message(FATAL_ERROR "Native dependency escaped QRX_DEPS_PREFIX: ${_qrx_dep_path}")
    endif()
  endforeach()
endif()
if(PNG_FOUND)
  set(QRX_UPSCALER_PNG ON)
  message(STATUS "QRX Upscaler: PNG support enabled (libpng/zlib)")
else()
  set(QRX_UPSCALER_PNG OFF)
  message(STATUS "QRX Upscaler: libpng not found, PPM/PGM only")
endif()

add_executable(qrx-upscaler src/apps/qrx_upscaler.c src/apps/qrx_upscaler_capabilities.c src/apps/qrx_upscaler_ai.c src/apps/qrx_upscaler_main.c)
target_include_directories(qrx-upscaler PRIVATE src)
if(CMAKE_DL_LIBS)
  target_link_libraries(qrx-upscaler PRIVATE ${CMAKE_DL_LIBS})
endif()
if(UNIX)
  target_link_libraries(qrx-upscaler PRIVATE m)
endif()
if(QRX_UPSCALER_PNG)
  target_compile_definitions(qrx-upscaler PRIVATE QRX_HAVE_PNG)
  target_link_libraries(qrx-upscaler PRIVATE PNG::PNG)
endif()


if(QRX_BUILD_TESTS)
    enable_testing()
    add_executable(qrx_velocity_engine_test tests/velocity_phase4_engine.c)
    target_include_directories(qrx_velocity_engine_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_engine_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4_engine COMMAND qrx_velocity_engine_test)

    add_executable(qrx_velocity_mvcc_test tests/velocity_phase4b_mvcc.c)
    target_include_directories(qrx_velocity_mvcc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_mvcc_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4b_mvcc COMMAND qrx_velocity_mvcc_test)

    add_executable(qrx_velocity_stateful_mvcc_test tests/velocity_phase4c_stateful.c)
    target_include_directories(qrx_velocity_stateful_mvcc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_stateful_mvcc_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4c_stateful_mvcc COMMAND qrx_velocity_stateful_mvcc_test)

    add_executable(qrx_velocity_dynamic_mvcc_test tests/velocity_phase4d_dynamic.c)
    target_include_directories(qrx_velocity_dynamic_mvcc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_dynamic_mvcc_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4d_dynamic_mvcc COMMAND qrx_velocity_dynamic_mvcc_test)

    add_executable(qrx_velocity_speculative_mvcc_test tests/velocity_phase4e_speculative.c)
    target_include_directories(qrx_velocity_speculative_mvcc_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_speculative_mvcc_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4e_speculative_mvcc COMMAND qrx_velocity_speculative_mvcc_test)

    add_executable(qrx_velocity_block_scheduler_test tests/velocity_phase4f_scheduler.c)
    target_include_directories(qrx_velocity_block_scheduler_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_velocity_block_scheduler_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME velocity_phase4f_block_scheduler COMMAND qrx_velocity_block_scheduler_test)

    add_executable(qrx_btc_spv_hardening_test tests/qrx_btc_spv_hardening.c)
    target_include_directories(qrx_btc_spv_hardening_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_btc_spv_hardening_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME bitcoin_spv_phase71_hardening COMMAND qrx_btc_spv_hardening_test)

    add_executable(qrx_resource_foundation_test tests/resource_phase080_foundation.c)
    target_include_directories(qrx_resource_foundation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_resource_foundation_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME resource_phase080_foundation COMMAND qrx_resource_foundation_test)

    add_executable(qrx_storage_filesystem_test tests/storage_phase081_filesystem.c)
    target_include_directories(qrx_storage_filesystem_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_filesystem_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase081_filesystem COMMAND qrx_storage_filesystem_test)

    add_executable(qrx_storage_capacity_test tests/storage_phase082_capacity.c)
    target_include_directories(qrx_storage_capacity_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_capacity_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase082_capacity COMMAND qrx_storage_capacity_test)

    add_executable(qrx_capacity_proof_test tests/storage_phase084_capacity_proof.c)
    target_include_directories(qrx_capacity_proof_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_capacity_proof_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase084_capacity_proof COMMAND qrx_capacity_proof_test)

    add_executable(qrx_drive_pq_crypto_test tests/storage_phase085_pq_crypto.c)
    target_include_directories(qrx_drive_pq_crypto_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_drive_pq_crypto_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase085_pq_crypto COMMAND qrx_drive_pq_crypto_test)

    add_executable(qrx_drive_manifest_test tests/storage_phase086_manifest.c)
    target_include_directories(qrx_drive_manifest_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_drive_manifest_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase086_manifest COMMAND qrx_drive_manifest_test)

    add_executable(qrx_erasure_test tests/storage_phase087_erasure.c)
    target_include_directories(qrx_erasure_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_erasure_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase087_erasure COMMAND qrx_erasure_test)

    add_executable(qrx_storage_placement_test tests/storage_phase088_placement.c)
    target_include_directories(qrx_storage_placement_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_placement_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase088_placement COMMAND qrx_storage_placement_test)

    add_executable(qrx_postor_test tests/storage_phase089_postor.c)
    target_include_directories(qrx_postor_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_postor_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase089_postor COMMAND qrx_postor_test)

    add_executable(qrx_storage_market_test tests/storage_phase090_market.c)
    target_include_directories(qrx_storage_market_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_market_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase090_market COMMAND qrx_storage_market_test)

    add_executable(qrx_storage_repair_test tests/storage_phase091_repair.c)
    target_include_directories(qrx_storage_repair_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_repair_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase091_repair COMMAND qrx_storage_repair_test)

    add_executable(qrx_storage_atlas_test tests/storage_phase092_atlas.c)
    target_include_directories(qrx_storage_atlas_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_atlas_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase092_atlas COMMAND qrx_storage_atlas_test)

    add_executable(qrx_storage_transport_test tests/storage_phase093_transport.c)
    target_include_directories(qrx_storage_transport_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_transport_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase093_transport COMMAND qrx_storage_transport_test)

    add_executable(qrx_net_name_test tests/net_phase844_name.c)
    target_include_directories(qrx_net_name_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_name_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase844_name COMMAND qrx_net_name_test)

    add_executable(qrx_net_registry_test tests/net_phase844_registry.c)
    target_include_directories(qrx_net_registry_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_registry_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase844_registry COMMAND qrx_net_registry_test)

    add_executable(qrx_net_resolver_test tests/net_phase846_resolver.c)
    target_include_directories(qrx_net_resolver_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_resolver_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase846_resolver COMMAND qrx_net_resolver_test)

    add_executable(qrx_net_site_test tests/net_phase847_site.c)
    target_include_directories(qrx_net_site_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_site_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase847_site COMMAND qrx_net_site_test)

    add_executable(qrx_net_permissions_test tests/net_phase854_permissions.c)
    target_include_directories(qrx_net_permissions_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_permissions_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase854_permissions COMMAND qrx_net_permissions_test)

    add_executable(qrx_storage_consensus_test tests/storage_phase094_consensus.c)
    target_include_directories(qrx_storage_consensus_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_consensus_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase094_consensus COMMAND qrx_storage_consensus_test)

    add_executable(qrx_net_consensus_test tests/net_phase855_consensus.c)
    target_include_directories(qrx_net_consensus_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_net_consensus_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME net_phase855_consensus COMMAND qrx_net_consensus_test)

    add_executable(qrx_storage_attestation_test tests/storage_phase095_attestation.c)
    target_include_directories(qrx_storage_attestation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_attestation_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase095_attestation COMMAND qrx_storage_attestation_test)

    add_executable(qrx_storage_p2p_test tests/storage_phase096_p2p.c)
    target_include_directories(qrx_storage_p2p_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_p2p_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase096_p2p COMMAND qrx_storage_p2p_test)

    add_executable(qrx_storage_large_object_test tests/storage_phase097_large_object.c)
    target_link_libraries(qrx_storage_large_object_test PRIVATE qrxcore ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase097_large_object COMMAND qrx_storage_large_object_test)


    add_executable(qrx_storage_discovery_test tests/storage_phase099_discovery.c)
    target_include_directories(qrx_storage_discovery_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_discovery_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase099_discovery COMMAND qrx_storage_discovery_test)

    add_executable(qrx_resource_dashboard_test tests/storage_phase100_dashboard.c)
    target_include_directories(qrx_resource_dashboard_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_resource_dashboard_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase100_resource_dashboard COMMAND qrx_resource_dashboard_test)
    add_executable(qrx_resource_live_test tests/storage_phase101_live_dashboard.c)
    target_link_libraries(qrx_resource_live_test PRIVATE qrxcore)
    add_test(NAME storage_phase101_live_dashboard COMMAND qrx_resource_live_test)
    add_executable(qrx_drive_live_test tests/storage_phase102_drive_live.c)
    target_link_libraries(qrx_drive_live_test PRIVATE qrxcore)
    add_test(NAME storage_phase102_drive_live COMMAND qrx_drive_live_test)
    add_executable(qrx_storage_network_transfer_test tests/storage_phase103_network_transfer.c)
    target_link_libraries(qrx_storage_network_transfer_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase103_network_transfer COMMAND qrx_storage_network_transfer_test)

    add_executable(qrx_drive_runtime_test tests/storage_phase104_drive_runtime.c)
    target_link_libraries(qrx_drive_runtime_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase104_drive_runtime COMMAND qrx_drive_runtime_test)

    add_executable(qrx_drive_recovery_test tests/storage_phase105_drive_recovery.c)
    target_link_libraries(qrx_drive_recovery_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase105_drive_recovery COMMAND qrx_drive_recovery_test)

    add_executable(qrx_storage_gossip_streaming_test tests/storage_phase106_gossip_streaming.c)
    target_link_libraries(qrx_storage_gossip_streaming_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase106_gossip_streaming COMMAND qrx_storage_gossip_streaming_test)

    add_executable(qrx_storage_identity_gossip_test tests/storage_phase107_identity_gossip.c)
    target_link_libraries(qrx_storage_identity_gossip_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase107_identity_gossip COMMAND qrx_storage_identity_gossip_test)

    add_executable(qrx_drive_private_pq_test tests/storage_phase108_private_pq.c)
    target_link_libraries(qrx_drive_private_pq_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase108_private_pq COMMAND qrx_drive_private_pq_test)

    add_executable(qrx_drive_prepare_test tests/storage_phase109_prepare.c)
    target_link_libraries(qrx_drive_prepare_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase109_prepare COMMAND qrx_drive_prepare_test)
    add_executable(qrx_drive_prepared_runtime_test tests/storage_phase110_prepared_runtime.c)
    target_link_libraries(qrx_drive_prepared_runtime_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase110_prepared_runtime COMMAND qrx_drive_prepared_runtime_test)
    add_executable(qrx_drive_contract_orchestration_test tests/storage_phase111_contract_orchestration.c)
    target_link_libraries(qrx_drive_contract_orchestration_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase111_contract_orchestration COMMAND qrx_drive_contract_orchestration_test)

    add_executable(qrx_storage_multifetch_test tests/storage_phase098_multifetch.c)
    target_include_directories(qrx_storage_multifetch_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(qrx_storage_multifetch_test PRIVATE qrxcore Threads::Threads ${QRX_OPENSSL_LINK_LIBS})
    add_test(NAME storage_phase098_multifetch COMMAND qrx_storage_multifetch_test)

    if(NOT MSVC)
        foreach(test_tgt qrx_velocity_engine_test qrx_velocity_mvcc_test qrx_velocity_stateful_mvcc_test qrx_velocity_dynamic_mvcc_test qrx_velocity_speculative_mvcc_test qrx_velocity_block_scheduler_test qrx_btc_spv_hardening_test qrx_resource_foundation_test qrx_storage_filesystem_test qrx_storage_capacity_test qrx_capacity_proof_test qrx_drive_pq_crypto_test qrx_drive_manifest_test qrx_erasure_test qrx_storage_placement_test qrx_postor_test qrx_storage_market_test qrx_storage_repair_test qrx_storage_atlas_test qrx_storage_transport_test qrx_net_name_test qrx_net_registry_test qrx_net_resolver_test qrx_net_site_test qrx_net_permissions_test qrx_storage_consensus_test qrx_net_consensus_test qrx_storage_attestation_test qrx_storage_p2p_test qrx_storage_large_object_test qrx_storage_multifetch_test qrx_storage_discovery_test)
            target_compile_options(${test_tgt} PRIVATE -UNDEBUG)
            if(QRX_ENABLE_ASAN)
                target_link_options(${test_tgt} PRIVATE -fsanitize=address)
            endif()
            if(QRX_ENABLE_UBSAN)
                target_link_options(${test_tgt} PRIVATE -fsanitize=undefined)
            endif()
        endforeach()
    endif()

  add_executable(storage_phase112_provider_activation tests/storage_phase112_provider_activation.c)
  target_link_libraries(storage_phase112_provider_activation PRIVATE qrxcore)
  add_test(NAME storage_phase112_provider_activation COMMAND storage_phase112_provider_activation)
  add_executable(storage_phase113_postor_runtime tests/storage_phase113_postor_runtime.c)
  target_link_libraries(storage_phase113_postor_runtime PRIVATE qrxcore)
  add_test(NAME storage_phase113_postor_runtime COMMAND storage_phase113_postor_runtime)
  add_executable(storage_phase114_repair_runtime tests/storage_phase114_repair_runtime.c)
  target_link_libraries(storage_phase114_repair_runtime PRIVATE qrxcore)
  add_test(NAME storage_phase114_repair_runtime COMMAND storage_phase114_repair_runtime)
  add_executable(net_phase115_domain_management tests/net_phase115_domain_management.c)
  target_link_libraries(net_phase115_domain_management PRIVATE qrxcore)
  add_test(NAME net_phase115_domain_management COMMAND net_phase115_domain_management)
  add_executable(net_phase116_site_package tests/net_phase116_site_package.c)
  target_link_libraries(net_phase116_site_package PRIVATE qrxcore)
  add_test(NAME net_phase116_site_package COMMAND net_phase116_site_package)
  add_executable(net_phase117_directory_publisher tests/net_phase117_directory_publisher.c)
  target_link_libraries(net_phase117_directory_publisher PRIVATE qrxcore)
  add_test(NAME net_phase117_directory_publisher COMMAND net_phase117_directory_publisher)
  add_executable(net_phase118_hosting_activation tests/net_phase118_hosting_activation.c)
  target_link_libraries(net_phase118_hosting_activation PRIVATE qrxcore)
  add_test(NAME net_phase118_hosting_activation COMMAND net_phase118_hosting_activation)
  add_executable(net_phase119_browser_fetch tests/net_phase119_browser_fetch.c)
  target_link_libraries(net_phase119_browser_fetch PRIVATE qrxcore)
  add_test(NAME net_phase119_browser_fetch COMMAND net_phase119_browser_fetch)
  add_executable(net_phase120_browser_sandbox tests/net_phase120_browser_sandbox.c)
  target_link_libraries(net_phase120_browser_sandbox PRIVATE qrxcore)
  add_test(NAME net_phase120_browser_sandbox COMMAND net_phase120_browser_sandbox)
  add_executable(net_phase121_dapp_bridge tests/net_phase121_dapp_bridge.c)
  target_link_libraries(net_phase121_dapp_bridge PRIVATE qrxcore)
  add_test(NAME net_phase121_dapp_bridge COMMAND net_phase121_dapp_bridge)
  add_executable(net_phase122_ad_economy tests/net_phase122_ad_economy.c)
  target_link_libraries(net_phase122_ad_economy PRIVATE qrxcore)
  add_test(NAME net_phase122_ad_economy COMMAND net_phase122_ad_economy)
  add_executable(net_phase123_youth_safety tests/net_phase123_youth_safety.c)
  target_link_libraries(net_phase123_youth_safety PRIVATE qrxcore)
  add_test(NAME net_phase123_youth_safety COMMAND net_phase123_youth_safety)
  add_executable(net_phase124_hosting_missions tests/net_phase124_hosting_missions.c)
  target_link_libraries(net_phase124_hosting_missions PRIVATE qrxcore)
  add_test(NAME net_phase124_hosting_missions COMMAND net_phase124_hosting_missions)

  add_executable(net_phase125_final_readiness tests/net_phase125_final_readiness.c)
  target_link_libraries(net_phase125_final_readiness PRIVATE qrxcore)
  add_test(NAME net_phase125_final_readiness COMMAND net_phase125_final_readiness)

  add_executable(compute_phase126_foundation tests/compute_phase126_foundation.c)
  target_link_libraries(compute_phase126_foundation PRIVATE qrxcore)
  add_test(NAME compute_phase126_foundation COMMAND compute_phase126_foundation)

  add_executable(compute_phase127_capability_discovery tests/compute_phase127_capability_discovery.c)
  target_link_libraries(compute_phase127_capability_discovery PRIVATE qrxcore)
  add_test(NAME compute_phase127_capability_discovery COMMAND compute_phase127_capability_discovery)

  add_executable(compute_phase128_benchmark_normalization tests/compute_phase128_benchmark_normalization.c)
  target_link_libraries(compute_phase128_benchmark_normalization PRIVATE qrxcore)
  add_test(NAME compute_phase128_benchmark_normalization COMMAND compute_phase128_benchmark_normalization)

  add_executable(compute_phase129_model_registry tests/compute_phase129_model_registry.c)
  target_link_libraries(compute_phase129_model_registry PRIVATE qrxcore)
  add_test(NAME compute_phase129_model_registry COMMAND compute_phase129_model_registry)

  add_executable(compute_phase130_job_protocol tests/compute_phase130_job_protocol.c)
  target_link_libraries(compute_phase130_job_protocol PRIVATE qrxcore)
  add_test(NAME compute_phase130_job_protocol COMMAND compute_phase130_job_protocol)

  add_executable(compute_phase131_market_escrow tests/compute_phase131_market_escrow.c)
  target_link_libraries(compute_phase131_market_escrow PRIVATE qrxcore)
  add_test(NAME compute_phase131_market_escrow COMMAND compute_phase131_market_escrow)

  add_executable(compute_phase132_secure_sandbox tests/compute_phase132_secure_sandbox.c)
  target_link_libraries(compute_phase132_secure_sandbox PRIVATE qrxcore)
  add_test(NAME compute_phase132_secure_sandbox COMMAND compute_phase132_secure_sandbox)

  add_executable(compute_phase133_pouc_verification tests/compute_phase133_pouc_verification.c)
  target_link_libraries(compute_phase133_pouc_verification PRIVATE qrxcore)
  add_test(NAME compute_phase133_pouc_verification COMMAND compute_phase133_pouc_verification)

  add_executable(compute_phase134_aura_runtime tests/compute_phase134_aura_runtime.c)
  target_link_libraries(compute_phase134_aura_runtime PRIVATE qrxcore)
  add_test(NAME compute_phase134_aura_runtime COMMAND compute_phase134_aura_runtime)

  add_executable(compute_phase135_aura_chat tests/compute_phase135_aura_chat.c)
  target_link_libraries(compute_phase135_aura_chat PRIVATE qrxcore)
  add_test(NAME compute_phase135_aura_chat COMMAND compute_phase135_aura_chat)

  add_executable(compute_phase136_aura_artifacts tests/compute_phase136_aura_artifacts.c)
  target_link_libraries(compute_phase136_aura_artifacts PRIVATE qrxcore)
  add_test(NAME compute_phase136_aura_artifacts COMMAND compute_phase136_aura_artifacts)

  add_executable(compute_phase137_aura_code_workspace tests/compute_phase137_aura_code_workspace.c)
  target_link_libraries(compute_phase137_aura_code_workspace PRIVATE qrxcore)
  add_test(NAME compute_phase137_aura_code_workspace COMMAND compute_phase137_aura_code_workspace)

  add_executable(compute_phase138_aura_code_lifecycle tests/compute_phase138_aura_code_lifecycle.c)
  target_link_libraries(compute_phase138_aura_code_lifecycle PRIVATE qrxcore)
  add_test(NAME compute_phase138_aura_code_lifecycle COMMAND compute_phase138_aura_code_lifecycle)

  add_executable(compute_phase139_moe_traffic_optimistic tests/compute_phase139_moe_traffic_optimistic.c)
  target_link_libraries(compute_phase139_moe_traffic_optimistic PRIVATE qrxcore)
  add_test(NAME compute_phase139_moe_traffic_optimistic COMMAND compute_phase139_moe_traffic_optimistic)
  add_executable(compute_phase140_moe_coordinator_prefetch tests/compute_phase140_moe_coordinator_prefetch.c)
  target_link_libraries(compute_phase140_moe_coordinator_prefetch PRIVATE qrxcore)
  add_test(NAME compute_phase140_moe_coordinator_prefetch COMMAND compute_phase140_moe_coordinator_prefetch)

  add_executable(compute_phase141_moe_batch_stream_aggregation tests/compute_phase141_moe_batch_stream_aggregation.c)
  target_link_libraries(compute_phase141_moe_batch_stream_aggregation PRIVATE qrxcore)
  add_test(NAME compute_phase141_moe_batch_stream_aggregation COMMAND compute_phase141_moe_batch_stream_aggregation)

  add_executable(compute_phase142_moe_adaptive_scheduler_telemetry tests/compute_phase142_moe_adaptive_scheduler_telemetry.c)
  target_link_libraries(compute_phase142_moe_adaptive_scheduler_telemetry PRIVATE qrxcore)
  add_test(NAME compute_phase142_moe_adaptive_scheduler_telemetry COMMAND compute_phase142_moe_adaptive_scheduler_telemetry)

  add_executable(compute_phase143_moe_runtime_benchmark tests/compute_phase143_moe_runtime_benchmark.c)
  target_link_libraries(compute_phase143_moe_runtime_benchmark PRIVATE qrxcore)
  add_test(NAME compute_phase143_moe_runtime_benchmark COMMAND compute_phase143_moe_runtime_benchmark)

  add_executable(compute_phase144_native_runtime_calibration tests/compute_phase144_native_runtime_calibration.c)
  target_link_libraries(compute_phase144_native_runtime_calibration PRIVATE qrxcore)
  add_test(NAME compute_phase144_native_runtime_calibration COMMAND compute_phase144_native_runtime_calibration)

  add_executable(compute_phase145_resource_globe tests/compute_phase145_resource_globe.c)
  target_link_libraries(compute_phase145_resource_globe PRIVATE qrxcore)
  add_test(NAME compute_phase145_resource_globe COMMAND compute_phase145_resource_globe)

  add_executable(compute_phase146_opportunity_engine tests/compute_phase146_opportunity_engine.c)
  target_link_libraries(compute_phase146_opportunity_engine PRIVATE qrxcore)
  add_test(NAME compute_phase146_opportunity_engine COMMAND compute_phase146_opportunity_engine)

  add_executable(compute_phase147_task_globe tests/compute_phase147_task_globe.c)
  target_link_libraries(compute_phase147_task_globe PRIVATE qrxcore)
  add_test(NAME compute_phase147_task_globe COMMAND compute_phase147_task_globe)

  add_executable(compute_phase148_qrx_os_compute tests/compute_phase148_qrx_os_compute.c)
  target_link_libraries(compute_phase148_qrx_os_compute PRIVATE qrxcore)
  add_test(NAME compute_phase148_qrx_os_compute COMMAND compute_phase148_qrx_os_compute)

  add_executable(compute_phase149_resource_provider_ux tests/compute_phase149_resource_provider_ux.c)
  target_link_libraries(compute_phase149_resource_provider_ux PRIVATE qrxcore)
  add_test(NAME compute_phase149_resource_provider_ux COMMAND compute_phase149_resource_provider_ux)

  add_executable(compute_phase150_provider_runtime_market tests/compute_phase150_provider_runtime_market.c)
  target_link_libraries(compute_phase150_provider_runtime_market PRIVATE qrxcore)
  add_test(NAME compute_phase150_provider_runtime_market COMMAND compute_phase150_provider_runtime_market)

  add_executable(compute_phase151_adversarial_testnet tests/compute_phase151_adversarial_testnet.c)
  target_link_libraries(compute_phase151_adversarial_testnet PRIVATE qrxcore)
  add_test(NAME compute_phase151_adversarial_testnet COMMAND compute_phase151_adversarial_testnet)

  add_executable(compute_phase152_pouc_mainnet_activation tests/compute_phase152_pouc_mainnet_activation.c)
  target_link_libraries(compute_phase152_pouc_mainnet_activation PRIVATE qrxcore)
  add_test(NAME compute_phase152_pouc_mainnet_activation COMMAND compute_phase152_pouc_mainnet_activation)

  add_executable(compute_phase153_pouc_durable_journal tests/compute_phase153_pouc_durable_journal.c)
  target_link_libraries(compute_phase153_pouc_durable_journal PRIVATE qrxcore)
  add_test(NAME compute_phase153_pouc_durable_journal COMMAND compute_phase153_pouc_durable_journal)

  add_executable(compute_phase154_pouc_block_pipeline tests/compute_phase154_pouc_block_pipeline.c)
  target_link_libraries(compute_phase154_pouc_block_pipeline PRIVATE qrxcore)
  add_test(NAME compute_phase154_pouc_block_pipeline COMMAND compute_phase154_pouc_block_pipeline)

  add_executable(compute_phase155_pouc_upstream_transactions tests/compute_phase155_pouc_upstream_transactions.c)
  target_link_libraries(compute_phase155_pouc_upstream_transactions PRIVATE qrxcore)
  add_test(NAME compute_phase155_pouc_upstream_transactions COMMAND compute_phase155_pouc_upstream_transactions)

  add_executable(compute_phase156_verifier_selection_rewards_slashing tests/compute_phase156_verifier_selection_rewards_slashing.c)
  target_link_libraries(compute_phase156_verifier_selection_rewards_slashing PRIVATE qrxcore)
  add_test(NAME compute_phase156_verifier_selection_rewards_slashing COMMAND compute_phase156_verifier_selection_rewards_slashing)

  add_executable(compute_phase157_verifier_timeout_reorg_penalty tests/compute_phase157_verifier_timeout_reorg_penalty.c)
  target_link_libraries(compute_phase157_verifier_timeout_reorg_penalty PRIVATE qrxcore)
  add_test(NAME compute_phase157_verifier_timeout_reorg_penalty COMMAND compute_phase157_verifier_timeout_reorg_penalty)

  add_executable(compute_phase158_canonical_reorg_reward_governance tests/compute_phase158_canonical_reorg_reward_governance.c)
  target_link_libraries(compute_phase158_canonical_reorg_reward_governance PRIVATE qrxcore)
  add_test(NAME compute_phase158_canonical_reorg_reward_governance COMMAND compute_phase158_canonical_reorg_reward_governance)

  add_executable(compute_phase159_pouc_upstream_undo_e2e_reorg tests/compute_phase159_pouc_upstream_undo_e2e_reorg.c)
  target_link_libraries(compute_phase159_pouc_upstream_undo_e2e_reorg PRIVATE qrxcore)
  add_test(NAME compute_phase159_pouc_upstream_undo_e2e_reorg COMMAND compute_phase159_pouc_upstream_undo_e2e_reorg)

  add_executable(compute_phase160_aura_adaptive_model_fabric tests/compute_phase160_aura_adaptive_model_fabric.c)
  target_link_libraries(compute_phase160_aura_adaptive_model_fabric PRIVATE qrxcore)
  add_test(NAME compute_phase160_aura_adaptive_model_fabric COMMAND compute_phase160_aura_adaptive_model_fabric)

  add_executable(compute_phase161_aura_pod_gossip_live_globe tests/compute_phase161_aura_pod_gossip_live_globe.c)
  target_link_libraries(compute_phase161_aura_pod_gossip_live_globe PRIVATE qrxcore)
  add_test(NAME compute_phase161_aura_pod_gossip_live_globe COMMAND compute_phase161_aura_pod_gossip_live_globe)

  add_executable(compute_phase162_aura_live_admission_identity_cache_dispatch tests/compute_phase162_aura_live_admission_identity_cache_dispatch.c)
  target_link_libraries(compute_phase162_aura_live_admission_identity_cache_dispatch PRIVATE qrxcore)
  add_test(NAME compute_phase162_aura_live_admission_identity_cache_dispatch COMMAND compute_phase162_aura_live_admission_identity_cache_dispatch)

  add_executable(compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy tests/compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy.c)
  target_link_libraries(compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy PRIVATE qrxcore)
  add_test(NAME compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy COMMAND compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy)

  add_executable(compute_phase164_aura_provider_service_secure_durable_moe tests/compute_phase164_aura_provider_service_secure_durable_moe.c)
  target_link_libraries(compute_phase164_aura_provider_service_secure_durable_moe PRIVATE qrxcore)
  add_test(NAME compute_phase164_aura_provider_service_secure_durable_moe COMMAND compute_phase164_aura_provider_service_secure_durable_moe)

  add_library(qrx_aura_test_runtime_plugin SHARED tests/qrx_aura_test_runtime_plugin.c)
  target_include_directories(qrx_aura_test_runtime_plugin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  set_target_properties(qrx_aura_test_runtime_plugin PROPERTIES PREFIX "")

  add_executable(compute_phase165_aura_autobootstrap_pq_runtime_moe tests/compute_phase165_aura_autobootstrap_pq_runtime_moe.c)
  target_link_libraries(compute_phase165_aura_autobootstrap_pq_runtime_moe PRIVATE qrxcore)
  add_dependencies(compute_phase165_aura_autobootstrap_pq_runtime_moe qrx_aura_test_runtime_plugin)
  add_test(NAME compute_phase165_aura_autobootstrap_pq_runtime_moe COMMAND compute_phase165_aura_autobootstrap_pq_runtime_moe $<TARGET_FILE:qrx_aura_test_runtime_plugin>)

  add_executable(compute_phase166_aura_host_runtime_journal_relay tests/compute_phase166_aura_host_runtime_journal_relay.c)
  target_link_libraries(compute_phase166_aura_host_runtime_journal_relay PRIVATE qrxcore)
  add_dependencies(compute_phase166_aura_host_runtime_journal_relay qrx_aura_test_runtime_plugin)
  add_test(NAME compute_phase166_aura_host_runtime_journal_relay COMMAND compute_phase166_aura_host_runtime_journal_relay $<TARGET_FILE:qrx_aura_test_runtime_plugin>)

  add_executable(compute_phase167_aura_zero_config_model_fabric tests/compute_phase167_aura_zero_config_model_fabric.c)
  target_link_libraries(compute_phase167_aura_zero_config_model_fabric PRIVATE qrxcore)
  add_test(NAME compute_phase167_aura_zero_config_model_fabric COMMAND compute_phase167_aura_zero_config_model_fabric)

  add_executable(compute_phase168_aura_autoplacement_repair_hot_expert tests/compute_phase168_aura_autoplacement_repair_hot_expert.c)
  target_link_libraries(compute_phase168_aura_autoplacement_repair_hot_expert PRIVATE qrxcore)
  add_test(NAME compute_phase168_aura_autoplacement_repair_hot_expert COMMAND compute_phase168_aura_autoplacement_repair_hot_expert)

  add_executable(compute_phase169_aura_provider_supervisor_failover_health tests/compute_phase169_aura_provider_supervisor_failover_health.c)
  target_link_libraries(compute_phase169_aura_provider_supervisor_failover_health PRIVATE qrxcore)
  add_test(NAME compute_phase169_aura_provider_supervisor_failover_health COMMAND compute_phase169_aura_provider_supervisor_failover_health)

  add_executable(compute_phase170_aura_signed_runtime_oneclick tests/compute_phase170_aura_signed_runtime_oneclick.c)
  target_link_libraries(compute_phase170_aura_signed_runtime_oneclick PRIVATE qrxcore)
  add_test(NAME compute_phase170_aura_signed_runtime_oneclick COMMAND compute_phase170_aura_signed_runtime_oneclick)

  add_executable(compute_phase171_aura_model_governance_provenance_rollback tests/compute_phase171_aura_model_governance_provenance_rollback.c)
  target_link_libraries(compute_phase171_aura_model_governance_provenance_rollback PRIVATE qrxcore)
  add_test(NAME compute_phase171_aura_model_governance_provenance_rollback COMMAND compute_phase171_aura_model_governance_provenance_rollback)

  add_executable(compute_phase172_aura_production_wan_routing_telemetry tests/compute_phase172_aura_production_wan_routing_telemetry.c)
  target_link_libraries(compute_phase172_aura_production_wan_routing_telemetry PRIVATE qrxcore)
  add_test(NAME compute_phase172_aura_production_wan_routing_telemetry COMMAND compute_phase172_aura_production_wan_routing_telemetry)

  add_executable(compute_phase173_aura_mainnet_release_hardening tests/compute_phase173_aura_mainnet_release_hardening.c)
  target_link_libraries(compute_phase173_aura_mainnet_release_hardening PRIVATE qrxcore)
  add_test(NAME compute_phase173_aura_mainnet_release_hardening COMMAND compute_phase173_aura_mainnet_release_hardening)

  add_executable(compute_phase174_qrx_a_to_z_documentation_gate tests/compute_phase174_qrx_a_to_z_documentation_gate.c)
  target_link_libraries(compute_phase174_qrx_a_to_z_documentation_gate PRIVATE qrxcore)
  add_test(NAME compute_phase174_qrx_a_to_z_documentation_gate COMMAND compute_phase174_qrx_a_to_z_documentation_gate "${CMAKE_CURRENT_SOURCE_DIR}/../GUIWALLET/src/index.html" "${CMAKE_CURRENT_SOURCE_DIR}/../docs/QRX_A_TO_Z_0.0.9.md")

  find_package(Python3 COMPONENTS Interpreter REQUIRED)

  add_executable(compute_phase175_aura_real_model_origin_bootstrap tests/compute_phase175_aura_real_model_origin_bootstrap.c)
  target_link_libraries(compute_phase175_aura_real_model_origin_bootstrap PRIVATE qrxcore)
  add_test(NAME compute_phase175_aura_real_model_origin_bootstrap
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/aura_https_fixture_runner.py
      --cert ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/aura_https/localhost-cert.pem
      --key ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/aura_https/localhost-key.pem
      -- $<TARGET_FILE:compute_phase175_aura_real_model_origin_bootstrap>
      "${CMAKE_CURRENT_SOURCE_DIR}/../config/aura/models/official-origin-catalog.qrx")

  add_executable(compute_phase176_aura_edge_models_zero_touch tests/compute_phase176_aura_edge_models_zero_touch.c)
  target_link_libraries(compute_phase176_aura_edge_models_zero_touch PRIVATE qrxcore)
  add_test(NAME compute_phase176_aura_edge_models_zero_touch
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/aura_https_fixture_runner.py
      --cert ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/aura_https/localhost-cert.pem
      --key ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/aura_https/localhost-key.pem
      -- $<TARGET_FILE:compute_phase176_aura_edge_models_zero_touch>
      "${CMAKE_CURRENT_SOURCE_DIR}/../config/aura/models/official-origin-catalog.qrx"
      "${CMAKE_CURRENT_SOURCE_DIR}/../config/aura/models/optional-gated-origin-catalog.qrx")

  add_executable(compute_phase177_aura_runtime_delivery_matrix tests/compute_phase177_aura_runtime_delivery_matrix.c)
  target_link_libraries(compute_phase177_aura_runtime_delivery_matrix PRIVATE qrxcore)
  add_dependencies(compute_phase177_aura_runtime_delivery_matrix qrx_aura_test_runtime_plugin)
  add_test(NAME compute_phase177_aura_runtime_delivery_matrix COMMAND compute_phase177_aura_runtime_delivery_matrix $<TARGET_FILE:qrx_aura_test_runtime_plugin>)

  add_executable(genesis_phase178_tokenomics_policy tests/genesis_phase178_tokenomics_policy.c)
  target_link_libraries(genesis_phase178_tokenomics_policy PRIVATE qrxcore)
  add_test(NAME genesis_phase178_tokenomics_policy COMMAND genesis_phase178_tokenomics_policy)

  add_executable(genesis_phase179_memo_assetburn_ad_activation tests/genesis_phase179_memo_assetburn_ad_activation.c)
  target_link_libraries(genesis_phase179_memo_assetburn_ad_activation PRIVATE qrxcore)
  add_test(NAME genesis_phase179_memo_assetburn_ad_activation COMMAND genesis_phase179_memo_assetburn_ad_activation)

  add_test(NAME genesis_phase180_governance_vault
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/genesis_phase180_governance_vault.py $<TARGET_FILE:qrx>)

  add_executable(genesis_phase181_drive_activation_readiness tests/genesis_phase181_drive_activation_readiness.c)
  target_link_libraries(genesis_phase181_drive_activation_readiness PRIVATE qrxcore)
  add_test(NAME genesis_phase181_drive_activation_readiness COMMAND genesis_phase181_drive_activation_readiness)

  add_test(NAME genesis_phase182_onchain_protocol_governance
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/genesis_phase182_onchain_protocol_governance.py $<TARGET_FILE:qrx>)

  add_executable(genesis_phase183_protocol_readiness_framework tests/genesis_phase183_protocol_readiness_framework.c)
  target_link_libraries(genesis_phase183_protocol_readiness_framework PRIVATE qrxcore)
  add_test(NAME genesis_phase183_protocol_readiness_framework COMMAND genesis_phase183_protocol_readiness_framework)

  # Phase 187: QRX Upscaler. Determinism and sharding equivalence are what the
  # accelerated PoUC mode depends on, so they are regression-gated.
  add_executable(apps_phase187_upscaler tests/apps_phase187_upscaler.c src/apps/qrx_upscaler.c)
  target_include_directories(apps_phase187_upscaler PRIVATE src)
  if(UNIX)
    target_link_libraries(apps_phase187_upscaler PRIVATE m)
  endif()
  if(QRX_UPSCALER_PNG)
    target_compile_definitions(apps_phase187_upscaler PRIVATE QRX_HAVE_PNG)
    target_link_libraries(apps_phase187_upscaler PRIVATE PNG::PNG)
  endif()
  add_test(NAME apps_phase187_upscaler COMMAND apps_phase187_upscaler)

  # Phase 188: host capability profiles for zero-touch AI/classical fallback.
  add_executable(apps_phase188_upscaler_capabilities tests/apps_phase188_upscaler_capabilities.c src/apps/qrx_upscaler_capabilities.c)
  target_include_directories(apps_phase188_upscaler_capabilities PRIVATE src)
  if(CMAKE_DL_LIBS)
    target_link_libraries(apps_phase188_upscaler_capabilities PRIVATE ${CMAKE_DL_LIBS})
  endif()
  add_test(NAME apps_phase188_upscaler_capabilities COMMAND apps_phase188_upscaler_capabilities)

  # Phase 189: QRX third-party app foundation. Static/package regression gate for
  # .qrxapp v1, sandbox host, permission bridge, Mini JS SDK and demo package.
  add_test(NAME apps_phase189_qrxapp_foundation
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/apps_phase189_qrxapp_foundation.py ${CMAKE_CURRENT_SOURCE_DIR}/..)

  # Phase 190: translated Apps/Upscaler/App Host UX and full-width workspace regression gate.
  add_test(NAME apps_phase190_i18n_fullwidth
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/apps_phase190_i18n_fullwidth.py ${CMAKE_CURRENT_SOURCE_DIR}/..)

  # --- Genesis whitehat hardening 0.0.9 -----------------------------------
  # Phase 184: fault-barrier semantics for untrusted network input.
  add_executable(genesis_phase184_untrusted_guard_semantics tests/test_untrusted_guard_semantics.c)
  add_test(NAME genesis_phase184_untrusted_guard_semantics COMMAND genesis_phase184_untrusted_guard_semantics)
  find_package(Threads REQUIRED)
  target_link_libraries(genesis_phase184_untrusted_guard_semantics PRIVATE Threads::Threads)

  # Phase 185: MAINNET BLOCKER. A live node must survive remote malformed
  # transactions instead of terminating through die()/exit().
  add_test(NAME genesis_phase185_remote_malformed_tx_survival
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/genesis_phase185_remote_malformed_tx_survival.py $<TARGET_FILE:qrx>)
  set_tests_properties(genesis_phase185_remote_malformed_tx_survival PROPERTIES TIMEOUT 900)

  add_test(NAME p2p_bootstrap_dns_dedup_self_filter
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/p2p_bootstrap_regression.py $<TARGET_FILE:qrx>)
  set_tests_properties(p2p_bootstrap_dns_dedup_self_filter PROPERTIES TIMEOUT 30)

  add_test(NAME p2p_daemon_post_unlock_signed_bootstrap
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/daemon_unlock_bootstrap_regression.py $<TARGET_FILE:qrx> $<TARGET_FILE:qrxd>)
  set_tests_properties(p2p_daemon_post_unlock_signed_bootstrap PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)

  # Phase 186: static proof that no unguarded die()/exit()/abort()/assert()
  # is reachable from an untrusted network ingress point.
  add_test(NAME genesis_phase186_untrusted_abort_reachability
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../scripts/audit-untrusted-abort-reachability.py ${CMAKE_CURRENT_SOURCE_DIR}/src)

  if(NOT MSVC)
    foreach(test_tgt qrx_resource_live_test qrx_drive_live_test qrx_storage_network_transfer_test qrx_drive_runtime_test qrx_drive_recovery_test qrx_storage_gossip_streaming_test qrx_storage_identity_gossip_test qrx_drive_private_pq_test qrx_drive_prepare_test qrx_drive_prepared_runtime_test qrx_drive_contract_orchestration_test storage_phase112_provider_activation storage_phase113_postor_runtime storage_phase114_repair_runtime net_phase115_domain_management net_phase116_site_package net_phase117_directory_publisher net_phase118_hosting_activation net_phase119_browser_fetch net_phase120_browser_sandbox net_phase121_dapp_bridge net_phase122_ad_economy net_phase123_youth_safety net_phase124_hosting_missions net_phase125_final_readiness compute_phase126_foundation compute_phase127_capability_discovery compute_phase128_benchmark_normalization compute_phase129_model_registry compute_phase130_job_protocol compute_phase131_market_escrow compute_phase132_secure_sandbox compute_phase133_pouc_verification compute_phase134_aura_runtime compute_phase135_aura_chat compute_phase136_aura_artifacts compute_phase137_aura_code_workspace compute_phase138_aura_code_lifecycle compute_phase139_moe_traffic_optimistic compute_phase140_moe_coordinator_prefetch compute_phase141_moe_batch_stream_aggregation compute_phase142_moe_adaptive_scheduler_telemetry compute_phase143_moe_runtime_benchmark compute_phase144_native_runtime_calibration compute_phase145_resource_globe compute_phase146_opportunity_engine compute_phase147_task_globe compute_phase148_qrx_os_compute compute_phase149_resource_provider_ux compute_phase150_provider_runtime_market compute_phase151_adversarial_testnet compute_phase152_pouc_mainnet_activation compute_phase153_pouc_durable_journal compute_phase154_pouc_block_pipeline compute_phase155_pouc_upstream_transactions compute_phase156_verifier_selection_rewards_slashing compute_phase157_verifier_timeout_reorg_penalty compute_phase158_canonical_reorg_reward_governance compute_phase159_pouc_upstream_undo_e2e_reorg compute_phase160_aura_adaptive_model_fabric compute_phase161_aura_pod_gossip_live_globe compute_phase162_aura_live_admission_identity_cache_dispatch compute_phase163_aura_remote_dispatch_leases_drive_anti_entropy compute_phase164_aura_provider_service_secure_durable_moe compute_phase165_aura_autobootstrap_pq_runtime_moe compute_phase166_aura_host_runtime_journal_relay compute_phase167_aura_zero_config_model_fabric compute_phase168_aura_autoplacement_repair_hot_expert compute_phase169_aura_provider_supervisor_failover_health compute_phase170_aura_signed_runtime_oneclick compute_phase171_aura_model_governance_provenance_rollback compute_phase172_aura_production_wan_routing_telemetry compute_phase173_aura_mainnet_release_hardening compute_phase174_qrx_a_to_z_documentation_gate compute_phase175_aura_real_model_origin_bootstrap compute_phase176_aura_edge_models_zero_touch compute_phase177_aura_runtime_delivery_matrix genesis_phase178_tokenomics_policy genesis_phase179_memo_assetburn_ad_activation genesis_phase181_drive_activation_readiness genesis_phase183_protocol_readiness_framework)
      target_compile_options(${test_tgt} PRIVATE -UNDEBUG)
      if(QRX_ENABLE_ASAN)
        target_link_options(${test_tgt} PRIVATE -fsanitize=address)
      endif()
      if(QRX_ENABLE_UBSAN)
        target_link_options(${test_tgt} PRIVATE -fsanitize=undefined)
      endif()
    endforeach()
  endif()
endif()
