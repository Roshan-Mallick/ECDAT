cmake_minimum_required(VERSION 3.16)

# Only call project()/enable_testing() when Member 1 is the top-level project.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(ecdat_discovery CXX)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL QUIET)
    if(NOT OpenSSL_FOUND)
        return()
    endif()
endif()

# tree-sitter: link manually if not found via pkg-config
find_library(TREE_SITTER_LIB tree-sitter)
find_library(TREE_SITTER_PY_LIB tree-sitter-python)
find_path(TREE_SITTER_INCLUDE_DIR tree_sitter/api.h)

# Member 1 (discovery) needs tree-sitter at build time. When this module is a
# subdirectory of the integrated ECDAT build, silently skip it if the
# tree-sitter libraries are unavailable so the rest of the build still works.
if(NOT TREE_SITTER_LIB OR NOT TREE_SITTER_PY_LIB OR NOT TREE_SITTER_INCLUDE_DIR)
    if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        message(FATAL_ERROR "tree-sitter and tree-sitter-python libraries are required for the standalone Member 1 build.")
    endif()
    message(STATUS "ECDAT: tree-sitter not found; skipping Member 1 (discovery).")
    return()
endif()

# ---------------------------------------------------------------------------
# Member 1 - Discovery library
#
# Consumes the authoritative Member 2 shared contract (ecdat/types.hpp) via
# the Member 2 core include directory, so Member 1 produces the SAME
# ecdat::CryptoAsset that Member 2 classifies and Member 3 scores. There is no
# duplicate contract.
# ---------------------------------------------------------------------------
add_library(discovery_lib
    src/source_scanner.cpp
    src/cert_scanner.cpp
    src/tls_scanner.cpp
)
target_include_directories(discovery_lib PUBLIC include)
# Make the authoritative Member 2 contract header reachable.
target_include_directories(discovery_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../member_2/core/include)
target_include_directories(discovery_lib PUBLIC ${TREE_SITTER_INCLUDE_DIR})
target_link_libraries(discovery_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto
    ${TREE_SITTER_PY_LIB} ${TREE_SITTER_LIB} ${TREE_SITTER_PY_LIB})
target_compile_features(discovery_lib PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# Member 1 - standalone discovery driver
# ---------------------------------------------------------------------------
add_executable(discovery src/main.cpp)
target_link_libraries(discovery PRIVATE discovery_lib)

# ---------------------------------------------------------------------------
# Member 1 - standalone discovery tests (plain C++, no gtest)
# ---------------------------------------------------------------------------
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_executable(discovery_tests tests/test_discovery.cpp)
    target_link_libraries(discovery_tests PRIVATE discovery_lib)
    add_test(NAME member1_discovery_tests COMMAND discovery_tests)
endif()
