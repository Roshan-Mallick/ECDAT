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

# tree-sitter: first try to locate system/shared libraries. If they are not
# present and ECDAT_FETCH_DEPENDENCIES=ON, vendor (FetchContent) a static
# tree-sitter + tree-sitter-python so a fresh developer build is fully
# self-bootstrapping. When unavailable and fetch is disabled, discovery is
# skipped gracefully so the rest of the build still works.
find_library(TREE_SITTER_LIB NAMES tree-sitter)
find_library(TREE_SITTER_PY_LIB NAMES tree-sitter-python)
find_path(TREE_SITTER_INCLUDE_DIR tree_sitter/api.h)

if(NOT TREE_SITTER_LIB OR NOT TREE_SITTER_PY_LIB OR NOT TREE_SITTER_INCLUDE_DIR)
    if(ECDAT_FETCH_DEPENDENCIES)
        include(FetchContent)
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "build tree-sitter static for ECDAT" FORCE)
        set(TREE_SITTER_CLI "${CMAKE_CURRENT_SOURCE_DIR}/../cmake/tree-sitter-noop.sh"
            CACHE FILEPATH "no-op tree-sitter CLI for vendored tree-sitter-python" FORCE)
        FetchContent_Declare(
            tree_sitter
            GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
            GIT_TAG ee0c20b1f5fa26d0c567d5f438b0ac46644b530b)
        FetchContent_Declare(
            tree_sitter_python
            GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-python.git
            GIT_TAG 26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64)
        FetchContent_MakeAvailable(tree_sitter tree_sitter_python)
        if(TARGET tree-sitter AND TARGET tree-sitter-python)
            set(TREE_SITTER_LIB tree-sitter)
            set(TREE_SITTER_PY_LIB tree-sitter-python)
            set(TREE_SITTER_INCLUDE_DIR "${FETCHCONTENT_BASE_DIR}/tree_sitter-src/lib/include")
            message(STATUS "ECDAT: vendoring tree-sitter + tree-sitter-python via FetchContent.")
        else()
            message(FATAL_ERROR "tree-sitter FetchContent targets were not produced.")
        endif()
    else()
        if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
            message(FATAL_ERROR
                "tree-sitter and tree-sitter-python libraries are required. Install them "
                "or configure with -DECDAT_FETCH_DEPENDENCIES=ON to vendor them.")
        endif()
        message(STATUS "ECDAT: tree-sitter not found and fetch disabled; skipping Member 1 (discovery).")
        return()
    endif()
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
    ${CMAKE_CURRENT_SOURCE_DIR}/../taxonomy/core/include)
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
