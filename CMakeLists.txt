cmake_minimum_required(VERSION 3.21)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

project(ecdat
    VERSION 0.1.0
    DESCRIPTION "ECDAT - Cryptography Discovery and Analysis Tool"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(ECDAT_ENABLE_SANITIZERS "Build with ASan + UBSan" OFF)
option(ECDAT_BUILD_TESTS       "Build all unit tests"    ON)
option(ECDAT_FETCH_DEPENDENCIES "Download missing dependencies from GitHub (self-bootstrapping)" OFF)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Sanitizers (applied globally when enabled)
# ---------------------------------------------------------------------------
if(ECDAT_ENABLE_SANITIZERS)
    message(STATUS "ECDAT: enabling AddressSanitizer + UndefinedBehaviorSanitizer")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Enable testing before any subdirectory so add_test() calls are registered.
# ---------------------------------------------------------------------------
enable_testing()
include(CTest)

# ---------------------------------------------------------------------------
# Member modules (each subdirectory defines its own libraries/tests)
# ---------------------------------------------------------------------------
add_subdirectory(taxonomy)
add_subdirectory(risk)

# Member 1 (discovery) is optional: it needs OpenSSL + tree-sitter. Only wire
# it (and the Member1 -> 2 -> 3 flow) into the build when those are available,
# so a minimal build without the discovery dependency still works.
find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    add_subdirectory(discovery)
endif()

# ---------------------------------------------------------------------------
# Integration pipeline: connects Member 2 (classification) + Member 3 (risk)
#
#   CryptoAsset
#       → classify_asset()    [Member 2]
#       → risk_score (0-10)
#       → scale to 0-100
#       → calculateRisk()     [Member 3]
#       → RiskLevel + final score
# ---------------------------------------------------------------------------
add_library(ecdat_pipeline STATIC
    integration/pipeline.cpp)
target_include_directories(ecdat_pipeline PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/integration
    ${CMAKE_CURRENT_SOURCE_DIR}/taxonomy/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/taxonomy/taxonomy/include
    ${CMAKE_CURRENT_SOURCE_DIR}/risk
    ${CMAKE_CURRENT_SOURCE_DIR}/risk/pqc)
target_link_libraries(ecdat_pipeline
    PUBLIC ecdat_taxonomy ecdat_risk ecdat_pqc)
target_compile_features(ecdat_pipeline PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# Full Member 1 -> Member 2 -> Member 3 flow (only when Member 1 is present)
# ---------------------------------------------------------------------------
if(TARGET discovery_lib)
    add_library(ecdat_flow STATIC
        integration/flow.cpp)
    target_include_directories(ecdat_flow PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/integration
        ${CMAKE_CURRENT_SOURCE_DIR}/discovery/include
        ${CMAKE_CURRENT_SOURCE_DIR}/taxonomy/core/include)
    target_link_libraries(ecdat_flow PUBLIC discovery_lib ecdat_pipeline)
    target_compile_features(ecdat_flow PUBLIC cxx_std_20)
endif()

# ---------------------------------------------------------------------------
# Member 4 - Platform / CLI / Storage / Reporting
# Must come after taxonomy, risk, integration pipeline, and optionally flow.
# ---------------------------------------------------------------------------
add_subdirectory(platform)

# ---------------------------------------------------------------------------
# Integration tests & demo (only when building with tests)
# ---------------------------------------------------------------------------
include(GoogleTest)

if(BUILD_TESTING AND ECDAT_BUILD_TESTS)
    # Integration test (uses GoogleTest)
    add_executable(ecdat_integration_tests
        integration/test_pipeline.cpp)
    target_link_libraries(ecdat_integration_tests
        PRIVATE ecdat_pipeline GTest::gtest_main)
    target_compile_features(ecdat_integration_tests PRIVATE cxx_std_20)
    gtest_discover_tests(ecdat_integration_tests)

    # Full Member 1 -> Member 2 -> Member 3 flow test (when Member 1 present)
    if(TARGET ecdat_flow)
        add_executable(ecdat_flow_tests
            integration/test_flow.cpp)
        target_link_libraries(ecdat_flow_tests PRIVATE ecdat_flow GTest::gtest_main)
        target_compile_definitions(ecdat_flow_tests PRIVATE
            ECDAT_TAXONOMY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/taxonomy/taxonomy/data/taxonomy.yaml"
            M1_FIXTURE_PY="${CMAKE_CURRENT_SOURCE_DIR}/discovery/fixtures/sample.py"
            M1_FIXTURE_TLS="${CMAKE_CURRENT_SOURCE_DIR}/discovery/fixtures/sample_nginx.conf")
        target_compile_features(ecdat_flow_tests PRIVATE cxx_std_20)
        gtest_discover_tests(ecdat_flow_tests)
    endif()
endif()

# ---------------------------------------------------------------------------
# Installation & packaging
# ---------------------------------------------------------------------------
include(GNUInstallDirs)

# Install the primary CLI binary (defined in platform/CMakeLists.txt).
install(TARGETS ecdat
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

# Install application data (taxonomy). The CLI resolves this from the
# executable location at runtime, so it works from any working directory.
install(FILES taxonomy/taxonomy/data/taxonomy.yaml
    DESTINATION "${CMAKE_INSTALL_DATADIR}/ecdat")
# Also place a copy next to the binary for relocatable/unpacked use.
install(FILES taxonomy/taxonomy/data/taxonomy.yaml
    DESTINATION "${CMAKE_INSTALL_BINDIR}/resources")

# ---------------------------------------------------------------------------
# CPack: standalone tar.gz and Debian package
# ---------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "ecdat")
set(CPACK_PACKAGE_VENDOR "ECDAT Project Team")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Enterprise Cryptography Discovery & Assessment Tool")
set(CPACK_PACKAGE_CONTACT "ECDAT Project Team")
set(CPACK_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_PACKAGE_FILE_NAME "ECDAT-${PROJECT_VERSION}")
set(CPACK_STRIP_FILES TRUE)
set(CPACK_GENERATOR "TGZ;DEB")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "ECDAT Project Team")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.31), libstdc++6 (>= 12), libssl3 (>= 3.0)")
include(CPack)
