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
# Member modules (each subdirectory defines its own libraries/tests)
# ---------------------------------------------------------------------------
add_subdirectory(member_2)
add_subdirectory(member_3)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/member_2/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/member_2/taxonomy/include
    ${CMAKE_CURRENT_SOURCE_DIR}/member_3)
target_link_libraries(ecdat_pipeline
    PUBLIC ecdat_taxonomy ecdat_risk)
target_compile_features(ecdat_pipeline PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# Integration tests & demo (only when building with tests)
# ---------------------------------------------------------------------------
include(CTest)
include(GoogleTest)

if(BUILD_TESTING AND ECDAT_BUILD_TESTS)
    # Integration test (uses GoogleTest)
    add_executable(ecdat_integration_tests
        integration/test_pipeline.cpp)
    target_link_libraries(ecdat_integration_tests
        PRIVATE ecdat_pipeline GTest::gtest_main)
    target_compile_features(ecdat_integration_tests PRIVATE cxx_std_20)
    gtest_discover_tests(ecdat_integration_tests)

    # Combined demo (member_2 demo + member_3 risk engine)
    add_executable(ecdat_combined_demo
        integration/combined_demo.cpp)
    target_link_libraries(ecdat_combined_demo PRIVATE ecdat_pipeline)
    target_compile_definitions(ecdat_combined_demo PRIVATE
        ECDAT_TAXONOMY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/member_2/taxonomy/data/taxonomy.yaml"
        DEMO_OUTPUT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/member_2/temp_out")
    target_compile_features(ecdat_combined_demo PRIVATE cxx_std_20)
endif()
