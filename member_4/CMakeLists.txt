cmake_minimum_required(VERSION 3.21)

# ---------------------------------------------------------------------------
# Member 4 - Platform Engineering & Integration Lead
# ---------------------------------------------------------------------------
project(ecdat_member4
    VERSION 0.1.0
    DESCRIPTION "ECDAT Member 4 - Platform Engineering, Storage, Reporting & CLI"
    LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# 1. Embedded SQLite C Library
# ---------------------------------------------------------------------------
add_library(sqlite3_lib STATIC
    storage/3rdparty/sqlite/sqlite3.c)
target_include_directories(sqlite3_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/storage/3rdparty/sqlite)
target_compile_options(sqlite3_lib PRIVATE
    -DSQLITE_THREADSAFE=1
    -DSQLITE_ENABLE_FTS5
    -DSQLITE_ENABLE_RTREE
    -DSQLITE_ENABLE_JSON1)

# ---------------------------------------------------------------------------
# 2. Member 4 Storage Library
# ---------------------------------------------------------------------------
add_library(ecdat_storage STATIC
    storage/src/storage.cpp)
target_include_directories(ecdat_storage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/storage/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../member_2/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../integration)
target_link_libraries(ecdat_storage PUBLIC
    sqlite3_lib
    ecdat_core
    ecdat_pipeline)
target_compile_features(ecdat_storage PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# 3. Member 4 Reporting Library (JSON, CSV, PDF)
# ---------------------------------------------------------------------------
add_library(ecdat_reporting STATIC
    reporting/src/json_report.cpp
    reporting/src/csv_report.cpp
    reporting/src/pdf_report.cpp)
target_include_directories(ecdat_reporting PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/reporting/include)
target_link_libraries(ecdat_reporting PUBLIC
    ecdat_storage
    nlohmann_json::nlohmann_json)
target_compile_features(ecdat_reporting PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# 4. Member 4 CLI Library (CLI11, spdlog, fmt, UX)
# ---------------------------------------------------------------------------
add_library(ecdat_cli STATIC
    cli/src/cli.cpp)
target_include_directories(ecdat_cli PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/cli/include
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty
    ${CMAKE_CURRENT_SOURCE_DIR}/../member_1/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../member_2/taxonomy/include)
target_link_libraries(ecdat_cli PUBLIC
    ecdat_reporting
    ecdat_storage
    ecdat_pipeline)

if(TARGET ecdat_flow)
    target_link_libraries(ecdat_cli PUBLIC ecdat_flow)
endif()
if(TARGET discovery_lib)
    target_link_libraries(ecdat_cli PUBLIC discovery_lib)
endif()

target_compile_definitions(ecdat_cli PRIVATE
    ECDAT_TAXONOMY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../member_2/taxonomy/data/taxonomy.yaml")
target_compile_features(ecdat_cli PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# 5. Primary ECDAT Executable Binary
# ---------------------------------------------------------------------------
add_executable(ecdat
    cli/src/main.cpp)
target_link_libraries(ecdat PRIVATE ecdat_cli)
target_compile_features(ecdat PRIVATE cxx_std_20)

# ---------------------------------------------------------------------------
# 6. Member 4 Unit & Integration Tests
# ---------------------------------------------------------------------------
if(BUILD_TESTING AND ECDAT_BUILD_TESTS AND TARGET GTest::gtest_main)
    # Storage Tests
    add_executable(ecdat_storage_tests
        tests/test_storage.cpp)
    target_link_libraries(ecdat_storage_tests PRIVATE ecdat_storage GTest::gtest_main)
    target_compile_features(ecdat_storage_tests PRIVATE cxx_std_20)
    gtest_discover_tests(ecdat_storage_tests)

    # Reporting Tests
    add_executable(ecdat_reporting_tests
        tests/test_reporting.cpp)
    target_link_libraries(ecdat_reporting_tests PRIVATE ecdat_reporting GTest::gtest_main)
    target_compile_features(ecdat_reporting_tests PRIVATE cxx_std_20)
    gtest_discover_tests(ecdat_reporting_tests)

    # CLI Tests
    add_executable(ecdat_cli_tests
        tests/test_cli.cpp)
    target_link_libraries(ecdat_cli_tests PRIVATE ecdat_cli GTest::gtest_main)
    target_compile_definitions(ecdat_cli_tests PRIVATE
        M1_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../member_1/fixtures")
    target_compile_features(ecdat_cli_tests PRIVATE cxx_std_20)
    gtest_discover_tests(ecdat_cli_tests)

    # Member 4 End-to-End Integration Tests
    if(TARGET ecdat_flow)
        add_executable(ecdat_m4_integration_tests
            tests/test_integration.cpp)
        target_link_libraries(ecdat_m4_integration_tests PRIVATE ecdat_cli GTest::gtest_main)
        target_compile_definitions(ecdat_m4_integration_tests PRIVATE
            ECDAT_TAXONOMY_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../member_2/taxonomy/data/taxonomy.yaml"
            M1_FIXTURE_PY="${CMAKE_CURRENT_SOURCE_DIR}/../member_1/fixtures/sample.py"
            M1_FIXTURE_TLS="${CMAKE_CURRENT_SOURCE_DIR}/../member_1/fixtures/sample_nginx.conf")
        target_compile_features(ecdat_m4_integration_tests PRIVATE cxx_std_20)
        gtest_discover_tests(ecdat_m4_integration_tests)
    endif()
endif()
