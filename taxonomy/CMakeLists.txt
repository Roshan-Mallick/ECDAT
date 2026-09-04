cmake_minimum_required(VERSION 3.21)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(ecdat_member2
    VERSION 0.1.0
    DESCRIPTION "ECDAT Member 2 - Data & Taxonomy Engineer"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(ECDAT_ENABLE_SANITIZERS "Build Member 2 with Address+UB sanitizers" OFF)
option(ECDAT_BUILD_TESTS "Build Member 2 unit tests" ON)
option(ECDAT_FETCH_DEPENDENCIES "Download missing dependencies from GitHub" OFF)

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
# Dependencies
# ---------------------------------------------------------------------------
# Prefer system packages so a normal configure never blocks on network I/O.
# Git-based FetchContent remains available as an explicit opt-in fallback.
find_package(nlohmann_json CONFIG QUIET)
find_package(yaml-cpp CONFIG QUIET)
if(ECDAT_BUILD_TESTS)
    find_package(GTest QUIET)
    if(NOT TARGET GTest::gtest_main)
        find_path(GTEST_INCLUDE_DIR gtest/gtest.h)
        find_library(GTEST_LIBRARY NAMES gtest)
        find_library(GTEST_MAIN_LIBRARY NAMES gtest_main)
        if(GTEST_INCLUDE_DIR AND GTEST_LIBRARY AND GTEST_MAIN_LIBRARY)
            include(FindThreads)
            add_library(GTest::gtest STATIC IMPORTED GLOBAL)
            set_target_properties(GTest::gtest PROPERTIES
                IMPORTED_LOCATION "${GTEST_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
                INTERFACE_LINK_LIBRARIES Threads::Threads)
            add_library(GTest::gtest_main STATIC IMPORTED GLOBAL)
            set_target_properties(GTest::gtest_main PROPERTIES
                IMPORTED_LOCATION "${GTEST_MAIN_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${GTEST_INCLUDE_DIR}"
                INTERFACE_LINK_LIBRARIES "Threads::Threads;GTest::gtest")
        endif()
    endif()
    if(TARGET GTest::gtest AND TARGET GTest::gtest_main)
        set_property(TARGET GTest::gtest PROPERTY IMPORTED_GLOBAL TRUE)
        set_property(TARGET GTest::gtest_main PROPERTY IMPORTED_GLOBAL TRUE)
    endif()
endif()

if(ECDAT_FETCH_DEPENDENCIES AND
   (NOT nlohmann_json_FOUND OR NOT yaml-cpp_FOUND OR
    (ECDAT_BUILD_TESTS AND NOT GTest_FOUND)))
    include(FetchContent)

    if(NOT nlohmann_json_FOUND)
        FetchContent_Declare(
            nlohmann_json
            GIT_REPOSITORY https://github.com/nlohmann/json.git
            GIT_TAG v3.11.3)
        FetchContent_MakeAvailable(nlohmann_json)
    endif()

    if(NOT yaml-cpp_FOUND)
        FetchContent_Declare(
            yaml-cpp
            GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
            GIT_TAG 0.8.0)
        FetchContent_MakeAvailable(yaml-cpp)
    endif()

    if(ECDAT_BUILD_TESTS AND NOT GTest_FOUND)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()

if(NOT nlohmann_json_FOUND AND NOT TARGET nlohmann_json::nlohmann_json)
    message(FATAL_ERROR
        "nlohmann_json is required. Install nlohmann-json3-dev or configure "
        "with -DECDAT_FETCH_DEPENDENCIES=ON.")
endif()
if(NOT yaml-cpp_FOUND AND NOT TARGET yaml-cpp::yaml-cpp)
    message(FATAL_ERROR
        "yaml-cpp is required. Install libyaml-cpp-dev or configure "
        "with -DECDAT_FETCH_DEPENDENCIES=ON.")
endif()
if(ECDAT_BUILD_TESTS AND NOT GTest_FOUND AND NOT TARGET GTest::gtest_main)
    message(FATAL_ERROR
        "GoogleTest is required when ECDAT_BUILD_TESTS=ON. Install libgtest-dev "
        "or configure with -DECDAT_FETCH_DEPENDENCIES=ON.")
endif()

# ---------------------------------------------------------------------------
# Member 2 core library (shared CryptoAsset contract + serialization)
# ---------------------------------------------------------------------------
add_library(ecdat_core
    core/src/serialization.cpp)
target_include_directories(ecdat_core PUBLIC core/include)
target_link_libraries(ecdat_core PUBLIC nlohmann_json::nlohmann_json)
target_compile_features(ecdat_core PUBLIC cxx_std_20)

# ---------------------------------------------------------------------------
# Member 2 taxonomy library (TaxonomyDB + classifier)
# ---------------------------------------------------------------------------
add_library(ecdat_taxonomy
    taxonomy/src/taxonomy_loader.cpp
    taxonomy/src/classifier.cpp)
target_include_directories(ecdat_taxonomy PUBLIC taxonomy/include)
target_link_libraries(ecdat_taxonomy
    PUBLIC ecdat_core yaml-cpp::yaml-cpp)
target_compile_features(ecdat_taxonomy PUBLIC cxx_std_20)

# Path to the shipped taxonomy data file, exposed for tests/tools.
set(ECDAT_TAXONOMY_PATH "${CMAKE_CURRENT_SOURCE_DIR}/taxonomy/data/taxonomy.yaml" CACHE FILEPATH
    "Path to the ECDAT taxonomy data file")

# ---------------------------------------------------------------------------
# Sanitizers
# ---------------------------------------------------------------------------
# Applied globally so that both the static libraries and the test executables
# are instrumented and linked against the ASan/UBSan runtime.
if(ECDAT_ENABLE_SANITIZERS)
    message(STATUS "ECDAT: enabling AddressSanitizer + UndefinedBehaviorSanitizer")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
include(CTest)
include(GoogleTest)
if(BUILD_TESTING AND ECDAT_BUILD_TESTS)
    add_executable(ecdat_serialization_tests
        core/tests/test_serialization.cpp)
    target_link_libraries(ecdat_serialization_tests PRIVATE ecdat_core GTest::gtest_main)
    target_compile_features(ecdat_serialization_tests PRIVATE cxx_std_20)

    add_executable(ecdat_taxonomy_tests
        taxonomy/tests/test_taxonomy.cpp)
    target_link_libraries(ecdat_taxonomy_tests PRIVATE ecdat_taxonomy GTest::gtest_main)
    target_compile_definitions(ecdat_taxonomy_tests PRIVATE
        ECDAT_TAXONOMY_PATH="${ECDAT_TAXONOMY_PATH}")
    target_compile_features(ecdat_taxonomy_tests PRIVATE cxx_std_20)

    add_executable(ecdat_classifier_tests
        taxonomy/tests/test_classifier.cpp)
    target_link_libraries(ecdat_classifier_tests PRIVATE ecdat_taxonomy GTest::gtest_main)
    target_compile_features(ecdat_classifier_tests PRIVATE cxx_std_20)

    gtest_discover_tests(ecdat_serialization_tests)
    gtest_discover_tests(ecdat_taxonomy_tests)
    gtest_discover_tests(ecdat_classifier_tests)
endif()
