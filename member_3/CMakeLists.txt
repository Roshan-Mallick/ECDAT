# ---------------------------------------------------------------------------
# Member 3 - Risk Engine library (standalone, no dependency on Member 2)
# ---------------------------------------------------------------------------
add_library(ecdat_risk STATIC
    risk/risk_engine.cpp
    risk/exposure.cpp
    taxonomy/taxonomy.cpp)
target_include_directories(ecdat_risk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ecdat_risk PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------
# Member 3 - PQC Intelligence library (migration, readiness, explanation)
#
# Consumes the authoritative Member 2 taxonomy via the shared CryptoAsset
# contract and Classification result. Member 2 owns classification metadata;
# Member 3 does NOT maintain a second algorithm-metadata source of truth.
#
# The dependency on member_2's core/taxonomy targets is declared OPTIONALLY
# (if TARGET exists) so member_3 can still be configured standalone with
# only its own mock fixtures, while the integrated build links the real
# member_2 libraries.
# ---------------------------------------------------------------------------
set(ECDAT_MEMBER2_CORE_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../member_2/core/include")
set(ECDAT_MEMBER2_TAXONOMY_INCLUDE "${CMAKE_CURRENT_SOURCE_DIR}/../member_2/taxonomy/include")

add_library(ecdat_pqc STATIC
    pqc/migration.cpp
    pqc/readiness.cpp
    pqc/explanation.cpp)
target_include_directories(ecdat_pqc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/pqc)
# Include member_2 headers so the shared CryptoAsset/Classification types are
# always visible regardless of link mode.
target_include_directories(ecdat_pqc PUBLIC
    ${ECDAT_MEMBER2_CORE_INCLUDE}
    ${ECDAT_MEMBER2_TAXONOMY_INCLUDE})
target_compile_features(ecdat_pqc PUBLIC cxx_std_20)

# Link the real member_2 libraries when they are present (integrated build).
if(TARGET ecdat_core AND TARGET ecdat_taxonomy)
    target_link_libraries(ecdat_pqc PUBLIC ecdat_core ecdat_taxonomy)
endif()

# ---------------------------------------------------------------------------
# Member 3 standalone tests (plain C++, no gtest needed)
# ---------------------------------------------------------------------------
add_executable(ecdat_risk_tests
    test/risk_engine_tests.cpp)
target_link_libraries(ecdat_risk_tests PRIVATE ecdat_risk)
target_compile_features(ecdat_risk_tests PRIVATE cxx_std_17)

# Register the plain-C++ risk tests with CTest (exit code indicates pass/fail).
add_test(NAME member3_risk_tests COMMAND ecdat_risk_tests)

# PQC unit tests (GoogleTest). These validate migration, readiness,
# explainability, and the sharing of the real CryptoAsset. They are built
# when GoogleTest is available (i.e. the integrated top-level build).
if(TARGET GTest::gtest_main)
    add_executable(ecdat_pqc_tests
        test/pqc_tests.cpp)
    target_link_libraries(ecdat_pqc_tests PRIVATE ecdat_pqc
        ecdat_taxonomy GTest::gtest_main)
    target_compile_features(ecdat_pqc_tests PRIVATE cxx_std_20)
    if(COMMAND gtest_discover_tests)
        gtest_discover_tests(ecdat_pqc_tests)
    endif()
endif()
