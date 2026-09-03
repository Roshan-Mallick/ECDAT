# Member 3 - Risk Engine library (standalone, no dependency on Member 2)
add_library(ecdat_risk STATIC
    risk/risk_engine.cpp
    risk/exposure.cpp
    taxonomy/taxonomy.cpp)
target_include_directories(ecdat_risk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ecdat_risk PUBLIC cxx_std_17)

# Member 3 standalone tests (plain C++, no gtest needed)
add_executable(ecdat_risk_tests
    test/risk_engine_tests.cpp)
target_link_libraries(ecdat_risk_tests PRIVATE ecdat_risk)
target_compile_features(ecdat_risk_tests PRIVATE cxx_std_17)
