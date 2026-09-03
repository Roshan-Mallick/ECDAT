cmake_minimum_required(VERSION 3.16)
project(ecdat_discovery CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
# tree-sitter: link manually if not found via pkg-config
find_library(TREE_SITTER_LIB tree-sitter)
find_library(TREE_SITTER_PY_LIB tree-sitter-python)

add_library(discovery_lib
    src/source_scanner.cpp
    src/cert_scanner.cpp
    src/tls_scanner.cpp
)
target_include_directories(discovery_lib PUBLIC include)
target_link_libraries(discovery_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto
    ${TREE_SITTER_LIB} ${TREE_SITTER_PY_LIB})

add_executable(discovery src/main.cpp)
target_link_libraries(discovery PRIVATE discovery_lib)

enable_testing()
add_executable(discovery_tests tests/test_discovery.cpp)
target_link_libraries(discovery_tests PRIVATE discovery_lib)
