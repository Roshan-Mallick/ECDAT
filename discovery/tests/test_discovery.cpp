#include "source_scanner.hpp"
#include "cert_scanner.hpp"
#include "tls_scanner.hpp"
#include <iostream>
#include <cassert>

// Minimal manual test runner. Swap for GoogleTest once the team fixture repo exists.

void test_source_scanner() {
    auto results = scan_source_file("fixtures/sample.py");
    assert(!results.empty() && "expected weak crypto detection in sample.py");
    std::cout << "test_source_scanner: PASS\n";
}

void test_tls_scanner() {
    auto results = scan_tls_config("fixtures/sample_nginx.conf");
    assert(!results.empty() && "expected weak TLS detection in sample config");
    std::cout << "test_tls_scanner: PASS\n";
}

int main() {
    test_source_scanner();
    test_tls_scanner();
    // test_cert_scanner() once fixtures/sample.pem is added
    std::cout << "All tests passed.\n";
    return 0;
}
