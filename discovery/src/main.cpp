#include "source_scanner.hpp"
#include "cert_scanner.hpp"
#include "tls_scanner.hpp"
#include <iostream>
#include <vector>

static void print_assets(const std::vector<ecdat::CryptoAsset>& assets) {
    for (const auto& a : assets) {
        std::cout << "  [" << a.source_type << "] " << a.file << ":" << a.line
                  << " -> " << a.algorithm;
        if (a.key_size) std::cout << " (" << a.key_size << "-bit)";
        std::cout << "\n";
        if (!a.context.empty()) std::cout << "    " << a.context << "\n";
    }
}

// Usage: discovery <source.py|.js> <cert.pem> <tls.conf>
int main(int argc, char** argv) {
    std::vector<ecdat::CryptoAsset> all;

    if (argc > 1) {
        auto r = scan_source_file(argv[1]);
        all.insert(all.end(), r.begin(), r.end());
    }
    if (argc > 2) {
        auto r = scan_certificate(argv[2]);
        all.insert(all.end(), r.begin(), r.end());
    }
    if (argc > 3) {
        auto r = scan_tls_config(argv[3]);
        all.insert(all.end(), r.begin(), r.end());
    }

    std::cout << "Found " << all.size() << " asset(s):\n";
    print_assets(all);
    return 0;
}
