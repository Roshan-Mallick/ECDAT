#include "tls_scanner.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

static const std::vector<std::string> WEAK_TLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"};
static const std::vector<std::string> WEAK_CIPHERS = {"RC4", "DES", "MD5", "NULL"};

std::vector<ecdat::CryptoAsset> scan_tls_config(const std::string& filepath) {
    std::vector<ecdat::CryptoAsset> results;
    std::ifstream f(filepath);
    if (!f) {
        std::cerr << "Could not open config: " << filepath << "\n";
        return results;
    }

    std::string line;
    int line_num = 0;
    while (std::getline(f, line)) {
        line_num++;

        for (const auto& proto : WEAK_TLS) {
            if (line.find(proto) != std::string::npos) {
                ecdat::CryptoAsset a;
                a.source_type = "tls_config";
                a.file = filepath;
                a.line = line_num;
                a.algorithm = proto;
                a.context = line;
                results.push_back(a);
            }
        }
        for (const auto& cipher : WEAK_CIPHERS) {
            if (line.find(cipher) != std::string::npos) {
                ecdat::CryptoAsset a;
                a.source_type = "tls_config";
                a.file = filepath;
                a.line = line_num;
                a.algorithm = cipher;
                a.context = line;
                results.push_back(a);
            }
        }
    }
    return results;
}
