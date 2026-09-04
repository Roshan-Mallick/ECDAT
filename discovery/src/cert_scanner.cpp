#include "cert_scanner.hpp"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <iostream>

std::vector<ecdat::CryptoAsset> scan_certificate(const std::string& filepath) {
    std::vector<ecdat::CryptoAsset> results;

    FILE* fp = fopen(filepath.c_str(), "r");
    if (!fp) {
        std::cerr << "Could not open cert: " << filepath << "\n";
        return results;
    }
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!cert) {
        std::cerr << "Could not parse cert: " << filepath << "\n";
        return results;
    }

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    ecdat::CryptoAsset a;
    a.source_type = "certificate";
    a.file = filepath;
    a.line = -1;

    int base_id = EVP_PKEY_base_id(pkey);
    if (base_id == EVP_PKEY_RSA) {
        a.algorithm = "RSA";
        a.key_size = EVP_PKEY_bits(pkey);
    } else if (base_id == EVP_PKEY_EC) {
        a.algorithm = "ECDSA";
        a.key_size = EVP_PKEY_bits(pkey);
        // TODO: extract curve name via EC_KEY_get0_group + OBJ_nid2sn
    } else {
        a.algorithm = "unknown";
    }

    results.push_back(a);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return results;
}
