#pragma once
#include "types.hpp"
#include <vector>
#include <string>

// Reads an X.509 certificate (.pem) and extracts algorithm, key size, curve.
std::vector<ecdat::CryptoAsset> scan_certificate(const std::string& filepath);
