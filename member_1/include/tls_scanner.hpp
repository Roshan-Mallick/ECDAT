#pragma once
#include "types.hpp"
#include <vector>
#include <string>

// Parses nginx/Apache/HAProxy-style config files for TLS version + weak ciphers.
std::vector<ecdat::CryptoAsset> scan_tls_config(const std::string& filepath);
