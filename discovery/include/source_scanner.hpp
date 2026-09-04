#pragma once
#include "types.hpp"
#include <vector>
#include <string>

// Scans a source file for weak-crypto calls (MD5, SHA1, DES, RC4, hardcoded keys).
// Currently supports Python; extend WEAK_CALLS / language grammar for JS/Java.
std::vector<ecdat::CryptoAsset> scan_source_file(const std::string& filepath);
