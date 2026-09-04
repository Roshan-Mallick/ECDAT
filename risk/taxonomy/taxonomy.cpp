#include "taxonomy.h"
#include "../common/simple_json.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>

using ecdat::simple_json::Value;

std::string TaxonomyLookup::normalize(const std::string& algorithm) {
    std::string name;
    for (unsigned char c : algorithm) {
        if (!std::isspace(c)) {
            name += static_cast<char>(std::toupper(c));
        }
    }

    if (name.rfind("RSA", 0) == 0) return "RSA";
    if (name.rfind("ECDSA", 0) == 0) return "ECDSA";
    if (name == "DH" || name.rfind("DIFFIE-HELLMAN", 0) == 0) return "DH";

    return name; // AES-256 remains AES-256
}

TaxonomyLookup::TaxonomyLookup(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file) throw std::runtime_error("Cannot open taxonomy file: " + jsonPath);

    const Value rules = Value::parse(file);

    for (const auto& item : rules.items()) {
        const auto& algorithm = item.first;
        const auto& rule = item.second;
        entries_[normalize(algorithm)] = {
            rule.at("weakness").numberValue(),
            rule.at("remediation").numberValue(),
            rule.at("role").stringValue(),
            rule.at("pqc_vulnerable").boolValue()
        };
    }
}

const TaxonomyEntry& TaxonomyLookup::lookup(const std::string& algorithm) const {
    const auto it = entries_.find(normalize(algorithm));
    if (it == entries_.end()) {
        throw std::runtime_error("Unknown algorithm in taxonomy: " + algorithm);
    }
    return it->second;
}