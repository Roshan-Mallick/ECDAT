// migration.cpp
//
// Implementation of the ECDAT Member 3 PQC migration mapping.
// See migration.h for the full contract.

#include "migration.h"

#include <cctype>
#include <string>
#include <unordered_map>

namespace ecdat {
namespace pqc {

namespace {

// Centralized, role-aware migration rule table.
//
// Key is an upper-cased, whitespace-stripped algorithm name; value maps a
// Role to the PQC replacement. This is the single configuration point for
// migration and is intentionally data-driven rather than scattered through
// the implementation.
struct MigrationRule {
    std::string signature;
    std::string key_exchange;
    std::string other;
};

const std::unordered_map<std::string, MigrationRule>& rules() {
    static const std::unordered_map<std::string, MigrationRule> kRules = {
        {"RSA",   {"ML-DSA", "", "ML-DSA"}},
        {"ECDSA", {"ML-DSA", "", ""}},
        {"DH",    {"", "ML-KEM", ""}},
    };
    return kRules;
}

std::string normalize(std::string_view name) {
    std::string out;
    for (unsigned char c : name) {
        if (!std::isspace(c)) {
            out += static_cast<char>(std::toupper(c));
        }
    }
    return out;
}

std::string lowercase(std::string_view s) {
    std::string out;
    for (unsigned char c : s) {
        out += static_cast<char>(std::tolower(c));
    }
    return out;
}

bool contains(std::string_view haystack, std::string_view needle) {
    return lowercase(haystack).find(lowercase(needle)) != std::string::npos;
}

} // namespace

Role detect_role(std::string_view type, std::string_view context) {
    if (contains(type, "signature") || contains(type, "sign") ||
        contains(context, "signature") || contains(context, "sign") ||
        contains(context, "signing")) {
        return Role::Signature;
    }
    if (contains(type, "key-exchange") || contains(type, "key_exchange") ||
        contains(type, "exchange") ||
        contains(context, "key exchange") || contains(context, "key_exchange") ||
        contains(context, "exchange") || contains(context, "handshake") ||
        contains(context, "tls") || contains(context, "agreement")) {
        return Role::KeyExchange;
    }

    return Role::Other;
}

std::string_view role_to_string(Role role) {
    switch (role) {
        case Role::Signature:   return "signature";
        case Role::KeyExchange: return "key_exchange";
        case Role::Other:       return "other";
    }
    return "other";
}

Migration map_migration(const CryptoAsset& asset, const TaxonomyEntry* entry) {
    Role role = Role::Other;
    bool pqc_vulnerable = false;

    if (entry != nullptr) {
        // Member 2 taxonomy is authoritative for the PQC vulnerability and
        // provides the canonical algorithm type for role detection.
        pqc_vulnerable = entry->pqc_vulnerable;
        role = detect_role(entry->type, asset.context);
    } else {
        role = detect_role("", asset.context);
    }

    if (role == Role::Other) {
        // No explicit role signal. Default by algorithm family.
        const std::string algo = normalize(asset.algorithm);
        if (algo == "RSA" || algo == "ECDSA") {
            role = Role::Signature;
        } else if (algo == "DH") {
            role = Role::KeyExchange;
        }
    }

    return map_migration_for_role(asset.algorithm, role, pqc_vulnerable);
}

Migration map_migration_for_role(const std::string& algorithm,
                                 Role role,
                                 bool pqc_vulnerable) {
    Migration result;
    result.algorithm = algorithm;
    result.role = std::string(role_to_string(role));
    result.pqc_vulnerable = pqc_vulnerable;

    const auto it = rules().find(normalize(algorithm));
    if (it == rules().end()) {
        // Algorithm is not in the migration catalog -> no replacement.
        result.supported = false;
        return result;
    }

    const MigrationRule& rule = it->second;
    std::string replacement;
    switch (role) {
        case Role::Signature:   replacement = rule.signature;    break;
        case Role::KeyExchange: replacement = rule.key_exchange; break;
        case Role::Other:       replacement = rule.other;        break;
    }

    result.replacement = replacement;
    // A replacement is "supported" only when we actually know one for the
    // given algorithm+role combination.
    result.supported = !replacement.empty();
    return result;
}

} // namespace pqc
} // namespace ecdat
