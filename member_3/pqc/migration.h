// migration.h
//
// ECDAT Member 3 - PQC Migration Mapping
//
// Purpose:
//   Maps a PQC-vulnerable cryptographic asset to an appropriate post-quantum
//   replacement algorithm. The mapping is role-aware: the same algorithm used
//   in a different role can migrate to a different PQC primitive.
//
//   Required role-aware mappings:
//     RSA   + signature   -> ML-DSA
//     ECDSA + signature   -> ML-DSA
//     DH    + key exchange-> ML-KEM
//
//   This module does NOT own classification. It consumes the asset's
//   algorithm, its cryptographic role (derived from the authoritative
//   Member 2 taxonomy type, falling back to the asset context), and the
//   already-computed PQC vulnerability signal from Member 2.
//
//   The rule table is centralized here (a single configuration point),
//   rather than scattering hard-coded checks across the implementation.

#pragma once

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"

#include <string>
#include <string_view>

namespace ecdat {
namespace pqc {

// The cryptographic role of an asset. Determines which PQC primitive is the
// appropriate replacement.
enum class Role {
    Signature,   // e.g. RSA/ECDSA used for signing
    KeyExchange, // e.g. DH used for key agreement
    Other
};

// Result of a migration lookup for a single asset.
struct Migration {
    std::string algorithm;     // source algorithm (original display name)
    std::string role;          // detected role name ("signature", ...)
    std::string replacement;   // PQC replacement algorithm, "" if unsupported
    bool supported = false;    // true when a replacement is available
    bool pqc_vulnerable = false; // true when the source is quantum-threatened
};

// Detect the cryptographic role from the asset's context and the taxonomy
// entry type. The taxonomy type (authoritative, from Member 2) is preferred;
// the asset context is used as a fallback for keyword matching.
//
//   - type/context containing "signature"/"sign"/"signing"  -> Signature
//   - type/context containing "key-exchange"/"key_exchange"/
//     "exchange"/"handshake"/"tls"/"agreement"              -> KeyExchange
//   - otherwise: RSA/ECDSA default to Signature (their most common use),
//     DH defaults to KeyExchange.
[[nodiscard]] Role detect_role(std::string_view type,
                               std::string_view context);

// Convert a Role to a stable lowercase string name.
[[nodiscard]] std::string_view role_to_string(Role role);

// Compute the PQC migration for a single asset.
//
// Consumes the real CryptoAsset (for algorithm + context) and the Member 2
// taxonomy entry type (for role determination). Returns the role-aware
// replacement. Non-vulnerable and unknown algorithms produce
// supported=false with an empty replacement.
[[nodiscard]] Migration map_migration(const CryptoAsset& asset,
                                      const TaxonomyEntry* entry);

// Compute the PQC migration for a single asset given an explicit role.
// Useful for callers that already know the role.
[[nodiscard]] Migration map_migration_for_role(const std::string& algorithm,
                                               Role role,
                                               bool pqc_vulnerable);

} // namespace pqc
} // namespace ecdat
