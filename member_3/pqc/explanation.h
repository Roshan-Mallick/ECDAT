// explanation.h
//
// ECDAT Member 3 - Explainability
//
// Purpose:
//   Produces structured, human-readable explanations for a cryptographic
//   finding. Each explanation contains four fields drawn from the real
//   CryptoAsset and its Member 2 classification:
//
//     What    - a summary of what was detected (algorithm + key size)
//     Where   - the source location (file:line)
//     Why     - the reason it is risky / PQC-vulnerable
//     Action  - the recommended remediation
//
//   Values are built from the actual asset's file, line, algorithm, key_size,
//   curve and context, plus the classification result; nothing is fabricated.

#pragma once

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"
#include "migration.h"

#include <string>

namespace ecdat {
namespace pqc {

struct Explanation {
    std::string what;
    std::string where;
    std::string why;
    std::string action;
};

// Build a structured explanation for a single asset.
// The migration is used to recommend a concrete PQC action when available.
[[nodiscard]] Explanation explain(const CryptoAsset& asset,
                                  const Classification& classification,
                                  const Migration& migration);

} // namespace pqc
} // namespace ecdat
