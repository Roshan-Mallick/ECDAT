// readiness.h
//
// ECDAT Member 3 - PQC Readiness Calculation
//
// Purpose:
//   Computes a single "PQC readiness" measure for a collection of discovered
//   assets.
//
//   Definition:
//     readiness_percentage = (ready assets / total assets) * 100
//
//   An empty collection (total == 0) is handled safely and produces 0% to
//   avoid a division by zero.
//
//   An individual asset is considered "ready" when it does not require PQC
//   migration: either it is not quantum-vulnerable at all (pqc_flag false),
//   or it is vulnerable but a supported migration path is available.

#pragma once

#include <cstddef>
#include <vector>

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"
#include "migration.h"

namespace ecdat {
namespace pqc {

// Numeric readiness percentage in [0, 100]. Returns 0.0 when total == 0.
[[nodiscard]] double readiness_percentage(std::size_t ready,
                                          std::size_t total);

// Per-asset readiness decision: true when a single asset is PQC-ready.
[[nodiscard]] bool is_asset_ready(const Migration& migration);

// Assess a collection of assets. Consumes each asset with its authoritative
// Member 2 taxonomy entry; that entry supplies the PQC vulnerability signal.
struct ReadinessReport {
    std::size_t ready = 0;
    std::size_t total = 0;
    double percentage = 0.0;
};

[[nodiscard]] ReadinessReport assess_readiness(
    const std::vector<std::pair<CryptoAsset, const TaxonomyEntry*>>& assets);

} // namespace pqc
} // namespace ecdat
