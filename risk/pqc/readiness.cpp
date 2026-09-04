// readiness.cpp
//
// Implementation of the ECDAT Member 3 PQC readiness calculation.
// See readiness.h for the full contract.

#include "readiness.h"

namespace ecdat {
namespace pqc {

double readiness_percentage(std::size_t ready, std::size_t total) {
    if (total == 0) {
        return 0.0;
    }
    return (static_cast<double>(ready) / static_cast<double>(total)) * 100.0;
}

bool is_asset_ready(const Migration& migration) {
    // Not quantum-vulnerable -> already PQC-ready (no migration needed).
    // Quantum-vulnerable -> ready only if a supported migration exists.
    return !migration.pqc_vulnerable || migration.supported;
}

ReadinessReport assess_readiness(
    const std::vector<std::pair<CryptoAsset, const TaxonomyEntry*>>& assets) {
    ReadinessReport report;
    report.total = assets.size();

    for (const auto& [asset, entry] : assets) {
        Migration migration = map_migration(asset, entry);
        if (is_asset_ready(migration)) {
            ++report.ready;
        }
    }

    report.percentage = readiness_percentage(report.ready, report.total);
    return report;
}

} // namespace pqc
} // namespace ecdat
