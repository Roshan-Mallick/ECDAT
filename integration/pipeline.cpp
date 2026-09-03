#include "pipeline.h"

#include <algorithm>
#include <stdexcept>

namespace ecdat {

namespace {

// Member 2 risk_score is on [0,10]. The risk engine expects inputs on [0,100].
// A simple ×10 scaling maps between them faithfully.
constexpr double kScaleTo100 = 10.0;

} // namespace

PipelineResult run_pipeline(const CryptoAsset& asset,
                            const TaxonomyDB& db,
                            double exposure,
                            double remediation) {
    PipelineResult result;

    // --- Stage 1: Member 2 classification (authoritative taxonomy) ---------
    Classification c = classify_asset(asset, db);
    result.taxonomy_entry = c.entry;
    result.status         = c.status;
    result.risk_score     = c.risk_score;
    result.pqc_flag       = c.pqc_flag;

    // --- Stage 2: Map to Member 3 risk-engine inputs -----------------------
    // For unknown algorithms (risk_score == 0), the weakness is 0 — the
    // risk engine will weight it accordingly.  This is intentional:
    // unknown algorithms carry zero "known weakness" signal.
    result.weakness    = std::clamp(c.risk_score * kScaleTo100, 0.0, 100.0);
    result.exposure    = exposure;
    result.remediation = remediation;

    // --- Stage 3: Member 3 risk engine -------------------------------------
    result.final_risk = risk::calculateRisk(
        result.weakness, result.exposure, result.remediation);
    result.risk_level = risk::classifyRisk(result.final_risk);

    // --- Stage 4: Member 3 PQC intelligence --------------------------------
    // The real Member 2 CryptoAsset + Classification flow straight into
    // Member 3; nothing is reconstructed here.
    result.migration   = pqc::map_migration(asset, c.entry);
    result.explanation = pqc::explain(asset, c, result.migration);

    return result;
}

Classification classify_only(const CryptoAsset& asset, const TaxonomyDB& db) {
    return classify_asset(asset, db);
}

} // namespace ecdat
