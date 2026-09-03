#pragma once

// ECDAT Integration Pipeline
//
// Connects Member 2 (classification) with Member 3 (risk engine + PQC
// intelligence). The pipeline is a THIN adapter: it passes the real Member 2
// CryptoAsset and its classification directly into Member 3 and adapts only
// the interface boundary (risk score scale). It owns no classification or
// intelligence logic.
//
//   Member 2 CryptoAsset
//        ↓ classify_asset()          [Member 2, authoritative taxonomy]
//        ↓ risk_score [0-10] → ×10 → weakness
//        ↓                            [Member 3]
//        ↓ calculateRisk()            risk engine
//        ↓ map_migration()            PQC migration (role-aware)
//        ↓ explain()                  What / Where / Why / Action
//
// Member 3 receives the real CryptoAsset (algorithm, key_size, curve, file,
// line, context) and the Member 2 Classification (status, pqc_flag), so it
// never needs to reconstruct or duplicate asset data.

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"
#include "risk/risk_engine.h"
#include "pqc/pqc.h"

#include <string>

namespace ecdat {

// Complete result of running an asset through the full pipeline.
struct PipelineResult {
    // From Member 2 classification
    const TaxonomyEntry* taxonomy_entry = nullptr;
    Status               status        = Status::Unknown;
    double               risk_score    = 0.0;   // Member 2 score (0-10)
    bool                 pqc_flag      = false;

    // From Member 3 risk engine
    double  weakness     = 0.0;   // scaled from risk_score (0-100)
    double  exposure     = 0.0;
    double  remediation  = 0.0;
    double  final_risk   = 0.0;   // Member 3 weighted score (0-100)
    risk::RiskLevel risk_level = risk::RiskLevel::LOW;

    // From Member 3 PQC intelligence (built from the real CryptoAsset)
    pqc::Migration migration;
    pqc::Explanation explanation;
};

// Run a single CryptoAsset through the full ECDAT pipeline.
//
// Parameters:
//   asset        - the real asset to classify and score (its fields are
//                  preserved and forwarded to Member 3)
//   db           - the Member 2 authoritative taxonomy database
//   exposure     - 0-100, how exposed/public this asset is
//   remediation  - 0-100, how hard the fix would be
//
// Returns:
//   A PipelineResult containing classification, risk, migration, and
//   explanation results.
//
// Throws:
//   std::invalid_argument if exposure/remediation are out of 0-100 range.
PipelineResult run_pipeline(const CryptoAsset& asset,
                            const TaxonomyDB& db,
                            double exposure,
                            double remediation);

// Convenience: classify only (ignores exposure/remediation).
// Returns the Member 2 Classification directly.
Classification classify_only(const CryptoAsset& asset, const TaxonomyDB& db);

} // namespace ecdat
