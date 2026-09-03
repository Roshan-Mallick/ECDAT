#pragma once

// ECDAT Integration Pipeline
//
// Connects Member 2 (classification) with Member 3 (risk engine).
//
//   CryptoAsset → classify_asset() → risk_score [0-10]
//                                          ↓ (scale ×10)
//   weakness [0-100] + exposure + remediation → calculateRisk()
//                                                      ↓
//                                              RiskLevel + final score
//
// This module owns no classification or risk logic itself. It delegates
// to the existing member libraries and adapts their interfaces.

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"
#include "risk/risk_engine.h"

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
};

// Run a single CryptoAsset through the full ECDAT pipeline.
//
// Parameters:
//   asset        - the asset to classify and score
//   db           - the loaded taxonomy database
//   exposure     - 0-100, how exposed/public this asset is
//   remediation  - 0-100, how hard the fix would be
//
// Returns:
//   A PipelineResult containing classification + risk results.
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
