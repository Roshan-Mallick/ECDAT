// flow.h
//
// ECDAT Full Discovery -> Analysis Flow (Member 1 -> Member 2 -> Member 3).
//
// Overview:
//   Member 1 (discovery scanners)  produce ecdat::CryptoAsset
//        ↓  (authoritative shared contract)
//   Member 2 (taxonomy classifier)  ecdat::classify_asset()
//        ↓  Classification
//   Member 3 (risk + PQC)           run_pipeline() -> risk, migration,
//                                   readiness contribution, explanation
//
// This module owns no analysis logic; it is a thin orchestration layer that
// feeds real Member 1 output straight into the existing pipeline.

#pragma once

#include "ecdat/types.hpp"
#include "ecdat/taxonomy.hpp"
#include "pipeline.h"

#include <string>
#include <vector>

namespace ecdat {
namespace flow {

// Run the full flow over every asset discovered by a single Member 1 scanner.
// Each discovered asset yields one PipelineResult (risk, migration,
// explanation) produced from real Member 1 output.
std::vector<PipelineResult> analyze_source_file(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation);

std::vector<PipelineResult> analyze_certificate(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation);

std::vector<PipelineResult> analyze_tls_config(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation);

// Aggregate outcome of analyzing every discovered asset.
struct Summary {
    std::vector<PipelineResult> results;
    std::size_t ready = 0;
    std::size_t total = 0;
    double readiness_percent = 0.0;
};

// Run the complete Member 1 -> Member 2 -> Member 3 flow over a source file,
// a certificate, and a TLS config (as produced by the Member 1 main driver),
// and aggregate the per-asset readiness.
Summary analyze_all(const std::string& source_path,
                    const std::string& cert_path,
                    const std::string& tls_path,
                    const TaxonomyDB& db,
                    double exposure, double remediation);

} // namespace flow
} // namespace ecdat
