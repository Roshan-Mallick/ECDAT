// flow.cpp
//
// Implementation of the ECDAT full discovery -> analysis flow.
// See flow.h for the contract.

#include "flow.h"

#include "source_scanner.hpp"
#include "cert_scanner.hpp"
#include "tls_scanner.hpp"
#include "pqc/readiness.h"

#include <algorithm>
#include <utility>
#include <vector>

namespace ecdat {
namespace flow {

namespace {

// Run the pipeline on a batch of assets discovered by Member 1.
std::vector<PipelineResult> process(const std::vector<CryptoAsset>& assets,
                                    const TaxonomyDB& db,
                                    double exposure, double remediation) {
    std::vector<PipelineResult> results;
    results.reserve(assets.size());
    for (const auto& asset : assets) {
        results.push_back(run_pipeline(asset, db, exposure, remediation));
    }
    return results;
}

} // namespace

std::vector<PipelineResult> analyze_source_file(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation) {
    return process(scan_source_file(path), db, exposure, remediation);
}

std::vector<PipelineResult> analyze_certificate(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation) {
    return process(scan_certificate(path), db, exposure, remediation);
}

std::vector<PipelineResult> analyze_tls_config(
    const std::string& path, const TaxonomyDB& db,
    double exposure, double remediation) {
    return process(scan_tls_config(path), db, exposure, remediation);
}

Summary analyze_all(const std::string& source_path,
                    const std::string& cert_path,
                    const std::string& tls_path,
                    const TaxonomyDB& db,
                    double exposure, double remediation) {
    Summary s;
    auto src = analyze_source_file(source_path, db, exposure, remediation);
    auto cert = analyze_certificate(cert_path, db, exposure, remediation);
    auto tls = analyze_tls_config(tls_path, db, exposure, remediation);

    // Merge results from every scanner. A scanner may return nothing (e.g. a
    // missing/optional file), which is fine.
    for (auto& r : src) s.results.push_back(std::move(r));
    for (auto& r : cert) s.results.push_back(std::move(r));
    for (auto& r : tls) s.results.push_back(std::move(r));
    s.total = s.results.size();
    s.ready = static_cast<std::size_t>(std::count_if(
        s.results.begin(), s.results.end(),
        [](const PipelineResult& r) {
            return !r.pqc_flag || r.migration.supported;
        }));
    s.readiness_percent = pqc::readiness_percentage(s.ready, s.total);
    return s;
}

} // namespace flow
} // namespace ecdat
