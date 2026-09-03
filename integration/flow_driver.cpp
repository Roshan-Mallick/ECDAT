// flow_driver.cpp
//
// Standalone driver for the full ECDAT Member 1 -> Member 2 -> Member 3 flow.
//
//   Member 1 (scanners)  ->   Member 2 (taxonomy)  ->  Member 3 (risk + PQC)
//
// Usage:
//   ecdat_discovery_driver [source.py] [cert.pem] [tls.conf]
// Defaults to the bundled Member 1 fixtures when arguments are omitted.

#include "flow.h"
#include "ecdat/taxonomy.hpp"

#include <iostream>
#include <string>

#ifndef ECDAT_TAXONOMY_PATH
#define ECDAT_TAXONOMY_PATH "member_2/taxonomy/data/taxonomy.yaml"
#endif
#ifndef M1_FIXTURE_PY
#define M1_FIXTURE_PY "member_1/fixtures/sample.py"
#endif
#ifndef M1_FIXTURE_TLS
#define M1_FIXTURE_TLS "member_1/fixtures/sample_nginx.conf"
#endif

int main(int argc, char** argv) {
    const std::string src = (argc > 1) ? argv[1] : M1_FIXTURE_PY;
    const std::string cert = (argc > 2) ? argv[2] : "";
    const std::string tls = (argc > 3) ? argv[3] : M1_FIXTURE_TLS;

    std::cout << "=== ECDAT Full Flow (Member 1 -> 2 -> 3) ===\n";

    ecdat::TaxonomyDB db;
    try {
        db = ecdat::TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << "\n";
        return 1;
    }
    std::cout << "Taxonomy loaded: " << db.size() << " algorithm(s)\n\n";

    auto summary = ecdat::flow::analyze_all(src, cert, tls, db, 60.0, 40.0);

    std::cout << "Discovered: " << summary.total << " asset(s)\n\n";
    for (std::size_t i = 0; i < summary.results.size(); ++i) {
        const auto& r = summary.results[i];
        std::cout << "  [" << (i + 1) << "] " << r.migration.algorithm
                  << "  status=" << ecdat::status_to_string(r.status)
                  << "  risk=" << r.final_risk
                  << " (" << ecdat::risk::riskLevelToString(r.risk_level) << ")"
                  << "  pqc=" << (r.pqc_flag ? "yes" : "no") << "\n"
                  << "      where: " << r.explanation.where << "\n"
                  << "      why:   " << r.explanation.why << "\n"
                  << "      act:   " << r.explanation.action << "\n";
    }

    std::cout << "\nReadiness: " << summary.ready << " / " << summary.total
              << " (" << summary.readiness_percent << "%)\n";
    return 0;
}
