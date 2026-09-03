// test_flow.cpp
//
// End-to-end integration test of the full Member 1 -> Member 2 -> Member 3
// flow, using Member 1's real discovery fixtures and the authoritative
// Member 2 taxonomy. Verifies that real Member 1 output flows through the
// pipeline into Member 3's risk / migration / explanation.

#include "flow.h"
#include "ecdat/taxonomy.hpp"

#include <gtest/gtest.h>

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

namespace ecdat {
namespace flow {
namespace {

TaxonomyDB load_db() {
    return TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
}

TEST(FlowIntegration, SourceScannerFlowClassifiesAndExplainsMd5) {
    auto db = load_db();
    auto results = analyze_source_file(M1_FIXTURE_PY, db, 60.0, 40.0);

    // sample.py contains a single md5 weak-crypto call.
    ASSERT_GE(results.size(), 1u);

    // Member 2 classifies md5 (case-insensitive) -> Deprecated.
    EXPECT_EQ(results[0].status, Status::Deprecated);
    EXPECT_FALSE(results[0].pqc_flag);

    // Member 3 explanation uses the REAL Member 1 file + line.
    EXPECT_EQ(results[0].explanation.where, std::string(M1_FIXTURE_PY) + ":4");
    EXPECT_EQ(results[0].explanation.what, "md5 detected");
}

TEST(FlowIntegration, TlsConfigFlowDiscoversWeakTlsAndCiphers) {
    auto db = load_db();
    auto results = analyze_tls_config(M1_FIXTURE_TLS, db, 60.0, 40.0);

    // ssl_protocols TLSv1.0 TLSv1.1 + ssl_ciphers RC4:DES -> 4 assets.
    ASSERT_GE(results.size(), 4u);

    bool found_rc4 = false;
    bool found_des = false;
    for (const auto& r : results) {
        if (r.migration.algorithm == "RC4" && r.status == Status::Deprecated) found_rc4 = true;
        if (r.migration.algorithm == "DES" && r.status == Status::Deprecated) found_des = true;
    }
    EXPECT_TRUE(found_rc4);
    EXPECT_TRUE(found_des);
}

TEST(FlowIntegration, FullFlowProducesReadinessSummary) {
    auto db = load_db();
    // No certificate fixture exists yet; pass the TLS fixture as a dummy so the
    // cert scanner simply finds nothing parseable.
    auto s = analyze_all(M1_FIXTURE_PY, M1_FIXTURE_TLS, M1_FIXTURE_TLS, db, 60.0, 40.0);

    // src: md5 (source) + 4 tls assets. Cert scan on a non-PEM file yields 0.
    ASSERT_EQ(s.total, 5u);

    // All discovered weak assets here are non-quantum-vulnerable (MD5/RC4/DES/
    // TLS versions), so they need no PQC migration and count as "ready".
    EXPECT_EQ(s.ready, 5u);
    EXPECT_DOUBLE_EQ(s.readiness_percent, 100.0);

    // Every result carries Member 3 risk + readiness + explanation fields.
    bool any = false;
    for (const auto& r : s.results) {
        any = true;
        EXPECT_GE(r.final_risk, 0.0);
        EXPECT_LE(r.final_risk, 100.0);
        EXPECT_FALSE(r.explanation.what.empty());
        EXPECT_FALSE(r.explanation.where.empty());
    }
    EXPECT_TRUE(any);
}

} // namespace
} // namespace flow
} // namespace ecdat
