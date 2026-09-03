#include "ecdat/storage.hpp"
#include "ecdat/reporting.hpp"
#include "ecdat/taxonomy.hpp"
#include "flow.h"
#include "pipeline.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
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
namespace {

TEST(Member4Integration, FullDiscoveryToStorageAndReports) {
    // 1. Load authoritative Member 2 taxonomy
    ASSERT_TRUE(std::filesystem::exists(ECDAT_TAXONOMY_PATH));
    auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    EXPECT_GT(db.size(), 0u);

    // 2. Run Member 1 -> Member 2 -> Member 3 Flow
    auto summary = flow::analyze_all(M1_FIXTURE_PY, "", M1_FIXTURE_TLS, db, 60.0, 40.0);
    ASSERT_GE(summary.total, 5u);

    // 3. Persist to Member 4 SQLite Storage
    storage::Storage store(":memory:");
    std::int64_t scan_id = store.save_scan("integration_test_target", summary.results, summary.readiness_percent);
    EXPECT_GT(scan_id, 0);

    // 4. Retrieve Scan Detail
    auto opt_detail = store.get_scan(scan_id);
    ASSERT_TRUE(opt_detail.has_value());
    const auto& detail = *opt_detail;

    EXPECT_EQ(detail.scan.id, scan_id);
    EXPECT_EQ(detail.scan.total_assets, static_cast<std::int64_t>(summary.total));
    EXPECT_DOUBLE_EQ(detail.scan.pqc_readiness_pct, summary.readiness_percent);
    ASSERT_EQ(detail.findings.size(), summary.results.size());

    // 5. Generate JSON report and verify structure
    std::string json_data = reporting::generate_json(detail);
    ASSERT_FALSE(json_data.empty());
    auto parsed = nlohmann::json::parse(json_data);
    EXPECT_EQ(parsed["summary"]["total_assets"], summary.total);
    EXPECT_EQ(parsed["findings"].size(), summary.total);

    // 6. Generate CSV report and verify lines
    std::string csv_data = reporting::generate_csv(detail);
    ASSERT_FALSE(csv_data.empty());
    EXPECT_TRUE(csv_data.find("md5") != std::string::npos || csv_data.find("MD5") != std::string::npos);
    EXPECT_TRUE(csv_data.find("RC4") != std::string::npos || csv_data.find("rc4") != std::string::npos);

    // 7. Generate PDF report and verify binary structure
    std::string pdf_data = reporting::generate_pdf(detail);
    ASSERT_GE(pdf_data.size(), 200u);
    EXPECT_EQ(pdf_data.substr(0, 5), "%PDF-");
    EXPECT_NE(pdf_data.find("%%EOF"), std::string::npos);
}

TEST(Member4Integration, SQLiteRoundTripPreservesExactCryptoAsset) {
    // 1. Load taxonomy
    ASSERT_TRUE(std::filesystem::exists(ECDAT_TAXONOMY_PATH));
    auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);

    // 2. Construct CryptoAsset with distinctive non-default values
    CryptoAsset original;
    original.source_type = "source_code";
    original.file = "fixtures/roundtrip_unique_crypto.py";
    original.line = 137;
    original.algorithm = "AES";
    original.key_size = 256;
    original.curve = "secp256r1";
    original.context = "DISTINCTIVE_ROUND_TRIP_CONTEXT_FOR_TEST";

    // 3. Run pipeline and verify PipelineResult retains the original asset
    PipelineResult p_res = run_pipeline(original, db, 50.0, 50.0);
    EXPECT_EQ(p_res.asset.source_type, original.source_type);
    EXPECT_EQ(p_res.asset.file, original.file);
    EXPECT_EQ(p_res.asset.line, original.line);
    EXPECT_EQ(p_res.asset.algorithm, original.algorithm);
    EXPECT_EQ(p_res.asset.key_size, original.key_size);
    EXPECT_EQ(p_res.asset.curve, original.curve);
    EXPECT_EQ(p_res.asset.context, original.context);

    // 4. Save to SQLite storage
    storage::Storage store(":memory:");
    std::vector<PipelineResult> results = { p_res };
    std::int64_t scan_id = store.save_scan("roundtrip_target", results, 100.0);
    ASSERT_GT(scan_id, 0);

    // 5. Retrieve from SQLite storage
    auto opt_detail = store.get_scan(scan_id);
    ASSERT_TRUE(opt_detail.has_value());
    const auto& detail = *opt_detail;
    ASSERT_EQ(detail.findings.size(), 1u);

    const auto& f = detail.findings[0];
    EXPECT_EQ(f.source_type, "source_code");
    EXPECT_EQ(f.file, "fixtures/roundtrip_unique_crypto.py");
    EXPECT_EQ(f.line, 137);
    EXPECT_EQ(f.algorithm, "AES");
    EXPECT_EQ(f.key_size, 256);
    EXPECT_EQ(f.curve, "secp256r1");
    EXPECT_EQ(f.context, "DISTINCTIVE_ROUND_TRIP_CONTEXT_FOR_TEST");
}

} // namespace
} // namespace ecdat
