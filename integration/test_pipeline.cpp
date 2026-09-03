#include "pipeline.h"

#include <gtest/gtest.h>

#include <string>

namespace ecdat {
namespace {

// Shared taxonomy DB for integration tests.
TaxonomyDB test_db() {
    return TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: AES-256, type: symmetric, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
  - {name: RSA, type: asymmetric, status: Weak, risk_base: 5.0, pqc_vulnerable: true, replacement: ECDSA-P256, min_secure_key_bits: 2048}
  - {name: MD5, type: hash, status: Deprecated, risk_base: 9.0, pqc_vulnerable: false, replacement: SHA-256}
)");
}

CryptoAsset make(const std::string& algo, long long bits = 0,
                  const std::string& curve = "") {
    CryptoAsset a;
    a.algorithm = algo;
    a.key_size  = bits;
    a.curve     = curve;
    return a;
}

// ---- Classification stage works independently -----------------------------

TEST(Pipeline, ClassifyOnlyReturnsCorrectStatus) {
    auto db = test_db();
    auto r = classify_only(make("AES-256", 256), db);
    EXPECT_EQ(r.status, Status::Safe);
    EXPECT_EQ(r.risk_score, 1.0);
}

// ---- Full pipeline: Safe algorithm ----------------------------------------

TEST(Pipeline, SafeAlgorithmLowRisk) {
    auto db = test_db();
    auto r = run_pipeline(make("AES-256", 256), db,
                          /*exposure=*/5.0, /*remediation=*/5.0);

    EXPECT_EQ(r.status, Status::Safe);
    EXPECT_FALSE(r.pqc_flag);
    EXPECT_DOUBLE_EQ(r.weakness, 10.0);   // 1.0 × 10
    // 10*0.4 + 5*0.3 + 5*0.3 = 4+1.5+1.5 = 7 → LOW
    EXPECT_DOUBLE_EQ(r.final_risk, 7.0);
    EXPECT_EQ(r.risk_level, risk::RiskLevel::LOW);
}

// ---- Full pipeline: Weak algorithm with key downgrade ---------------------

TEST(Pipeline, RsaSmallKeyHigherRisk) {
    auto db = test_db();
    // RSA 1024-bit → key override, risk_score = 5.0+2.0 = 7.0
    auto r = run_pipeline(make("RSA", 1024), db,
                          /*exposure=*/80.0, /*remediation=*/60.0);

    EXPECT_EQ(r.status, Status::Weak);
    EXPECT_TRUE(r.pqc_flag);
    EXPECT_DOUBLE_EQ(r.weakness, 70.0);  // 7.0 × 10
    EXPECT_EQ(r.risk_level, risk::RiskLevel::HIGH);
}

// ---- Full pipeline: Deprecated algorithm (MD5) ---------------------------

TEST(Pipeline, DeprecatedAlgorithmVeryHighRisk) {
    auto db = test_db();
    // MD5: risk_base=9.0, no key override → weakness=90
    auto r = run_pipeline(make("MD5"), db,
                          /*exposure=*/100.0, /*remediation=*/100.0);

    EXPECT_EQ(r.status, Status::Deprecated);
    EXPECT_DOUBLE_EQ(r.weakness, 90.0);
    // 90*0.4 + 100*0.3 + 100*0.3 = 36+30+30 = 96
    EXPECT_DOUBLE_EQ(r.final_risk, 96.0);
    EXPECT_EQ(r.risk_level, risk::RiskLevel::CRITICAL);
}

// ---- Unknown algorithm returns 0 weakness ---------------------------------

TEST(Pipeline, UnknownAlgorithmZeroWeakness) {
    auto db = test_db();
    auto r = run_pipeline(make("BLOWFISH"), db,
                          /*exposure=*/50.0, /*remediation=*/50.0);

    EXPECT_EQ(r.status, Status::Unknown);
    EXPECT_FALSE(r.pqc_flag);
    EXPECT_DOUBLE_EQ(r.weakness, 0.0);
    // 0*0.4 + 50*0.3 + 50*0.3 = 0+15+15 = 30
    EXPECT_DOUBLE_EQ(r.final_risk, 30.0);
    EXPECT_EQ(r.risk_level, risk::RiskLevel::MEDIUM);
}

// ---- Pipeline result propagates taxonomy entry pointer --------------------

TEST(Pipeline, TaxonomyEntryAvailable) {
    auto db = test_db();
    auto r = run_pipeline(make("RSA", 4096), db, 50.0, 50.0);
    ASSERT_NE(r.taxonomy_entry, nullptr);
    EXPECT_EQ(r.taxonomy_entry->name, "RSA");
    EXPECT_TRUE(r.taxonomy_entry->pqc_vulnerable);
}

TEST(Pipeline, UnknownAlgorithmNoEntry) {
    auto db = test_db();
    auto r = run_pipeline(make("FOO"), db, 50.0, 50.0);
    EXPECT_EQ(r.taxonomy_entry, nullptr);
}

// ---- Exposure/remediation out of range throws -----------------------------

TEST(Pipeline, InvalidExposureThrows) {
    auto db = test_db();
    EXPECT_THROW(run_pipeline(make("RSA"), db, 150.0, 50.0),
                 std::invalid_argument);
}

TEST(Pipeline, NegativeRemediationThrows) {
    auto db = test_db();
    EXPECT_THROW(run_pipeline(make("RSA"), db, 50.0, -10.0),
                 std::invalid_argument);
}

// ---- Risk level boundaries through pipeline -------------------------------

TEST(Pipeline, RiskLevelBoundaries) {
    auto db = test_db();

    // LOW: AES-256 (weakness=10) with low exposure/remediation
    // 10*0.4 + 10*0.3 + 10*0.3 = 4+3+3 = 10 → LOW
    {
        auto r = run_pipeline(make("AES-256", 256), db, 10.0, 10.0);
        EXPECT_EQ(r.risk_level, risk::RiskLevel::LOW);
    }
    // MEDIUM: AES-256 (weakness=10) with moderate exposure/remediation
    // 10*0.4 + 70*0.3 + 50*0.3 = 4+21+15 = 40 → MEDIUM
    {
        auto r = run_pipeline(make("AES-256", 256), db, 70.0, 50.0);
        EXPECT_EQ(r.risk_level, risk::RiskLevel::MEDIUM);
    }
    // HIGH: MD5 (weakness=90) with moderate exposure/remediation
    // 90*0.4 + 60*0.3 + 50*0.3 = 36+18+15 = 69 → HIGH
    {
        auto r = run_pipeline(make("MD5"), db, 60.0, 50.0);
        EXPECT_EQ(r.risk_level, risk::RiskLevel::HIGH);
    }
}

// ---- PQC flag propagates through pipeline ---------------------------------

TEST(Pipeline, PqcFlagPropagated) {
    auto db = test_db();
    auto r = run_pipeline(make("RSA", 2048), db, 50.0, 50.0);
    EXPECT_TRUE(r.pqc_flag);
    EXPECT_EQ(r.taxonomy_entry->pqc_vulnerable, true);
}

} // namespace
} // namespace ecdat
