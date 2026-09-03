#include "ecdat/taxonomy.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace ecdat {
namespace {

// Hand-crafted assets as required by the member contract (no dependency on
// Member 1 discovery).
CryptoAsset asset(const std::string& algorithm, long long key_size = 0,
                  const std::string& curve = "") {
    CryptoAsset a;
    a.algorithm = algorithm;
    a.key_size = key_size;
    a.curve = curve;
    return a;
}

TaxonomyDB default_db() {
    return TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: SHA-256, type: hash, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
  - {name: MD5, type: hash, status: Deprecated, risk_base: 9.0, pqc_vulnerable: false, replacement: SHA-256}
  - {name: ChaCha20, type: symmetric, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
  - {name: RC4, type: symmetric, status: Deprecated, risk_base: 9.5, pqc_vulnerable: false, replacement: AES-256, min_secure_key_bits: 128}
  - {name: RSA, type: asymmetric, status: Weak, risk_base: 5.0, pqc_vulnerable: true, replacement: ECDSA-P256, min_secure_key_bits: 2048}
  - {name: ECDSA, type: signature, status: Weak, risk_base: 5.5, pqc_vulnerable: true, replacement: ECDSA-P384, weak_curves: [P-192, P-160]}
  - {name: AESTEST, type: symmetric, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
)");
}

// ---- Known algorithm classification --------------------------------------

TEST(Classifier, KnownSafeAlgorithm) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("SHA-256"), db), Status::Safe);
    EXPECT_EQ(classify(asset("ChaCha20"), db), Status::Safe);
}

TEST(Classifier, KnownWeakAlgorithm) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("RSA"), db), Status::Weak);
    EXPECT_EQ(classify(asset("ECDSA"), db), Status::Weak);
}

TEST(Classifier, KnownDeprecatedAlgorithm) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("MD5"), db), Status::Deprecated);
    EXPECT_EQ(classify(asset("RC4"), db), Status::Deprecated);
}

// ---- Unknown / fallback ---------------------------------------------------

TEST(Classifier, UnknownAlgorithmIsUnknown) {
    auto db = default_db();
    CryptoAsset a;
    a.algorithm = "FOOCIPHER";
    const auto result = classify_asset(a, db);
    EXPECT_EQ(result.status, Status::Unknown);
    EXPECT_EQ(result.risk_score, 0.0);
    EXPECT_FALSE(result.pqc_flag);
    EXPECT_EQ(result.entry, nullptr);
}

TEST(Classifier, EmptyAlgorithmIsUnknown) {
    auto db = default_db();
    EXPECT_EQ(classify(asset(""), db), Status::Unknown);
}

TEST(Classifier, UnknownAlgorithmNeverClaimsPqcSafeOrRisky) {
    auto db = default_db();
    const auto result = classify_asset(asset("UNKNOWN-X"), db);
    EXPECT_FALSE(result.pqc_flag);
    EXPECT_EQ(result.risk_score, 0.0);
}

// ---- Case insensitivity -----------------------------------------------------

TEST(Classifier, CaseInsensitiveClassification) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("SHA-256"), db), Status::Safe);
    EXPECT_EQ(classify(asset("sha-256"), db), Status::Safe);
    EXPECT_EQ(classify(asset("ShA-256"), db), Status::Safe);
    EXPECT_EQ(classify(asset("sHa-256"), db), Status::Safe);
}

TEST(Classifier, MixedCaseWeak) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("rsa"), db), Status::Weak);
    EXPECT_EQ(classify(asset("RSA"), db), Status::Weak);
    EXPECT_EQ(classify(asset("rSa"), db), Status::Weak);
}

// ---- Key / curve overrides ------------------------------------------------

TEST(Classifier, Rsa1024OverrideToWeak) {
    auto db = default_db();
    // RSA general status is Weak, but with a 1024-bit key the risk must be
    // adjusted (+2.0) and status remains/to Weak.
    const auto large = classify_asset(asset("RSA", 4096), db);
    const auto small = classify_asset(asset("RSA", 1024), db);

    EXPECT_EQ(large.status, Status::Weak);
    EXPECT_EQ(small.status, Status::Weak);

    // 4096 -> base 5.0; 1024 -> base 5.0 + 2.0 = 7.0.
    EXPECT_EQ(large.risk_score, 5.0);
    EXPECT_EQ(small.risk_score, 7.0);
}

TEST(Classifier, EcdsaP192CurveOverride) {
    auto db = default_db();
    const auto normal = classify_asset(asset("ECDSA", 256, "P-256"), db);
    const auto weak_curve = classify_asset(asset("ECDSA", 256, "P-192"), db);

    EXPECT_EQ(normal.status, Status::Weak);
    EXPECT_EQ(weak_curve.status, Status::Weak);
    EXPECT_EQ(normal.risk_score, 5.5);
    EXPECT_EQ(weak_curve.risk_score, 7.5); // +2.0 adjustment
}

TEST(Classifier, CurveOverrideIsCaseInsensitive) {
    auto db = default_db();
    EXPECT_EQ(classify(asset("ECDSA", 256, "p-192"), db), Status::Weak);
    EXPECT_EQ(classify(asset("ECDSA", 256, "P-192"), db), Status::Weak);
    EXPECT_EQ(classify(asset("ECDSA", 256, "P-160"), db), Status::Weak);
}

TEST(Classifier, CurveOverrideRespectsUnknownCurve) {
    auto db = default_db();
    // Unknown curve that is not in the weak list -> no extra adjustment.
    const auto result = classify_asset(asset("ECDSA", 256, "MysteryCurve"), db);
    EXPECT_EQ(result.risk_score, 5.5);
}

TEST(Classifier, KeyBitsZeroIsNotDowngraded) {
    auto db = default_db();
    // key_size == 0 means "unknown"; it must not trigger a min-key downgrade.
    const auto result = classify_asset(asset("RSA", 0), db);
    EXPECT_EQ(result.risk_score, 5.0);
}

TEST(Classifier, VeryLargeKeyBitsNotDowngraded) {
    auto db = default_db();
    const auto result = classify_asset(asset("RSA", 8192), db);
    EXPECT_EQ(result.risk_score, 5.0);
}

// ---- Risk score -----------------------------------------------------------

TEST(Classifier, RiskScoreEqualsBaseForSafe) {
    auto db = default_db();
    EXPECT_EQ(classify_asset(asset("SHA-256"), db).risk_score, 1.0);
}

TEST(Classifier, DowngradeAdjustmentAddsTwo) {
    auto db = default_db();
    const auto result = classify_asset(asset("RC4", 40), db);
    // RC4 base 9.5 + 2.0 = 11.5 -> clamped to 10.0.
    EXPECT_EQ(result.risk_score, 10.0);
}

TEST(Classifier, RiskScoreUpperClamp) {
    auto db = TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: HIRISK, type: asymmetric, status: Weak, risk_base: 9.8, pqc_vulnerable: true, replacement: "", min_secure_key_bits: 2048}
)");
    // 9.8 + 2.0 = 11.8 -> clamped to 10.0.
    EXPECT_EQ(classify_asset(asset("HIRISK", 512), db).risk_score, 10.0);
    // base alone (large key) is 9.8 < 10, unchanged.
    EXPECT_EQ(classify_asset(asset("HIRISK", 4096), db).risk_score, 9.8);
}

TEST(Classifier, RiskScoreLowerClampForNegativeBase) {
    auto db = TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: NEGRISK, type: hash, status: Safe, risk_base: -5.0, pqc_vulnerable: false, replacement: ""}
)");
    EXPECT_EQ(classify_asset(asset("NEGRISK"), db).risk_score, 0.0);
}

TEST(Classifier, RiskScoreBaseExactlyTen) {
    auto db = TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: TENRISK, type: hash, status: Deprecated, risk_base: 10.0, pqc_vulnerable: false, replacement: ""}
)");
    EXPECT_EQ(classify_asset(asset("TENRISK"), db).risk_score, 10.0);
}

TEST(Classifier, RiskScoreBaseOverTenIsClamped) {
    auto db = TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: OVERRISK, type: hash, status: Deprecated, risk_base: 12.0, pqc_vulnerable: false, replacement: ""}
)");
    EXPECT_EQ(classify_asset(asset("OVERRISK"), db).risk_score, 10.0);
}

TEST(Classifier, RiskScoreNeverNegativeOrOverTen) {
    auto db = TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: LOW, type: hash, status: Safe, risk_base: 0.0, pqc_vulnerable: false}
  - {name: HIGH, type: hash, status: Deprecated, risk_base: 99.0, pqc_vulnerable: false, min_secure_key_bits: 128}
)");
    const auto low = classify_asset(asset("LOW"), db);
    const auto high = classify_asset(asset("HIGH", 64), db);
    EXPECT_GE(low.risk_score, 0.0);
    EXPECT_LE(low.risk_score, 10.0);
    EXPECT_GE(high.risk_score, 0.0);
    EXPECT_LE(high.risk_score, 10.0);
}

// ---- PQC flag propagation ---------------------------------------------------

TEST(Classifier, PqcFlagPropagatedForVulnerableAlgorithm) {
    auto db = default_db();
    EXPECT_TRUE(classify_asset(asset("RSA"), db).pqc_flag);
    EXPECT_TRUE(classify_asset(asset("ECDSA"), db).pqc_flag);
}

TEST(Classifier, PqcFlagFalseForNonVulnerableAlgorithm) {
    auto db = default_db();
    EXPECT_FALSE(classify_asset(asset("SHA-256"), db).pqc_flag);
    EXPECT_FALSE(classify_asset(asset("ChaCha20"), db).pqc_flag);
}

TEST(Classifier, PqcFlagFalseForUnknown) {
    auto db = default_db();
    EXPECT_FALSE(classify_asset(asset("NOPE"), db).pqc_flag);
}

// ---- Taxonomy status propagation ------------------------------------------

TEST(Classifier, TaxonomyStatusPropagatesToAsset) {
    auto db = default_db();

    CryptoAsset a = asset("MD5");
    a.status = Status::Unknown; // classifier should overwrite
    const auto result = classify_asset(a, db);
    EXPECT_EQ(result.status, Status::Deprecated);
}

// ---- Empty database ---------------------------------------------------------

TEST(Classifier, EmptyDatabaseEverythingUnknown) {
    auto db = TaxonomyDB::load_from_string("algorithms: []");
    EXPECT_TRUE(db.empty());
    EXPECT_EQ(classify(asset("RSA"), db), Status::Unknown);
    EXPECT_EQ(classify(asset("SHA-256"), db), Status::Unknown);
}

} // namespace
} // namespace ecdat
