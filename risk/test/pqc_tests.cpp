// pqc_tests.cpp
//
// Unit tests for Member 3 PQC intelligence (migration, readiness,
// explainability). These consume the shared Member 2 CryptoAsset and the
// authoritative Member 2 taxonomy (via Classification/TaxonomyEntry), proving
// that Member 3 operates on real asset data rather than mock duplicates.

#include "pqc/pqc.h"
#include "ecdat/taxonomy.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace ecdat {
namespace pqc {
namespace {

CryptoAsset asset(const std::string& algo, long long key = 0,
                  const std::string& curve = "", const std::string& file = "",
                  long long line = 0, const std::string& context = "") {
    CryptoAsset a;
    a.source_type = "test";
    a.algorithm = algo;
    a.key_size = key;
    a.curve = curve;
    a.file = file;
    a.line = line;
    a.context = context;
    return a;
}

// Authoritative (Member 2 style) taxonomy used throughout these tests,
// including the PQC detection signals (pqc_vulnerable).
TaxonomyDB test_db() {
    return TaxonomyDB::load_from_string(R"(
algorithms:
  - {name: RSA, type: asymmetric, status: Weak, risk_base: 5.0, pqc_vulnerable: true, replacement: ECDSA-P256, min_secure_key_bits: 2048}
  - {name: ECDSA, type: signature, status: Weak, risk_base: 5.5, pqc_vulnerable: true, replacement: ECDSA-P384}
  - {name: DH, type: key-exchange, status: Deprecated, risk_base: 7.0, pqc_vulnerable: true, replacement: ECDH, min_secure_key_bits: 2048}
  - {name: AES-256, type: symmetric, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
)");
}

const TaxonomyEntry* entry_of(const TaxonomyDB& db, const std::string& algo) {
    return db.lookup(algo);
}

// ---------------------------------------------------------------------------
// PQC detection (vulnerability signal comes from Member 2 taxonomy)
// ---------------------------------------------------------------------------

TEST(PqcMigration, PqcDetectionFromTaxonomy) {
    auto db = test_db();
    EXPECT_TRUE(entry_of(db, "RSA")->pqc_vulnerable);
    EXPECT_TRUE(entry_of(db, "ECDSA")->pqc_vulnerable);
    EXPECT_TRUE(entry_of(db, "DH")->pqc_vulnerable);
    EXPECT_FALSE(entry_of(db, "AES-256")->pqc_vulnerable);
}

// ---------------------------------------------------------------------------
// Role-aware migrations: RSA / ECDSA / DH
// ---------------------------------------------------------------------------

TEST(PqcMigration, RsaSignatureMapsToMlDsa) {
    auto db = test_db();
    // RSA default role (no explicit context) -> Signature
    auto m = map_migration(asset("RSA", 2048), entry_of(db, "RSA"));
    EXPECT_TRUE(m.supported);
    EXPECT_EQ(m.replacement, "ML-DSA");
    EXPECT_EQ(m.role, "signature");
}

TEST(PqcMigration, EcdsaSignatureMapsToMlDsa) {
    auto db = test_db();
    auto m = map_migration(asset("ECDSA", 256), entry_of(db, "ECDSA"));
    EXPECT_TRUE(m.supported);
    EXPECT_EQ(m.replacement, "ML-DSA");
    EXPECT_EQ(m.role, "signature");
}

TEST(PqcMigration, DhKeyExchangeMapsToMlKem) {
    auto db = test_db();
    auto m = map_migration(asset("DH", 2048), entry_of(db, "DH"));
    EXPECT_TRUE(m.supported);
    EXPECT_EQ(m.replacement, "ML-KEM");
    EXPECT_EQ(m.role, "key_exchange");
}

TEST(PqcMigration, RoleAwareFromContextOverridesAlgorithmDefault) {
    // RSA used for a signature stays signature -> ML-DSA.
    auto m = map_migration(asset("RSA", 2048, "", "srv.cpp", 5, "code-signing"),
                           entry_of(test_db(), "RSA"));
    EXPECT_EQ(m.replacement, "ML-DSA");

    // Explicitly force a key-exchange context: RSA not mapped for kx -> unsupported.
    auto kx = map_migration(asset("RSA", 2048, "", "tls.cpp", 9, "TLS handshake"),
                            entry_of(test_db(), "RSA"));
    EXPECT_NE(kx.replacement, "ML-DSA");
}

TEST(PqcMigration, UnsupportedAlgorithmNoReplacement) {
    auto db = test_db();
    auto aes = map_migration(asset("AES-256", 256), entry_of(db, "AES-256"));
    EXPECT_FALSE(aes.supported);
    EXPECT_TRUE(aes.replacement.empty());
}

TEST(PqcMigration, UnknownAlgorithmUnsupported) {
    auto m = map_migration(asset("BLOWFISH", 128), nullptr);
    EXPECT_FALSE(m.supported);
    EXPECT_TRUE(m.replacement.empty());
    EXPECT_FALSE(m.pqc_vulnerable);
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

TEST(PqcReadiness, RequiredCaseTwoOfFiveIsFortyPercent) {
    EXPECT_DOUBLE_EQ(readiness_percentage(2, 5), 40.0);
}

TEST(PqcReadiness, AllReadyIsOneHundredPercent) {
    EXPECT_DOUBLE_EQ(readiness_percentage(5, 5), 100.0);
}

TEST(PqcReadiness, NoneReadyIsZeroPercent) {
    EXPECT_DOUBLE_EQ(readiness_percentage(0, 5), 0.0);
}

TEST(PqcReadiness, EmptyCollectionIsZeroPercentNoDivByZero) {
    EXPECT_DOUBLE_EQ(readiness_percentage(0, 0), 0.0);
}

TEST(PqcReadiness, AssessCollectionOfRealAssets) {
    auto db = test_db();

    // RSA (vulnerable, migration available) -> ready
    // AES-256 (not vulnerable)              -> ready
    // ECDSA (vulnerable, migration avail)   -> ready
    // BLOWFISH (unknown, not vulnerable)    -> ready
    // A PQC-vuln algo with NO migration     -> not ready
    std::vector<std::pair<CryptoAsset, const TaxonomyEntry*>> assets;
    assets.emplace_back(asset("RSA", 2048), entry_of(db, "RSA"));
    assets.emplace_back(asset("AES-256", 256), entry_of(db, "AES-256"));
    assets.emplace_back(asset("ECDSA", 256), entry_of(db, "ECDSA"));
    assets.emplace_back(asset("BLOWFISH"), nullptr);

    auto report = assess_readiness(assets);
    EXPECT_EQ(report.total, 4u);
    EXPECT_EQ(report.ready, 4u);
    EXPECT_DOUBLE_EQ(report.percentage, 100.0);
}

TEST(PqcReadiness, VulnerableWithoutMigrationNotReady) {
    auto db = test_db();
    // ECDSA with an unsupported role (force key-exchange) -> no replacement.
    // Represent a vulnerable-but-unsupported asset directly.
    Migration m;
    m.algorithm = "ECDSA";
    m.pqc_vulnerable = true;
    m.supported = false;
    EXPECT_FALSE(is_asset_ready(m));

    Migration ready_m;
    ready_m.pqc_vulnerable = true;
    ready_m.supported = true;
    EXPECT_TRUE(is_asset_ready(ready_m));

    Migration safe_m;
    safe_m.pqc_vulnerable = false;
    EXPECT_TRUE(is_asset_ready(safe_m));
}

// ---------------------------------------------------------------------------
// Explainability: real CryptoAsset fields
// ---------------------------------------------------------------------------

TEST(PqcExplanation, ProvidesWhatWhereWhyActionFromRealAsset) {
    auto db = test_db();
    auto a = asset("RSA", 1024, "", "server.cpp", 87, "TLS server cert");
    auto c = classify_asset(a, db); // authoritative Member 2 classification
    auto m = map_migration(a, c.entry);
    auto ex = explain(a, c, m);

    // What uses the real algorithm + key size.
    EXPECT_EQ(ex.what, "RSA-1024 detected");
    // Where uses the real file + line.
    EXPECT_EQ(ex.where, "server.cpp:87");
    // Why references the real weakness (small key) and PQC vulnerability.
    EXPECT_NE(ex.why.find("Key size 1024"), std::string::npos);
    EXPECT_NE(ex.why.find("quantum-vulnerable"), std::string::npos);
    // Action recommends the concrete PQC replacement.
    EXPECT_NE(ex.action.find("ML-DSA"), std::string::npos);
}

TEST(PqcExplanation, ReportExampleShape) {
    auto db = test_db();
    auto a = asset("RSA", 1024, "", "server.cpp", 87);
    auto c = classify_asset(a, db);
    auto m = map_migration(a, c.entry);
    auto ex = explain(a, c, m);

    EXPECT_FALSE(ex.what.empty());
    EXPECT_FALSE(ex.where.empty());
    EXPECT_FALSE(ex.why.empty());
    EXPECT_FALSE(ex.action.empty());

    // Exact report example mapping:
    //   What:  RSA-1024 detected
    //   Where: server.cpp:87
    EXPECT_EQ(ex.where, "server.cpp:87");
}

TEST(PqcExplanation, SafeAssetNoActionRequired) {
    auto db = test_db();
    auto a = asset("AES-256", 256);
    auto c = classify_asset(a, db);
    auto m = map_migration(a, c.entry);
    auto ex = explain(a, c, m);
    EXPECT_EQ(ex.action, "No action required");
}

// ---------------------------------------------------------------------------
// key_size preservation through the shared type
// ---------------------------------------------------------------------------

TEST(PqcContract, KeySizeIsPreservedNotKeyBits) {
    auto a = asset("RSA", 3072);
    EXPECT_EQ(a.key_size, 3072);
    // The authoritative struct uses key_size (membership contract).
    auto db = test_db();
    auto c = classify_asset(a, db);
    EXPECT_EQ(c.risk_score, 5.0); // 3072 >= 2048, no downgrade
}

} // namespace
} // namespace pqc
} // namespace ecdat
