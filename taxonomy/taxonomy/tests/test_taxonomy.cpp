#include "ecdat/taxonomy.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace ecdat {
namespace {

// Path to the shipped taxonomy data file. Set by CMake via the
// ECDAT_TAXONOMY_PATH compile definition, overridable in tests.
#ifndef ECDAT_TAXONOMY_PATH
#define ECDAT_TAXONOMY_PATH "taxonomy/data/taxonomy.yaml"
#endif

// Asserts that parsing the given YAML text throws std::runtime_error.
// Consumes the [[nodiscard]] result of load_from_string so the expression
// evaluates cleanly inside EXPECT_THROW.
void expect_load_error(std::string_view yaml) {
    EXPECT_THROW({ (void)TaxonomyDB::load_from_string(yaml); }, std::runtime_error);
}

constexpr std::string_view kSmallYaml = R"(
algorithms:
  - {name: RSA, type: asymmetric, status: Weak, risk_base: 5.0, pqc_vulnerable: true, replacement: ECDSA-P256}
  - {name: SHA-256, type: hash, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
)";

TEST(Taxonomy, LoadValidFile) {
    EXPECT_NO_THROW({
        auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
        EXPECT_GT(db.size(), 0u);
    });
}

TEST(Taxonomy, LoadFromString) {
    auto db = TaxonomyDB::load_from_string(kSmallYaml);
    EXPECT_EQ(db.size(), 2u);
}

TEST(Taxonomy, ExpectedNumberOfEntriesFromDataFile) {
    auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    EXPECT_EQ(db.size(), 16u);
}

TEST(Taxonomy, LookupCaseInsensitive) {
    auto db = TaxonomyDB::load_from_string(kSmallYaml);

    const TaxonomyEntry* a = db.lookup("RSA");
    const TaxonomyEntry* b = db.lookup("rsa");
    const TaxonomyEntry* c = db.lookup("RsA");
    const TaxonomyEntry* d = db.lookup("rSa");

    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a, c);
    EXPECT_EQ(a, d);
    EXPECT_EQ(a->name, "RSA"); // original display name preserved
}

TEST(Taxonomy, UnknownAlgorithmReturnsNullptr) {
    auto db = TaxonomyDB::load_from_string(kSmallYaml);
    EXPECT_EQ(db.lookup("FOOCIPHER"), nullptr);
    EXPECT_EQ(db.lookup(""), nullptr);
}

TEST(Taxonomy, DuplicateLastOccurrenceWins) {
    constexpr std::string_view yaml = R"(
algorithms:
  - {name: AES, type: symmetric, status: Safe, risk_base: 1.0, pqc_vulnerable: false, replacement: ""}
  - {name: AES, type: symmetric, status: Weak, risk_base: 7.0, pqc_vulnerable: true, replacement: AES-256}
)";
    auto db = TaxonomyDB::load_from_string(yaml);
    EXPECT_EQ(db.size(), 1u);
    const TaxonomyEntry* entry = db.lookup("aes");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->status, Status::Weak);
    EXPECT_EQ(entry->risk_base, 7.0);
    EXPECT_TRUE(entry->pqc_vulnerable);
}

TEST(Taxonomy, MultipleDuplicateEntries) {
    constexpr std::string_view yaml = R"(
algorithms:
  - {name: X, type: hash, status: Safe, risk_base: 1.0, pqc_vulnerable: false}
  - {name: x, type: hash, status: Weak, risk_base: 3.0, pqc_vulnerable: false}
  - {name: X, type: hash, status: Deprecated, risk_base: 8.0, pqc_vulnerable: true}
)";
    auto db = TaxonomyDB::load_from_string(yaml);
    EXPECT_EQ(db.size(), 1u);
    const TaxonomyEntry* entry = db.lookup("X");
    ASSERT_NE(entry, nullptr);
    EXPECT_EQ(entry->status, Status::Deprecated);
    EXPECT_EQ(entry->risk_base, 8.0);
}

TEST(Taxonomy, MalformedYamlThrows) {
    expect_load_error("not: [valid: yaml] {{{");
}

TEST(Taxonomy, MissingAlgorithmsSectionThrows) {
    expect_load_error("foo: bar");
}

TEST(Taxonomy, MissingRequiredFieldThrows) {
    // Missing 'name'.
    expect_load_error("algorithms:\n  - {type: hash, status: Safe, risk_base: 1.0, pqc_vulnerable: false}");
    // Missing 'status'.
    expect_load_error("algorithms:\n  - {name: A, type: hash, risk_base: 1.0, pqc_vulnerable: false}");
    // Missing 'risk_base'.
    expect_load_error("algorithms:\n  - {name: A, type: hash, status: Safe, pqc_vulnerable: false}");
    // Missing 'pqc_vulnerable'.
    expect_load_error("algorithms:\n  - {name: A, type: hash, status: Safe, risk_base: 1.0}");
    // Missing 'type'.
    expect_load_error("algorithms:\n  - {name: A, status: Safe, risk_base: 1.0, pqc_vulnerable: false}");
}

TEST(Taxonomy, WrongTypeFieldThrows) {
    // risk_base as a string.
    expect_load_error("algorithms:\n  - {name: A, type: hash, status: Safe, risk_base: high, pqc_vulnerable: false}");
    // pqc_vulnerable as a string.
    expect_load_error("algorithms:\n  - {name: A, type: hash, status: Safe, risk_base: 1.0, pqc_vulnerable: yes-ish}");
    // invalid status.
    expect_load_error("algorithms:\n  - {name: A, type: hash, status: MegaSafe, risk_base: 1.0, pqc_vulnerable: false}");
}

TEST(Taxonomy, RiskBasePqcAndReplacementLoading) {
    auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);

    const TaxonomyEntry* rsa = db.lookup("RSA");
    ASSERT_NE(rsa, nullptr);
    EXPECT_EQ(rsa->risk_base, 5.0);
    EXPECT_TRUE(rsa->pqc_vulnerable);
    EXPECT_EQ(rsa->replacement, "ECDSA-P256");
    EXPECT_TRUE(rsa->min_secure_key_bits.has_value());
    EXPECT_EQ(*rsa->min_secure_key_bits, 2048);

    const TaxonomyEntry* sha256 = db.lookup("SHA-256");
    ASSERT_NE(sha256, nullptr);
    EXPECT_EQ(sha256->risk_base, 1.0);
    EXPECT_FALSE(sha256->pqc_vulnerable);
    EXPECT_EQ(sha256->status, Status::Safe);

    const TaxonomyEntry* ecdsa = db.lookup("ECDSA");
    ASSERT_NE(ecdsa, nullptr);
    EXPECT_TRUE(ecdsa->pqc_vulnerable);
    ASSERT_FALSE(ecdsa->weak_curves.empty());
    EXPECT_EQ(ecdsa->weak_curves.front(), "P-192");
}

TEST(Taxonomy, EmptyTaxonomyAllowed) {
    constexpr std::string_view yaml = "algorithms: []";
    auto db = TaxonomyDB::load_from_string(yaml);
    EXPECT_TRUE(db.empty());
    EXPECT_EQ(db.size(), 0u);
    EXPECT_EQ(db.lookup("anything"), nullptr);
}

TEST(Taxonomy, EmptyDocumentIsEmptyDatabase) {
    auto db = TaxonomyDB::load_from_string("");
    EXPECT_TRUE(db.empty());
    EXPECT_EQ(db.lookup("anything"), nullptr);
}

TEST(Taxonomy, AlgorithmsNotPresentAreUnknown) {
    auto db = TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    EXPECT_EQ(db.lookup("BLOWFISH"), nullptr);
    EXPECT_EQ(db.lookup("CAMELLIA"), nullptr);
}

} // namespace
} // namespace ecdat
