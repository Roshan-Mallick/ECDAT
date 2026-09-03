#include "ecdat/serialization.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace ecdat {
namespace {

CryptoAsset make_asset() {
    CryptoAsset a;
    a.source_type = "source";
    a.file = "main.cpp";
    a.line = 42;
    a.algorithm = "RSA";
    a.key_bits = 1024;
    a.curve = "P-256";
    a.context = "tls handshake";
    a.status = Status::Weak;
    a.risk_score = 6.0;
    a.pqc_flag = true;
    return a;
}

TEST(Serialization, ToJsonRoundTrip) {
    const auto asset = make_asset();
    const auto json = to_json(asset);

    EXPECT_EQ(json["algorithm"], "RSA");
    EXPECT_EQ(json["status"], "Weak");
    EXPECT_EQ(json["risk_score"], 6.0);
    EXPECT_EQ(json["pqc_flag"], true);

    const auto parsed = from_json(json);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->source_type, asset.source_type);
    EXPECT_EQ(parsed->file, asset.file);
    EXPECT_EQ(parsed->line, asset.line);
    EXPECT_EQ(parsed->algorithm, asset.algorithm);
    EXPECT_EQ(parsed->key_bits, asset.key_bits);
    EXPECT_EQ(parsed->curve, asset.curve);
    EXPECT_EQ(parsed->context, asset.context);
    EXPECT_EQ(parsed->status, asset.status);
    EXPECT_EQ(parsed->risk_score, asset.risk_score);
    EXPECT_EQ(parsed->pqc_flag, asset.pqc_flag);
}

TEST(Serialization, EveryStatusSerializesAsString) {
    const std::array<Status, 4> statuses = {
        Status::Safe, Status::Weak, Status::Deprecated, Status::Unknown};

    for (const auto status : statuses) {
        CryptoAsset a;
        a.algorithm = "X";
        a.status = status;
        const auto json = to_json(a);
        EXPECT_TRUE(json["status"].is_string()) << "status must serialize as string";
        EXPECT_EQ(json["status"], status_to_string(status));
    }
}

TEST(Serialization, StatusToStringAndFromString) {
    EXPECT_EQ(status_to_string(Status::Safe), "Safe");
    EXPECT_EQ(status_to_string(Status::Weak), "Weak");
    EXPECT_EQ(status_to_string(Status::Deprecated), "Deprecated");
    EXPECT_EQ(status_to_string(Status::Unknown), "Unknown");

    EXPECT_EQ(*status_from_string("Safe"), Status::Safe);
    EXPECT_EQ(*status_from_string("Weak"), Status::Weak);
    EXPECT_EQ(*status_from_string("Deprecated"), Status::Deprecated);
    EXPECT_EQ(*status_from_string("Unknown"), Status::Unknown);
}

TEST(Serialization, ParseAssetValidJson) {
    const auto asset = parse_asset(
        R"({"source_type":"s","file":"f.c","line":7,"algorithm":"AES-256",
            "key_bits":256,"curve":"","context":"","status":"Safe",
            "risk_score":1.0,"pqc_flag":false})");
    ASSERT_TRUE(asset.has_value());
    EXPECT_EQ(asset->algorithm, "AES-256");
    EXPECT_EQ(asset->status, Status::Safe);
    EXPECT_EQ(asset->line, 7);
    EXPECT_EQ(asset->risk_score, 1.0);
    EXPECT_FALSE(asset->pqc_flag);
}

TEST(Serialization, ParseAssetMissingOptionalFieldsTakesDefaults) {
    const auto asset = parse_asset(R"({"algorithm":"FOO"})");
    ASSERT_TRUE(asset.has_value());
    EXPECT_EQ(asset->algorithm, "FOO");
    EXPECT_EQ(asset->source_type, "");
    EXPECT_EQ(asset->line, 0);
    EXPECT_EQ(asset->key_bits, 0);
    EXPECT_EQ(asset->curve, "");
    EXPECT_EQ(asset->status, Status::Unknown);
    EXPECT_EQ(asset->risk_score, 0.0);
    EXPECT_FALSE(asset->pqc_flag);
}

TEST(Serialization, ParseAssetMissingAlgorithmFails) {
    EXPECT_FALSE(parse_asset(R"({"source_type":"s"})").has_value());
    EXPECT_FALSE(parse_asset(R"({})").has_value());
}

TEST(Serialization, ParseAssetWrongFieldTypeFails) {
    // algorithm present but wrong type.
    EXPECT_FALSE(parse_asset(R"({"algorithm":123})").has_value());
    // line wrong type (string) is rejected.
    EXPECT_FALSE(parse_asset(R"({"algorithm":"X","line":"notanint"})").has_value());
    // risk_score wrong type.
    EXPECT_FALSE(parse_asset(R"({"algorithm":"X","risk_score":"high"})").has_value());
}

TEST(Serialization, ParseAssetInvalidStatusFails) {
    EXPECT_FALSE(parse_asset(R"({"algorithm":"X","status":"SuperSafe"})").has_value());
    EXPECT_FALSE(parse_asset(R"({"algorithm":"X","status":42})").has_value());
}

TEST(Serialization, ParseAssetMalformedJsonReturnsNullopt) {
    EXPECT_FALSE(parse_asset("").has_value());
    EXPECT_FALSE(parse_asset("{ not valid json").has_value());
    EXPECT_FALSE(parse_asset("[1,2,3]").has_value());
    EXPECT_FALSE(parse_asset("null").has_value());
}

TEST(Serialization, ParseAssetIntegerStatusRejected) {
    // A status represented as an integer must not be silently coerced.
    EXPECT_FALSE(parse_asset(R"({"algorithm":"X","status":1})").has_value());
}

TEST(Serialization, FromJsonNotObjectFails) {
    EXPECT_FALSE(from_json(nlohmann::json::array({1, 2})).has_value());
    EXPECT_FALSE(from_json(nlohmann::json("string")).has_value());
    EXPECT_FALSE(from_json(nlohmann::json::value_t::discarded).has_value());
}

} // namespace
} // namespace ecdat
