#include "ecdat/serialization.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>

namespace ecdat {

std::string_view status_to_string(Status status) {
    switch (status) {
        case Status::Safe: return "Safe";
        case Status::Weak: return "Weak";
        case Status::Deprecated: return "Deprecated";
        case Status::Unknown: return "Unknown";
    }
    return "Unknown";
}

std::optional<Status> status_from_string(std::string_view text) {
    if (text == "Safe") return Status::Safe;
    if (text == "Weak") return Status::Weak;
    if (text == "Deprecated") return Status::Deprecated;
    if (text == "Unknown") return Status::Unknown;
    return std::nullopt;
}

nlohmann::json status_to_json(Status status) {
    return nlohmann::json(status_to_string(status));
}

nlohmann::json to_json(const CryptoAsset& asset) {
    return nlohmann::json{
        {"source_type", asset.source_type},
        {"file", asset.file},
        {"line", asset.line},
        {"algorithm", asset.algorithm},
        {"key_bits", asset.key_bits},
        {"curve", asset.curve},
        {"context", asset.context},
        {"status", status_to_string(asset.status)},
        {"risk_score", asset.risk_score},
        {"pqc_flag", asset.pqc_flag},
    };
}

namespace {

// Read an optional string field.
//
// Returns true on success (setting `out`). Distinguishes an absent field
// (returns true, leaves default) from a field present with the wrong type
// (returns false, meaning the whole document is rejected). Absent optional
// fields are tolerated; a wrong-typed field is treated as malformed input.
bool read_string(const nlohmann::json& json, const char* key, std::string& out) {
    auto it = json.find(key);
    if (it == json.end()) {
        return true; // absent -> keep default
    }
    if (!it->is_string()) {
        return false; // present, wrong type
    }
    out = it->get<std::string>();
    return true;
}

// Read an optional integer field (same semantics as read_string).
bool read_int(const nlohmann::json& json, const char* key, std::int64_t& out) {
    auto it = json.find(key);
    if (it == json.end()) {
        return true;
    }
    if (!it->is_number_integer()) {
        return false;
    }
    out = it->get<std::int64_t>();
    return true;
}

// Read an optional number field (integer or float; same semantics).
bool read_number(const nlohmann::json& json, const char* key, double& out) {
    auto it = json.find(key);
    if (it == json.end()) {
        return true;
    }
    if (!it->is_number()) {
        return false;
    }
    out = it->get<double>();
    return true;
}

// Read an optional boolean field (same semantics).
bool read_bool(const nlohmann::json& json, const char* key, bool& out) {
    auto it = json.find(key);
    if (it == json.end()) {
        return true;
    }
    if (!it->is_boolean()) {
        return false;
    }
    out = it->get<bool>();
    return true;
}

} // namespace

std::optional<CryptoAsset> from_json(const nlohmann::json& json) {
    if (!json.is_object()) {
        return std::nullopt;
    }

    CryptoAsset asset;

    // The algorithm is the mandatory, identifying field of an asset; its
    // absence or wrong type fails the parse.
    {
        auto it = json.find("algorithm");
        if (it == json.end() || !it->is_string()) {
            return std::nullopt;
        }
        asset.algorithm = it->get<std::string>();
    }

    // All remaining fields are optional. Absent fields keep their defaults;
    // any field present with the wrong type makes the document malformed.
    if (!read_string(json, "source_type", asset.source_type) ||
        !read_string(json, "file", asset.file) ||
        !read_int(json, "line", asset.line) ||
        !read_int(json, "key_bits", asset.key_bits) ||
        !read_string(json, "curve", asset.curve) ||
        !read_string(json, "context", asset.context) ||
        !read_number(json, "risk_score", asset.risk_score) ||
        !read_bool(json, "pqc_flag", asset.pqc_flag)) {
        return std::nullopt;
    }

    // Status must be a valid status string. An absent status keeps the
    // default (Unknown); a present-but-invalid status is a hard failure.
    auto status_it = json.find("status");
    if (status_it != json.end()) {
        if (!status_it->is_string()) {
            return std::nullopt;
        }
        auto parsed = status_from_string(status_it->get<std::string>());
        if (!parsed) {
            return std::nullopt;
        }
        asset.status = *parsed;
    }

    return asset;
}

std::optional<CryptoAsset> parse_asset(std::string_view text) {
    try {
        const auto json = nlohmann::json::parse(text);
        return from_json(json);
    } catch (const nlohmann::json::exception&) {
        // Malformed JSON (syntax error or type mismatch) -> parse failure.
        return std::nullopt;
    }
}

} // namespace ecdat
