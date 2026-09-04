#pragma once

#include "ecdat/types.hpp"

#include <nlohmann/json_fwd.hpp>

#include <optional>
#include <string_view>

namespace ecdat {

// Convert a CryptoAsset to its JSON representation.
//
// Status is always serialized as a string ("Safe", "Weak", ...), never as an
// integer.
[[nodiscard]] nlohmann::json to_json(const CryptoAsset& asset);

// Deserialize a CryptoAsset from JSON.
//
// * Missing optional fields take their defaults.
// * Missing/invalid mandatory fields (algorithm) fail and return std::nullopt.
// * An invalid status string fails and returns std::nullopt.
// * Wrong JSON types are rejected instead of being coerced silently.
[[nodiscard]] std::optional<CryptoAsset> from_json(const nlohmann::json& json);

// Parse a CryptoAsset from a raw JSON string. Returns std::nullopt when the
// input is malformed JSON, is not an object, or fails from_json validation.
// This function never throws and never crashes on malformed input.
[[nodiscard]] std::optional<CryptoAsset> parse_asset(std::string_view text);

// Convert a Status to its JSON string representation.
[[nodiscard]] nlohmann::json status_to_json(Status status);

} // namespace ecdat
