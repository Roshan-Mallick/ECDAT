#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace ecdat {

// Security classification for a cryptographic asset.
//
// This is the canonical enum used across ECDAT. Statuses are represented
// internally as an enum class, never as arbitrary strings. Serialization to
// and from strings happens only in the serialization layer.
enum class Status {
    Safe,
    Weak,
    Deprecated,
    Unknown
};

// Convert a Status to its canonical display string ("Safe", "Weak", ...).
[[nodiscard]] std::string_view status_to_string(Status status);

// Parse a Status from its canonical string. Returns std::nullopt if the
// string does not match a known status (case-sensitive).
[[nodiscard]] std::optional<Status> status_from_string(std::string_view text);

// The shared, cross-member contract for a single cryptographic asset
// discovered in a codebase, certificate, or network configuration.
//
// A CryptoAsset carries both discovery provenance (where it was found) and
// the classification result fields (status, risk_score, pqc_flag). Fields
// that are not yet known use default/empty values; the classifier is
// responsible for filling in status/risk_score/pqc_flag.
struct CryptoAsset {
    // Provenance / discovery fields (populated by Member 1).
    std::string source_type;
    std::string file;
    std::int64_t line = 0;
    std::string algorithm;
    std::int64_t key_bits = 0;
    std::string curve;

    // Free-form context describing how the asset is used.
    std::string context;

    // Classification result fields (populated by Member 2).
    Status status = Status::Unknown;
    double risk_score = 0.0;
    bool pqc_flag = false;
};

// A single finding, combining the asset with a human-readable message.
// Reserved for later integration with reporting/storage members; kept
// lightweight and ownership-free.
struct Finding {
    CryptoAsset asset;
    std::string message;
};

} // namespace ecdat
