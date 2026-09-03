#pragma once

#include "ecdat/types.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ecdat {

// Taxonomy schema
// ===============
// Each entry describes one cryptographic algorithm. Metadata is loaded from
// taxonomy/data/taxonomy.yaml (see that file for the full schema
// documentation). The C++ classifier only consumes this data and generic
// policy rules; it does not hard-code the algorithm list.
struct TaxonomyEntry {
    // Original display name as written in the taxonomy file.
    std::string name;

    // Category, e.g. "symmetric", "asymmetric", "hash", "signature",
    // "key-exchange". Informational; used by future ECDAT members.
    std::string type;

    Status status = Status::Unknown;
    double risk_base = 0.0;
    bool pqc_vulnerable = false;

    // Recommended modern replacement algorithm; empty when none.
    std::string replacement;

    // Optional data-driven security overrides. When the classified asset's
    // key_bits (zero meaning unknown) is below min_secure_key_bits, or its
    // curve matches one of weak_curves (case-insensitive), the classifier
    // forces the status to at least Weak and adds +2.0 to the risk score.
    std::optional<long long> min_secure_key_bits;
    std::vector<std::string> weak_curves;

    // Convenience: is this entry known to be vulnerable to quantum attacks?
    [[nodiscard]] bool is_pqc_vulnerable() const noexcept { return pqc_vulnerable; }
};

// A case-insensitive, extension-friendly database of taxonomy entries.
//
// Lookup keys are normalized to lowercase internally; the original display
// name is preserved in each entry. Duplicate algorithms are allowed and the
// last occurrence wins (matching the "additive overrides" contract).
class TaxonomyDB {
public:
    // Load from a YAML file. Throws std::runtime_error (with a descriptive
    // message) on missing files or malformed/structurally-invalid YAML.
    [[nodiscard]] static TaxonomyDB load_from_file(const std::string& path);

    // Load from an in-memory YAML string. Useful for policy testing and
    // future hot-reload; same validation and error behavior as load_from_file.
    [[nodiscard]] static TaxonomyDB load_from_string(std::string_view yaml_text);

    // Case-insensitive lookup. Returns nullptr when the algorithm is not
    // present (the caller then treats the asset as Unknown).
    [[nodiscard]] const TaxonomyEntry* lookup(std::string_view name) const;

    [[nodiscard]] std::size_t size() const noexcept { return entries_.size(); }
    [[nodiscard]] bool empty() const noexcept { return entries_.empty(); }

private:
    std::unordered_map<std::string, TaxonomyEntry> entries_;
};

// Normalize a lookup key: trim surrounding whitespace and convert to
// lowercase. Centralized so case-insensitive matching is defined in exactly
// one place.
[[nodiscard]] std::string normalize_key(std::string_view name);

// Result of classifying a CryptoAsset: the severity plus the derived risk
// score and PQC flag. `entry` is non-null when the algorithm was recognized.
struct Classification {
    Status status = Status::Unknown;
    double risk_score = 0.0;
    bool pqc_flag = false;
    const TaxonomyEntry* entry = nullptr;
};

// Classification precedence (deterministic):
//   1. Explicit key-size / curve security override (Weak downgrade +2.0)
//   2. Taxonomy lookup (status, risk_base, pqc_vulnerable)
//   3. Unknown fallback (Status::Unknown, risk 0.0, pqc_flag false)
//
// The risk score is clamped to [0,10] before and after any adjustment.
[[nodiscard]] Classification classify_asset(const CryptoAsset& asset,
                                            const TaxonomyDB& db);

// Convenience wrapper returning only the status; equivalent to
// classify_asset(asset, db).status.
[[nodiscard]] Status classify(const CryptoAsset& asset, const TaxonomyDB& db);

} // namespace ecdat
