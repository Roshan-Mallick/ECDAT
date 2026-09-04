#include "ecdat/taxonomy.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace ecdat {

namespace {

// Policy constants for risk-score adjustment.
constexpr double kDowngradeAdjustment = 2.0;
constexpr double kMinRisk = 0.0;
constexpr double kMaxRisk = 10.0;

// Case-insensitive substring comparison helper used to match a curve name
// against the taxonomy's weak-curve list without duplicating normalization
// logic in the classifier.
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        const unsigned char ca = static_cast<unsigned char>(a[i]);
        const unsigned char cb = static_cast<unsigned char>(b[i]);
        if (std::tolower(ca) != std::tolower(cb)) {
            return false;
        }
    }
    return true;
}

// Determine whether a recognized asset should be downgraded because its key
// size or curve is below the taxonomy's required security threshold.
//
// This is the only place where size/curve security policy lives in C++; the
// actual thresholds are still supplied by taxonomy.yaml per algorithm (no
// hard-coded algorithm list).
bool requires_downgrade(const TaxonomyEntry& entry, const CryptoAsset& asset) {
    if (entry.min_secure_key_bits.has_value() && asset.key_size > 0 &&
        asset.key_size < *entry.min_secure_key_bits) {
        return true;
    }
    if (!asset.curve.empty()) {
        for (const auto& weak : entry.weak_curves) {
            if (iequals(weak, asset.curve)) {
                return true;
            }
        }
    }
    return false;
}

// Merge an applied downgrade into a classification.
void apply_downgrade(Classification& result) {
    // Deprecated outranks Weak; Safe/Unknown (when recognized) are raised to
    // Weak. Never lower an already-stronger severity.
    if (result.status == Status::Safe || result.status == Status::Unknown) {
        result.status = Status::Weak;
    }
    result.risk_score = std::clamp(result.risk_score + kDowngradeAdjustment,
                                   kMinRisk, kMaxRisk);
}

} // namespace

Classification classify_asset(const CryptoAsset& asset, const TaxonomyDB& db) {
    Classification result;

    const TaxonomyEntry* entry = db.lookup(asset.algorithm);

    // Unknown algorithm: never guess. Status stays Unknown, risk stays 0, and
    // PQC safety is not falsely claimed.
    if (entry == nullptr) {
        result.status = Status::Unknown;
        result.risk_score = kMinRisk;
        result.pqc_flag = false;
        result.entry = nullptr;
        return result;
    }

    result.entry = entry;
    result.status = entry->status;
    result.risk_score = std::clamp(entry->risk_base, kMinRisk, kMaxRisk);
    result.pqc_flag = entry->pqc_vulnerable;

    // Explicit security override: key-size or curve downgrade.
    if (requires_downgrade(*entry, asset)) {
        apply_downgrade(result);
    }

    return result;
}

Status classify(const CryptoAsset& asset, const TaxonomyDB& db) {
    return classify_asset(asset, db).status;
}

} // namespace ecdat
