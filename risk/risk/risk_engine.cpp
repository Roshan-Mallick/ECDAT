// risk_engine.cpp
//
// Implementation of the ECDAT Member 3 Risk Engine.
// See risk_engine.h for the full contract and formula.

#include "risk_engine.h"

#include <cmath>
#include <sstream>

namespace ecdat {
namespace risk {

namespace {
// Weights are fixed by the ECDAT specification. Kept as named constants
// (instead of inline magic numbers) so the formula is easy to read and
// impossible to accidentally alter in more than one place.
constexpr double kWeaknessWeight = 0.4;
constexpr double kExposureWeight = 0.3;
constexpr double kRemediationWeight = 0.3;

constexpr double kMinFactor = 0.0;
constexpr double kMaxFactor = 100.0;
}  // namespace

void validateFactor(double value, const std::string& fieldName) {
    if (std::isnan(value) || std::isinf(value)) {
        std::ostringstream oss;
        oss << fieldName << " must be a finite number (got " << value << ")";
        throw std::invalid_argument(oss.str());
    }
    if (value < kMinFactor || value > kMaxFactor) {
        std::ostringstream oss;
        oss << fieldName << " must be between 0 and 100 (got " << value << ")";
        throw std::invalid_argument(oss.str());
    }
}

double calculateRisk(double weakness, double exposure, double remediation) {
    // Validate every input individually so the error message tells the
    // caller exactly which field was invalid, rather than a generic failure.
    validateFactor(weakness, "weakness");
    validateFactor(exposure, "exposure");
    validateFactor(remediation, "remediation");

    // The required, fixed weighted formula. Do not add extra factors here.
    double score = weakness * kWeaknessWeight
                  + exposure * kExposureWeight
                  + remediation * kRemediationWeight;

    return score;
}

RiskLevel classifyRisk(double score) {
    validateFactor(score, "score");

    // Team-defined boundaries (not part of the ECDAT specification).
    if (score < 25.0) {
        return RiskLevel::LOW;
    } else if (score < 50.0) {
        return RiskLevel::MEDIUM;
    } else if (score < 75.0) {
        return RiskLevel::HIGH;
    } else {
        return RiskLevel::CRITICAL;
    }
}

std::string riskLevelToString(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW:      return "LOW";
        case RiskLevel::MEDIUM:   return "MEDIUM";
        case RiskLevel::HIGH:     return "HIGH";
        case RiskLevel::CRITICAL: return "CRITICAL";
    }
    // Unreachable for a valid enum value, but keeps compilers happy.
    return "UNKNOWN";
}

}  // namespace risk
}  // namespace ecdat
