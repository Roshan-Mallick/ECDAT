// risk_engine.h
//
// ECDAT Member 3 - Component 1: Risk Engine
//
// Purpose:
//   Converts three 0-100 input factors (weakness, exposure, remediation)
//   into a single reproducible risk score using a fixed weighted formula:
//
//       Risk = weakness * 0.4 + exposure * 0.3 + remediation * 0.3
//
//   This module is intentionally standalone: it has no dependency on the
//   scanner, taxonomy, PQC, reporting, GUI, or database layers of ECDAT.
//
// Notes:
//   - The 0.4 / 0.3 / 0.3 weights come directly from the ECDAT specification
//     and must not be changed here.
//   - LOW/MEDIUM/HIGH/CRITICAL boundaries are NOT specified by ECDAT's
//     spec documents. They are a team-defined convenience provided by
//     classifyRisk() below, clearly separated from the required formula.

#ifndef ECDAT_RISK_ENGINE_H
#define ECDAT_RISK_ENGINE_H

#include <stdexcept>
#include <string>

namespace ecdat {
namespace risk {

// Team-defined risk levels (NOT part of the ECDAT specification).
// Boundaries are configurable project decisions; adjust freely as a team.
enum class RiskLevel {
    LOW,       // 0  - 24
    MEDIUM,    // 25 - 49
    HIGH,      // 50 - 74
    CRITICAL   // 75 - 100
};

// Converts a RiskLevel enum value to a human-readable string.
std::string riskLevelToString(RiskLevel level);

// Validates that a single input factor is within the required 0-100 range.
// Throws std::invalid_argument (with a message naming the offending field)
// if the value is out of range, NaN, or otherwise invalid.
//
// fieldName is used only to produce a clear, actionable error message,
// e.g. "weakness must be between 0 and 100 (got -5)".
void validateFactor(double value, const std::string& fieldName);

// Calculates the ECDAT risk score from the three required factors.
//
// Formula (fixed, do not modify):
//   Risk = weakness * 0.4 + exposure * 0.3 + remediation * 0.3
//
// Parameters:
//   weakness    - 0-100, how weak/broken the cryptography is
//   exposure    - 0-100, how reachable/exposed the asset is
//   remediation - 0-100, how difficult the fix is
//
// Returns:
//   A reproducible double risk score, always in the range 0-100
//   (since it is a convex combination of three 0-100 inputs).
//
// Throws:
//   std::invalid_argument if any input is outside 0-100.
double calculateRisk(double weakness, double exposure, double remediation);

// Classifies a risk score (0-100) into a team-defined RiskLevel.
// This is a convenience layer on top of calculateRisk() and is NOT
// mandated by the ECDAT specification; boundaries may be revisited
// by the team at any time without affecting calculateRisk().
//
// Throws std::invalid_argument if score is outside 0-100.
RiskLevel classifyRisk(double score);

}  // namespace risk
}  // namespace ecdat

#endif  // ECDAT_RISK_ENGINE_H
