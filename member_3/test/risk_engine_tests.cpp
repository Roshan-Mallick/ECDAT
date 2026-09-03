// risk_engine_tests.cpp
//
// Standalone test runner for the ECDAT Member 3 Risk Engine.
// No third-party test framework is used - just a small PASS/FAIL helper
// built on plain C++ so this compiles anywhere with just a C++17 compiler.
//
// Run with:
//   g++ -std=c++17 -Wall -Wextra risk/risk_engine.cpp tests/risk_engine_tests.cpp -o risk_engine_test
//   ./risk_engine_test

#include "risk/risk_engine.h"

#include <cmath>
#include <iostream>
#include <string>

namespace {

int g_passed = 0;
int g_failed = 0;

// Compares two doubles with a small tolerance, since risk scores are
// computed from floating point multiplication/addition.
bool approxEqual(double a, double b, double epsilon = 1e-9) {
    return std::fabs(a - b) < epsilon;
}

void reportResult(const std::string& testName, bool passed, const std::string& detail = "") {
    if (passed) {
        std::cout << "[PASS] " << testName << "\n";
        ++g_passed;
    } else {
        std::cout << "[FAIL] " << testName;
        if (!detail.empty()) {
            std::cout << " -- " << detail;
        }
        std::cout << "\n";
        ++g_failed;
    }
}

}  // namespace

int main() {
    using namespace ecdat::risk;

    std::cout << "=== ECDAT Risk Engine Test ===\n";

    // Test 1: Required test case from the spec.
    // weakness=80, exposure=60, remediation=40 -> expected 62
    {
        double score = calculateRisk(80.0, 60.0, 40.0);
        bool ok = approxEqual(score, 62.0);
        reportResult("Required risk calculation (80,60,40 -> 62)", ok,
                     "got " + std::to_string(score));
    }

    // Test 2: All-zero inputs -> expected 0
    {
        double score = calculateRisk(0.0, 0.0, 0.0);
        bool ok = approxEqual(score, 0.0);
        reportResult("All-zero inputs (0,0,0 -> 0)", ok,
                     "got " + std::to_string(score));
    }

    // Test 3: All-100 inputs -> expected 100
    {
        double score = calculateRisk(100.0, 100.0, 100.0);
        bool ok = approxEqual(score, 100.0);
        reportResult("All-100 inputs (100,100,100 -> 100)", ok,
                     "got " + std::to_string(score));
    }

    // Test 4: Weighted formula is respected for an asymmetric case.
    // weakness=90, exposure=80, remediation=40 -> 36 + 24 + 12 = 72
    {
        double score = calculateRisk(90.0, 80.0, 40.0);
        bool ok = approxEqual(score, 72.0);
        reportResult("Asymmetric inputs (90,80,40 -> 72)", ok,
                     "got " + std::to_string(score));
    }

    // Test 5: Exposure change alone should change the risk score
    // (public exposure should score higher than internal exposure).
    {
        double internalScore = calculateRisk(80.0, 20.0, 40.0);  // -> 50
        double publicScore = calculateRisk(80.0, 80.0, 40.0);    // -> 68
        bool ok = approxEqual(internalScore, 50.0)
                  && approxEqual(publicScore, 68.0)
                  && (publicScore > internalScore);
        reportResult("Exposure raises risk (internal 50 < public 68)", ok,
                     "internal=" + std::to_string(internalScore)
                     + " public=" + std::to_string(publicScore));
    }

    // Test 6: Out-of-range input throws std::invalid_argument.
    {
        bool threw = false;
        try {
            calculateRisk(-5.0, 50.0, 50.0);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        reportResult("Negative weakness rejected", threw);
    }

    {
        bool threw = false;
        try {
            calculateRisk(50.0, 150.0, 50.0);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        reportResult("Exposure above 100 rejected", threw);
    }

    // Test 7: classifyRisk() team-defined boundaries.
    {
        bool ok = classifyRisk(0.0) == RiskLevel::LOW
                  && classifyRisk(24.9) == RiskLevel::LOW
                  && classifyRisk(25.0) == RiskLevel::MEDIUM
                  && classifyRisk(49.9) == RiskLevel::MEDIUM
                  && classifyRisk(50.0) == RiskLevel::HIGH
                  && classifyRisk(74.9) == RiskLevel::HIGH
                  && classifyRisk(75.0) == RiskLevel::CRITICAL
                  && classifyRisk(100.0) == RiskLevel::CRITICAL;
        reportResult("classifyRisk boundaries (team-defined)", ok);
    }

    // Test 8: riskLevelToString produces readable labels.
    {
        bool ok = riskLevelToString(RiskLevel::LOW) == "LOW"
                  && riskLevelToString(RiskLevel::MEDIUM) == "MEDIUM"
                  && riskLevelToString(RiskLevel::HIGH) == "HIGH"
                  && riskLevelToString(RiskLevel::CRITICAL) == "CRITICAL";
        reportResult("riskLevelToString labels", ok);
    }

    std::cout << g_passed << "/" << (g_passed + g_failed) << " TESTS PASSED\n";

    return (g_failed == 0) ? 0 : 1;
}
