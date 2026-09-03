#pragma once
#include <string>
#include <cstdint>

// ============================================================
// ECDAT Shared Contract — types.hpp
// This is the ONE file all four members compile against.
// Do not edit without a quick team sync (per merge plan Section 4).
// ============================================================

namespace ecdat {

// ---------- Shared enums ----------

enum class Status {
    Safe,
    Weak,
    Deprecated,
    Unknown
};

enum class Severity {
    Low,
    Medium,
    High,
    Critical
};

// ---------- CryptoAsset ----------
// Produced by: Member 1 (discovery)
// Consumed by: Members 2, 3, 4
struct CryptoAsset {
    std::string source_type;   // "source_code" | "certificate" | "tls_config"
    std::string file;          // path to file where found
    int line = -1;             // line number (-1 if not applicable, e.g. certs)
    std::string algorithm;     // e.g. "MD5", "RSA", "AES"
    int key_size = 0;          // in bits, 0 if unknown/not applicable
    std::string curve;         // for ECC, empty otherwise
    std::string context;       // surrounding snippet or config line

    Status status = Status::Unknown;   // filled in by Member 2 (taxonomy)
    double risk_score = 0.0;           // filled in by Member 3 (risk engine)
    bool pqc_flag = false;             // filled in by Member 3 (pqc)
};

// ---------- Finding / Report ----------
// Produced by: Member 3 (risk/pqc explainability formatter)
// Consumed by: Member 4 (reporting)
struct Finding {
    Severity severity = Severity::Low;
    std::string what;      // what was found
    std::string where;     // file:line or cert path
    std::string why;       // why it's a problem
    std::string action;    // recommended remediation
    std::string timestamp; // ISO 8601
};

} // namespace ecdat
