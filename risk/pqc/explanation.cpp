// explanation.cpp
//
// Implementation of the ECDAT Member 3 explainability module.
// See explanation.h for the full contract.

#include "explanation.h"

#include <string>

namespace ecdat {
namespace pqc {

namespace {

std::string status_name(Status status) {
    switch (status) {
        case Status::Safe:       return "Safe";
        case Status::Weak:       return "Weak";
        case Status::Deprecated: return "Deprecated";
        case Status::Unknown:    return "Unknown";
    }
    return "Unknown";
}

std::string describe_why(const CryptoAsset& asset,
                         const Classification& classification) {
    std::string why;
    bool need_sep = false;

    if (asset.key_size > 0 && classification.entry != nullptr &&
        classification.entry->min_secure_key_bits.has_value() &&
        asset.key_size < *classification.entry->min_secure_key_bits) {
        why += "Key size " + std::to_string(asset.key_size) + " is below the "
               "secure minimum";
        need_sep = true;
    }

    if (classification.pqc_flag) {
        if (need_sep) why += "; ";
        why += "quantum-vulnerable public-key cryptography";
        need_sep = true;
    } else if (asset.algorithm.empty()) {
        if (need_sep) why += "; ";
        why += "unrecognized algorithm";
        need_sep = true;
    }

    if (why.empty()) {
        why = "no known cryptographic weakness detected";
    }
    return why;
}

} // namespace

Explanation explain(const CryptoAsset& asset,
                    const Classification& classification,
                    const Migration& migration) {
    Explanation ex;

    // What: algorithm, optionally with key size and curve.
    std::string what = asset.algorithm.empty() ? "Unknown algorithm" : asset.algorithm;
    if (asset.key_size > 0) {
        what += "-" + std::to_string(asset.key_size);
    }
    if (!asset.curve.empty()) {
        what += " (" + asset.curve + ")";
    }
    what += " detected";
    ex.what = what;

    // Where: file:line from the real asset. Handle missing location.
    if (!asset.file.empty()) {
        ex.where = asset.file;
        if (asset.line > 0) {
            ex.where += ":" + std::to_string(asset.line);
        }
    } else if (asset.line > 0) {
        ex.where = "line " + std::to_string(asset.line);
    } else {
        ex.where = "(location unknown)";
    }

    // Why: real reasons derived from the asset + classification.
    ex.why = describe_why(asset, classification);

    // Action: concrete PQC action when a migration is supported, otherwise
    // a generic recommendation tied to the detection.
    if (classification.pqc_flag) {
        if (migration.supported) {
            ex.action = "Migrate to an appropriate PQC algorithm: " +
                        migration.replacement +
                        " (status: " + status_name(classification.status) + ")";
        } else if (classification.status == Status::Unknown) {
            ex.action = "Classify and remediate the unrecognized algorithm";
        } else {
            ex.action = "Migrate to an appropriate PQC algorithm (status: " +
                        status_name(classification.status) + ")";
        }
    } else if (classification.status == Status::Deprecated ||
               classification.status == Status::Weak) {
        const char* replacement =
            (classification.entry != nullptr &&
             !classification.entry->replacement.empty())
                ? classification.entry->replacement.c_str()
                : "a modern alternative";
        ex.action = std::string("Replace with ") + replacement +
                    " (status: " + status_name(classification.status) + ")";
    } else {
        ex.action = "No action required";
    }

    return ex;
}

} // namespace pqc
} // namespace ecdat
