// ECDAT Combined Demo
//
// Demonstrates Member 2 (taxonomy classification) + Member 3 (risk engine)
// working together through the integration pipeline.
//
// No dependency on Members 1 or 4.

#include "pipeline.h"
#include "ecdat/serialization.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#ifndef ECDAT_TAXONOMY_PATH
#define ECDAT_TAXONOMY_PATH "member_2/taxonomy/data/taxonomy.yaml"
#endif

#ifndef DEMO_OUTPUT_DIR
#define DEMO_OUTPUT_DIR "member_2/temp_out"
#endif

namespace {

bool write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    if (!out) { std::cerr << "[demo] ERROR: " << path << '\n'; return false; }
    out << content;
    return true;
}

struct DemoAsset {
    std::string algorithm;
    long long   key_size = 0;
    std::string curve;
    std::string file;
    long long   line = 0;
    std::string context;
    double      exposure;
    double      remediation;
};

std::vector<DemoAsset> make_assets() {
    return {
        {"AES-256",  256,    "",       "src/crypto.cpp",     10, "AES-GCM at rest",          30.0, 20.0},
        {"RSA",      1024,   "",       "config/cert.pem",    42, "TLS server cert (weak)",   90.0, 80.0},
        {"ECDSA",    256,    "P-192",  "src/sign.rs",        78, "Code signing (weak curve)",70.0, 60.0},
        {"MD5",      0,      "",       "vendor/hashes.cpp", 200, "Legacy integrity check",   60.0, 40.0},
        {"BLOWFISH", 128,    "",       "legacy/enc.dll",    112, "Not in taxonomy",          20.0, 15.0},
    };
}

} // anon

int main() {
    std::cout << "========================================\n";
    std::cout << "  ECDAT Combined Demo\n";
    std::cout << "  Member 2 (Taxonomy) + Member 3 (Risk)\n";
    std::cout << "========================================\n\n";

    // ---- Load taxonomy ---------------------------------------------------
    std::cout << "[pipeline] Loading taxonomy from " << ECDAT_TAXONOMY_PATH << '\n';
    ecdat::TaxonomyDB db;
    try {
        db = ecdat::TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    } catch (const std::exception& e) {
        std::cerr << "[pipeline] FATAL: " << e.what() << '\n';
        return 1;
    }
    std::cout << "[pipeline] Loaded " << db.size() << " algorithm(s)\n\n";

    // ---- Ensure output directory -----------------------------------------
    std::filesystem::create_directories(DEMO_OUTPUT_DIR);

    // ---- Run pipeline on each asset --------------------------------------
    const auto assets = make_assets();
    int pass = 0, fail = 0;
    std::string summary;

    for (std::size_t i = 0; i < assets.size(); ++i) {
        const auto& da = assets[i];

        // Build CryptoAsset from demo data
        ecdat::CryptoAsset ca;
        ca.algorithm   = da.algorithm;
        ca.key_size    = da.key_size;
        ca.curve       = da.curve;
        ca.file        = da.file;
        ca.line        = da.line;
        ca.context     = da.context;

        // Run full pipeline
        ecdat::PipelineResult r;
        try {
            r = ecdat::run_pipeline(ca, db, da.exposure, da.remediation);
        } catch (const std::exception& e) {
            std::cerr << "[pipeline] ERROR on asset " << (i+1) << ": " << e.what() << '\n';
            ++fail;
            continue;
        }

        // Console output
        std::cout << "  Asset " << (i+1) << ": " << da.algorithm;
        if (!da.curve.empty()) std::cout << "/" << da.curve;
        std::cout << "  " << da.key_size << "b\n"
                  << "    Status:     " << ecdat::status_to_string(r.status) << "\n"
                  << "    Risk(0-10): " << r.risk_score << "\n"
                  << "    Weakness:   " << r.weakness << " (scaled)\n"
                  << "    Exposure:   " << r.exposure << "\n"
                  << "    Remediation:" << r.remediation << "\n"
                  << "    FinalRisk:  " << r.final_risk << " (weighted)\n"
                  << "    RiskLevel:  " << ecdat::risk::riskLevelToString(r.risk_level) << "\n"
                  << "    PQC:        " << (r.pqc_flag ? "YES" : "no") << "\n";
        if (r.migration.supported) {
            std::cout << "    Migration:  " << r.migration.algorithm << " ("
                      << r.migration.role << ") -> " << r.migration.replacement << "\n";
        }
        std::cout << "    Where:      " << r.explanation.where << "\n"
                  << "    Why:        " << r.explanation.why << "\n"
                  << "    Action:     " << r.explanation.action << "\n\n";

        // Write per-asset JSON
        ecdat::CryptoAsset out = ca;
        out.status     = r.status;
        out.risk_score = r.final_risk;  // pipeline risk score (0-100)
        out.pqc_flag   = r.pqc_flag;

        nlohmann::json j = ecdat::to_json(out);
        j["weakness"]    = r.weakness;
        j["exposure"]    = r.exposure;
        j["remediation"] = r.remediation;
        j["final_risk"]  = r.final_risk;
        j["risk_level"]  = ecdat::risk::riskLevelToString(r.risk_level);

        std::string tag = std::string(DEMO_OUTPUT_DIR) + "/combined_" + std::to_string(i+1) + ".json";
        if (write_file(tag, j.dump(2))) ++pass; else ++fail;

        // Accumulate summary
        summary += "combined_" + std::to_string(i+1) + ".json : "
                 + da.algorithm;
        if (!da.curve.empty()) summary += "/" + da.curve;
        summary += " -> " + std::string(ecdat::status_to_string(r.status))
                 + "  weakness=" + std::to_string(r.weakness)
                 + "  final_risk=" + std::to_string(r.final_risk)
                 + "  level=" + ecdat::risk::riskLevelToString(r.risk_level)
                 + "  pqc=" + (r.pqc_flag ? "true" : "false")
                 + "\n";
    }

    std::cout << '\n';

    // ---- Write summary ---------------------------------------------------
    std::string hdr;
    hdr += "ECDAT Combined Demo - Pipeline Summary\n";
    hdr += "=======================================\n";
    hdr += "Taxonomy algorithms : " + std::to_string(db.size()) + "\n";
    hdr += "Assets classified   : " + std::to_string(assets.size()) + "\n";
    hdr += "JSON files written  : " + std::to_string(pass) + "\n";
    hdr += "Write failures      : " + std::to_string(fail) + "\n\n";
    hdr += "Per-asset results:\n";
    hdr += summary;

    if (!write_file(std::string(DEMO_OUTPUT_DIR) + "/combined_summary.txt", hdr)) return 1;
    std::cout << "[pipeline] Wrote " << DEMO_OUTPUT_DIR << "/combined_summary.txt\n";

    if (fail > 0) {
        std::cerr << "[pipeline] FAIL: " << fail << " file(s)\n";
        return 1;
    }
    std::cout << "[pipeline] OK - all " << assets.size() << " assets processed\n";
    return 0;
}
