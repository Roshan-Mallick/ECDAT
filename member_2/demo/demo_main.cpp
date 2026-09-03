// Standalone demo for Member 2 (Data & Taxonomy Engineer).
//
// No dependency on Members 1, 3, or 4.  Loads taxonomy.yaml from the
// source tree (path injected at compile-time via CMake), builds
// hand-crafted CryptoAsset objects, classifies them, serialises every
// result to an individual JSON file in temp_out/, and writes a plain-
// text summary.

#include "ecdat/taxonomy.hpp"
#include "ecdat/serialization.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Compile-time absolute path to the shipped taxonomy file.
#ifndef ECDAT_TAXONOMY_PATH
#define ECDAT_TAXONOMY_PATH "taxonomy/data/taxonomy.yaml"
#endif

// Output directory (relative to the build root where the demo binary runs).
#ifndef DEMO_OUTPUT_DIR
#define DEMO_OUTPUT_DIR "temp_out"
#endif

namespace {

// Write a single string to a file, returning true on success.
bool write_file(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    if (!out) {
        std::cerr << "[demo] ERROR: cannot write " << path << '\n';
        return false;
    }
    out << content;
    return true;
}

// Build the hand-crafted assets that demonstrate Safe / Weak / Unknown.
std::vector<ecdat::CryptoAsset> make_demo_assets() {
    std::vector<ecdat::CryptoAsset> assets;

    {
        ecdat::CryptoAsset a;
        a.source_type = "hand-crafted";
        a.file        = "demo/demo_main.cpp";
        a.line        = 42;
        a.algorithm   = "AES-256";
        a.key_bits    = 256;
        a.context     = "symmetric encryption at rest";
        assets.push_back(std::move(a));
    }
    {
        ecdat::CryptoAsset a;
        a.source_type = "hand-crafted";
        a.file        = "config/keys.cfg";
        a.line        = 7;
        a.algorithm   = "RSA";
        a.key_bits    = 1024;
        a.context     = "TLS server certificate (weak key)";
        assets.push_back(std::move(a));
    }
    {
        ecdat::CryptoAsset a;
        a.source_type = "hand-crafted";
        a.file        = "src/sign.rs";
        a.line        = 118;
        a.algorithm   = "ECDSA";
        a.key_bits    = 256;
        a.curve       = "P-192";
        a.context     = "code-signing (weak curve)";
        assets.push_back(std::move(a));
    }
    {
        ecdat::CryptoAsset a;
        a.source_type = "hand-crafted";
        a.file        = "vendor/legacy.dll";
        a.line        = 200;
        a.algorithm   = "BLOWFISH";
        a.key_bits    = 128;
        a.context     = "legacy cipher not in taxonomy";
        assets.push_back(std::move(a));
    }
    return assets;
}

} // anon namespace

int main() {
    // ---- 1. Load taxonomy ------------------------------------------------
    std::cout << "[demo] Loading taxonomy from " << ECDAT_TAXONOMY_PATH << '\n';
    ecdat::TaxonomyDB db;
    try {
        db = ecdat::TaxonomyDB::load_from_file(ECDAT_TAXONOMY_PATH);
    } catch (const std::exception& e) {
        std::cerr << "[demo] FATAL: taxonomy load failed: " << e.what() << '\n';
        return 1;
    }
    std::cout << "[demo] Loaded " << db.size() << " algorithm(s)\n\n";

    // ---- 1b. Ensure output directory exists -----------------------------
    std::filesystem::create_directories(DEMO_OUTPUT_DIR);

    // ---- 2. Build mock assets -------------------------------------------
    const auto assets = make_demo_assets();
    std::cout << "[demo] Classified " << assets.size() << " hand-crafted assets\n\n";

    // ---- 3. Classify, serialize, write files ----------------------------
    int pass_count = 0;
    int fail_count = 0;
    std::string summary;

    std::cout << "  #  Algorithm          Status       Risk   PQC   File\n";
    std::cout << "  --- -----------------  -----------  -----  ----  ----\n";

    for (std::size_t i = 0; i < assets.size(); ++i) {
        const auto& asset = assets[i];
        const auto  result = ecdat::classify_asset(asset, db);

        // Console one-liner.
        std::string tag = std::string(DEMO_OUTPUT_DIR) + "/asset_"
                        + std::to_string(i + 1) + ".json";
        std::cout << "  " << (i + 1) << "  "
                  << std::string(17, ' ').replace(0, std::min<std::size_t>(asset.algorithm.size(), 17), asset.algorithm.substr(0, 17))
                  << "  " << ecdat::status_to_string(result.status)
                  << "  " << result.risk_score
                  << "  " << (result.pqc_flag ? "yes" : "no ")
                  << "  " << tag << '\n';

        // Serialize to JSON and write file.
        ecdat::CryptoAsset out_asset = asset;
        out_asset.status     = result.status;
        out_asset.risk_score = result.risk_score;
        out_asset.pqc_flag   = result.pqc_flag;

        const std::string json_str = ecdat::to_json(out_asset).dump(2);
        const bool ok = write_file(tag, json_str);
        if (ok) {
            ++pass_count;
        } else {
            ++fail_count;
        }

        // Accumulate summary line.
        summary += "asset_" + std::to_string(i + 1) + ".json : "
                 + asset.algorithm;
        if (!asset.curve.empty()) summary += "/" + asset.curve;
        if (asset.key_bits > 0)   summary += " " + std::to_string(asset.key_bits) + "b";
        summary += " -> " + std::string(ecdat::status_to_string(result.status))
                 + "  risk=" + std::to_string(result.risk_score)
                 + "  pqc=" + (result.pqc_flag ? "true" : "false")
                 + "\n";
    }

    std::cout << '\n';

    // ---- 4. Write summary.txt -------------------------------------------
    std::string header;
    header += "ECDAT Member 2 Demo - Classification Summary\n";
    header += "=============================================\n";
    header += "Taxonomy algorithms loaded : " + std::to_string(db.size()) + "\n";
    header += "Assets classified          : " + std::to_string(assets.size()) + "\n";
    header += "JSON files written         : " + std::to_string(pass_count) + "\n";
    header += "Write failures             : " + std::to_string(fail_count) + "\n";
    header += "\n";
    header += "Per-asset results:\n";
    header += summary;

    if (!write_file(std::string(DEMO_OUTPUT_DIR) + "/summary.txt", header)) {
        return 1;
    }

    std::cout << "[demo] Wrote " << DEMO_OUTPUT_DIR << "/summary.txt\n";

    // ---- 5. Final verdict -----------------------------------------------
    if (fail_count > 0) {
        std::cerr << "[demo] FAIL: " << fail_count << " file(s) could not be written\n";
        return 1;
    }
    std::cout << "[demo] OK - all outputs written successfully\n";
    return 0;
}
