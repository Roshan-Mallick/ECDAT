#include "ecdat/cli.hpp"
#include "ecdat/storage.hpp"
#include "ecdat/reporting.hpp"
#include "ecdat/taxonomy.hpp"
#include "ecdat/serialization.hpp"
#include "pipeline.h"
#include "flow.h"
#include "source_scanner.hpp"
#include "cert_scanner.hpp"
#include "tls_scanner.hpp"

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstdlib>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#ifndef __APPLE__
#include <linux/limits.h>
#endif
#endif

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#ifndef ECDAT_TAXONOMY_PATH
#define ECDAT_TAXONOMY_PATH "taxonomy/taxonomy/data/taxonomy.yaml"
#endif

namespace ecdat::cli {

namespace {

// Terminal color helpers respecting --no-color and non-tty
class TermColor {
public:
    explicit TermColor(bool disable) : disable_(disable || is_no_color_env() || !is_tty()) {}

    std::string bold(const std::string& s) const { return disable_ ? s : "\033[1m" + s + "\033[0m"; }
    std::string red(const std::string& s) const { return disable_ ? s : "\033[1;31m" + s + "\033[0m"; }
    std::string green(const std::string& s) const { return disable_ ? s : "\033[1;32m" + s + "\033[0m"; }
    std::string yellow(const std::string& s) const { return disable_ ? s : "\033[1;33m" + s + "\033[0m"; }
    std::string blue(const std::string& s) const { return disable_ ? s : "\033[1;34m" + s + "\033[0m"; }
    std::string cyan(const std::string& s) const { return disable_ ? s : "\033[1;36m" + s + "\033[0m"; }
    std::string magenta(const std::string& s) const { return disable_ ? s : "\033[1;35m" + s + "\033[0m"; }
    std::string gray(const std::string& s) const { return disable_ ? s : "\033[90m" + s + "\033[0m"; }

    std::string risk_tier(const std::string& tier) const {
        if (tier == "CRITICAL") return red("CRITICAL");
        if (tier == "HIGH")     return red("HIGH");
        if (tier == "MEDIUM")   return yellow("MEDIUM");
        return green("LOW");
    }

    std::string status_badge(Status st) const {
        switch (st) {
            case Status::Safe:       return green("Safe");
            case Status::Weak:       return yellow("Weak");
            case Status::Deprecated: return red("Deprecated");
            case Status::Unknown:    return gray("Unknown");
        }
        return gray("Unknown");
    }

private:
    bool disable_ = false;

    static bool is_no_color_env() {
        return std::getenv("NO_COLOR") != nullptr;
    }

    static bool is_tty() {
#ifdef _WIN32
        return _isatty(_fileno(stdout)) != 0;
#else
        return isatty(fileno(stdout)) != 0;
#endif
    }
};

std::string find_taxonomy_path() {
    // Allow an explicit override (useful for packagers and testing).
    if (const char* env = std::getenv("ECDAT_TAXONOMY")) {
        if (std::filesystem::exists(env)) {
            return env;
        }
    }

    std::vector<std::string> candidates;

    // Paths relative to the running executable so ECDAT works from any working
    // directory. Works for an unpacked tarball, a system install, or a dev tree.
    std::string exe_dir;
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        exe_dir = std::filesystem::path(buf).parent_path().string();
    }
#elif defined(__APPLE__)
    char buf[1024];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        exe_dir = std::filesystem::absolute(buf).parent_path().string();
    }
#else
    char buf[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        exe_dir = std::filesystem::path(buf).parent_path().string();
    }
#endif
    if (!exe_dir.empty()) {
        candidates.push_back(exe_dir + "/resources/taxonomy.yaml");
        candidates.push_back(exe_dir + "/../share/ecdat/taxonomy.yaml");
        candidates.push_back(exe_dir + "/../resources/taxonomy.yaml");
    }

    // Legacy / development-tree relative paths.
    candidates.push_back(ECDAT_TAXONOMY_PATH);
    candidates.push_back("taxonomy/taxonomy/data/taxonomy.yaml");
    candidates.push_back("../taxonomy/taxonomy/data/taxonomy.yaml");
    candidates.push_back("../../taxonomy/taxonomy/data/taxonomy.yaml");

    // System-wide fallback for packaged (e.g. .deb) installs.
    candidates.push_back("/usr/share/ecdat/taxonomy.yaml");
    candidates.push_back("/etc/ecdat/taxonomy.yaml");

    for (const auto& path : candidates) {
        if (std::filesystem::exists(path)) {
            return path;
        }
    }
    return ECDAT_TAXONOMY_PATH;
}

} // namespace

CliApp::CliApp() = default;
CliApp::~CliApp() = default;

int CliApp::run(int argc, char** argv) {
    CLI::App app{"ECDAT — Enterprise Cryptography Discovery & Assessment Tool\n"
                 "A high-performance security toolkit for cryptographic discovery, "
                 "risk assessment, and post-quantum readiness."};

    app.require_subcommand(0, 1);
    app.set_version_flag("-V,--version", "0.1.0");

    CliConfig config;

    // Global flags
    app.add_flag("--no-color", config.no_color, "Disable ANSI colored terminal output");
    app.add_flag("-v,--verbose", config.verbose, "Enable verbose logging");
    app.add_flag("-q,--quiet", config.quiet, "Quiet mode: print minimal output");
    app.add_option("--db", config.db_path, "Path to SQLite database file");

    // ============================================================
    // Subcommand: scan
    // ============================================================
    auto* sub_scan = app.add_subcommand("scan", "Scan source code, certificates, and TLS configs for cryptography");
    sub_scan->fallthrough();
    sub_scan->add_option("target", config.target_path, "Path to target file or directory")->required();
    sub_scan->add_option("--exposure", config.exposure, "Asset exposure factor [0-100] (default: 60.0)");
    sub_scan->add_option("--remediation", config.remediation, "Fix difficulty factor [0-100] (default: 40.0)");
    sub_scan->add_option("-o,--output", config.output_path, "Output file base path (appropriate extension is added automatically)");
    sub_scan->add_option("-f,--format", config.format, "Report format: json, csv, pdf, all (default: none)")
        ->check(CLI::IsMember({"json", "csv", "pdf", "all"}));
    sub_scan->add_option("--db", config.db_path, "Path to SQLite database file");

    // ============================================================
    // Subcommand: report
    // ============================================================
    auto* sub_report = app.add_subcommand("report", "Generate assessment reports from stored scan results");
    sub_report->fallthrough();
    sub_report->add_flag("--latest", config.latest, "Generate report from the most recent scan");
    sub_report->add_option("--scan", config.scan_id, "Scan ID to generate report from");
    sub_report->add_option("-f,--format", config.format, "Report format: json, csv, pdf, all (default: json)")
        ->default_val("json")
        ->check(CLI::IsMember({"json", "csv", "pdf", "all"}));
    sub_report->add_option("-o,--output", config.output_path, "Output file base path (appropriate extension is added automatically)");
    sub_report->add_option("--db", config.db_path, "Path to SQLite database file");

    // ============================================================
    // Subcommand: history
    // ============================================================
    auto* sub_history = app.add_subcommand("history", "View or manage previous scan history");
    sub_history->fallthrough();
    sub_history->add_option("-n,--limit", config.limit, "Maximum number of history records to display (default: 20)");
    sub_history->add_flag("--clear", config.clear, "Clear all historical scan records from database");
    sub_history->add_flag("--json", config.json_output, "Output scan history as raw JSON");
    sub_history->add_option("--db", config.db_path, "Path to SQLite database file");

    // ============================================================
    // Subcommand: export
    // ============================================================
    auto* sub_export = app.add_subcommand("export", "Export scan findings into JSON, CSV, or PDF formats");
    sub_export->fallthrough();
    sub_export->add_flag("--latest", config.latest, "Export from the most recent scan");
    sub_export->add_option("--scan", config.scan_id, "Scan ID to export");
    sub_export->add_option("-f,--format", config.format, "Export format: json, csv, pdf")
        ->required()
        ->check(CLI::IsMember({"json", "csv", "pdf"}));
    sub_export->add_option("-o,--output", config.output_path, "Output destination file path")->required();
    sub_export->add_option("--db", config.db_path, "Path to SQLite database file");

    // ============================================================
    // Subcommand: version
    // ============================================================
    auto* sub_version = app.add_subcommand("version", "Display detailed version and build information");
    sub_version->fallthrough();

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    // Configure logging
    if (config.verbose) {
        spdlog::set_level(spdlog::level::debug);
    } else if (config.quiet) {
        spdlog::set_level(spdlog::level::warn);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    try {
        if (sub_scan->parsed()) {
            return handle_scan(config);
        } else if (sub_report->parsed()) {
            return handle_report(config);
        } else if (sub_history->parsed()) {
            return handle_history(config);
        } else if (sub_export->parsed()) {
            return handle_export(config);
        } else if (sub_version->parsed()) {
            return handle_version();
        } else {
            std::cout << app.help() << "\n";
            return 1;
        }
    } catch (const std::exception& ex) {
        spdlog::error("Error: {}", ex.what());
        return 1;
    }

    return 0;
}

int CliApp::handle_version() {
    TermColor c(false);
    std::cout << "\n"
              << c.bold("ECDAT — Enterprise Cryptography Discovery & Assessment Tool") << "\n"
              << c.cyan("Version:") << "  0.1.0\n"
              << c.cyan("Language:") << " C++20 (Native Static Build)\n"
              << c.cyan("Platform:") << " Linux (x86_64)\n"
              << c.cyan("Engines:")  << " Tree-sitter AST, OpenSSL X.509, SQLite3, NIST PQC (ML-DSA/ML-KEM)\n"
              << c.gray("Copyright (c) 2026 ECDAT Project Team. Apache-2.0 License.") << "\n\n";
    return 0;
}

int CliApp::handle_scan(const CliConfig& config) {
    TermColor c(config.no_color);

    if (!std::filesystem::exists(config.target_path)) {
        std::cerr << c.red("Error:") << " Target path does not exist: " << config.target_path << "\n";
        return 1;
    }

    std::string tax_path = find_taxonomy_path();
    TaxonomyDB db;
    try {
        db = TaxonomyDB::load_from_file(tax_path);
    } catch (const std::exception& e) {
        std::cerr << c.red("Error loading taxonomy:") << " " << e.what() << " (searched: " << tax_path << ")\n";
        return 1;
    }

    if (!config.quiet) {
        std::cout << "\n"
                  << c.bold("============================================================") << "\n"
                  << c.bold("  ECDAT — Enterprise Cryptography Discovery & Assessment") << "\n"
                  << c.bold("============================================================") << "\n"
                  << c.cyan("Target:") << " " << config.target_path << "\n"
                  << c.cyan("Taxonomy:") << " " << tax_path << " (" << db.size() << " algorithms loaded)\n"
                  << c.cyan("Parameters:") << " Exposure=" << config.exposure << ", Remediation=" << config.remediation << "\n\n";
    }

    std::vector<std::string> py_files;
    std::vector<std::string> pem_files;
    std::vector<std::string> conf_files;

    auto get_lower_ext = [](const std::string& filepath) -> std::string {
        std::filesystem::path p(filepath);
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return ext;
    };

    if (std::filesystem::is_directory(config.target_path)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(config.target_path)) {
            if (!entry.is_regular_file()) continue;
            std::string ext = get_lower_ext(entry.path().string());
            std::string filename = entry.path().filename().string();

            if (ext == ".py") {
                py_files.push_back(entry.path().string());
            } else if (ext == ".pem" || ext == ".crt" || ext == ".cer") {
                pem_files.push_back(entry.path().string());
            } else if (ext == ".conf" || ext == ".cfg" || filename == "nginx.conf" || filename == "httpd.conf") {
                conf_files.push_back(entry.path().string());
            }
        }
    } else {
        std::string ext = get_lower_ext(config.target_path);
        if (ext == ".py") {
            py_files.push_back(config.target_path);
        } else if (ext == ".pem" || ext == ".crt" || ext == ".cer") {
            pem_files.push_back(config.target_path);
        } else {
            conf_files.push_back(config.target_path);
        }
    }

    std::vector<PipelineResult> all_results;

    // Scan Python source files
    for (const auto& f : py_files) {
        auto r = flow::analyze_source_file(f, db, config.exposure, config.remediation);
        all_results.insert(all_results.end(), r.begin(), r.end());
    }

    // Scan PEM certificates
    for (const auto& f : pem_files) {
        auto r = flow::analyze_certificate(f, db, config.exposure, config.remediation);
        all_results.insert(all_results.end(), r.begin(), r.end());
    }

    // Scan TLS configs
    for (const auto& f : conf_files) {
        auto r = flow::analyze_tls_config(f, db, config.exposure, config.remediation);
        all_results.insert(all_results.end(), r.begin(), r.end());
    }

    // Compute PQC readiness
    std::size_t ready_count = 0;
    for (const auto& r : all_results) {
        if (!r.pqc_flag || r.migration.supported) {
            ++ready_count;
        }
    }
    double readiness_pct = pqc::readiness_percentage(ready_count, all_results.size());

    // Save to SQLite storage
    storage::Storage store(config.db_path);
    std::int64_t scan_id = store.save_scan(config.target_path, all_results, readiness_pct);

    // Build ScanDetail
    auto scan_detail = store.get_scan(scan_id).value_or(
        reporting::build_scan_detail(config.target_path, all_results, readiness_pct));

    // Console output
    if (!config.quiet) {
        std::cout << c.bold("[DISCOVERY]") << "\n"
                  << "  Source files scanned:       " << py_files.size() << "\n"
                  << "  Certificates scanned:       " << pem_files.size() << "\n"
                  << "  TLS configurations scanned: " << conf_files.size() << "\n"
                  << "  Total assets discovered:    " << c.bold(std::to_string(all_results.size())) << "\n\n";

        std::cout << c.bold("[ASSESSMENT & RISK BREAKDOWN]") << "\n"
                  << "  Safe:        " << c.green(std::to_string(scan_detail.scan.safe_count)) << "\n"
                  << "  Weak:        " << c.yellow(std::to_string(scan_detail.scan.weak_count)) << "\n"
                  << "  Deprecated:  " << c.red(std::to_string(scan_detail.scan.deprecated_count)) << "\n"
                  << "  Unknown:     " << c.gray(std::to_string(scan_detail.scan.unknown_count)) << "\n"
                  << "  -------------------------------------\n"
                  << "  CRITICAL Risk: " << c.red(std::to_string(scan_detail.scan.critical_risk_count)) << "\n"
                  << "  HIGH Risk:     " << c.red(std::to_string(scan_detail.scan.high_risk_count)) << "\n"
                  << "  MEDIUM Risk:   " << c.yellow(std::to_string(scan_detail.scan.medium_risk_count)) << "\n"
                  << "  LOW Risk:      " << c.green(std::to_string(scan_detail.scan.low_risk_count)) << "\n\n";

        std::cout << c.bold("[POST-QUANTUM READINESS]") << "\n"
                  << "  PQC-Ready Assets:  " << ready_count << " / " << all_results.size() << "\n"
                  << "  Readiness Score:   " << c.cyan(fmt::format("{:.1f}%", readiness_pct)) << "\n\n";

        if (!all_results.empty()) {
            std::cout << c.bold("[FINDINGS SUMMARY]") << "\n";
            for (std::size_t i = 0; i < all_results.size(); ++i) {
                const auto& r = all_results[i];
                std::cout << "  " << c.bold(fmt::format("[{}]", i + 1)) << " "
                          << c.cyan(r.migration.algorithm.empty() ? (r.taxonomy_entry ? r.taxonomy_entry->name : "Unknown") : r.migration.algorithm)
                          << "  Status: " << c.status_badge(r.status)
                          << "  Risk: " << fmt::format("{:.1f}", r.final_risk)
                          << " (" << c.risk_tier(risk::riskLevelToString(r.risk_level)) << ")"
                          << "  PQC: " << (r.pqc_flag ? c.yellow("YES") : c.green("NO")) << "\n"
                          << "      Where:  " << r.explanation.where << "\n"
                          << "      Why:    " << r.explanation.why << "\n"
                          << "      Action: " << c.bold(r.explanation.action) << "\n";
                if (r.migration.supported) {
                    std::cout << "      PQC Replacement: " << c.green(r.migration.replacement)
                              << " (" << r.migration.role << ")\n";
                }
                std::cout << "\n";
            }
        }
    }

    // Export reports if requested
    bool report_ok = true;
    if (!config.format.empty() || !config.output_path.empty()) {
        std::string fmt_str = config.format.empty() ? "json" : config.format;
        std::string out_base = config.output_path.empty() ? "ecdat_report" : config.output_path;

        std::string base_path = out_base;
        if (fmt_str == "all") {
            if (base_path.ends_with(".json")) base_path = base_path.substr(0, base_path.size() - 5);
            else if (base_path.ends_with(".csv") || base_path.ends_with(".pdf")) base_path = base_path.substr(0, base_path.size() - 4);
        }

        if (fmt_str == "json" || fmt_str == "all") {
            std::string path = (fmt_str == "all") ? (base_path + ".json") : (out_base.ends_with(".json") ? out_base : (out_base + ".json"));
            if (reporting::write_json(scan_detail, path)) {
                std::cout << c.green("  [REPORT]") << " JSON report written to: " << path << "\n";
            } else {
                std::cerr << c.red("Error:") << " Failed to write JSON report to: " << path << "\n";
                report_ok = false;
            }
        }
        if (fmt_str == "csv" || fmt_str == "all") {
            std::string path = (fmt_str == "all") ? (base_path + ".csv") : (out_base.ends_with(".csv") ? out_base : (out_base + ".csv"));
            if (reporting::write_csv(scan_detail, path)) {
                std::cout << c.green("  [REPORT]") << " CSV report written to: " << path << "\n";
            } else {
                std::cerr << c.red("Error:") << " Failed to write CSV report to: " << path << "\n";
                report_ok = false;
            }
        }
        if (fmt_str == "pdf" || fmt_str == "all") {
            std::string path = (fmt_str == "all") ? (base_path + ".pdf") : (out_base.ends_with(".pdf") ? out_base : (out_base + ".pdf"));
            if (reporting::write_pdf(scan_detail, path)) {
                std::cout << c.green("  [REPORT]") << " PDF report written to: " << path << "\n";
            } else {
                std::cerr << c.red("Error:") << " Failed to write PDF report to: " << path << "\n";
                report_ok = false;
            }
        }
    }

    if (!report_ok) {
        return 1;
    }

    std::cout << c.bold(c.green("Scan completed successfully.")) << " (Scan ID: " << scan_id << ")\n\n";
    return 0;
}

int CliApp::handle_report(const CliConfig& config) {
    TermColor c(config.no_color);
    storage::Storage store(config.db_path);

    std::optional<storage::ScanDetail> opt_scan;
    if (config.scan_id > 0) {
        opt_scan = store.get_scan(config.scan_id);
    } else {
        opt_scan = store.get_latest_scan();
    }

    if (!opt_scan) {
        std::cerr << c.red("Error:") << " No scan record found "
                  << (config.scan_id > 0 ? ("for ID " + std::to_string(config.scan_id)) : "in database") << "\n";
        return 1;
    }

    const auto& detail = *opt_scan;
    std::string fmt_str = config.format.empty() ? "json" : config.format;
    std::string out_dest = config.output_path;

    if (out_dest.empty()) {
        // Output to stdout if json or csv and no path specified
        if (fmt_str == "json") {
            std::cout << reporting::generate_json(detail) << "\n";
            return 0;
        } else if (fmt_str == "csv") {
            std::cout << reporting::generate_csv(detail);
            return 0;
        } else {
            out_dest = "ecdat_scan_" + std::to_string(detail.scan.id);
        }
    }

    std::string base_path = out_dest;
    if (base_path.ends_with(".json")) base_path = base_path.substr(0, base_path.size() - 5);
    else if (base_path.ends_with(".csv") || base_path.ends_with(".pdf")) base_path = base_path.substr(0, base_path.size() - 4);

    bool report_ok = true;

    if (fmt_str == "json" || fmt_str == "all") {
        std::string p = (fmt_str == "all") ? (base_path + ".json") : (out_dest.ends_with(".json") ? out_dest : (out_dest + ".json"));
        if (reporting::write_json(detail, p)) {
            std::cout << c.green("Successfully generated JSON report:") << " " << p << "\n";
        } else {
            std::cerr << c.red("Error:") << " Failed to write JSON report to: " << p << "\n";
            report_ok = false;
        }
    }
    if (fmt_str == "csv" || fmt_str == "all") {
        std::string p = (fmt_str == "all") ? (base_path + ".csv") : (out_dest.ends_with(".csv") ? out_dest : (out_dest + ".csv"));
        if (reporting::write_csv(detail, p)) {
            std::cout << c.green("Successfully generated CSV report:") << " " << p << "\n";
        } else {
            std::cerr << c.red("Error:") << " Failed to write CSV report to: " << p << "\n";
            report_ok = false;
        }
    }
    if (fmt_str == "pdf" || fmt_str == "all") {
        std::string p = (fmt_str == "all") ? (base_path + ".pdf") : (out_dest.ends_with(".pdf") ? out_dest : (out_dest + ".pdf"));
        if (reporting::write_pdf(detail, p)) {
            std::cout << c.green("Successfully generated PDF report:") << " " << p << "\n";
        } else {
            std::cerr << c.red("Error:") << " Failed to write PDF report to: " << p << "\n";
            report_ok = false;
        }
    }

    return report_ok ? 0 : 1;
}

int CliApp::handle_history(const CliConfig& config) {
    TermColor c(config.no_color);
    storage::Storage store(config.db_path);

    if (config.clear) {
        store.clear_history();
        std::cout << c.green("Scan history cleared successfully.") << "\n";
        return 0;
    }

    auto history = store.get_history(config.limit);

    if (config.json_output) {
        nlohmann::json j = nlohmann::json::array();
        for (const auto& s : history) {
            j.push_back({
                {"id", s.id},
                {"uuid", s.scan_uuid},
                {"timestamp", s.timestamp},
                {"target_path", s.target_path},
                {"total_assets", s.total_assets},
                {"safe_count", s.safe_count},
                {"weak_count", s.weak_count},
                {"deprecated_count", s.deprecated_count},
                {"unknown_count", s.unknown_count},
                {"critical_risk", s.critical_risk_count},
                {"high_risk", s.high_risk_count},
                {"medium_risk", s.medium_risk_count},
                {"low_risk", s.low_risk_count},
                {"pqc_ready_count", s.pqc_ready_count},
                {"pqc_readiness_pct", s.pqc_readiness_pct}
            });
        }
        std::cout << j.dump(2) << "\n";
        return 0;
    }

    std::cout << "\n"
              << c.bold("ECDAT SCAN HISTORY") << "\n"
              << "--------------------------------------------------------------------------------\n"
              << fmt::format("{:<6} {:<20} {:<26} {:<10} {:<12}\n",
                             "ID", "DATE / TIME (UTC)", "TARGET", "FINDINGS", "PQC READINESS")
              << "--------------------------------------------------------------------------------\n";

    if (history.empty()) {
        std::cout << "  (No previous scans recorded in database)\n";
    } else {
        for (const auto& s : history) {
            std::string target_display = s.target_path.size() > 24 ? (s.target_path.substr(0, 21) + "...") : s.target_path;
            std::string pqc_str = fmt::format("{:.1f}% ({}/{})", s.pqc_readiness_pct, s.pqc_ready_count, s.total_assets);

            std::cout << fmt::format("{:<6} {:<20} {:<26} {:<10} {:<12}\n",
                                     s.id, s.timestamp, target_display, s.total_assets, pqc_str);
        }
    }
    std::cout << "--------------------------------------------------------------------------------\n\n";
    return 0;
}

int CliApp::handle_export(const CliConfig& config) {
    TermColor c(config.no_color);
    storage::Storage store(config.db_path);

    std::optional<storage::ScanDetail> opt_scan;
    if (config.scan_id > 0) {
        opt_scan = store.get_scan(config.scan_id);
    } else {
        opt_scan = store.get_latest_scan();
    }

    if (!opt_scan) {
        std::cerr << c.red("Error:") << " No scan available for export "
                  << (config.scan_id > 0 ? ("for ID " + std::to_string(config.scan_id)) : "in database") << "\n";
        return 1;
    }

    const auto& detail = *opt_scan;
    bool ok = false;

    if (config.format == "json") {
        ok = reporting::write_json(detail, config.output_path);
    } else if (config.format == "csv") {
        ok = reporting::write_csv(detail, config.output_path);
    } else if (config.format == "pdf") {
        ok = reporting::write_pdf(detail, config.output_path);
    } else {
        std::cerr << c.red("Error:") << " Unsupported export format: '" << config.format << "'. Supported: json, csv, pdf.\n";
        return 1;
    }

    if (!ok) {
        std::cerr << c.red("Error:") << " Failed to write export file to: " << config.output_path << "\n";
        return 1;
    }

    std::cout << c.green("Export completed:") << " " << config.output_path << "\n";
    return 0;
}

} // namespace ecdat::cli
