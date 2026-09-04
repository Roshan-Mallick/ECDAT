#include "ecdat/reporting.hpp"
#include "ecdat/serialization.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace ecdat::reporting {

namespace {

std::string escape_csv(const std::string& field) {
    bool needs_quotes = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quotes = true;
            break;
        }
    }

    if (!needs_quotes) {
        return field;
    }

    std::string escaped = "\"";
    for (char c : field) {
        if (c == '"') {
            escaped += "\"\"";
        } else {
            escaped += c;
        }
    }
    escaped += "\"";
    return escaped;
}

} // namespace

std::string generate_csv(const storage::ScanDetail& detail) {
    std::ostringstream oss;

    // CSV Header
    oss << "scan_id,scan_uuid,timestamp,target_path,finding_id,source_type,file,line,"
        << "algorithm,key_size,curve,context,status,risk_score,risk_level,pqc_vulnerable,"
        << "pqc_supported,pqc_role,pqc_replacement,what,where,why,action\n";

    for (const auto& f : detail.findings) {
        oss << detail.scan.id << ","
            << escape_csv(detail.scan.scan_uuid) << ","
            << escape_csv(detail.scan.timestamp) << ","
            << escape_csv(detail.scan.target_path) << ","
            << f.id << ","
            << escape_csv(f.source_type) << ","
            << escape_csv(f.file) << ","
            << f.line << ","
            << escape_csv(f.algorithm) << ","
            << f.key_size << ","
            << escape_csv(f.curve) << ","
            << escape_csv(f.context) << ","
            << escape_csv(std::string(status_to_string(f.status))) << ","
            << f.risk_score << ","
            << escape_csv(f.risk_level) << ","
            << (f.pqc_flag ? "true" : "false") << ","
            << (f.pqc_supported ? "true" : "false") << ","
            << escape_csv(f.pqc_role) << ","
            << escape_csv(f.pqc_replacement) << ","
            << escape_csv(f.what) << ","
            << escape_csv(f.where_text) << ","
            << escape_csv(f.why) << ","
            << escape_csv(f.action) << "\n";
    }

    return oss.str();
}

bool write_csv(const storage::ScanDetail& detail, const std::string& filepath) {
    try {
        std::filesystem::path p(filepath);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
        std::ofstream out(filepath);
        if (!out.is_open()) return false;
        out << generate_csv(detail);
        return out.good();
    } catch (...) {
        return false;
    }
}

} // namespace ecdat::reporting
