#include "ecdat/reporting.hpp"
#include "ecdat/serialization.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace ecdat::reporting {

storage::ScanDetail build_scan_detail(
    const std::string& target_path,
    const std::vector<PipelineResult>& results,
    double readiness_pct) {

    storage::ScanDetail detail;
    detail.scan.id = 0;
    detail.scan.scan_uuid = storage::Storage::generate_uuid();
    detail.scan.timestamp = storage::Storage::current_timestamp();
    detail.scan.target_path = target_path;
    detail.scan.total_assets = static_cast<std::int64_t>(results.size());
    detail.scan.pqc_readiness_pct = readiness_pct;

    std::int64_t fid = 1;
    for (const auto& r : results) {
        switch (r.status) {
            case Status::Safe:       ++detail.scan.safe_count; break;
            case Status::Weak:       ++detail.scan.weak_count; break;
            case Status::Deprecated: ++detail.scan.deprecated_count; break;
            case Status::Unknown:    ++detail.scan.unknown_count; break;
        }

        switch (r.risk_level) {
            case risk::RiskLevel::CRITICAL: ++detail.scan.critical_risk_count; break;
            case risk::RiskLevel::HIGH:     ++detail.scan.high_risk_count; break;
            case risk::RiskLevel::MEDIUM:   ++detail.scan.medium_risk_count; break;
            case risk::RiskLevel::LOW:      ++detail.scan.low_risk_count; break;
        }

        if (!r.pqc_flag || r.migration.supported) {
            ++detail.scan.pqc_ready_count;
        }

        storage::FindingRecord f;
        f.id = fid++;
        f.scan_id = 0;
        f.source_type = !r.asset.source_type.empty() ? r.asset.source_type :
                       (r.explanation.where.find(".py") != std::string::npos ? "source_code" :
                       (r.explanation.where.find(".pem") != std::string::npos ? "certificate" : "tls_config"));
        f.file = !r.asset.file.empty() ? r.asset.file : r.explanation.where;
        f.line = r.asset.line;
        f.algorithm = !r.asset.algorithm.empty() ? r.asset.algorithm :
                      (r.migration.algorithm.empty() ? (r.taxonomy_entry ? r.taxonomy_entry->name : "Unknown") : r.migration.algorithm);
        f.key_size = r.asset.key_size;
        f.curve = r.asset.curve;
        f.context = r.asset.context;
        f.status = r.status;
        f.risk_score = r.final_risk;
        f.risk_level = risk::riskLevelToString(r.risk_level);
        f.pqc_flag = r.pqc_flag;
        f.pqc_supported = r.migration.supported;
        f.pqc_role = r.migration.role;
        f.pqc_replacement = r.migration.replacement;
        f.what = r.explanation.what;
        f.where_text = r.explanation.where;
        f.why = r.explanation.why;
        f.action = r.explanation.action;
        detail.findings.push_back(std::move(f));
    }

    if (detail.scan.total_assets > 0 && readiness_pct == 0.0) {
        detail.scan.pqc_readiness_pct = (static_cast<double>(detail.scan.pqc_ready_count) /
                                         static_cast<double>(detail.scan.total_assets)) * 100.0;
    }

    return detail;
}

std::string generate_json(const storage::ScanDetail& detail) {
    nlohmann::json root;

    // Scan Metadata
    root["scan_metadata"] = {
        {"id", detail.scan.id},
        {"uuid", detail.scan.scan_uuid},
        {"timestamp", detail.scan.timestamp},
        {"target_path", detail.scan.target_path},
        {"tool_name", "ECDAT"},
        {"tool_version", ECDAT_VERSION},
        {"platform", "Linux (Native C++20)"}
    };

    // Executive Summary
    root["summary"] = {
        {"total_assets", detail.scan.total_assets},
        {"status_counts", {
            {"safe", detail.scan.safe_count},
            {"weak", detail.scan.weak_count},
            {"deprecated", detail.scan.deprecated_count},
            {"unknown", detail.scan.unknown_count}
        }},
        {"risk_distribution", {
            {"critical", detail.scan.critical_risk_count},
            {"high", detail.scan.high_risk_count},
            {"medium", detail.scan.medium_risk_count},
            {"low", detail.scan.low_risk_count}
        }},
        {"pqc_readiness", {
            {"ready_count", detail.scan.pqc_ready_count},
            {"total_count", detail.scan.total_assets},
            {"readiness_percentage", detail.scan.pqc_readiness_pct}
        }}
    };

    // Findings List
    nlohmann::json findings_array = nlohmann::json::array();
    for (const auto& f : detail.findings) {
        findings_array.push_back({
            {"id", f.id},
            {"scan_id", f.scan_id},
            {"provenance", {
                {"source_type", f.source_type},
                {"file", f.file},
                {"line", f.line},
                {"context", f.context}
            }},
            {"cryptography", {
                {"algorithm", f.algorithm},
                {"key_size", f.key_size},
                {"curve", f.curve}
            }},
            {"assessment", {
                {"status", status_to_string(f.status)},
                {"risk_score", f.risk_score},
                {"risk_level", f.risk_level}
            }},
            {"pqc", {
                {"vulnerable", f.pqc_flag},
                {"migration_supported", f.pqc_supported},
                {"role", f.pqc_role},
                {"replacement", f.pqc_replacement}
            }},
            {"explanation", {
                {"what", f.what},
                {"where", f.where_text},
                {"why", f.why},
                {"action", f.action}
            }}
        });
    }

    root["findings"] = std::move(findings_array);

    return root.dump(2);
}

bool write_json(const storage::ScanDetail& detail, const std::string& filepath) {
    try {
        std::filesystem::path p(filepath);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
        std::ofstream out(filepath);
        if (!out.is_open()) return false;
        out << generate_json(detail) << "\n";
        return out.good();
    } catch (...) {
        return false;
    }
}

} // namespace ecdat::reporting
