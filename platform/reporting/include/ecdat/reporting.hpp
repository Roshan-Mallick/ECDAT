#pragma once

#include "ecdat/storage.hpp"
#include "pipeline.h"

#include <string>
#include <vector>

namespace ecdat::reporting {

// ============================================================
// JSON Reporting
// ============================================================
[[nodiscard]] std::string generate_json(const storage::ScanDetail& detail);
bool write_json(const storage::ScanDetail& detail, const std::string& filepath);

// ============================================================
// CSV Reporting (RFC 4180 compliant)
// ============================================================
[[nodiscard]] std::string generate_csv(const storage::ScanDetail& detail);
bool write_csv(const storage::ScanDetail& detail, const std::string& filepath);

// ============================================================
// Native C++ PDF Reporting
// ============================================================
[[nodiscard]] std::string generate_pdf(const storage::ScanDetail& detail);
bool write_pdf(const storage::ScanDetail& detail, const std::string& filepath);

// ============================================================
// Convenience helper: construct a ScanDetail from live PipelineResults
// ============================================================
[[nodiscard]] storage::ScanDetail build_scan_detail(
    const std::string& target_path,
    const std::vector<PipelineResult>& results,
    double readiness_pct = 0.0);

} // namespace ecdat::reporting
