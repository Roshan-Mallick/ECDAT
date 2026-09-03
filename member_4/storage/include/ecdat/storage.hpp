#pragma once

#include "ecdat/types.hpp"
#include "pipeline.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ecdat::storage {

// A persistent record for a complete scan execution.
struct ScanRecord {
    std::int64_t id = 0;
    std::string  scan_uuid;
    std::string  timestamp;
    std::string  target_path;
    std::int64_t total_assets = 0;
    std::int64_t safe_count = 0;
    std::int64_t weak_count = 0;
    std::int64_t deprecated_count = 0;
    std::int64_t unknown_count = 0;
    std::int64_t critical_risk_count = 0;
    std::int64_t high_risk_count = 0;
    std::int64_t medium_risk_count = 0;
    std::int64_t low_risk_count = 0;
    std::int64_t pqc_ready_count = 0;
    double       pqc_readiness_pct = 0.0;
    std::string  metadata_json;
};

// A persistent record for a single cryptographic finding in a scan.
struct FindingRecord {
    std::int64_t id = 0;
    std::int64_t scan_id = 0;
    std::string  source_type;
    std::string  file;
    std::int64_t line = 0;
    std::string  algorithm;
    std::int64_t key_size = 0;
    std::string  curve;
    std::string  context;
    Status       status = Status::Unknown;
    double       risk_score = 0.0;
    std::string  risk_level;
    bool         pqc_flag = false;
    bool         pqc_supported = false;
    std::string  pqc_role;
    std::string  pqc_replacement;
    std::string  what;
    std::string  where_text;
    std::string  why;
    std::string  action;

    // Convert to authoritative ecdat::CryptoAsset
    [[nodiscard]] CryptoAsset to_crypto_asset() const;

    // Convert to authoritative ecdat::Finding
    [[nodiscard]] Finding to_finding() const;
};

// Aggregation of a scan header with all its associated findings.
struct ScanDetail {
    ScanRecord                 scan;
    std::vector<FindingRecord> findings;
};

// Storage manager using embedded SQLite C API with prepared statements.
class Storage {
public:
    explicit Storage(const std::string& db_path);
    ~Storage();

    // Non-copyable, movable
    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;
    Storage(Storage&&) noexcept;
    Storage& operator=(Storage&&) noexcept;

    // Lifecycle
    void initialize();
    void close();
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] const std::string& db_path() const noexcept { return db_path_; }

    // Persistence methods
    std::int64_t save_scan(const std::string& target_path,
                           const std::vector<PipelineResult>& results,
                           double readiness_pct = 0.0,
                           const std::string& custom_uuid = "");

    std::int64_t save_findings(const std::string& target_path,
                               const std::vector<Finding>& findings,
                               const std::string& custom_uuid = "");

    // Query methods
    [[nodiscard]] std::vector<ScanRecord> get_history(std::size_t limit = 100) const;
    [[nodiscard]] std::optional<ScanDetail> get_scan(std::int64_t scan_id) const;
    [[nodiscard]] std::optional<ScanDetail> get_latest_scan() const;
    [[nodiscard]] std::optional<ScanDetail> get_scan_by_uuid(const std::string& uuid) const;

    // Maintenance
    void clear_history();
    void delete_scan(std::int64_t scan_id);

    // Helpers
    static std::string default_db_path();
    static std::string generate_uuid();
    static std::string current_timestamp();

private:
    std::string db_path_;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ecdat::storage
