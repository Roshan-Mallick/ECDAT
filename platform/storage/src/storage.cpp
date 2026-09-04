#include "ecdat/storage.hpp"
#include "ecdat/serialization.hpp"
#include "risk/risk_engine.h"

#include <sqlite3.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace ecdat::storage {

namespace {

// RAII helper for SQLite prepared statements
class Statement {
public:
    Statement(sqlite3* db, const std::string& sql) {
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt_, nullptr);
        if (rc != SQLITE_OK) {
            std::string err = sqlite3_errmsg(db);
            throw std::runtime_error("SQLite prepare failed: " + err + " (SQL: " + sql + ")");
        }
    }

    ~Statement() {
        if (stmt_) {
            sqlite3_finalize(stmt_);
        }
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return stmt_; }

    void reset() {
        if (stmt_) {
            sqlite3_reset(stmt_);
            sqlite3_clear_bindings(stmt_);
        }
    }

    void bind_int64(int index, std::int64_t val) {
        int rc = sqlite3_bind_int64(stmt_, index, val);
        check_rc(rc, "bind_int64");
    }

    void bind_double(int index, double val) {
        int rc = sqlite3_bind_double(stmt_, index, val);
        check_rc(rc, "bind_double");
    }

    void bind_text(int index, const std::string& text) {
        int rc = sqlite3_bind_text(stmt_, index, text.c_str(), -1, SQLITE_TRANSIENT);
        check_rc(rc, "bind_text");
    }

    void bind_null(int index) {
        int rc = sqlite3_bind_null(stmt_, index);
        check_rc(rc, "bind_null");
    }

    [[nodiscard]] int step() {
        return sqlite3_step(stmt_);
    }

private:
    sqlite3_stmt* stmt_ = nullptr;

    void check_rc(int rc, const char* op) {
        if (rc != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite bind failed in ") + op);
        }
    }
};

// RAII helper for SQLite transactions
class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) {
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::string err = err_msg ? err_msg : "unknown";
            sqlite3_free(err_msg);
            throw std::runtime_error("Failed to begin SQLite transaction: " + err);
        }
    }

    ~Transaction() {
        if (!committed_ && db_) {
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        }
    }

    void commit() {
        char* err_msg = nullptr;
        int rc = sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            std::string err = err_msg ? err_msg : "unknown";
            sqlite3_free(err_msg);
            throw std::runtime_error("Failed to commit SQLite transaction: " + err);
        }
        committed_ = true;
    }

private:
    sqlite3* db_ = nullptr;
    bool committed_ = false;
};

std::string column_text(sqlite3_stmt* stmt, int col) {
    const unsigned char* text = sqlite3_column_text(stmt, col);
    return text ? reinterpret_cast<const char*>(text) : "";
}

} // namespace

CryptoAsset FindingRecord::to_crypto_asset() const {
    CryptoAsset asset;
    asset.source_type = source_type;
    asset.file = file;
    asset.line = line;
    asset.algorithm = algorithm;
    asset.key_size = key_size;
    asset.curve = curve;
    asset.context = context;
    asset.status = status;
    asset.risk_score = risk_score;
    asset.pqc_flag = pqc_flag;
    return asset;
}

Finding FindingRecord::to_finding() const {
    Finding finding;
    finding.asset = to_crypto_asset();
    if (!action.empty()) {
        finding.message = action;
    } else if (!what.empty()) {
        finding.message = what;
    } else {
        finding.message = algorithm + " finding";
    }
    return finding;
}

struct Storage::Impl {
    sqlite3* db = nullptr;
};

Storage::Storage(const std::string& db_path)
    : db_path_(db_path.empty() ? default_db_path() : db_path),
      impl_(std::make_unique<Impl>()) {
    initialize();
}

Storage::~Storage() {
    close();
}

Storage::Storage(Storage&&) noexcept = default;
Storage& Storage::operator=(Storage&&) noexcept = default;

void Storage::initialize() {
    if (impl_->db != nullptr) {
        return;
    }

    // Ensure parent directory exists for file-based database
    if (db_path_ != ":memory:") {
        std::filesystem::path path(db_path_);
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path());
        }
    }

    int rc = sqlite3_open_v2(db_path_.c_str(), &impl_->db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = impl_->db ? sqlite3_errmsg(impl_->db) : "cannot open database";
        if (impl_->db) {
            sqlite3_close_v2(impl_->db);
            impl_->db = nullptr;
        }
        throw std::runtime_error("Cannot open SQLite database at '" + db_path_ + "': " + err);
    }

    // Set foreign keys and WAL mode
    sqlite3_exec(impl_->db, "PRAGMA foreign_keys = ON;", nullptr, nullptr, nullptr);

    // Create schema
    const char* schema_sql = R"(
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_uuid TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            target_path TEXT NOT NULL,
            total_assets INTEGER NOT NULL DEFAULT 0,
            safe_count INTEGER NOT NULL DEFAULT 0,
            weak_count INTEGER NOT NULL DEFAULT 0,
            deprecated_count INTEGER NOT NULL DEFAULT 0,
            unknown_count INTEGER NOT NULL DEFAULT 0,
            critical_risk_count INTEGER NOT NULL DEFAULT 0,
            high_risk_count INTEGER NOT NULL DEFAULT 0,
            medium_risk_count INTEGER NOT NULL DEFAULT 0,
            low_risk_count INTEGER NOT NULL DEFAULT 0,
            pqc_ready_count INTEGER NOT NULL DEFAULT 0,
            pqc_readiness_pct REAL NOT NULL DEFAULT 0.0,
            metadata_json TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            source_type TEXT NOT NULL,
            file TEXT NOT NULL,
            line INTEGER NOT NULL DEFAULT 0,
            algorithm TEXT NOT NULL,
            key_size INTEGER NOT NULL DEFAULT 0,
            curve TEXT DEFAULT '',
            context TEXT DEFAULT '',
            status TEXT NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0.0,
            risk_level TEXT NOT NULL,
            pqc_flag INTEGER NOT NULL DEFAULT 0,
            pqc_supported INTEGER NOT NULL DEFAULT 0,
            pqc_role TEXT DEFAULT '',
            pqc_replacement TEXT DEFAULT '',
            what TEXT DEFAULT '',
            where_text TEXT DEFAULT '',
            why TEXT DEFAULT '',
            action TEXT DEFAULT '',
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
    )";

    char* err_msg = nullptr;
    rc = sqlite3_exec(impl_->db, schema_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "schema creation error";
        sqlite3_free(err_msg);
        throw std::runtime_error("SQLite schema initialization failed: " + err);
    }
}

void Storage::close() {
    if (impl_ && impl_->db) {
        sqlite3_close_v2(impl_->db);
        impl_->db = nullptr;
    }
}

bool Storage::is_open() const noexcept {
    return impl_ && impl_->db != nullptr;
}

std::int64_t Storage::save_scan(const std::string& target_path,
                                const std::vector<PipelineResult>& results,
                                double readiness_pct,
                                const std::string& custom_uuid) {
    if (!is_open()) initialize();

    std::string uuid = custom_uuid.empty() ? generate_uuid() : custom_uuid;
    std::string ts = current_timestamp();

    ScanRecord s;
    s.scan_uuid = uuid;
    s.timestamp = ts;
    s.target_path = target_path;
    s.total_assets = static_cast<std::int64_t>(results.size());
    s.pqc_readiness_pct = readiness_pct;

    for (const auto& r : results) {
        switch (r.status) {
            case Status::Safe:       ++s.safe_count; break;
            case Status::Weak:       ++s.weak_count; break;
            case Status::Deprecated: ++s.deprecated_count; break;
            case Status::Unknown:    ++s.unknown_count; break;
        }

        switch (r.risk_level) {
            case risk::RiskLevel::CRITICAL: ++s.critical_risk_count; break;
            case risk::RiskLevel::HIGH:     ++s.high_risk_count; break;
            case risk::RiskLevel::MEDIUM:   ++s.medium_risk_count; break;
            case risk::RiskLevel::LOW:      ++s.low_risk_count; break;
        }

        if (!r.pqc_flag || r.migration.supported) {
            ++s.pqc_ready_count;
        }
    }

    Transaction txn(impl_->db);

    Statement stmt_scan(impl_->db, R"(
        INSERT INTO scans (
            scan_uuid, timestamp, target_path, total_assets,
            safe_count, weak_count, deprecated_count, unknown_count,
            critical_risk_count, high_risk_count, medium_risk_count, low_risk_count,
            pqc_ready_count, pqc_readiness_pct, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )");

    stmt_scan.bind_text(1, s.scan_uuid);
    stmt_scan.bind_text(2, s.timestamp);
    stmt_scan.bind_text(3, s.target_path);
    stmt_scan.bind_int64(4, s.total_assets);
    stmt_scan.bind_int64(5, s.safe_count);
    stmt_scan.bind_int64(6, s.weak_count);
    stmt_scan.bind_int64(7, s.deprecated_count);
    stmt_scan.bind_int64(8, s.unknown_count);
    stmt_scan.bind_int64(9, s.critical_risk_count);
    stmt_scan.bind_int64(10, s.high_risk_count);
    stmt_scan.bind_int64(11, s.medium_risk_count);
    stmt_scan.bind_int64(12, s.low_risk_count);
    stmt_scan.bind_int64(13, s.pqc_ready_count);
    stmt_scan.bind_double(14, s.pqc_readiness_pct);
    stmt_scan.bind_text(15, "");

    if (stmt_scan.step() != SQLITE_DONE) {
        throw std::runtime_error("Failed to insert scan record into database");
    }

    std::int64_t scan_id = sqlite3_last_insert_rowid(impl_->db);

    Statement stmt_find(impl_->db, R"(
        INSERT INTO findings (
            scan_id, source_type, file, line, algorithm, key_size, curve, context,
            status, risk_score, risk_level, pqc_flag, pqc_supported, pqc_role,
            pqc_replacement, what, where_text, why, action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )");

    for (const auto& r : results) {
        stmt_find.reset();
        stmt_find.bind_int64(1, scan_id);
        std::string src_type = !r.asset.source_type.empty() ? r.asset.source_type :
                               (r.explanation.where.find(".py") != std::string::npos ? "source_code" :
                               (r.explanation.where.find(".pem") != std::string::npos ? "certificate" : "tls_config"));
        std::string file_path = !r.asset.file.empty() ? r.asset.file : r.explanation.where;
        std::string algo = !r.asset.algorithm.empty() ? r.asset.algorithm :
                           (r.migration.algorithm.empty() ? (r.taxonomy_entry ? r.taxonomy_entry->name : "Unknown") : r.migration.algorithm);

        stmt_find.bind_text(2, src_type);
        stmt_find.bind_text(3, file_path);
        stmt_find.bind_int64(4, r.asset.line);
        stmt_find.bind_text(5, algo);
        stmt_find.bind_int64(6, r.asset.key_size);
        stmt_find.bind_text(7, r.asset.curve);
        stmt_find.bind_text(8, r.asset.context);
        stmt_find.bind_text(9, std::string(status_to_string(r.status)));
        stmt_find.bind_double(10, r.final_risk);
        stmt_find.bind_text(11, risk::riskLevelToString(r.risk_level));
        stmt_find.bind_int64(12, r.pqc_flag ? 1 : 0);
        stmt_find.bind_int64(13, r.migration.supported ? 1 : 0);
        stmt_find.bind_text(14, r.migration.role);
        stmt_find.bind_text(15, r.migration.replacement);
        stmt_find.bind_text(16, r.explanation.what);
        stmt_find.bind_text(17, r.explanation.where);
        stmt_find.bind_text(18, r.explanation.why);
        stmt_find.bind_text(19, r.explanation.action);

        if (stmt_find.step() != SQLITE_DONE) {
            throw std::runtime_error("Failed to insert finding record into database");
        }
    }

    txn.commit();
    return scan_id;
}

std::int64_t Storage::save_findings(const std::string& target_path,
                                    const std::vector<Finding>& findings,
                                    const std::string& custom_uuid) {
    if (!is_open()) initialize();

    std::string uuid = custom_uuid.empty() ? generate_uuid() : custom_uuid;
    std::string ts = current_timestamp();

    ScanRecord s;
    s.scan_uuid = uuid;
    s.timestamp = ts;
    s.target_path = target_path;
    s.total_assets = static_cast<std::int64_t>(findings.size());

    for (const auto& f : findings) {
        switch (f.asset.status) {
            case Status::Safe:       ++s.safe_count; break;
            case Status::Weak:       ++s.weak_count; break;
            case Status::Deprecated: ++s.deprecated_count; break;
            case Status::Unknown:    ++s.unknown_count; break;
        }

        // Evaluate risk level from score on 0-100 scale
        double score = f.asset.risk_score;
        if (score >= 75.0) ++s.critical_risk_count;
        else if (score >= 50.0) ++s.high_risk_count;
        else if (score >= 25.0) ++s.medium_risk_count;
        else ++s.low_risk_count;

        auto mig = pqc::map_migration(f.asset, nullptr);
        if (!f.asset.pqc_flag || mig.supported) {
            ++s.pqc_ready_count;
        }
    }

    s.pqc_readiness_pct = s.total_assets > 0
        ? (static_cast<double>(s.pqc_ready_count) / static_cast<double>(s.total_assets)) * 100.0
        : 0.0;

    Transaction txn(impl_->db);

    Statement stmt_scan(impl_->db, R"(
        INSERT INTO scans (
            scan_uuid, timestamp, target_path, total_assets,
            safe_count, weak_count, deprecated_count, unknown_count,
            critical_risk_count, high_risk_count, medium_risk_count, low_risk_count,
            pqc_ready_count, pqc_readiness_pct, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )");

    stmt_scan.bind_text(1, s.scan_uuid);
    stmt_scan.bind_text(2, s.timestamp);
    stmt_scan.bind_text(3, s.target_path);
    stmt_scan.bind_int64(4, s.total_assets);
    stmt_scan.bind_int64(5, s.safe_count);
    stmt_scan.bind_int64(6, s.weak_count);
    stmt_scan.bind_int64(7, s.deprecated_count);
    stmt_scan.bind_int64(8, s.unknown_count);
    stmt_scan.bind_int64(9, s.critical_risk_count);
    stmt_scan.bind_int64(10, s.high_risk_count);
    stmt_scan.bind_int64(11, s.medium_risk_count);
    stmt_scan.bind_int64(12, s.low_risk_count);
    stmt_scan.bind_int64(13, s.pqc_ready_count);
    stmt_scan.bind_double(14, s.pqc_readiness_pct);
    stmt_scan.bind_text(15, "");

    if (stmt_scan.step() != SQLITE_DONE) {
        throw std::runtime_error("Failed to insert scan record into database");
    }

    std::int64_t scan_id = sqlite3_last_insert_rowid(impl_->db);

    Statement stmt_find(impl_->db, R"(
        INSERT INTO findings (
            scan_id, source_type, file, line, algorithm, key_size, curve, context,
            status, risk_score, risk_level, pqc_flag, pqc_supported, pqc_role,
            pqc_replacement, what, where_text, why, action
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )");

    for (const auto& f : findings) {
        const auto& a = f.asset;
        double score = a.risk_score;
        std::string rlevel = score >= 75.0 ? "CRITICAL" : (score >= 50.0 ? "HIGH" : (score >= 25.0 ? "MEDIUM" : "LOW"));
        auto mig = pqc::map_migration(a, nullptr);

        stmt_find.reset();
        stmt_find.bind_int64(1, scan_id);
        stmt_find.bind_text(2, a.source_type);
        stmt_find.bind_text(3, a.file);
        stmt_find.bind_int64(4, a.line);
        stmt_find.bind_text(5, a.algorithm);
        stmt_find.bind_int64(6, a.key_size);
        stmt_find.bind_text(7, a.curve);
        stmt_find.bind_text(8, a.context);
        stmt_find.bind_text(9, std::string(status_to_string(a.status)));
        stmt_find.bind_double(10, score);
        stmt_find.bind_text(11, rlevel);
        stmt_find.bind_int64(12, a.pqc_flag ? 1 : 0);
        stmt_find.bind_int64(13, mig.supported ? 1 : 0);
        stmt_find.bind_text(14, mig.role);
        stmt_find.bind_text(15, mig.replacement);
        stmt_find.bind_text(16, a.algorithm + (a.key_size > 0 ? ("-" + std::to_string(a.key_size)) : "") + " detected");
        stmt_find.bind_text(17, a.file + (a.line > 0 ? (":" + std::to_string(a.line)) : ""));
        stmt_find.bind_text(18, f.message);
        stmt_find.bind_text(19, f.message);

        if (stmt_find.step() != SQLITE_DONE) {
            throw std::runtime_error("Failed to insert finding record into database");
        }
    }

    txn.commit();
    return scan_id;
}

std::vector<ScanRecord> Storage::get_history(std::size_t limit) const {
    std::vector<ScanRecord> history;
    if (!is_open()) return history;

    Statement stmt(impl_->db, R"(
        SELECT id, scan_uuid, timestamp, target_path, total_assets,
               safe_count, weak_count, deprecated_count, unknown_count,
               critical_risk_count, high_risk_count, medium_risk_count, low_risk_count,
               pqc_ready_count, pqc_readiness_pct, metadata_json
        FROM scans
        ORDER BY id DESC
        LIMIT ?;
    )");

    stmt.bind_int64(1, static_cast<std::int64_t>(limit));

    while (stmt.step() == SQLITE_ROW) {
        ScanRecord s;
        s.id = sqlite3_column_int64(stmt.get(), 0);
        s.scan_uuid = column_text(stmt.get(), 1);
        s.timestamp = column_text(stmt.get(), 2);
        s.target_path = column_text(stmt.get(), 3);
        s.total_assets = sqlite3_column_int64(stmt.get(), 4);
        s.safe_count = sqlite3_column_int64(stmt.get(), 5);
        s.weak_count = sqlite3_column_int64(stmt.get(), 6);
        s.deprecated_count = sqlite3_column_int64(stmt.get(), 7);
        s.unknown_count = sqlite3_column_int64(stmt.get(), 8);
        s.critical_risk_count = sqlite3_column_int64(stmt.get(), 9);
        s.high_risk_count = sqlite3_column_int64(stmt.get(), 10);
        s.medium_risk_count = sqlite3_column_int64(stmt.get(), 11);
        s.low_risk_count = sqlite3_column_int64(stmt.get(), 12);
        s.pqc_ready_count = sqlite3_column_int64(stmt.get(), 13);
        s.pqc_readiness_pct = sqlite3_column_double(stmt.get(), 14);
        s.metadata_json = column_text(stmt.get(), 15);
        history.push_back(std::move(s));
    }

    return history;
}

std::optional<ScanDetail> Storage::get_scan(std::int64_t scan_id) const {
    if (!is_open()) return std::nullopt;

    Statement stmt_scan(impl_->db, R"(
        SELECT id, scan_uuid, timestamp, target_path, total_assets,
               safe_count, weak_count, deprecated_count, unknown_count,
               critical_risk_count, high_risk_count, medium_risk_count, low_risk_count,
               pqc_ready_count, pqc_readiness_pct, metadata_json
        FROM scans
        WHERE id = ?;
    )");

    stmt_scan.bind_int64(1, scan_id);

    if (stmt_scan.step() != SQLITE_ROW) {
        return std::nullopt;
    }

    ScanDetail detail;
    detail.scan.id = sqlite3_column_int64(stmt_scan.get(), 0);
    detail.scan.scan_uuid = column_text(stmt_scan.get(), 1);
    detail.scan.timestamp = column_text(stmt_scan.get(), 2);
    detail.scan.target_path = column_text(stmt_scan.get(), 3);
    detail.scan.total_assets = sqlite3_column_int64(stmt_scan.get(), 4);
    detail.scan.safe_count = sqlite3_column_int64(stmt_scan.get(), 5);
    detail.scan.weak_count = sqlite3_column_int64(stmt_scan.get(), 6);
    detail.scan.deprecated_count = sqlite3_column_int64(stmt_scan.get(), 7);
    detail.scan.unknown_count = sqlite3_column_int64(stmt_scan.get(), 8);
    detail.scan.critical_risk_count = sqlite3_column_int64(stmt_scan.get(), 9);
    detail.scan.high_risk_count = sqlite3_column_int64(stmt_scan.get(), 10);
    detail.scan.medium_risk_count = sqlite3_column_int64(stmt_scan.get(), 11);
    detail.scan.low_risk_count = sqlite3_column_int64(stmt_scan.get(), 12);
    detail.scan.pqc_ready_count = sqlite3_column_int64(stmt_scan.get(), 13);
    detail.scan.pqc_readiness_pct = sqlite3_column_double(stmt_scan.get(), 14);
    detail.scan.metadata_json = column_text(stmt_scan.get(), 15);

    Statement stmt_find(impl_->db, R"(
        SELECT id, scan_id, source_type, file, line, algorithm, key_size, curve, context,
               status, risk_score, risk_level, pqc_flag, pqc_supported, pqc_role,
               pqc_replacement, what, where_text, why, action
        FROM findings
        WHERE scan_id = ?
        ORDER BY id ASC;
    )");

    stmt_find.bind_int64(1, scan_id);

    while (stmt_find.step() == SQLITE_ROW) {
        FindingRecord f;
        f.id = sqlite3_column_int64(stmt_find.get(), 0);
        f.scan_id = sqlite3_column_int64(stmt_find.get(), 1);
        f.source_type = column_text(stmt_find.get(), 2);
        f.file = column_text(stmt_find.get(), 3);
        f.line = sqlite3_column_int64(stmt_find.get(), 4);
        f.algorithm = column_text(stmt_find.get(), 5);
        f.key_size = sqlite3_column_int64(stmt_find.get(), 6);
        f.curve = column_text(stmt_find.get(), 7);
        f.context = column_text(stmt_find.get(), 8);
        auto st = status_from_string(column_text(stmt_find.get(), 9));
        f.status = st.value_or(Status::Unknown);
        f.risk_score = sqlite3_column_double(stmt_find.get(), 10);
        f.risk_level = column_text(stmt_find.get(), 11);
        f.pqc_flag = sqlite3_column_int64(stmt_find.get(), 12) != 0;
        f.pqc_supported = sqlite3_column_int64(stmt_find.get(), 13) != 0;
        f.pqc_role = column_text(stmt_find.get(), 14);
        f.pqc_replacement = column_text(stmt_find.get(), 15);
        f.what = column_text(stmt_find.get(), 16);
        f.where_text = column_text(stmt_find.get(), 17);
        f.why = column_text(stmt_find.get(), 18);
        f.action = column_text(stmt_find.get(), 19);
        detail.findings.push_back(std::move(f));
    }

    return detail;
}

std::optional<ScanDetail> Storage::get_latest_scan() const {
    if (!is_open()) return std::nullopt;

    Statement stmt(impl_->db, "SELECT id FROM scans ORDER BY id DESC LIMIT 1;");
    if (stmt.step() != SQLITE_ROW) {
        return std::nullopt;
    }

    std::int64_t latest_id = sqlite3_column_int64(stmt.get(), 0);
    return get_scan(latest_id);
}

std::optional<ScanDetail> Storage::get_scan_by_uuid(const std::string& uuid) const {
    if (!is_open()) return std::nullopt;

    Statement stmt(impl_->db, "SELECT id FROM scans WHERE scan_uuid = ?;");
    stmt.bind_text(1, uuid);

    if (stmt.step() != SQLITE_ROW) {
        return std::nullopt;
    }

    std::int64_t scan_id = sqlite3_column_int64(stmt.get(), 0);
    return get_scan(scan_id);
}

void Storage::clear_history() {
    if (!is_open()) return;

    {
        Transaction txn(impl_->db);
        char* err = nullptr;
        sqlite3_exec(impl_->db, "DELETE FROM findings; DELETE FROM scans;", nullptr, nullptr, &err);
        if (err) {
            std::string msg = err;
            sqlite3_free(err);
            throw std::runtime_error("Failed to clear SQLite history: " + msg);
        }
        txn.commit();
    }
    sqlite3_exec(impl_->db, "VACUUM;", nullptr, nullptr, nullptr);
}

void Storage::delete_scan(std::int64_t scan_id) {
    if (!is_open()) return;

    Transaction txn(impl_->db);
    Statement stmt(impl_->db, "DELETE FROM scans WHERE id = ?;");
    stmt.bind_int64(1, scan_id);
    if (stmt.step() != SQLITE_DONE) {
        throw std::runtime_error("Failed to delete scan with id " + std::to_string(scan_id));
    }
    txn.commit();
}

std::string Storage::default_db_path() {
    const char* home = std::getenv("HOME");
    if (home) {
        return std::string(home) + "/.ecdat/ecdat.db";
    }
    return "ecdat.db";
}

std::string Storage::generate_uuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << (part1 >> 32) << "-"
        << std::setw(4) << ((part1 >> 16) & 0xFFFF) << "-"
        << std::setw(4) << (part1 & 0xFFFF) << "-"
        << std::setw(4) << (part2 >> 48) << "-"
        << std::setw(12) << (part2 & 0xFFFFFFFFFFFFULL);
    return oss.str();
}

std::string Storage::current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &in_time_t);
#else
    gmtime_r(&in_time_t, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%SZ");
    return oss.str();
}

} // namespace ecdat::storage
