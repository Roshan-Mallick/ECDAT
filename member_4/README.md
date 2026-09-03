# ECDAT Member 4 — Platform Engineer & Integration Lead

Member 4 provides the platform layer for **ECDAT** (**E**nterprise **C**ryptography **D**iscovery and **A**ssessment **T**ool), unifying the discovery capabilities of Member 1, the taxonomy/classification contracts of Member 2, and the risk/PQC engines of Member 3 into a cohesive, professional native C++20 CLI application.

---

## 1. Architectural Role & Responsibilities

```
+-----------------------------------------------------------------------------+
|                          MEMBER 4 PLATFORM LAYER                            |
+-----------------------------------------------------------------------------+
|                                                                             |
|      [ ecdat CLI (CLI11 + spdlog + fmt) ]                                   |
|        ├── ecdat scan <target>                                              |
|        ├── ecdat report                                                     |
|        ├── ecdat history                                                    |
|        ├── ecdat export                                                     |
|        └── ecdat version                                                    |
|                                                                             |
|      [ Integration Flow Orchestrator ]                                      |
|        └── Coordinates Member 1 Scanners -> Member 2 Taxonomy -> Member 3   |
|                                                                             |
|      [ SQLite Persistence Layer (Embedded SQLite3 C API) ]                  |
|        └── Prepared statements, bound parameters, scans & findings tables   |
|                                                                             |
|      [ Multi-Format Reporting Engine ]                                      |
|        ├── JSON (nlohmann/json, machine-readable)                           |
|        ├── CSV  (RFC 4180 compliant escaping)                               |
|        └── PDF  (Native C++ multi-page vector PDF 1.4 generator)            |
+-----------------------------------------------------------------------------+
```

Member 4 acts strictly as an **orchestration, persistence, reporting, and interface layer**. It does not duplicate or compete with the domain logic of Members 1–3:
- Consumes authoritative `ecdat::CryptoAsset` and `ecdat::Finding` from Member 2.
- Uses `ecdat::flow` and `ecdat::pipeline` to execute discovery, classification, risk scoring, PQC migration, and explainability.
- Persists all results to local SQLite storage using prepared statements and transactions.
- Exports findings into JSON, CSV, and native C++ PDF reports.

---

## 2. Directory Layout

```
member_4/
├── CMakeLists.txt
├── README.md
├── cli/
│   ├── include/ecdat/cli.hpp
│   └── src/
│       ├── cli.cpp                # Subcommand handlers (scan, report, history, export, version)
│       └── main.cpp               # Top-level executable entry point
├── storage/
│   ├── include/ecdat/storage.hpp
│   ├── src/storage.cpp            # SQLite C API wrapper with prepared statements
│   └── 3rdparty/sqlite/
│       ├── sqlite3.c              # Embedded SQLite amalgamation source
│       └── sqlite3.h
├── reporting/
│   ├── include/ecdat/reporting.hpp
│   └── src/
│       ├── json_report.cpp        # Structured JSON generator using nlohmann/json
│       ├── csv_report.cpp         # RFC 4180 CSV generator with quotation escaping
│       └── pdf_report.cpp         # Native C++ PDF 1.4 multi-page report generator
├── 3rdparty/
│   ├── fmt/                       # Standalone fmt library headers
│   └── spdlog/                    # Standalone spdlog structured logging headers
└── tests/
    ├── test_cli.cpp               # CLI parsing and command dispatch tests
    ├── test_storage.cpp           # SQLite persistence, transaction, and injection tests
    ├── test_reporting.cpp         # JSON, CSV, and PDF report validation tests
    └── test_integration.cpp       # End-to-end integration test with live fixtures
```

---

## 3. SQLite Database Schema

The database initializes itself automatically upon startup.

```sql
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
```

---

## 4. CLI Usage & Commands

### 1. `ecdat scan`
Scans source files (`.py`), certificates (`.pem`), or server configs (`.conf`) across a directory or single file, assesses risks, and saves results to SQLite:
```bash
# Scan a directory
./build/member_4/ecdat scan ./project

# Scan with custom exposure/remediation and auto-generate reports
./build/member_4/ecdat scan ./project --exposure 80 --remediation 50 --format all -o reports/project_scan
```

### 2. `ecdat report`
Generates assessment reports from stored scan records:
```bash
# Output JSON report of latest scan to stdout
./build/member_4/ecdat report --latest --format json

# Export PDF report for specific scan ID
./build/member_4/ecdat report --scan 1 --format pdf -o audit_report.pdf
```

### 3. `ecdat history`
Displays a table of previous scans:
```bash
./build/member_4/ecdat history

# Output as JSON
./build/member_4/ecdat history --json

# Clear all historical records
./build/member_4/ecdat history --clear
```

### 4. `ecdat export`
Explicit data export:
```bash
./build/member_4/ecdat export --latest --format csv -o findings.csv
./build/member_4/ecdat export --scan 1 --format pdf -o report.pdf
```

### 5. `ecdat version`
Prints version and build details:
```bash
./build/member_4/ecdat version
```

---

## 5. Build, Test & Sanitizer Verification

### Standard Build:
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DECDAT_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

### Sanitizer Build (ASan + UBSan):
```bash
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug -DECDAT_ENABLE_SANITIZERS=ON -DECDAT_BUILD_TESTS=ON
cmake --build build-sanitize -j$(nproc)
ctest --test-dir build-sanitize --output-on-failure
```
