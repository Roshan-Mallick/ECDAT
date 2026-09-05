# ECDAT

**Enterprise Cryptography Discovery & Assessment Tool**

ECDAT scans source code, X.509 certificates, and TLS configurations to discover cryptographic assets, classify their security status, assess risk, detect post-quantum vulnerability, recommend PQC migration, and produce machine-readable and human-readable reports. The system is designed to operate on real source-code repositories and produces actionable security assessments without hard-coded demo data.

## 1. Overview

Modern software projects accumulate cryptographic dependencies across source code, certificates, and network configurations — often without a complete inventory. Algorithms become deprecated, keys become too short, and post-quantum threats advance faster than most teams can migrate.

ECDAT solves this by providing an end-to-end pipeline:

- **Discovery**: Find every cryptographic asset in a repository (source code, certificates, TLS configs)
- **Classification**: Determine if each algorithm is Safe, Weak, Deprecated, or Unknown against a data-driven taxonomy
- **Risk Assessment**: Produce a reproducible risk score using a weighted formula
- **PQC Intelligence**: Identify post-quantum-vulnerable algorithms and recommend NIST-standard replacements (ML-DSA, ML-KEM)
- **Reporting**: Generate JSON, CSV, and PDF reports with full explainability (What / Where / Why / Action)

**Intended users**: security engineers, DevSecOps teams, platform engineers, and auditors who need to understand the cryptographic posture of a codebase or infrastructure.

## 2. Core Pipeline

```
Real Source Repository
        │
        ▼
┌─────────────────────────────────────┐
│  Member 1 — Discovery               │
│  Tree-sitter Python AST scanning    │
│  X.509 / OpenSSL certificate parsing│
│  TLS configuration line scanning    │
└──────────────┬──────────────────────┘
               │ CryptoAsset[]
               ▼
┌─────────────────────────────────────┐
│  Member 2 — Data & Taxonomy         │
│  Algorithm lookup (case-insensitive)│
│  Safe / Weak / Deprecated / Unknown │
│  Risk base, PQC vulnerability flag  │
│  Replacement metadata               │
└──────────────┬──────────────────────┘
               │ Classification[]
               ▼
┌─────────────────────────────────────┐
│  Member 3 — Intelligence            │
│  Risk = weakness×0.4 + exposure×0.3 │
│       + remediation×0.3             │
│  RiskLevel (LOW/MEDIUM/HIGH/CRIT)   │
│  PQC migration (role-aware)         │
│  ML-DSA / ML-KEM recommendations    │
│  PQC readiness percentage           │
│  Explanation (What/Where/Why/Action)│
└──────────────┬──────────────────────┘
               │ PipelineResult[]
               ▼
┌─────────────────────────────────────┐
│  Member 4 — Platform                │
│  CLI interface                      │
│  SQLite persistence + scan history  │
│  JSON / CSV / PDF report generation │
│  Export to file                     │
└──────────────┬──────────────────────┘
               │
               ▼
       Security Assessment
```

**What happens at each stage:**

| Stage | Input | Output | What It Adds |
|-------|-------|--------|--------------|
| Member 1 | Repository path | `CryptoAsset[]` | Algorithm, key_size, curve, file, line, context, source_type |
| Member 2 | `CryptoAsset` + `TaxonomyDB` | `Classification` | Status, risk_score (0–10), pqc_flag, taxonomy_entry |
| Member 3 | `CryptoAsset` + `Classification` | `PipelineResult` | weakness, exposure, remediation, final_risk, RiskLevel, Migration, Explanation |
| Member 4 | `PipelineResult[]` | Reports + DB | Persistent storage, JSON/CSV/PDF files, scan history, export |

## 3. Member Responsibilities

### Member 1 — Discovery

Member 1 locates cryptographic assets in a repository using three independent scanners:

| Scanner | Technology | Input | Detected Assets |
|---------|-----------|-------|-----------------|
| **Source Scanner** | Tree-sitter Python AST | `.py` files | `md5()`, `sha1()`, `sha256()`, `des()`, `rc4()` calls via `hashlib` |
| **Certificate Scanner** | OpenSSL `PEM_read_X509` + `EVP_PKEY` | `.pem`, `.crt`, `.cer` | RSA/ECDSA algorithm name + key size from X.509 certificates |
| **TLS Scanner** | Line-by-line pattern matching | `.conf`, `.cfg`, `nginx.conf`, `httpd.conf` | Weak protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and weak ciphers (RC4, DES, MD5, NULL) |

Each scanner produces `CryptoAsset` objects with provenance fields populated (file, line, algorithm, key_size, context).

Member 1 is optional at build time — it requires OpenSSL and tree-sitter to be present. The rest of the system builds and operates without it.

### Member 2 — Data & Taxonomy

Member 2 is the single source of truth for the shared data model and algorithm classification:

- **CryptoAsset contract** (`taxonomy/core/include/ecdat/types.hpp`): The authoritative struct used across all four members. Fields: `source_type`, `file`, `line`, `algorithm`, `key_size`, `curve`, `context`, `status`, `risk_score`, `pqc_flag`.
- **JSON serialization** (`taxonomy/core/`): `to_json()`, `from_json()`, `parse_asset()` with strict type validation, optional field handling, and malformed-JSON rejection.
- **Taxonomy database** (`taxonomy/taxonomy/`): Loads `taxonomy.yaml` (16 algorithm entries), normalizes algorithm names to lowercase, performs case-insensitive lookup, and resolves last-wins on duplicates.
- **Classification engine** (`taxonomy/taxonomy/src/classifier.cpp`): Looks up the algorithm in the taxonomy, determines status (Safe/Weak/Deprecated/Unknown), computes risk_score with key-size and curve downgrade logic (+2.0 risk penalty for weak keys/curves, clamped to [0, 10]), and sets the PQC vulnerability flag.
- **Taxonomy schema**: Each entry carries `name`, `type`, `status`, `risk_base`, `pqc_vulnerable`, `replacement`, `min_secure_key_bits`, and `weak_curves`.

### Member 3 — Intelligence / Risk & PQC

Member 3 consumes the real `CryptoAsset` and its `Classification` from Member 2 and adds intelligence:

- **Risk scoring** (`risk/risk/`): `Risk = weakness × 0.4 + exposure × 0.3 + remediation × 0.3`. Inputs validated to [0–100]. RiskLevel classified as LOW (0–24), MEDIUM (25–49), HIGH (50–74), or CRITICAL (75–100).
- **PQC detection**: Algorithms flagged `pqc_vulnerable: true` in the taxonomy are identified as quantum-threatened.
- **Role-aware migration** (`risk/pqc/migration.h`): The replacement algorithm depends on the cryptographic role:
  - RSA (signature) → **ML-DSA**
  - ECDSA (signature) → **ML-DSA**
  - DH (key exchange) → **ML-KEM**
  - Role is detected from the taxonomy `type` field, falling back to context keywords and sensible defaults (RSA/ECDSA default to Signature; DH defaults to KeyExchange).
- **PQC readiness** (`risk/pqc/readiness.h`): An asset is "ready" if it is not PQC-vulnerable or has a supported migration. Readiness percentage = ready / total × 100.
- **Explainability** (`risk/pqc/explanation.h`): Every finding receives a structured explanation: What (algorithm + role), Where (file:line), Why (vulnerability description), Action (specific replacement recommendation).

### Member 4 — Platform / CLI, Storage & Reporting

Member 4 is the user-facing layer:

- **CLI** (`platform/cli/`): Five subcommands — `scan`, `report`, `history`, `export`, `version`. Built with CLI11. Supports colored terminal output, `--no-color`, `--verbose`, `--quiet`.
- **Storage** (`platform/storage/`): Embedded SQLite database with prepared statements. Stores scan records (UUID, timestamp, target, aggregate counts, PQC readiness) and individual findings (19 fields). Provides `get_history()`, `get_scan()`, `get_latest_scan()`, `clear_history()`.
- **Reporting** (`platform/reporting/`):
  - **JSON**: Structured report with scan metadata + findings array (nlohmann/json)
  - **CSV**: RFC 4180 compliant with proper field escaping
  - **PDF**: Native C++ PDF 1.4 generator — no external PDF library dependency. Multi-page support, colored severity cards, headers/footers.

## 4. Key Features

- Source-code cryptographic discovery via Tree-sitter AST analysis
- X.509 certificate parsing via OpenSSL
- TLS configuration weakness detection
- Unified `CryptoAsset` data contract across all modules
- Data-driven cryptographic taxonomy (YAML, 16 algorithm entries)
- Case-insensitive algorithm lookup with normalization
- Safe / Weak / Deprecated / Unknown classification
- Key-size and curve-based risk downgrade logic
- Reproducible risk scoring (weighted formula)
- Post-quantum cryptography detection from taxonomy metadata
- Role-aware PQC migration recommendations
- NIST PQC replacements: ML-DSA (signatures), ML-KEM (key exchange)
- PQC readiness assessment with percentage score
- Explainable findings (What / Where / Why / Action)
- Persistent SQLite storage with scan history
- JSON, CSV, and native PDF report generation
- Export to file in any supported format
- CLI with colored terminal output, verbose/quiet modes
- 120 automated tests (GoogleTest + manual)
- Optional AddressSanitizer + UndefinedBehaviorSanitizer builds

## 5. Architecture

ECDAT uses a four-member modular architecture with a shared data contract.

### Module Responsibilities

| Module | Responsibility | Key Types |
|--------|---------------|-----------|
| `discovery/` | Discovery — source, cert, TLS scanning | `scan_source_file()`, `scan_certificate()`, `scan_tls_config()` |
| `taxonomy/` | Data contract + taxonomy + classification | `CryptoAsset`, `Status`, `TaxonomyDB`, `Classification` |
| `risk/` | Risk engine + PQC intelligence | `calculateRisk()`, `RiskLevel`, `Migration`, `Explanation` |
| `platform/` | CLI + storage + reporting | `CliApp`, `Storage`, `generate_json/csv/pdf()` |
| `integration/` | Pipeline adapter + full flow orchestration | `PipelineResult`, `run_pipeline()`, `analyze_all()` |

### Shared Data Contract

The `CryptoAsset` struct is defined once in `taxonomy/core/include/ecdat/types.hpp` and imported by all other members. This allows each member to be developed independently while maintaining type-safe integration.

```
CryptoAsset (taxonomy/core)
    │
    ├── discovery/ fills: source_type, file, line, algorithm, key_size, curve, context
    │
    ├── taxonomy/ fills: status, risk_score, pqc_flag
    │
    ├── risk/ consumes all fields, adds: weakness, final_risk, risk_level,
    │         migration, explanation
    │
    └── platform/ reads all fields for storage, reporting, and CLI output
```

### Integration Layer

- `integration/pipeline.h/cpp`: Thin adapter that bridges Member 2's risk_score [0–10] to Member 3's [0–100] weakness scale, then calls Member 3's risk engine, PQC migration, and explanation modules. Owns no classification logic.
- `integration/flow.h/cpp`: Orchestrates Member 1 → Member 2 → Member 3 for source files, certificates, and TLS configs. Aggregates PQC readiness across all discovered assets.

## 6. Repository Structure

```
ECDAT/
├── CMakeLists.txt                          # Root build configuration
├── README.md
├── LICENSE                                 # Apache 2.0
│
├── discovery/                              # DISCOVERY (Member 1)
│   ├── CMakeLists.txt
│   ├── include/
│   │   ├── types.hpp                       # Shim re-exporting taxonomy's CryptoAsset
│   │   ├── source_scanner.hpp              # scan_source_file()
│   │   ├── cert_scanner.hpp                # scan_certificate()
│   │   └── tls_scanner.hpp                 # scan_tls_config()
│   ├── src/
│   │   ├── source_scanner.cpp              # Tree-sitter Python AST walker
│   │   ├── cert_scanner.cpp                # OpenSSL X.509 parser
│   │   └── tls_scanner.cpp                 # TLS protocol/cipher scanner
│   ├── tests/
│   │   └── test_discovery.cpp
│   └── fixtures/
│       ├── sample.py                       # Test input: hashlib.md5 usage
│       └── sample_nginx.conf               # Test input: weak TLS + ciphers
│
├── taxonomy/                               # DATA & TAXONOMY (Member 2)
│   ├── CMakeLists.txt
│   ├── core/
│   │   ├── include/ecdat/
│   │   │   ├── types.hpp                   # CryptoAsset, Status, Finding
│   │   │   └── serialization.hpp           # JSON round-trip API
│   │   ├── src/
│   │   │   └── serialization.cpp
│   │   └── tests/
│   │       └── test_serialization.cpp      # 11 tests
│   └── taxonomy/
│       ├── include/ecdat/
│       │   └── taxonomy.hpp                # TaxonomyDB, classify_asset()
│       ├── src/
│       │   ├── taxonomy_loader.cpp         # YAML parser + normalization
│       │   └── classifier.cpp              # Classification engine
│       ├── data/
│       │   └── taxonomy.yaml               # 16 algorithm entries
│       └── tests/
│           ├── test_taxonomy.cpp           # 15 tests
│           └── test_classifier.cpp         # 26 tests
│
├── risk/                                   # INTELLIGENCE / RISK & PQC (Member 3)
│   ├── CMakeLists.txt
│   ├── common/
│   │   └── simple_json.h                   # Minimal hand-rolled JSON parser
│   ├── taxonomy/
│   │   ├── taxonomy.h                      # risk-local JSON taxonomy
│   │   └── taxonomy.cpp
│   ├── risk/
│   │   ├── risk_engine.h                   # calculateRisk(), RiskLevel
│   │   ├── risk_engine.cpp
│   │   ├── exposure.h                      # ExposureRules
│   │   └── exposure.cpp
│   ├── pqc/
│   │   ├── pqc.h                           # Umbrella header
│   │   ├── migration.h                     # Role-aware PQC migration
│   │   ├── migration.cpp
│   │   ├── readiness.h                     # PQC readiness assessment
│   │   ├── readiness.cpp
│   │   ├── explanation.h                   # What/Where/Why/Action
│   │   └── explanation.cpp
│   └── test/
│       ├── risk_engine_tests.cpp           # 8 tests
│       └── pqc_tests.cpp                   # 19 tests
│
├── integration/                            # PIPELINE & FLOW
│   ├── pipeline.h                          # PipelineResult, run_pipeline()
│   ├── pipeline.cpp
│   ├── flow.h                              # analyze_all(), Summary
│   ├── flow.cpp
│   ├── test_pipeline.cpp                   # 16 tests
│   └── test_flow.cpp                       # 3 tests
│
└── platform/                               # PLATFORM / CLI, STORAGE & REPORTING (Member 4)
    ├── CMakeLists.txt
    ├── 3rdparty/
    │   ├── spdlog/                          # Vendored structured logging
    │   └── fmt/                             # Vendored formatting
    ├── cli/
    │   ├── include/
    │   │   ├── ecdat/cli.hpp               # CliApp, CliConfig
    │   │   └── CLI/CLI.hpp                 # Vendored CLI11 v2.4.2
    │   └── src/
    │       ├── main.cpp                    # Entry point
    │       └── cli.cpp                     # 5 subcommands
    ├── storage/
    │   ├── include/ecdat/storage.hpp       # Storage, ScanRecord, FindingRecord
    │   ├── src/storage.cpp                 # SQLite3 C API wrapper
    │   └── 3rdparty/sqlite/               # Vendored SQLite amalgamation
    ├── reporting/
    │   ├── include/ecdat/reporting.hpp     # generate/write JSON/CSV/PDF
    │   └── src/
    │       ├── json_report.cpp
    │       ├── csv_report.cpp
    │       └── pdf_report.cpp              # Native PDF 1.4 generator
    └── tests/
        ├── test_cli.cpp                    # 13 tests
        ├── test_storage.cpp                # 8 tests
        ├── test_reporting.cpp              # 8 tests
        └── test_integration.cpp            # 2 tests
```

## 7. Technology Stack

### Languages & Standards

| Component | Standard |
|-----------|----------|
| C++ (all members) | C++20 (`CMAKE_CXX_STANDARD 20`) |
| Build system | CMake 3.21+ |
| Test framework | GoogleTest 1.14+ |

### External Dependencies (fetched or system-provided)

| Dependency | Version | Required By | Purpose |
|-----------|---------|-------------|---------|
| **nlohmann/json** | 3.11+ | Member 2 (core) | JSON serialization |
| **yaml-cpp** | 0.8+ | Member 2 (taxonomy) | YAML taxonomy loading |
| **OpenSSL** | system | Member 1 (optional) | X.509 certificate parsing |
| **tree-sitter** | 0.28+ | Member 1 (optional) | Python AST parsing |
| **tree-sitter-python** | 0.25+ | Member 1 (optional) | Python grammar |
| **GoogleTest** | 1.14+ | All test targets | Unit testing |

nlohmann/json, yaml-cpp, GoogleTest, tree-sitter, and tree-sitter-python are **automatically fetched from GitHub** when `-DECDAT_FETCH_DEPENDENCIES=ON` is passed and the system package is not found. This makes the build fully self-bootstrapping — no manual dependency installation is needed.

### Vendored (in-tree)

| Dependency | Location | Purpose |
|-----------|----------|---------|
| **SQLite3** (amalgamation) | `platform/storage/3rdparty/sqlite/` | Embedded database |
| **CLI11** v2.4.2 | `platform/cli/include/CLI/CLI.hpp` | Command-line parsing |
| **spdlog** | `platform/3rdparty/spdlog/` | Structured logging |
| **fmt** | `platform/3rdparty/spdlog/fmt/` | String formatting |

## 8. Requirements

ECDAT has two very different requirement profiles depending on whether you are an **end user** running a released binary or a **developer** building from source. A released binary user does **not** need any development toolchain.

### End User (running a released binary)

| Operating System | Requirements |
|------------------|--------------|
| Linux | Standard shared libraries present on virtually all distributions (glibc, libstdc++, OpenSSL `libcrypto`, zlib, zstd). No development packages needed. |
| macOS | Standard system libraries (via bundled/OpenSSL runtime). No development packages needed. |
| Windows | Standard system DLLs. OpenSSL DLLs are bundled with the archive if required. No development packages needed. |

In particular, a normal end user does **not** need to install:
- CMake
- GCC / Clang / MSVC
- tree-sitter
- yaml-cpp
- nlohmann/json

### Developer (building from source)

- **Compiler**: GCC 10+ or Clang 12+ with C++20 support (Linux/macOS), or MSVC (Windows)
- **CMake**: 3.21 or newer
- **Build tool**: Ninja, Make, or Visual Studio
- **OpenSSL**: Development libraries (for Member 1 — optional, gracefully skipped if absent)
- **tree-sitter** + **tree-sitter-python**: can be vendored automatically via FetchContent (no manual install needed)

Member 2, Member 3, integration, and Member 4 build without external system dependencies — nlohmann/json, yaml-cpp, GoogleTest, tree-sitter, and tree-sitter-python are all fetched automatically via CMake FetchContent when `-DECDAT_FETCH_DEPENDENCIES=ON` is passed and the system packages are not found.

## 9. Building ECDAT

```bash
git clone https://github.com/Roshan-Mallick/ECDAT.git
cd ECDAT

# Configure (tests ON by default)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build -j$(nproc)
```

The `ecdat` binary will be at `build/platform/ecdat`.

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `ECDAT_BUILD_TESTS` | `ON` | Build all unit tests |
| `ECDAT_ENABLE_SANITIZERS` | `OFF` | Build with AddressSanitizer + UndefinedBehaviorSanitizer |
| `ECDAT_FETCH_DEPENDENCIES` | `OFF` | Download missing dependencies from GitHub (self-bootstrapping build) |

```bash
# Debug build with sanitizers
cmake -S . -B build-debug -DCMAKE_BUILD_TYPE=Debug -DECDAT_ENABLE_SANITIZERS=ON
cmake --build build-debug -j$(nproc)
```

### Self-Bootstrapping Build (no system deps needed)

```bash
# Fully self-contained: fetches tree-sitter, nlohmann/json, yaml-cpp, gtest from GitHub
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DECDAT_FETCH_DEPENDENCIES=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure  # 120/120 tests pass
```

This requires only a C++20 compiler, CMake 3.21+, and a network connection on the first configure. All C++ dependencies are downloaded and built from source automatically. Subsequent rebuilds use the cached downloads.

### Minimal Build (without Member 1)

If OpenSSL and tree-sitter are not installed, ECDAT builds without Member 1. The CLI, taxonomy, risk engine, PQC intelligence, storage, and reporting all function normally — only the source/cert/TLS scanners are unavailable.

## 10. Testing

```bash
ctest --test-dir build --output-on-failure
```

**Current status: 120/120 tests pass.**

### Test Coverage by Member

| Test Suite | Tests | What It Covers |
|-----------|-------|----------------|
| `Pipeline.*` | 16 | Pipeline adapter, risk score bridging, end-to-end asset flow |
| `FlowIntegration.*` | 3 | Full Member 1 → 2 → 3 flow with real fixtures |
| `Serialization.*` | 11 | JSON round-trip, strict validation, error handling |
| `Taxonomy.*` | 15 | YAML loading, case-insensitive lookup, schema validation |
| `Classifier.*` | 26 | Status classification, risk scoring, curve/key-size downgrade, PQC flag |
| `risk_engine_tests` | 9 | Risk formula, RiskLevel boundaries, input validation |
| `PqcMigration.*` | 7 | Role-aware migration, ML-DSA/ML-KEM mapping |
| `PqcReadiness.*` | 6 | Readiness percentage, edge cases |
| `PqcExplanation.*` | 3 | Explanation generation from real assets |
| `PqcContract.*` | 1 | `key_size` field preservation |
| `StorageTest.*` | 8 | SQLite CRUD, history, disk persistence, SQL injection defense |
| `ReportingTest.*` | 8 | JSON/CSV/PDF generation, empty scans, escaping |
| `CliTest.*` | 13 | All subcommands, error handling, real fixture scanning |
| `Member4Integration.*` | 2 | End-to-end discovery → storage → report round-trip |

### Sanitizer Builds

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DECDAT_ENABLE_SANITIZERS=ON
cmake --build build-asan -j$(nproc)
ctest --test-dir build-asan --output-on-failure
```

### Cross-Platform Build & Validation

ECDAT is built and validated automatically on native GitHub Actions runners for all three platforms. The release workflow runs the full 120-test suite and the packaged validation (binary runs, taxonomy.yaml resolves, real repository scan) on each platform independently; the release only publishes artifacts whose platform build passed.

| Platform | Runner | Native Architecture | Release Artifact |
|----------|--------|--------------------|------------------|
| Linux | `ubuntu-24.04` | x86_64 | `.tar.gz` + `.deb` |
| macOS | `macos-14` | arm64 / x86_64 | `.tar.gz` |
| Windows | `windows-2022` | x86_64 | `.zip` |

Each artifact is validated in a clean environment before publication: `ecdat version` runs, `taxonomy.yaml` resolves from the bundled resources, and a real repository scan completes. The Windows `.zip` is validated on a separate runner with **no OpenSSL on `PATH`** (any `PATH` entry containing OpenSSL would otherwise mask a missing bundled DLL), proving the bundled `libcrypto-*`/`libssl-*` DLLs alone satisfy the runtime.

## 11. Installation / Distribution

ECDAT ships pre-built binaries for Linux, macOS, and Windows. Every release artifact is self-contained: the `taxonomy.yaml` resource is bundled next to the executable and resolved automatically at runtime, so **normal users do not need to install any development dependencies** (CMake, compilers, tree-sitter, yaml-cpp, nlohmann/json, etc.).

Select the section for your operating system.

### Linux

#### Debian / Ubuntu (`.deb`)

```bash
sudo dpkg -i ecdat_0.1.1_amd64.deb
```

This installs the `ecdat` executable to `/usr/bin/ecdat` and taxonomy data to `/usr/share/ecdat/taxonomy.yaml` (it never touches `/usr/bin/resources`, which is owned by Debian/Ubuntu's `resources` package).

Verify and scan:

```bash
ecdat version
ecdat scan /path/to/project
```

#### Linux Portable Tarball (`tar.gz`)

```bash
tar -xzf ECDAT-0.1.1-linux-x86_64.tar.gz
cd ECDAT-0.1.1
./bin/ecdat version
./bin/ecdat scan /path/to/project
```

No installation required — extract anywhere and run.

### macOS

ECDAT is built natively on GitHub Actions `macos-14` runners using the project's own CMake configuration. The `.tar.gz` archive bundles the executable and required runtime resources.

#### Apple Silicon (arm64)

```bash
# 1. Download ECDAT-0.1.1-macos-arm64.tar.gz
# 2. Extract
tar -xzf ECDAT-0.1.1-macos-arm64.tar.gz
cd ECDAT-0.1.1

# 3. Verify
./bin/ecdat version

# 4. Scan a project
./bin/ecdat scan /path/to/project
```

The v0.1.0 workflow produces an Apple Silicon artifact only. An Intel
(`x86_64`) macOS artifact is not published by this workflow.

**Note:** If your macOS shows "cannot be opened because the developer cannot be verified", right-click the executable in Finder and select **Open**, or run `xattr -d com.apple.quarantine ./bin/ecdat` once before executing. This is because the binaries are not notarized by Apple in this early release.

### Windows

```powershell
# 1. Download ECDAT-0.1.1-windows-x86_64.zip
# 2. Extract the ZIP
# 3. Open PowerShell
cd path\to\extracted\ECDAT-0.1.1\bin

# 4. Verify version
.\ecdat.exe version

# 5. Scan a project
.\ecdat.exe scan "C:\path\to\project"
```

The required DLLs (e.g. OpenSSL `libssl`/`libcrypto`) are bundled alongside `ecdat.exe` when needed — **you do not need to install them manually**.

### Building from Source (Developer)

```bash
git clone https://github.com/Roshan-Mallick/ECDAT.git
cd ECDAT

# Self-bootstrapping (fetches all C++ deps from GitHub)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DECDAT_FETCH_DEPENDENCIES=ON
cmake --build build -j$(nproc)

# Or system-installed deps (faster, but requires nlohmann-json3-dev, libyaml-cpp-dev, etc.)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ECDAT_TAXONOMY` | Override the taxonomy.yaml path (used by the CLI at runtime) |
| `NO_COLOR` | Disable colored terminal output (standard: https://no-color.org) |

The taxonomy path is resolved in this priority order:
1. `ECDAT_TAXONOMY` environment variable (if set and file exists)
2. `<exe-dir>/resources/taxonomy.yaml` (next to the binary)
3. `<exe-dir>/../share/ecdat/taxonomy.yaml` (FHS layout)
4. Legacy development-tree relative paths
5. `/usr/share/ecdat/taxonomy.yaml` (system install)
6. `/etc/ecdat/taxonomy.yaml` (fallback)

## 12. CLI

The `ecdat` binary provides five subcommands. All commands accept global flags:

| Flag | Description |
|------|-------------|
| `--no-color` | Disable ANSI colored terminal output |
| `-v, --verbose` | Enable verbose/debug logging |
| `-q, --quiet` | Minimal output mode |
| `--db <path>` | Path to SQLite database file (default: `ecdat.db`) |
| `-V, --version` | Display version |

### `ecdat scan`

Scan a file or directory for cryptographic assets.

```bash
ecdat scan <target> [options]
```

| Argument / Option | Description |
|------------------|-------------|
| `target` (required) | Path to a file or directory to scan |
| `--exposure <0-100>` | Asset exposure factor (default: 60.0) |
| `--remediation <0-100>` | Fix difficulty factor (default: 40.0) |
| `-o, --output <path>` | Output file base path (extension added automatically) |
| `-f, --format <fmt>` | Report format: `json`, `csv`, `pdf`, `all` |
| `--db <path>` | SQLite database path |

**What it does:**

1. Recursively scans the target for `.py`, `.pem`/`.crt`/`.cer`, and `.conf`/`.cfg` files
2. Runs the appropriate scanner for each file type (Tree-sitter for Python, OpenSSL for certificates, pattern matching for TLS configs)
3. Classifies each discovered asset against the taxonomy
4. Computes risk scores and PQC migration recommendations
5. Stores results in SQLite
6. Prints a detailed findings summary to the terminal
7. Optionally writes JSON/CSV/PDF reports

```bash
# Scan a repository and generate all report formats
ecdat scan /path/to/repository -f all -o results/report

# Scan with custom risk parameters
ecdat scan /path/to/project --exposure 80 --remediation 50

# Scan a single certificate
ecdat scan /path/to/cert.pem
```

### `ecdat report`

Generate reports from previously stored scan results.

```bash
ecdat report [options]
```

| Option | Description |
|--------|-------------|
| `--latest` | Use the most recent scan |
| `--scan <id>` | Use a specific scan ID |
| `-f, --format <fmt>` | Report format: `json`, `csv`, `pdf`, `all` (default: `json`) |
| `-o, --output <path>` | Output file base path |

```bash
# Generate JSON report from the latest scan (stdout)
ecdat report --latest

# Generate all formats from a specific scan
ecdat report --scan 3 -f all -o report_scan3
```

### `ecdat history`

View or manage previous scan history.

```bash
ecdat history [options]
```

| Option | Description |
|--------|-------------|
| `-n, --limit <N>` | Maximum records to display (default: 20) |
| `--clear` | Clear all historical scan records |
| `--json` | Output history as raw JSON |

```bash
# View last 10 scans
ecdat history -n 10

# Clear all history
ecdat history --clear
```

### `ecdat export`

Export scan findings to a specific file format.

```bash
ecdat export -f <format> -o <path> [options]
```

| Option | Description |
|--------|-------------|
| `-f, --format <fmt>` (required) | Export format: `json`, `csv`, `pdf` |
| `-o, --output <path>` (required) | Output file path |
| `--latest` | Export from the most recent scan |
| `--scan <id>` | Export from a specific scan ID |

```bash
# Export latest scan as PDF
ecdat export --latest -f pdf -o findings.pdf

# Export specific scan as CSV
ecdat export --scan 5 -f csv -o scan5.csv
```

### `ecdat version`

Display version and build information.

```bash
ecdat version
```

### Complete Example Workflow

The following walks through a typical ECDAT session from installation to report export. All commands are real and match the CLI exactly.

```bash
# 1. Install ECDAT (Linux .deb example)
sudo dpkg -i ecdat_0.1.1_amd64.deb

# 2. Verify installation
ecdat version

# 3. Scan a repository
ecdat scan /path/to/your/repository

# 4. Review findings
#    (findings summary is printed to the terminal: status, risk score,
#     risk level, PQC flag, and What/Where/Why/Action for each asset)

# 5. Generate a report from the latest scan
ecdat report --latest
ecdat report --latest -f all -o assessment

# 6. Export results to a specific file
ecdat export --latest -f pdf -o findings.pdf
ecdat export --latest -f csv -o findings.csv
ecdat export --latest -f json -o findings.json

# 7. View scan history
ecdat history
```

A typical scan produces:

- **Discovery summary** — files scanned per category (source, certificate, TLS configs) and total assets discovered
- **Assessment & risk breakdown** — Safe / Weak / Deprecated / Unknown counts plus CRITICAL / HIGH / MEDIUM / LOW risk tier counts
- **Post-quantum readiness** — ready asset count and readiness percentage
- **Findings summary** — per-asset status, risk score (0–10), risk level, PQC flag, and an explainable What / Where / Why / Action with the PQC replacement when available

## 13. Real Repository Workflow

When a user points ECDAT at a real source-code repository:

```
/path/to/real/repository
        │
        ▼
   Member 1 — Discovery
   ├─ Finds .py files → Tree-sitter AST scan → CryptoAsset[]
   ├─ Finds .pem/.crt → OpenSSL X.509 parse → CryptoAsset[]
   └─ Finds .conf     → TLS pattern scan    → CryptoAsset[]
        │
        ▼
   Member 2 — Data & Taxonomy
   ├─ Loads taxonomy.yaml (16 algorithms)
   ├─ Looks up each algorithm (case-insensitive)
   ├─ Classifies status: Safe / Weak / Deprecated / Unknown
   ├─ Computes risk_score with key-size/curve downgrade
   └─ Sets pqc_vulnerable flag
        │
        ▼
   Member 3 — Intelligence / Risk & PQC
   ├─ Computes final_risk = weakness×0.4 + exposure×0.3 + remediation×0.3
   ├─ Determines RiskLevel (LOW / MEDIUM / HIGH / CRITICAL)
   ├─ Maps PQC-vulnerable algorithms to ML-DSA or ML-KEM
   ├─ Calculates PQC readiness percentage
   └─ Generates Explanation: What / Where / Why / Action
        │
        ▼
   Member 4 — Platform
   ├─ Stores scan + findings in SQLite
   ├─ Prints colored terminal output with findings summary
   └─ Writes JSON / CSV / PDF reports (if requested)
```

Production execution no longer depends on any hard-coded demo assets. All input comes from the user-supplied repository path.

## 14. Member 1 — Discovery Details

### Source-Code Discovery

- **Technology**: Tree-sitter with the Python grammar
- **Input**: `.py` files
- **Method**: Walks the Python AST to identify calls to `hashlib.md5()`, `hashlib.sha1()`, `hashlib.sha256()`, `des()`, `rc4()`
- **Output**: `CryptoAsset` with `source_type="python"`, `algorithm`, `file`, `line`, `context`

### X.509 Certificate Discovery

- **Technology**: OpenSSL (`PEM_read_X509`, `EVP_PKEY`)
- **Input**: `.pem`, `.crt`, `.cer` files
- **Method**: Reads PEM-encoded X.509 certificates, extracts the public key algorithm (RSA/ECDSA) and key size
- **Output**: `CryptoAsset` with `source_type="certificate"`, `algorithm`, `key_size`, `file`

### TLS Configuration Discovery

- **Technology**: Line-by-line pattern matching
- **Input**: `.conf`, `.cfg`, `nginx.conf`, `httpd.conf` files
- **Method**: Scans for weak protocols (`SSLv2`, `SSLv3`, `TLSv1.0`, `TLSv1.1`) and weak ciphers (`RC4`, `DES`, `MD5`, `NULL`)
- **Output**: `CryptoAsset` with `source_type="tls_config"`, `algorithm`, `file`, `line`, `context`

## 15. Member 2 — Data & Taxonomy Details

### CryptoAsset Contract

Defined in `taxonomy/core/include/ecdat/types.hpp`:

```cpp
struct CryptoAsset {
    std::string source_type;      // "python", "certificate", "tls_config"
    std::string file;             // file path where asset was found
    std::int64_t line = 0;        // line number
    std::string algorithm;        // e.g. "RSA", "AES-256", "MD5"
    std::int64_t key_size = 0;    // key size in bits
    std::string curve;            // e.g. "P-256", "P-192"
    std::string context;          // free-form usage description
    Status status = Status::Unknown;   // filled by classifier
    double risk_score = 0.0;           // filled by classifier
    bool pqc_flag = false;             // filled by classifier
};
```

### Taxonomy Schema

Each entry in `taxonomy.yaml`:

```yaml
- name: "RSA"
  type: "signature"
  status: "Deprecated"
  risk_base: 7.0
  pqc_vulnerable: true
  replacement: "ML-DSA"
  min_secure_key_bits: 2048
  weak_curves: []
```

### Classification Logic

1. Normalize algorithm name to lowercase
2. Look up in `TaxonomyDB` (case-insensitive, last-wins on duplicates)
3. If found: status = entry status, risk_score = entry risk_base, pqc_flag = entry pqc_vulnerable
4. If `key_size > 0` and `min_secure_key_bits` defined and key is too small: downgrade status to Weak, risk_score += 2.0
5. If `curve` matches `weak_curves`: downgrade status to Weak, risk_score += 2.0
6. Clamp risk_score to [0, 10]
7. If not found: status = Unknown, risk_score = 0, pqc_flag = false

## 16. Member 3 — Intelligence Details

### Risk Scoring

```
Risk = weakness × 0.4 + exposure × 0.3 + remediation × 0.3
```

- **weakness**: Scaled from Member 2's risk_score (0–10) × 10 → (0–100)
- **exposure**: How publicly accessible the asset is (0–100)
- **remediation**: How difficult the fix would be (0–100)
- **RiskLevel boundaries**: LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75–100)

### PQC Detection

Algorithms with `pqc_vulnerable: true` in the taxonomy are flagged. Current PQC-vulnerable algorithms: RSA, DSA, ECDSA, DH, ECDH.

### Migration Recommendations

| Algorithm | Role | Replacement |
|-----------|------|-------------|
| RSA | Signature | ML-DSA |
| ECDSA | Signature | ML-DSA |
| DH | Key Exchange | ML-KEM |

Role detection priority:
1. Taxonomy `type` field (authoritative)
2. Context keywords: "sign", "signature", "signing" → Signature; "exchange", "handshake", "tls", "agreement" → KeyExchange
3. Algorithm defaults: RSA/ECDSA → Signature, DH → KeyExchange

### PQC Readiness

```
ready = (not pqc_vulnerable) OR (has supported migration)
readiness_percent = (ready_count / total_assets) × 100
```

### Explainability

Every finding receives:

| Field | Description |
|-------|-------------|
| **What** | Algorithm name + cryptographic role |
| **Where** | File path and line number |
| **Why** | Vulnerability description (deprecated algorithm, weak key, quantum threat) |
| **Action** | Specific replacement recommendation (e.g., "Replace with ML-DSA (signature)") |

## 17. Member 4 — Platform Details

### CLI

Five subcommands built with CLI11. Full details in Section 11.

### Storage

- **Engine**: Embedded SQLite3 (amalgamation, vendored)
- **Database**: Created automatically on first use (default: `ecdat.db`)
- **Schema**: `scans` table (UUID, timestamp, target, aggregate counts, PQC readiness) + `findings` table (19 fields per finding)
- **Operations**: Save scan, query history, retrieve by ID/UUID, clear history, delete individual scans

### Reporting

| Format | Technology | Output |
|--------|-----------|--------|
| JSON | nlohmann/json | Structured scan metadata + findings array |
| CSV | Custom generator | RFC 4180 compliant, proper field escaping |
| PDF | Native C++ PDF 1.4 builder | Multi-page, colored severity cards, headers/footers |

## 18. Data Flow Example

A single cryptographic asset moving through the pipeline:

```
Source: sample.py, line 4: hashlib.md5(data)
        │
        ▼ Member 1 — Discovery
CryptoAsset {
    source_type = "python"
    file = "sample.py"
    line = 4
    algorithm = "md5"
    key_size = 0
    curve = ""
    context = "hashlib call"
}
        │
        ▼ Member 2 — Classification
Classification {
    status = Deprecated
    risk_score = 7.0          (from taxonomy risk_base)
    pqc_flag = false           (MD5 is not PQC-vulnerable)
    entry = TaxonomyEntry { name="MD5", status=Deprecated, ... }
}
        │
        ▼ Member 3 — Intelligence
PipelineResult {
    weakness = 70.0            (risk_score 7.0 × 10)
    exposure = 60.0            (default parameter)
    remediation = 40.0         (default parameter)
    final_risk = 60.0          (70×0.4 + 60×0.3 + 40×0.3)
    risk_level = HIGH          (50–74 range)
    migration = { supported = false }   (MD5 has no PQC replacement)
    explanation = {
        what = "MD5 (hash)"
        where = "sample.py:4"
        why = "MD5 is deprecated — cryptographically broken"
        action = "Replace with SHA-256"
    }
}
        │
        ▼ Member 4 — Storage/Reporting
Stored in SQLite as scan + finding records.
Written to JSON/CSV/PDF with full explainability.
```

## 19. Example Usage

```bash
# Quick start: build with self-bootstrapping (fetches all deps automatically)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DECDAT_FETCH_DEPENDENCIES=ON
cmake --build build -j$(nproc)

# Scan a real repository
./build/platform/ecdat scan /path/to/your/repository

# Scan with custom risk parameters and generate all reports
./build/platform/ecdat scan /path/to/your/repository \
    --exposure 80 --remediation 50 \
    -f all -o results/assessment

# View scan history
./build/platform/ecdat history

# Export the latest scan as PDF
./build/platform/ecdat export --latest -f pdf -o latest_report.pdf

# Or use the pre-built binary (no build needed)
tar xzf ECDAT-0.1.1-linux-x86_64.tar.gz
./ECDAT-0.1.1/bin/ecdat scan /path/to/your/repository
```

The CLI output includes:

- **Discovery summary**: files scanned, assets found
- **Risk breakdown**: Safe / Weak / Deprecated / Unknown counts, CRITICAL / HIGH / MEDIUM / LOW risk counts
- **PQC readiness**: ready assets, readiness percentage
- **Findings summary**: per-asset status, risk score, risk level, PQC flag, explanation (Where / Why / Action), PQC replacement when available

## 20. Design Principles

- **Modular four-member architecture**: Each member has a single responsibility and can be developed independently
- **Shared CryptoAsset contract**: One struct defined once, imported by all members — type-safe integration without coupling
- **Data-driven taxonomy**: Algorithm classifications are defined in YAML, not hard-coded in source — easy to extend
- **Separation of discovery and intelligence**: Finding cryptographic assets is separate from assessing their risk
- **Role-aware PQC migration**: The same algorithm gets different replacement recommendations depending on how it is used
- **Persistent results**: All scans are stored in SQLite with full history — results survive across sessions
- **Explainable findings**: Every assessment includes What / Where / Why / Action — no black-box scores
- **Real repository input**: Production execution operates on user-supplied paths — no hard-coded demo data
- **Automated testing**: 120 tests across all members verify correctness at every layer
- **Graceful degradation**: Member 1 is optional — the system builds and runs without OpenSSL/tree-sitter

## 21. Project Status

| Component | Status |
|-----------|--------|
| Member 1 — Discovery | Verified (Tree-sitter, OpenSSL, TLS scanning) |
| Member 2 — Data & Taxonomy | Verified (CryptoAsset, taxonomy, classification) |
| Member 3 — Intelligence / Risk & PQC | Verified (risk engine, PQC migration, explainability) |
| Member 4 — Platform / CLI, Storage & Reporting | Verified (CLI, SQLite, JSON/CSV/PDF) |
| M1 → M2 → M3 → M4 integration | Verified |
| Automated tests | **120/120 PASS** |
| Hard-coded demo runtime data | Removed (commit `2380d05`) |

**Next phase**: Testing against real external source-code repositories.

Passing 120/120 automated tests confirms internal correctness. It does not guarantee that every possible external repository will be scanned without issues. Real-world validation is ongoing.

## 22. Limitations

- **Source scanning**: Currently limited to Python files (via Tree-sitter). C/C++/Java/Go/Rust source scanning is not yet implemented.
- **Certificate scanning**: Handles PEM-encoded X.509 certificates. DER-encoded and PKCS#12 formats are not supported.
- **TLS scanning**: Pattern-based — detects well-known weak protocol and cipher names in config files. Does not perform live TLS handshake analysis.
- **Taxonomy size**: The taxonomy contains 16 algorithm entries. Organizations with custom or niche algorithms will need to extend `taxonomy.yaml`.
- **Single-threaded scanning**: File discovery and scanning is sequential within a single `ecdat scan` invocation.
- **Platform**: Tested on Linux (x86_64). Other platforms are not officially supported.

## 23. Contribution & Development

ECDAT is organized around four member modules:

| Module | Owner Area |
|--------|-----------|
| `discovery/` | Discovery — source-code, certificate, and TLS scanning |
| `taxonomy/` | Data & Taxonomy — shared data model, classification, taxonomy |
| `risk/` | Intelligence — risk engine, PQC migration, explainability |
| `platform/` | Platform — CLI, storage, reporting |
| `integration/` | Pipeline adapter and full flow orchestration |

**Rules for cross-member changes:**

- The `CryptoAsset` struct is defined only in `taxonomy/core/include/ecdat/types.hpp`. All other members import it from there.
- Do not modify `CryptoAsset` fields without updating all consumers.
- The taxonomy YAML schema is authoritative in `taxonomy/taxonomy/data/taxonomy.yaml`.
- The risk formula weights (0.4 / 0.3 / 0.3) are specified externally and must not be changed in `risk_engine.cpp`.

## 24. License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.

Copyright (c) 2026 ECDAT Project Team.
