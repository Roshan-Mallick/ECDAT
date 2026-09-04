#include "ecdat/storage.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <vector>

namespace ecdat::storage {
namespace {

TEST(StorageTest, InMemDbAutoInitializes) {
    Storage store(":memory:");
    EXPECT_TRUE(store.is_open());
    auto history = store.get_history();
    EXPECT_TRUE(history.empty());
}

TEST(StorageTest, SaveAndRetrieveSingleScan) {
    Storage store(":memory:");

    std::vector<Finding> findings;
    {
        Finding f;
        f.asset.source_type = "source_code";
        f.asset.file = "crypto_utils.py";
        f.asset.line = 42;
        f.asset.algorithm = "MD5";
        f.asset.status = Status::Deprecated;
        f.asset.risk_score = 90.0;
        f.asset.pqc_flag = false;
        f.message = "Replace with SHA-256";
        findings.push_back(std::move(f));
    }

    std::int64_t id = store.save_findings("/path/to/project", findings, "custom-uuid-123");
    EXPECT_GT(id, 0);

    auto history = store.get_history();
    ASSERT_EQ(history.size(), 1u);
    EXPECT_EQ(history[0].id, id);
    EXPECT_EQ(history[0].scan_uuid, "custom-uuid-123");
    EXPECT_EQ(history[0].target_path, "/path/to/project");
    EXPECT_EQ(history[0].total_assets, 1);
    EXPECT_EQ(history[0].deprecated_count, 1);

    auto scan_opt = store.get_scan(id);
    ASSERT_TRUE(scan_opt.has_value());
    EXPECT_EQ(scan_opt->scan.id, id);
    ASSERT_EQ(scan_opt->findings.size(), 1u);
    EXPECT_EQ(scan_opt->findings[0].algorithm, "MD5");
    EXPECT_EQ(scan_opt->findings[0].status, Status::Deprecated);
    EXPECT_EQ(scan_opt->findings[0].file, "crypto_utils.py");
    EXPECT_EQ(scan_opt->findings[0].line, 42);
}

TEST(StorageTest, SaveMultipleFindingsAndRiskTiers) {
    Storage store(":memory:");

    std::vector<Finding> findings;
    // Critical risk finding
    {
        Finding f;
        f.asset.algorithm = "DES";
        f.asset.status = Status::Deprecated;
        f.asset.risk_score = 80.0;
        findings.push_back(f);
    }
    // High risk finding
    {
        Finding f;
        f.asset.algorithm = "RSA";
        f.asset.key_size = 1024;
        f.asset.status = Status::Weak;
        f.asset.risk_score = 65.0;
        f.asset.pqc_flag = true;
        findings.push_back(f);
    }
    // Low risk finding
    {
        Finding f;
        f.asset.algorithm = "AES-256";
        f.asset.key_size = 256;
        f.asset.status = Status::Safe;
        f.asset.risk_score = 10.0;
        findings.push_back(f);
    }

    std::int64_t id = store.save_findings("src/", findings);
    auto scan_opt = store.get_scan(id);
    ASSERT_TRUE(scan_opt.has_value());
    EXPECT_EQ(scan_opt->scan.total_assets, 3);
    EXPECT_EQ(scan_opt->scan.critical_risk_count, 1);
    EXPECT_EQ(scan_opt->scan.high_risk_count, 1);
    EXPECT_EQ(scan_opt->scan.low_risk_count, 1);
    EXPECT_EQ(scan_opt->scan.safe_count, 1);
    EXPECT_EQ(scan_opt->scan.weak_count, 1);
    EXPECT_EQ(scan_opt->scan.deprecated_count, 1);
}

TEST(StorageTest, MultipleScansAndHistoryOrdering) {
    Storage store(":memory:");

    std::vector<Finding> f1 = { Finding{CryptoAsset{"source", "a.py", 1, "MD5", 0, "", "", Status::Deprecated, 80.0, false}, "msg1"} };
    std::vector<Finding> f2 = { Finding{CryptoAsset{"source", "b.py", 10, "SHA-1", 0, "", "", Status::Deprecated, 75.0, false}, "msg2"} };
    std::vector<Finding> f3 = { Finding{CryptoAsset{"source", "c.py", 20, "AES-256", 256, "", "", Status::Safe, 10.0, false}, "msg3"} };

    std::int64_t id1 = store.save_findings("dir1", f1);
    std::int64_t id2 = store.save_findings("dir2", f2);
    std::int64_t id3 = store.save_findings("dir3", f3);

    auto history = store.get_history();
    ASSERT_EQ(history.size(), 3u);
    // Ordered by id DESC
    EXPECT_EQ(history[0].id, id3);
    EXPECT_EQ(history[1].id, id2);
    EXPECT_EQ(history[2].id, id1);

    auto latest = store.get_latest_scan();
    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(latest->scan.id, id3);
    EXPECT_EQ(latest->scan.target_path, "dir3");
}

TEST(StorageTest, HandlesSpecialCharactersAndSqlInjectionAttempts) {
    Storage store(":memory:");

    std::vector<Finding> findings;
    {
        Finding f;
        f.asset.source_type = "source'; DROP TABLE findings; --";
        f.asset.file = "file'with\"quotes,and\nnewlines.py";
        f.asset.line = 999;
        f.asset.algorithm = "RSA' OR '1'='1";
        f.asset.context = "context with 'quotes' and \"double quotes\" and `backticks` and \\backslashes\\";
        f.message = "message with \0-escaped characters and symbols: <>&*();'\"";
        findings.push_back(std::move(f));
    }

    std::int64_t id = store.save_findings("target'--", findings);
    auto scan_opt = store.get_scan(id);
    ASSERT_TRUE(scan_opt.has_value());
    ASSERT_EQ(scan_opt->findings.size(), 1u);

    const auto& rec = scan_opt->findings[0];
    EXPECT_EQ(rec.source_type, "source'; DROP TABLE findings; --");
    EXPECT_EQ(rec.file, "file'with\"quotes,and\nnewlines.py");
    EXPECT_EQ(rec.algorithm, "RSA' OR '1'='1");
    EXPECT_EQ(rec.context, "context with 'quotes' and \"double quotes\" and `backticks` and \\backslashes\\");
}

TEST(StorageTest, DiskFileReopeningPreservesData) {
    std::string test_db = "test_temp_storage.db";
    if (std::filesystem::exists(test_db)) {
        std::filesystem::remove(test_db);
    }

    std::int64_t saved_id = 0;
    {
        Storage store(test_db);
        std::vector<Finding> findings = {
            Finding{CryptoAsset{"certificate", "cert.pem", -1, "RSA", 2048, "", "TLS", Status::Weak, 50.0, true}, "PQC needed"}
        };
        saved_id = store.save_findings("server_certs", findings, "disk-uuid-999");
        EXPECT_GT(saved_id, 0);
    }

    // Reopen in another instance
    {
        Storage store(test_db);
        EXPECT_TRUE(store.is_open());
        auto scan_opt = store.get_scan(saved_id);
        ASSERT_TRUE(scan_opt.has_value());
        EXPECT_EQ(scan_opt->scan.scan_uuid, "disk-uuid-999");
        EXPECT_EQ(scan_opt->scan.target_path, "server_certs");
        ASSERT_EQ(scan_opt->findings.size(), 1u);
        EXPECT_EQ(scan_opt->findings[0].algorithm, "RSA");
        EXPECT_EQ(scan_opt->findings[0].key_size, 2048);
        EXPECT_TRUE(scan_opt->findings[0].pqc_flag);
    }

    std::filesystem::remove(test_db);
}

TEST(StorageTest, ClearHistoryWorks) {
    Storage store(":memory:");
    std::vector<Finding> findings = { Finding{CryptoAsset{"src", "f.py", 1, "MD5", 0, "", "", Status::Deprecated, 90.0, false}, "msg"} };
    store.save_findings("target", findings);
    EXPECT_EQ(store.get_history().size(), 1u);

    store.clear_history();
    EXPECT_EQ(store.get_history().size(), 0u);
    EXPECT_FALSE(store.get_latest_scan().has_value());
}

TEST(StorageTest, PqcReadinessConsistencyRule) {
    Storage store(":memory:");

    // Case 1: pqc_flag = false => Ready
    // Case 2: pqc_flag = true, algorithm = "RSA" (supported migration to ML-DSA) => Ready
    // Case 3: pqc_flag = true, algorithm = "CUSTOM_QUANTUM_UNSUPPORTED" => Not Ready
    std::vector<Finding> findings;
    {
        Finding f;
        f.asset.algorithm = "AES-256";
        f.asset.pqc_flag = false;
        findings.push_back(f);
    }
    {
        Finding f;
        f.asset.algorithm = "RSA";
        f.asset.context = "signature";
        f.asset.pqc_flag = true;
        findings.push_back(f);
    }
    {
        Finding f;
        f.asset.algorithm = "CUSTOM_UNKNOWN_CRYPTO";
        f.asset.pqc_flag = true;
        findings.push_back(f);
    }

    std::int64_t id = store.save_findings("test_pqc_readiness", findings);
    auto scan_opt = store.get_scan(id);
    ASSERT_TRUE(scan_opt.has_value());
    EXPECT_EQ(scan_opt->scan.total_assets, 3);
    EXPECT_EQ(scan_opt->scan.pqc_ready_count, 2);
    EXPECT_NEAR(scan_opt->scan.pqc_readiness_pct, (2.0 / 3.0) * 100.0, 0.01);
}

} // namespace
} // namespace ecdat::storage
