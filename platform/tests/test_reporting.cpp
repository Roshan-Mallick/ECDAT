#include "ecdat/reporting.hpp"
#include "ecdat/storage.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace ecdat::reporting {
namespace {

storage::ScanDetail make_test_detail() {
    storage::ScanDetail detail;
    detail.scan.id = 42;
    detail.scan.scan_uuid = "scan-uuid-42-test";
    detail.scan.timestamp = "2026-09-04 01:20:00Z";
    detail.scan.target_path = "./demo_project";
    detail.scan.total_assets = 2;
    detail.scan.safe_count = 1;
    detail.scan.weak_count = 1;
    detail.scan.deprecated_count = 0;
    detail.scan.unknown_count = 0;
    detail.scan.critical_risk_count = 0;
    detail.scan.high_risk_count = 1;
    detail.scan.medium_risk_count = 0;
    detail.scan.low_risk_count = 1;
    detail.scan.pqc_ready_count = 2;
    detail.scan.pqc_readiness_pct = 100.0;

    {
        storage::FindingRecord f;
        f.id = 1;
        f.scan_id = 42;
        f.source_type = "source_code";
        f.file = "server.py";
        f.line = 15;
        f.algorithm = "RSA";
        f.key_size = 1024;
        f.curve = "";
        f.context = "crypto.generate_rsa_key(1024)";
        f.status = Status::Weak;
        f.risk_score = 70.0;
        f.risk_level = "HIGH";
        f.pqc_flag = true;
        f.pqc_supported = true;
        f.pqc_role = "signature";
        f.pqc_replacement = "ML-DSA";
        f.what = "RSA-1024 detected";
        f.where_text = "server.py:15";
        f.why = "Key size 1024 is below the secure minimum; quantum-vulnerable public-key cryptography";
        f.action = "Migrate to an appropriate PQC algorithm: ML-DSA (status: Weak)";
        detail.findings.push_back(std::move(f));
    }
    {
        storage::FindingRecord f;
        f.id = 2;
        f.scan_id = 42;
        f.source_type = "source_code";
        f.file = "auth.py";
        f.line = 88;
        f.algorithm = "AES-256";
        f.key_size = 256;
        f.curve = "";
        f.context = "cipher = AES.new(key, AES.MODE_GCM)";
        f.status = Status::Safe;
        f.risk_score = 10.0;
        f.risk_level = "LOW";
        f.pqc_flag = false;
        f.pqc_supported = false;
        f.pqc_role = "encryption";
        f.pqc_replacement = "";
        f.what = "AES-256 detected";
        f.where_text = "auth.py:88";
        f.why = "no known cryptographic weakness detected";
        f.action = "No action required";
        detail.findings.push_back(std::move(f));
    }

    return detail;
}

TEST(ReportingTest, JsonReportValidAndParsable) {
    auto detail = make_test_detail();
    std::string json_str = generate_json(detail);
    ASSERT_FALSE(json_str.empty());

    auto parsed = nlohmann::json::parse(json_str);
    EXPECT_EQ(parsed["scan_metadata"]["id"], 42);
    EXPECT_EQ(parsed["scan_metadata"]["target_path"], "./demo_project");
    EXPECT_EQ(parsed["summary"]["total_assets"], 2);
    EXPECT_EQ(parsed["summary"]["status_counts"]["safe"], 1);
    EXPECT_EQ(parsed["summary"]["status_counts"]["weak"], 1);
    EXPECT_DOUBLE_EQ(parsed["summary"]["pqc_readiness"]["readiness_percentage"], 100.0);

    ASSERT_TRUE(parsed["findings"].is_array());
    ASSERT_EQ(parsed["findings"].size(), 2u);
    EXPECT_EQ(parsed["findings"][0]["cryptography"]["algorithm"], "RSA");
    EXPECT_EQ(parsed["findings"][0]["assessment"]["status"], "Weak");
    EXPECT_EQ(parsed["findings"][0]["pqc"]["replacement"], "ML-DSA");
    EXPECT_EQ(parsed["findings"][1]["cryptography"]["algorithm"], "AES-256");
}

TEST(ReportingTest, JsonReportEmptyScan) {
    storage::ScanDetail detail;
    detail.scan.id = 1;
    detail.scan.target_path = "empty_dir";
    std::string json_str = generate_json(detail);
    auto parsed = nlohmann::json::parse(json_str);
    EXPECT_EQ(parsed["summary"]["total_assets"], 0);
    EXPECT_TRUE(parsed["findings"].empty());
}

TEST(ReportingTest, CsvReportValidAndEscaped) {
    auto detail = make_test_detail();
    std::string csv_str = generate_csv(detail);
    ASSERT_FALSE(csv_str.empty());

    std::istringstream iss(csv_str);
    std::string header;
    std::getline(iss, header);
    EXPECT_NE(header.find("scan_id"), std::string::npos);
    EXPECT_NE(header.find("algorithm"), std::string::npos);
    EXPECT_NE(header.find("pqc_replacement"), std::string::npos);

    std::string row1;
    std::getline(iss, row1);
    EXPECT_NE(row1.find("RSA"), std::string::npos);
    EXPECT_NE(row1.find("ML-DSA"), std::string::npos);

    std::string row2;
    std::getline(iss, row2);
    EXPECT_NE(row2.find("AES-256"), std::string::npos);
}

TEST(ReportingTest, CsvReportEscapesCommasAndQuotes) {
    storage::ScanDetail detail;
    detail.scan.id = 1;
    detail.scan.target_path = "path/with,comma";

    storage::FindingRecord f;
    f.id = 1;
    f.algorithm = "RSA,with,comma";
    f.context = "code with \"quotes\"";
    f.why = "line 1\nline 2";
    detail.findings.push_back(f);

    std::string csv_str = generate_csv(detail);
    EXPECT_NE(csv_str.find("\"path/with,comma\""), std::string::npos);
    EXPECT_NE(csv_str.find("\"RSA,with,comma\""), std::string::npos);
    EXPECT_NE(csv_str.find("\"code with \"\"quotes\"\"\""), std::string::npos);
}

TEST(ReportingTest, PdfReportGeneratesValidStructure) {
    auto detail = make_test_detail();
    std::string pdf = generate_pdf(detail);

    ASSERT_GE(pdf.size(), 100u);
    // PDF Magic Header
    EXPECT_EQ(pdf.substr(0, 5), "%PDF-");
    // PDF End-of-file trailer
    EXPECT_NE(pdf.find("%%EOF"), std::string::npos);
    // Cross reference table
    EXPECT_NE(pdf.find("xref"), std::string::npos);
    EXPECT_NE(pdf.find("/Type /Catalog"), std::string::npos);
    EXPECT_NE(pdf.find("/Type /Pages"), std::string::npos);
}

TEST(ReportingTest, PdfReportEmptyScanDoesNotCrash) {
    storage::ScanDetail detail;
    detail.scan.id = 1;
    detail.scan.target_path = "empty_repo";
    std::string pdf = generate_pdf(detail);

    EXPECT_EQ(pdf.substr(0, 5), "%PDF-");
    EXPECT_NE(pdf.find("%%EOF"), std::string::npos);
}

TEST(ReportingTest, PdfReportHandlesMultiplePagesAndLongLists) {
    storage::ScanDetail detail;
    detail.scan.id = 100;
    detail.scan.target_path = "huge_enterprise_repo";
    detail.scan.total_assets = 50;

    for (int i = 1; i <= 50; ++i) {
        storage::FindingRecord f;
        f.id = i;
        f.algorithm = (i % 2 == 0) ? "RSA" : "ECDSA";
        f.key_size = 2048;
        f.file = "src/subsystem/module_" + std::to_string(i) + "/very_deep_nested_file_path_for_testing.cpp";
        f.line = i * 10;
        f.status = Status::Weak;
        f.risk_score = 65.0;
        f.risk_level = "HIGH";
        f.pqc_flag = true;
        f.pqc_supported = true;
        f.pqc_role = "signature";
        f.pqc_replacement = "ML-DSA";
        f.what = f.algorithm + " detected";
        f.where_text = f.file + ":" + std::to_string(f.line);
        f.why = "Extremely detailed rationale explaining that quantum algorithms like Shor's algorithm threaten public key cryptography.";
        f.action = "Replace immediately with NIST FIPS 204 standard ML-DSA post-quantum signature primitive.";
        detail.findings.push_back(f);
    }

    std::string pdf = generate_pdf(detail);
    EXPECT_EQ(pdf.substr(0, 5), "%PDF-");
    EXPECT_NE(pdf.find("%%EOF"), std::string::npos);
    // Multiple pages must exist
    EXPECT_NE(pdf.find("/Count "), std::string::npos);
}

TEST(ReportingTest, WriteFilesToDisk) {
    auto detail = make_test_detail();
    std::string jpath = "temp_test_out/report.json";
    std::string cpath = "temp_test_out/report.csv";
    std::string ppath = "temp_test_out/report.pdf";

    EXPECT_TRUE(write_json(detail, jpath));
    EXPECT_TRUE(write_csv(detail, cpath));
    EXPECT_TRUE(write_pdf(detail, ppath));

    EXPECT_TRUE(std::filesystem::exists(jpath));
    EXPECT_TRUE(std::filesystem::exists(cpath));
    EXPECT_TRUE(std::filesystem::exists(ppath));

    EXPECT_GT(std::filesystem::file_size(jpath), 0u);
    EXPECT_GT(std::filesystem::file_size(cpath), 0u);
    EXPECT_GT(std::filesystem::file_size(ppath), 0u);

    std::filesystem::remove_all("temp_test_out");
}

} // namespace
} // namespace ecdat::reporting
