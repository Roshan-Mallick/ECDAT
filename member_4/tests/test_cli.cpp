#include "ecdat/cli.hpp"
#include "ecdat/storage.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

namespace ecdat::cli {
#ifndef M1_FIXTURES_DIR
#define M1_FIXTURES_DIR "member_1/fixtures"
#endif

namespace {

std::string get_fixtures_dir() {
    std::vector<std::string> candidates = {
        M1_FIXTURES_DIR,
        "member_1/fixtures",
        "../../member_1/fixtures",
        "../member_1/fixtures"
    };
    for (const auto& c : candidates) {
        if (std::filesystem::exists(c)) return c;
    }
    return M1_FIXTURES_DIR;
}

int run_cli(std::vector<std::string> args) {
    std::vector<char*> c_args;
    c_args.push_back(const_cast<char*>("ecdat"));
    for (auto& a : args) {
        c_args.push_back(const_cast<char*>(a.data()));
    }
    CliApp app;
    return app.run(static_cast<int>(c_args.size()), c_args.data());
}

TEST(CliTest, VersionCommandSucceeds) {
    int rc = run_cli({"version"});
    EXPECT_EQ(rc, 0);
}

TEST(CliTest, HelpFlagSucceeds) {
    int rc = run_cli({"--help"});
    EXPECT_EQ(rc, 0);
}

TEST(CliTest, SubcommandHelpSucceeds) {
    EXPECT_EQ(run_cli({"scan", "--help"}), 0);
    EXPECT_EQ(run_cli({"report", "--help"}), 0);
    EXPECT_EQ(run_cli({"history", "--help"}), 0);
    EXPECT_EQ(run_cli({"export", "--help"}), 0);
    EXPECT_EQ(run_cli({"version", "--help"}), 0);
}

TEST(CliTest, ScanMissingTargetFailsCleanly) {
    int rc = run_cli({"scan"});
    EXPECT_NE(rc, 0);
}

TEST(CliTest, ScanNonExistentPathFailsCleanly) {
    int rc = run_cli({"scan", "this_path_does_not_exist_at_all_12345"});
    EXPECT_NE(rc, 0);
}

TEST(CliTest, ExportMissingRequiredArgumentsFailsCleanly) {
    int rc = run_cli({"export"});
    EXPECT_NE(rc, 0);

    // Missing output path
    rc = run_cli({"export", "--format", "json"});
    EXPECT_NE(rc, 0);

    // Missing format
    rc = run_cli({"export", "--output", "out.json"});
    EXPECT_NE(rc, 0);
}

TEST(CliTest, HistoryOnEmptyDbSucceeds) {
    int rc = run_cli({"history", "--db", ":memory:"});
    EXPECT_EQ(rc, 0);

    rc = run_cli({"history", "--json", "--db", ":memory:"});
    EXPECT_EQ(rc, 0);
}

TEST(CliTest, HistoryClearSucceeds) {
    int rc = run_cli({"history", "--clear", "--db", ":memory:"});
    EXPECT_EQ(rc, 0);
}

TEST(CliTest, ScanInvalidFormatFails) {
    int rc = run_cli({"scan", get_fixtures_dir(), "--format", "banana"});
    EXPECT_NE(rc, 0);
}

TEST(CliTest, ScanOutputFailureReturnsNonZero) {
    int rc = run_cli({"scan", get_fixtures_dir(), "--format", "json", "--output", "/non_existent_dir_12345/sub/report.json"});
    EXPECT_NE(rc, 0);
}

TEST(CliTest, ScanRealFixtureGeneratesAllReports) {
    std::string temp_dir = "temp_test_cli_out";
    std::filesystem::create_directories(temp_dir);
    std::string out_base = temp_dir + "/assessment";
    std::string db_file = temp_dir + "/test.db";

    int rc = run_cli({"scan", get_fixtures_dir(), "--format", "all", "--output", out_base, "--db", db_file});
    EXPECT_EQ(rc, 0);

    EXPECT_TRUE(std::filesystem::exists(out_base + ".json"));
    EXPECT_TRUE(std::filesystem::exists(out_base + ".csv"));
    EXPECT_TRUE(std::filesystem::exists(out_base + ".pdf"));

    // Verify JSON content
    std::ifstream jf(out_base + ".json");
    ASSERT_TRUE(jf.is_open());
    std::string json_str((std::istreambuf_iterator<char>(jf)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(json_str.find("summary") != std::string::npos);
    EXPECT_TRUE(json_str.find("findings") != std::string::npos);

    // Verify CSV content
    std::ifstream cf(out_base + ".csv");
    ASSERT_TRUE(cf.is_open());
    std::string csv_str((std::istreambuf_iterator<char>(cf)), std::istreambuf_iterator<char>());
    EXPECT_TRUE(csv_str.find("scan_id,scan_uuid") != std::string::npos);

    // Verify PDF content
    std::ifstream pf(out_base + ".pdf", std::ios::binary);
    ASSERT_TRUE(pf.is_open());
    std::string pdf_str((std::istreambuf_iterator<char>(pf)), std::istreambuf_iterator<char>());
    EXPECT_EQ(pdf_str.substr(0, 5), "%PDF-");
    EXPECT_NE(pdf_str.find("%%EOF"), std::string::npos);

    std::filesystem::remove_all(temp_dir);
}

TEST(CliTest, ReportFormatAllNoExtensionStacking) {
    std::string temp_dir = "temp_test_cli_stacking";
    std::filesystem::create_directories(temp_dir);
    std::string db_file = temp_dir + "/stacking.db";

    int rc = run_cli({"scan", get_fixtures_dir(), "--db", db_file});
    ASSERT_EQ(rc, 0);

    std::string out_base = temp_dir + "/my_report";
    rc = run_cli({"report", "--latest", "--format", "all", "--output", out_base, "--db", db_file});
    EXPECT_EQ(rc, 0);

    EXPECT_TRUE(std::filesystem::exists(out_base + ".json"));
    EXPECT_TRUE(std::filesystem::exists(out_base + ".csv"));
    EXPECT_TRUE(std::filesystem::exists(out_base + ".pdf"));

    // Ensure NO stacked extension files were created
    EXPECT_FALSE(std::filesystem::exists(out_base + ".pdf.json"));
    EXPECT_FALSE(std::filesystem::exists(out_base + ".pdf.csv"));
    EXPECT_FALSE(std::filesystem::exists(out_base + ".pdf.pdf"));

    std::filesystem::remove_all(temp_dir);
}

TEST(CliTest, ScanSingleFileCerRouting) {
    std::string temp_dir = "temp_test_cer";
    std::filesystem::create_directories(temp_dir);
    std::string cer_file = temp_dir + "/sample_cert.cer";

    // Write empty or dummy cert file
    {
        std::ofstream ofs(cer_file);
        ofs << "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";
    }

    int rc = run_cli({"scan", cer_file, "--db", ":memory:"});
    EXPECT_EQ(rc, 0);

    std::filesystem::remove_all(temp_dir);
}

} // namespace
} // namespace ecdat::cli
