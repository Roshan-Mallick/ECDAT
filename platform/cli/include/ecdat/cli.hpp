#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ecdat::cli {

struct CliConfig {
    std::string command;
    std::string target_path;
    double      exposure = 60.0;
    double      remediation = 40.0;
    std::string output_path;
    std::string format;
    std::string db_path;
    std::int64_t scan_id = 0;
    bool        latest = false;
    std::size_t limit = 20;
    bool        clear = false;
    bool        json_output = false;
    bool        no_color = false;
    bool        verbose = false;
    bool        quiet = false;
};

class CliApp {
public:
    CliApp();
    ~CliApp();

    int run(int argc, char** argv);

private:
    int handle_scan(const CliConfig& config);
    int handle_report(const CliConfig& config);
    int handle_history(const CliConfig& config);
    int handle_export(const CliConfig& config);
    int handle_version();
};

} // namespace ecdat::cli
