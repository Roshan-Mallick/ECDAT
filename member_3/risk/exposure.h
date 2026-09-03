#pragma once
#include <string>
#include <unordered_map>

struct ExposureResult {
    double score;
    std::string level;
    bool usedDefault;
};

class ExposureRules {
public:
    explicit ExposureRules(const std::string& jsonPath);

    ExposureResult scoreFor(const std::string& exposure) const;

private:
    std::unordered_map<std::string, double> scores_;
    std::string defaultLevel_;

    static std::string lowercase(const std::string& value);
};