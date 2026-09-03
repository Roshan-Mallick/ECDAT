#include "exposure.h"
#include "../common/simple_json.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <stdexcept>

using ecdat::simple_json::Value;

std::string ExposureRules::lowercase(const std::string& value) {
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

ExposureRules::ExposureRules(const std::string& jsonPath) {
    std::ifstream file(jsonPath);
    if (!file) throw std::runtime_error("Cannot open exposure file: " + jsonPath);

    const Value rules = Value::parse(file);

    defaultLevel_ = lowercase(rules.at("default").stringValue());

    for (const auto& item : rules.items()) {
        const auto& level = item.first;
        const auto& score = item.second;
        if (level != "default") {
            scores_[lowercase(level)] = score.numberValue();
        }
    }

    if (scores_.find(defaultLevel_) == scores_.end()) {
        throw std::runtime_error("Exposure default does not have a score");
    }
}

ExposureResult ExposureRules::scoreFor(const std::string& exposure) const {
    const std::string level = lowercase(exposure);

    if (!level.empty()) {
        const auto it = scores_.find(level);
        if (it != scores_.end()) {
            return {it->second, level, false};
        }
    }

    return {scores_.at(defaultLevel_), defaultLevel_, true};
}