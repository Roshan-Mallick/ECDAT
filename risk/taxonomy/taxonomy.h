#pragma once
#include <string>
#include <unordered_map>

struct TaxonomyEntry {
    double weakness;
    double remediation;
    std::string role;
    bool pqcVulnerable;
};

class TaxonomyLookup {
public:
    explicit TaxonomyLookup(const std::string& jsonPath);

    const TaxonomyEntry& lookup(const std::string& algorithm) const;

private:
    std::unordered_map<std::string, TaxonomyEntry> entries_;

    static std::string normalize(const std::string& algorithm);
};