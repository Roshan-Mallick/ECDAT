#include "ecdat/taxonomy.hpp"

#include "ecdat/serialization.hpp"   // status_from_string / status_to_string

#include <yaml-cpp/yaml.h>

#include <cctype>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace ecdat {

namespace {

// Trim ASCII whitespace and lower-case a string. Used to build normalized
// lookup keys (see normalize_key).
std::string to_lower_trimmed(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    // Strip leading whitespace.
    std::size_t begin = 0;
    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
    }
    for (std::size_t i = begin; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (std::isspace(c) != 0) {
            continue; // also strip internal/trailing whitespace
        }
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

// Read a required string scalar, producing a descriptive error on failure.
std::string require_string(const YAML::Node& node, const std::string& key,
                           const std::string& entry_name) {
    const YAML::Node& child = node[key];
    if (!child || !child.IsScalar()) {
        throw std::runtime_error(
            "taxonomy: entry '" + entry_name + "' is missing or has a non-string '" +
            key + "' field");
    }
    return child.as<std::string>();
}

std::vector<std::string> require_string_list(const YAML::Node& node,
                                             const std::string& key,
                                             const std::string& entry_name) {
    std::vector<std::string> result;
    if (auto it = node[key]; it) {
        if (!it.IsSequence()) {
            throw std::runtime_error(
                "taxonomy: entry '" + entry_name + "' field '" + key +
                "' must be a list");
        }
        for (const auto& item : it) {
            if (!item.IsScalar()) {
                throw std::runtime_error(
                    "taxonomy: entry '" + entry_name + "' field '" + key +
                    "' contains a non-scalar element");
            }
            result.push_back(item.as<std::string>());
        }
    }
    return result;
}

std::optional<long long> read_optional_int(const YAML::Node& node,
                                           const std::string& key) {
    if (const auto it = node[key]; it) {
        if (!it.IsScalar() || !it.IsDefined()) {
            throw std::runtime_error("taxonomy: field '" + key +
                                     "' must be an integer");
        }
        // yaml-cpp yields scalars; parse to long long safely.
        try {
            return it.as<long long>();
        } catch (const std::exception&) {
            throw std::runtime_error("taxonomy: field '" + key +
                                     "' is not a valid integer");
        }
    }
    return std::nullopt;
}

// Build a TaxonomyEntry from a parsed algorithm node.
TaxonomyEntry parse_entry(const YAML::Node& node) {
    const std::string name = require_string(node, "name", "<unnamed>");
    TaxonomyEntry entry;
    entry.name = name;

    entry.type = require_string(node, "type", name);

    const std::string status_text = require_string(node, "status", name);
    auto status = status_from_string(status_text);
    if (!status) {
        throw std::runtime_error(
            "taxonomy: entry '" + name + "' has invalid status '" + status_text + "'");
    }
    entry.status = *status;

    const YAML::Node& risk = node["risk_base"];
    if (!risk || !risk.IsScalar() || risk.as<std::string>().empty()) {
        throw std::runtime_error(
            "taxonomy: entry '" + name + "' is missing a numeric 'risk_base'");
    }
    try {
        entry.risk_base = risk.as<double>();
    } catch (const std::exception&) {
        throw std::runtime_error("taxonomy: entry '" + name +
                                 "' has a non-numeric 'risk_base'");
    }

    const YAML::Node& pqc = node["pqc_vulnerable"];
    if (!pqc || !pqc.IsScalar()) {
        throw std::runtime_error(
            "taxonomy: entry '" + name +
            "' is missing a boolean 'pqc_vulnerable'");
    }
    try {
        entry.pqc_vulnerable = pqc.as<bool>();
    } catch (const std::exception&) {
        throw std::runtime_error("taxonomy: entry '" + name +
                                 "' has a non-boolean 'pqc_vulnerable'");
    }

    if (const YAML::Node& replacement = node["replacement"]; replacement) {
        if (!replacement.IsScalar()) {
            throw std::runtime_error("taxonomy: entry '" + name +
                                     "' has a non-string 'replacement'");
        }
        entry.replacement = replacement.as<std::string>();
    }

    entry.min_secure_key_bits = read_optional_int(node, "min_secure_key_bits");
    entry.weak_curves = require_string_list(node, "weak_curves", name);

    return entry;
}

} // namespace

std::string normalize_key(std::string_view name) {
    const std::string lower = to_lower_trimmed(name);
    std::string key;
    key.reserve(lower.size());
    // Treat hyphens and underscores as separators so that common spellings of
    // the same algorithm normalize identically (e.g. "SHA-1", "SHA_1", "sha1").
    for (std::size_t i = 0; i < lower.size(); ++i) {
        if (lower[i] == '-' || lower[i] == '_') {
            continue;
        }
        key.push_back(lower[i]);
    }
    return key;
}

TaxonomyDB TaxonomyDB::load_from_string(std::string_view yaml_text) {
    TaxonomyDB db;

    YAML::Node root;
    try {
        root = YAML::Load(std::string(yaml_text));
    } catch (const YAML::Exception& e) {
        throw std::runtime_error("taxonomy: malformed YAML: " +
                                 std::string(e.what()));
    }

    // An empty document is tolerated as an empty taxonomy.
    if (!root.IsDefined() || root.IsNull()) {
        return db;
    }

    const YAML::Node& algorithms = root["algorithms"];
    if (!algorithms) {
        throw std::runtime_error(
            "taxonomy: document is missing the top-level 'algorithms' list");
    }
    if (!algorithms.IsSequence()) {
        throw std::runtime_error("taxonomy: 'algorithms' must be a list");
    }

    for (const auto& algo : algorithms) {
        if (!algo || !algo.IsMap()) {
            throw std::runtime_error(
                "taxonomy: each entry in 'algorithms' must be a mapping");
        }
        TaxonomyEntry entry = parse_entry(algo);

        // Insert by normalized key. Duplicates are allowed: the last
        // occurrence silently overwrites the previous one.
        db.entries_[normalize_key(entry.name)] = std::move(entry);
    }

    return db;
}

TaxonomyDB TaxonomyDB::load_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("taxonomy: cannot open file '" + path + "'");
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    if (file.bad()) {
        throw std::runtime_error("taxonomy: failed reading file '" + path + "'");
    }
    return load_from_string(buffer.str());
}

const TaxonomyEntry* TaxonomyDB::lookup(std::string_view name) const {
    const auto it = entries_.find(normalize_key(name));
    if (it == entries_.end()) {
        return nullptr;
    }
    return &it->second;
}

} // namespace ecdat
