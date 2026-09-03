#include "source_scanner.hpp"
#include <tree_sitter/api.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <set>

extern "C" TSLanguage* tree_sitter_python();

static const std::set<std::string> WEAK_CALLS = {"md5", "sha1", "des", "rc4"};

static std::string read_file(const std::string& path) {
    std::ifstream f(path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static void walk(TSNode node, const std::string& src, const std::string& filepath,
                  std::vector<ecdat::CryptoAsset>& out) {
    if (ts_node_type(node) == std::string("call")) {
        TSNode func = ts_node_child_by_field_name(node, "function", 8);
        if (!ts_node_is_null(func)) {
            uint32_t s = ts_node_start_byte(func), e = ts_node_end_byte(func);
            std::string call_text = src.substr(s, e - s);
            for (const auto& weak : WEAK_CALLS) {
                if (call_text.find(weak) != std::string::npos) {
                    ecdat::CryptoAsset a;
                    a.source_type = "source_code";
                    a.file = filepath;
                    a.line = ts_node_start_point(node).row + 1;
                    a.algorithm = weak;
                    uint32_t ls = ts_node_start_byte(node), le = ts_node_end_byte(node);
                    a.context = src.substr(ls, le - ls);
                    out.push_back(a);
                }
            }
        }
    }
    uint32_t n = ts_node_child_count(node);
    for (uint32_t i = 0; i < n; i++) walk(ts_node_child(node, i), src, filepath, out);
}

std::vector<ecdat::CryptoAsset> scan_source_file(const std::string& filepath) {
    std::vector<ecdat::CryptoAsset> results;
    std::string src = read_file(filepath);
    if (src.empty()) {
        std::cerr << "Could not read file: " << filepath << "\n";
        return results;
    }
    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_python());
    TSTree* tree = ts_parser_parse_string(parser, nullptr, src.c_str(), src.size());
    walk(ts_tree_root_node(tree), src, filepath, results);
    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return results;
}
