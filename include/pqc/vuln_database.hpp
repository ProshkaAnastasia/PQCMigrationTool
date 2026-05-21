#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <nlohmann/json.hpp>
namespace pqc {
struct ReplacementInfo {
    std::string function_name, library, standard, algorithm, type, migration_notes, example_code,
        tc26_note;
};
struct VulnerableFunction {
    std::string id, name, category, algorithm, quantum_vulnerability, description;
    std::string nist_reference, tc26_reference, deprecation_url, library_name;
    double risk_score = 0.0;
    std::vector<std::string> aliases, patterns, context_keywords;
    std::vector<std::string> safe_argument_substrings;
    std::vector<std::string> dangerous_argument_substrings;
    bool match_arguments_case_insensitive = true;
    std::vector<ReplacementInfo> replacements;
};
class VulnDatabase {
public:
    void load(const std::string& path);
    void merge_json(const nlohmann::json& j);
    std::optional<VulnerableFunction> find_by_name(const std::string& name) const;
    const std::vector<VulnerableFunction>& all() const { return functions_; }
    std::vector<VulnerableFunction> by_library(const std::string& lib) const;
    std::string db_version() const { return version_; }
    std::string last_updated() const { return last_updated_; }
    size_t size() const { return functions_.size(); }

private:
    std::vector<VulnerableFunction> functions_;
    std::unordered_map<std::string, size_t> name_index_;
    std::string version_, last_updated_;
    void rebuild_index();
    static std::string to_lower(std::string s);
};
}  // namespace pqc
