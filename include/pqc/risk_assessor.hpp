#pragma once
#include "pqc/code_analyzer.hpp"
#include "pqc/cert_analyzer.hpp"
#include "pqc/vuln_database.hpp"
#include "pqc/project_scanner.hpp"
#include <nlohmann/json.hpp>
#include <map>
namespace pqc {
enum class MigrationPriority { CRITICAL, HIGH, MEDIUM, LOW };
std::string priority_str(MigrationPriority p);
struct ContextFactors {
    bool is_network_facing = false, is_persistent_data = false;
    bool is_key_material = false, is_in_loop = false, is_test_code = false;
    int call_frequency = 1;
    std::string data_classification;
};
struct RiskScore {
    double base_score = 0, context_multiplier = 1, final_score = 0;
    MigrationPriority priority = MigrationPriority::LOW;
    ContextFactors factors;
    std::string rationale;
};
struct MigrationAction {
    std::string finding_id, file_path;
    int line_number = 0;
    std::string current_function, current_library;
    std::string replacement_function, replacement_library;
    std::string replacement_standard, replacement_algorithm, replacement_type;
    std::string migration_notes, example_code, nist_reference, tc26_note;
    RiskScore risk;
    MigrationPriority priority;
    int migration_order = 0;
};
struct FileRiskSummary {
    std::string file_path;
    int finding_count = 0;
    double max_score = 0, avg_score = 0;
    MigrationPriority overall_priority = MigrationPriority::LOW;
    std::vector<std::string> function_names;
    nlohmann::json to_json() const;
};
struct RiskReport {
    double overall_risk_score = 0;
    int critical_count = 0, high_count = 0, medium_count = 0, low_count = 0;
    std::vector<MigrationAction> migration_plan;
    std::map<std::string, FileRiskSummary> file_summaries;
    std::string nist_readiness;
    nlohmann::json to_json() const;
};
class RiskAssessor {
public:
    explicit RiskAssessor(const VulnDatabase& db);
    RiskReport assess(const std::vector<Finding>& findings, const ProjectInventory& inv,
                      const std::vector<CertInfo>& certs = {}) const;

private:
    const VulnDatabase& db_;
    ContextFactors analyze_context(const Finding& f, const ProjectInventory& inv) const;
    RiskScore compute_risk(const Finding& f, const ContextFactors& ctx) const;
    MigrationAction build_action(const Finding& f, const RiskScore& rs, int order) const;
    static bool is_network_file(const std::string& p);
    static bool is_test_file(const std::string& p);
    static bool is_persistence_file(const std::string& p);
    static int estimate_frequency(const Finding& f, const ProjectInventory& inv);
};
}  // namespace pqc
