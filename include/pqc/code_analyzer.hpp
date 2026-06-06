#pragma once
#include "pqc/vuln_database.hpp"
#include "pqc/project_scanner.hpp"
#include <string>
#include <vector>
#include <filesystem>
namespace pqc {
struct Finding {
    std::string file_path, function_name, library, algorithm, category;
    std::string quantum_vulnerability, context_function, context_class, context_namespace;
    std::string raw_line, analyzer_mode, vuln_id, nist_reference, tc26_reference;
    int line_number = 0, column = 0;
    double base_risk_score = 0.0;
    std::vector<std::string> arguments;
    std::vector<std::string> nested_vulnerable_calls;
};
class ICodeAnalyzer {
public:
    virtual ~ICodeAnalyzer() = default;
    virtual std::string mode_name() const = 0;
    virtual std::vector<Finding> analyze(const ProjectInventory& inv) const = 0;
    virtual std::vector<Finding> analyze_file(const std::filesystem::path& p) const = 0;
};
}  // namespace pqc
