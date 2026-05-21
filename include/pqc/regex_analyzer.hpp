#pragma once
#include "pqc/code_analyzer.hpp"
#include <regex>
namespace pqc {
class RegexAnalyzer : public ICodeAnalyzer {
public:
    explicit RegexAnalyzer(const VulnDatabase& db);
    std::string mode_name() const override { return "regex"; }
    std::vector<Finding> analyze(const ProjectInventory& inv) const override;
    std::vector<Finding> analyze_file(const std::filesystem::path& p) const override;

private:
    struct CompiledPattern {
        std::regex re;
        const VulnerableFunction* func;
    };
    const VulnDatabase& db_;
    std::vector<CompiledPattern> patterns_;
    void compile_patterns();
    static std::string extract_context_function(const std::vector<std::string>& lines, int idx);
};
}  // namespace pqc
