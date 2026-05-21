#pragma once
#include "pqc/code_analyzer.hpp"
namespace pqc {
class TokenAnalyzer : public ICodeAnalyzer {
public:
    explicit TokenAnalyzer(const VulnDatabase& db);
    std::string mode_name() const override { return "token"; }
    std::vector<Finding> analyze(const ProjectInventory& inv) const override;
    std::vector<Finding> analyze_file(const std::filesystem::path& p) const override;

private:
    const VulnDatabase& db_;
    static std::string strip_comments(const std::string& src);
    static std::string strip_strings(const std::string& src);
    enum class TokType { IDENT, PUNCT, NUMBER, END };
    struct Token {
        TokType type;
        std::string val;
        int line, col;
    };
    static std::vector<Token> tokenize(const std::string& s);
    std::vector<Finding> extract_findings(const std::vector<Token>& toks, const std::string& fpath,
                                          const std::vector<std::string>& lines) const;
    std::string extract_call_args(const std::vector<Token>& toks, size_t sp) const;
};
}  // namespace pqc
