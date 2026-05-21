#pragma once
#include "pqc/code_analyzer.hpp"
#include "pqc/token_analyzer.hpp"
#include <memory>
namespace pqc {
class ASTAnalyzer : public ICodeAnalyzer {
public:
    explicit ASTAnalyzer(const VulnDatabase& db);
    ~ASTAnalyzer();
    std::string mode_name() const override { return "ast"; }
    std::vector<Finding> analyze(const ProjectInventory& inv) const override;
    std::vector<Finding> analyze_file(const std::filesystem::path& p) const override;
    bool has_libclang() const { return has_libclang_; }
    void set_include_dirs(const std::vector<std::string>& dirs);

private:
    const VulnDatabase& db_;
    std::unique_ptr<TokenAnalyzer> fallback_;
    std::vector<std::string> include_dirs_;
    bool has_libclang_ = false;
#ifdef PQC_HAS_LIBCLANG
    bool try_libclang(const std::filesystem::path& path, std::vector<Finding>& out) const;
#endif
};
}  // namespace pqc
