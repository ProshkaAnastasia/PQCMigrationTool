#pragma once
#include "pqc/config.hpp"
#include "pqc/project_scanner.hpp"
#include "pqc/code_analyzer.hpp"
#include "pqc/cert_analyzer.hpp"
#include "pqc/risk_assessor.hpp"
#include "pqc/metrics.hpp"
#include "pqc/cbom.hpp"
#include <nlohmann/json.hpp>
namespace pqc {
class ReportGenerator {
public:
    void generate(const AppConfig& cfg, const ProjectInventory& inv,
                  const std::vector<Finding>& findings, const std::vector<CertInfo>& certs,
                  const RiskReport& rr, const AnalysisMetrics* metrics = nullptr) const;

private:
    Cbom build_cbom(const std::vector<Finding>& findings, const ProjectInventory&) const;
    nlohmann::json build_full_report(const AppConfig&, const ProjectInventory&,
                                     const std::vector<Finding>&, const std::vector<CertInfo>&,
                                     const RiskReport&, const Cbom&, const AnalysisMetrics*) const;
    void write_json(const std::string& path, const nlohmann::json& j) const;
    static std::string now_iso8601();
    static nlohmann::json nist_compliance_section(const RiskReport&);
    static nlohmann::json tc26_compliance_section(const RiskReport&);
};
}  // namespace pqc
