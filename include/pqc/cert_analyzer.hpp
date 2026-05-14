#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
namespace pqc {
enum class CertQuantumRisk { HIGH, MEDIUM, LOW, UNKNOWN };
std::string cert_quantum_risk_str(CertQuantumRisk r);
struct CertInfo {
    std::string file_path, subject, issuer, serial_number;
    std::string not_before, not_after, sig_algorithm, public_key_algorithm;
    int key_size_bits=0;
    CertQuantumRisk quantum_risk=CertQuantumRisk::UNKNOWN;
    std::string risk_explanation, tc26_note;
    bool is_expired=false, is_self_signed=false;
    double risk_score=0.0;
    nlohmann::json to_json() const;
};
class CertAnalyzer {
public:
    std::vector<CertInfo> analyze(const std::string& path) const;
    static CertQuantumRisk assess_algorithm(const std::string& alg, int key_bits);
    static double compute_cert_risk(CertQuantumRisk qr, int key_bits, bool expired, const std::string& alg);
private:
    std::vector<CertInfo> analyze_file(const std::string& fp) const;
};
} // namespace pqc
