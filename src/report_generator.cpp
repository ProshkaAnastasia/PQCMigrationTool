#include "pqc/report_generator.hpp"
#include <fstream>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
namespace pqc {
static std::string now_iso(){
    auto t=std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::ostringstream o; o<<std::put_time(std::gmtime(&t),"%Y-%m-%dT%H:%M:%SZ"); return o.str();
}
static std::string primitive_for(const std::string& alg){
    std::string a=alg; std::transform(a.begin(),a.end(),a.begin(),::tolower);
    // EVP abstraction-layer compound names ("RSA/EC/DH (EVP)", "RSA/EC (EVP)", …).
    // Parsed before individual checks to avoid the "rsa" substring firing first.
    if(a.find("(evp)")!=std::string::npos){
        if(a.find("ecdh")!=std::string::npos) return "ecdh"; // ECDH/DH (EVP)
        return "evp";  // RSA/EC/DH (EVP), RSA/EC (EVP)
    }
    // BIGNUM manual-arithmetic indicators
    if(a.find("bignum")!=std::string::npos) return "asymmetric_primitive";
    // Standard single-algorithm names
    if(a.find("rsa")!=std::string::npos)  return "rsa";
    if(a.find("ecdh")!=std::string::npos) return "ecdh";
    if(a.find("ecdsa")!=std::string::npos)return "ecdsa";
    if(a.find("ec")!=std::string::npos)   return "ecc";
    if(a.find("dh")!=std::string::npos)   return "dh";
    if(a.find("dsa")!=std::string::npos)  return "dsa";
    if(a.find("sha1")!=std::string::npos||a.find("sha-1")!=std::string::npos) return "sha1";
    if(a.find("sha256")!=std::string::npos||a.find("sha-256")!=std::string::npos) return "sha256";
    if(a.find("md5")!=std::string::npos)  return "md5";
    if(a.find("gost")!=std::string::npos) return "gost-r3410";
    return "unknown";
}
static std::string fn_for_cat(const std::string& cat){
    if(cat=="asymmetric_key_generation") return "keyGeneration";
    if(cat=="asymmetric_encryption")     return "keyEncapsulation";
    if(cat=="key_exchange")              return "keyAgreement";
    if(cat=="digital_signature")         return "sign";
    if(cat=="hash_function")             return "digest";
    if(cat=="asymmetric_primitive")      return "encryptAndDecrypt";
    return "other";
}
static int classical_sec(const std::string& alg, int /*key_bits*/){
    std::string a=alg; std::transform(a.begin(),a.end(),a.begin(),::tolower);
    if(a.find("rsa")!=std::string::npos)  return 112;
    if(a.find("ec")!=std::string::npos)   return 128;
    if(a.find("sha256")!=std::string::npos)return 128;
    if(a.find("sha1")!=std::string::npos) return 80;
    if(a.find("md5")!=std::string::npos)  return 64;
    return 0;
}
Cbom ReportGenerator::build_cbom(const std::vector<Finding>& findings, const ProjectInventory&) const {
    auto cbom=Cbom::create_new();
    int idx=0;
    for(auto& f:findings){
        CbomComponent c;
        c.bom_ref="finding-"+std::to_string(++idx);
        c.name=f.function_name;
        c.library_source=f.library;
        c.file_path=f.file_path;
        c.line_number=f.line_number;
        c.context_function=f.context_function;
        c.quantum_vulnerability=f.quantum_vulnerability;
        c.risk_score=f.base_risk_score;
        c.assetType=CbomAssetType::ALGORITHM;
        auto& ap=c.algorithmProperties;
        ap.primitive=primitive_for(f.algorithm);
        ap.cryptoFunctions=fn_for_cat(f.category);
        ap.classicalSecurityLevel=classical_sec(f.algorithm,0);
        // "conditional" findings are emitted only when a classical (vulnerable)
        // argument was detected, so treat them as fully broken (level 0).
        ap.quantumSecurityLevel=(f.quantum_vulnerability=="high"||
                                  f.quantum_vulnerability=="conditional"?0:
                                  f.quantum_vulnerability=="medium"?50:128);
        cbom.add_component(std::move(c));
    }
    return cbom;
}
nlohmann::json ReportGenerator::nist_compliance_section(const RiskReport& rr){
    nlohmann::json j;
    j["framework"]="NIST IR 8547 / NIST SP 800-131A Rev.2";
    j["readiness"]=rr.nist_readiness;
    j["migration_phases"]=nlohmann::json::array({
        {{"phase",1},{"name","Inventory cryptographic assets"},{"status","completed"},
         {"reference","NIST IR 8547 §4.1"}},
        {{"phase",2},{"name","Prioritize by risk"},{"status",rr.migration_plan.empty()?"completed":"in-progress"},
         {"reference","NIST IR 8547 §4.2"}},
        {{"phase",3},{"name","Develop migration plan"},{"status","completed"},
         {"reference","NIST IR 8547 §4.3"}},
        {{"phase",4},{"name","Execute migration"},{"status","pending"},
         {"reference","NIST IR 8547 §4.4"}},
        {{"phase",5},{"name","Verify and test"},{"status","pending"},
         {"reference","NIST IR 8547 §4.5"}}
    });
    j["recommended_algorithms"]=nlohmann::json::array({
        {{"standard","FIPS 203"},{"name","ML-KEM (CRYSTALS-Kyber)"},{"use","Key Encapsulation Mechanism"},
         {"nist_levels","1/3/5"}},
        {{"standard","FIPS 204"},{"name","ML-DSA (CRYSTALS-Dilithium)"},{"use","Digital Signature"},
         {"nist_levels","2/3/5"}},
        {{"standard","FIPS 205"},{"name","SLH-DSA (SPHINCS+)"},{"use","Digital Signature (stateless hash-based)"},
         {"nist_levels","1/3/5"}},
        {{"standard","draft FIPS 206"},{"name","FN-DSA (FALCON)"},{"use","Digital Signature (compact)"},
         {"nist_levels","1/5"}}
    });
    j["hybrid_mode_note"]="During transition, use hybrid key exchange: X25519+ML-KEM-768 and ECDSA+ML-DSA-65.";
    return j;
}
nlohmann::json ReportGenerator::tc26_compliance_section(const RiskReport& rr){
    nlohmann::json j;
    j["framework"]="ТК 26 Постквантовая криптография";
    j["readiness"]=rr.nist_readiness; // aligned with NIST readiness
    j["references"]=nlohmann::json::array({
        "ГОСТ Р 34.10-2012 — ЭЦП на эллиптических кривых (квантово-уязвим через ЗАДЛП)",
        "ГОСТ Р 34.11-2012 — Хеш-функция Стрибог (относительно стоек к квантовым атакам)",
        "ГОСТ Р 34.12-2015 — Блочный шифр (симметричный, стоек при размере ключа 256 бит)",
        "ТК 26: Рекомендации по применению постквантовых алгоритмов (в разработке)"
    });
    j["gost_vulnerabilities"]=nlohmann::json::array({
        {{"algorithm","ГОСТ Р 34.10-2012"},{"status","vulnerable"},
         {"reason","Алгоритм основан на задаче дискретного логарифмирования на эллиптических кривых (ЗАДЛП). Квантовый компьютер решает ЗАДЛП за полиномиальное время (алгоритм Шора)."},
         {"replacement","ML-DSA-65 или SLH-DSA (FIPS 204/205)"},
         {"transition","В переходный период: гибридная схема ГОСТ Р 34.10-2012 + ML-DSA-65"}},
        {{"algorithm","VKO ГОСТ Р 34.10-2012"},{"status","vulnerable"},
         {"reason","Протокол выработки общего ключа на основе ECDLP. Атака Шора применима."},
         {"replacement","ML-KEM-768 (FIPS 203)"},
         {"transition","Гибридный KEM: VKO + ML-KEM (КРФ от обоих shared secrets)"}}
    });
    j["transition_recommendation"]=
        "ТК 26 рекомендует гибридный подход в переходный период (2025–2030): "
        "применять классические алгоритмы (ГОСТ) совместно с постквантовыми (ML-KEM/ML-DSA), "
        "объединяя общие секреты через КРФ. Чистый постквантовый переход — цель после 2030 г.";
    return j;
}
void ReportGenerator::write_json(const std::string& path, const nlohmann::json& j) const {
    std::ofstream ofs(path);
    if(!ofs.is_open()) throw std::runtime_error("Cannot write to: " + path);
    ofs << j.dump(2);
}
void ReportGenerator::generate(const AppConfig& cfg, const ProjectInventory& inventory,
    const std::vector<Finding>& findings, const std::vector<CertInfo>& certs,
    const RiskReport& rr, const AnalysisMetrics* metrics) const {
    auto cbom=build_cbom(findings,inventory);
    write_json(cfg.cbom_output_path, cbom.to_json());
    std::cout<<"[OK] CBOM written: "<<cfg.cbom_output_path<<" ("<<findings.size()<<" components)\n";
    if(cfg.cbom_only) return;
    auto report=build_full_report(cfg,inventory,findings,certs,rr,cbom,metrics);
    write_json(cfg.output_path, report);
    std::cout<<"[OK] Report written: "<<cfg.output_path<<"\n";
    std::cout<<"\n=== Risk Summary ===\n";
    std::cout<<"  Overall risk      : "<<rr.overall_risk_score<<"/10\n";
    std::cout<<"  NIST readiness    : "<<rr.nist_readiness<<"\n";
    std::cout<<"  Critical findings : "<<rr.critical_count<<"\n";
    std::cout<<"  High findings     : "<<rr.high_count<<"\n";
    std::cout<<"  Medium findings   : "<<rr.medium_count<<"\n";
    std::cout<<"  Low findings      : "<<rr.low_count<<"\n";
    std::cout<<"  Certs analyzed    : "<<certs.size()<<"\n";
}
nlohmann::json ReportGenerator::build_full_report(const AppConfig& cfg,
    const ProjectInventory& inventory, const std::vector<Finding>& findings,
    const std::vector<CertInfo>& certs, const RiskReport& rr,
    const Cbom& cbom, const AnalysisMetrics* metrics) const {
    nlohmann::json j;
    j["generated_at"]=now_iso();
    j["tool"]={{"name","pqc-migration-tool"},{"version","2.0.0"},
        {"standards",{"NIST IR 8547","NIST FIPS 203","NIST FIPS 204","NIST FIPS 205","ТК 26"}}};
    j["analysis_mode"]=cfg.analysis_mode==AnalysisMode::STATIC_AST?"ast":"regex";
    j["source_path"]=cfg.source_path;
    j["project_inventory"]=inventory.to_cbom_metadata();
    nlohmann::json fa=nlohmann::json::array();
    for(auto& f:findings){
        fa.push_back({{"file_path",f.file_path},{"line",f.line_number},{"col",f.column},
            {"function",f.function_name},{"library",f.library},{"algorithm",f.algorithm},
            {"category",f.category},{"quantum_vulnerability",f.quantum_vulnerability},
            {"base_risk_score",f.base_risk_score},{"analyzer_mode",f.analyzer_mode},
            {"context_function",f.context_function},{"context_class",f.context_class},
            {"context_namespace",f.context_namespace},{"raw_line",f.raw_line},
            {"arguments",f.arguments},{"nist_reference",f.nist_reference},
            {"tc26_reference",f.tc26_reference}});
    }
    j["findings"]=fa; j["findings_count"]=(int)findings.size();
    nlohmann::json ca; ca["count"]=(int)certs.size();
    nlohmann::json cv=nlohmann::json::array(); for(auto& c:certs) cv.push_back(c.to_json()); ca["certificates"]=cv;
    j["certificate_analysis"]=ca;
    j["risk_assessment"]=rr.to_json();
    j["nist_compliance"]=nist_compliance_section(rr);
    j["tc26_compliance"]=tc26_compliance_section(rr);
    j["cbom_output_path"]=cfg.cbom_output_path;
    if(metrics) j["analysis_metrics"]=metrics->to_json();
    return j;
}
} // namespace pqc
