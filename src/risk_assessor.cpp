#include "pqc/risk_assessor.hpp"
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iostream>
namespace pqc {
std::string priority_str(MigrationPriority p){
    switch(p){
    case MigrationPriority::CRITICAL:return "critical";
    case MigrationPriority::HIGH:    return "high";
    case MigrationPriority::MEDIUM:  return "medium";
    default:                         return "low";
    }
}
RiskAssessor::RiskAssessor(const VulnDatabase& db) : db_(db) {}
bool RiskAssessor::is_network_file(const std::string& p){
    static const std::vector<std::string> kw={"socket","network","tls","ssl","http","client","server","conn","tcp","udp","net","proto","transport","rpc"};
    std::string lp=p; std::transform(lp.begin(),lp.end(),lp.begin(),::tolower);
    for(auto& k:kw) if(lp.find(k)!=std::string::npos) return true; return false;
}
bool RiskAssessor::is_test_file(const std::string& p){
    std::string lp=p; std::transform(lp.begin(),lp.end(),lp.begin(),::tolower);
    return lp.find("/test")!=std::string::npos||lp.find("_test.")!=std::string::npos||
           lp.find("test_")!=std::string::npos||lp.find("/mock")!=std::string::npos;
}
bool RiskAssessor::is_persistence_file(const std::string& p){
    static const std::vector<std::string> kw={"store","storage","db","database","persist","save","file","disk","cache","repo","serial","archive"};
    std::string lp=p; std::transform(lp.begin(),lp.end(),lp.begin(),::tolower);
    for(auto& k:kw) if(lp.find(k)!=std::string::npos) return true; return false;
}
int RiskAssessor::estimate_frequency(const Finding& f, const ProjectInventory& inv){
    int freq=1;
    for(auto* fe:inv.get_source_files()){
        if(fe->path.string()==f.file_path) freq+=fe->line_count/300;
    }
    return std::max(1,freq);
}
ContextFactors RiskAssessor::analyze_context(const Finding& f, const ProjectInventory& inv) const {
    ContextFactors ctx;
    ctx.is_test_code       = is_test_file(f.file_path);
    ctx.is_network_facing  = !ctx.is_test_code && is_network_file(f.file_path);
    ctx.is_persistent_data = !ctx.is_test_code && is_persistence_file(f.file_path);
    // Key material: keygen functions or "key" in calling function name
    std::string fn_lower=f.context_function;
    std::transform(fn_lower.begin(),fn_lower.end(),fn_lower.begin(),::tolower);
    ctx.is_key_material = (f.category=="asymmetric_key_generation"||
                           f.category=="key_exchange"||
                           fn_lower.find("key")!=std::string::npos);
    // In-loop: raw line contains for/while, or repeat patterns
    ctx.is_in_loop = (f.raw_line.find("for")!=std::string::npos ||
                      f.raw_line.find("while")!=std::string::npos);
    ctx.call_frequency = estimate_frequency(f,inv);
    // Data classification
    if(ctx.is_key_material) ctx.data_classification="key_material";
    else if(ctx.is_persistent_data) ctx.data_classification="long_term_data";
    else if(ctx.is_network_facing)  ctx.data_classification="session";
    else ctx.data_classification="arbitrary";
    return ctx;
}
RiskScore RiskAssessor::compute_risk(const Finding& f, const ContextFactors& ctx) const {
    RiskScore rs;
    rs.base_score = f.base_risk_score;
    double mult = 1.0;
    std::ostringstream oss;
    oss<<"Base: "<<f.base_risk_score<<" ("<<f.algorithm<<"/"<<f.library<<").";
    if(ctx.is_test_code)        { mult*=0.4;  oss<<" TestCode(x0.4)."; }
    if(ctx.is_network_facing)   { mult*=1.3;  oss<<" NetworkFacing(+30%)."; }
    if(ctx.is_persistent_data)  { mult*=1.25; oss<<" PersistentData(+25%)."; }
    if(ctx.is_key_material)     { mult*=1.2;  oss<<" KeyMaterial(+20%)."; }
    if(ctx.is_in_loop)          { mult*=1.1;  oss<<" InLoop(+10%)."; }
    if(ctx.call_frequency>5)    { mult*=1.1;  oss<<" HighFreq(+10%)."; }
    oss<<" DataClass: "<<ctx.data_classification<<".";
    // HNDL note for encryption/key exchange
    if(f.category=="asymmetric_encryption"||f.category=="key_exchange"){
        if(ctx.is_network_facing||ctx.is_persistent_data) oss<<" [HNDL-risk].";
    }
    rs.context_multiplier = mult;
    rs.final_score = std::min(10.0, rs.base_score * mult);
    rs.rationale   = oss.str();
    if(rs.final_score>=9.0)      rs.priority=MigrationPriority::CRITICAL;
    else if(rs.final_score>=7.0) rs.priority=MigrationPriority::HIGH;
    else if(rs.final_score>=5.0) rs.priority=MigrationPriority::MEDIUM;
    else                         rs.priority=MigrationPriority::LOW;
    rs.factors=ctx;
    return rs;
}
MigrationAction RiskAssessor::build_action(const Finding& f, const RiskScore& rs, int order) const {
    MigrationAction a;
    a.finding_id   = f.vuln_id+"@"+f.file_path+":"+std::to_string(f.line_number);
    a.file_path    = f.file_path;
    a.line_number  = f.line_number;
    a.current_function = f.function_name;
    a.current_library  = f.library;
    a.nist_reference   = f.nist_reference;
    a.tc26_note        = f.tc26_reference;
    a.risk         = rs;
    a.priority     = rs.priority;
    a.migration_order = order;
    auto opt=db_.find_by_name(f.function_name);
    if(opt&&!opt->replacements.empty()){
        auto& rep=opt->replacements[0];
        a.replacement_function  = rep.function_name;
        a.replacement_library   = rep.library;
        a.replacement_standard  = rep.standard;
        a.replacement_algorithm = rep.algorithm;
        a.replacement_type      = rep.type;
        a.migration_notes       = rep.migration_notes;
        a.example_code          = rep.example_code;
        if(a.tc26_note.empty()&&!rep.tc26_note.empty()) a.tc26_note=rep.tc26_note;
    }
    return a;
}
RiskReport RiskAssessor::assess(const std::vector<Finding>& findings,
                                 const ProjectInventory& inv,
                                 const std::vector<CertInfo>& certs) const {
    RiskReport report;
    std::vector<std::pair<MigrationAction,double>> actions_with_score;
    for(auto& f:findings){
        auto ctx = analyze_context(f,inv);
        auto rs  = compute_risk(f,ctx);
        int order = (int)actions_with_score.size()+1;
        auto a   = build_action(f,rs,order);
        actions_with_score.push_back({a,rs.final_score});
    }
    // Sort by risk descending
    std::sort(actions_with_score.begin(),actions_with_score.end(),
              [](auto& a,auto& b){ return a.second>b.second; });
    // Renumber
    for(int i=0;i<(int)actions_with_score.size();++i)
        actions_with_score[i].first.migration_order=i+1;
    for(auto& [a,_]:actions_with_score) report.migration_plan.push_back(a);
    // Count by priority
    for(auto& a:report.migration_plan){
        switch(a.priority){
        case MigrationPriority::CRITICAL: ++report.critical_count; break;
        case MigrationPriority::HIGH:     ++report.high_count; break;
        case MigrationPriority::MEDIUM:   ++report.medium_count; break;
        default:                          ++report.low_count; break;
        }
    }
    // Per-file aggregation (ТЗ: агрегатор оценок по файлам)
    for(auto& a:report.migration_plan){
        auto& fs=report.file_summaries[a.file_path];
        fs.file_path=a.file_path;
        ++fs.finding_count;
        fs.max_score=std::max(fs.max_score,a.risk.final_score);
        fs.avg_score=(fs.avg_score*(fs.finding_count-1)+a.risk.final_score)/fs.finding_count;
        fs.function_names.push_back(a.current_function);
        if(a.risk.final_score>=9.0) fs.overall_priority=MigrationPriority::CRITICAL;
        else if(a.risk.final_score>=7.0 && fs.overall_priority<MigrationPriority::HIGH)
            fs.overall_priority=MigrationPriority::HIGH;
    }
    // Overall risk (top-10 average + cert influence)
    double sum=0; int cnt=0;
    for(auto& a:report.migration_plan){ sum+=a.risk.final_score; if(++cnt>=10) break; }
    report.overall_risk_score = cnt>0 ? sum/cnt : 0.0;
    // Cert risk influence (30% weight)
    if(!certs.empty()){
        double maxCert=0;
        for(auto& c:certs) maxCert=std::max(maxCert,c.risk_score);
        report.overall_risk_score=std::min(10.0,report.overall_risk_score*0.7+maxCert*0.3);
    }
    // NIST readiness
    if(findings.empty()&&certs.empty()) report.nist_readiness="compliant";
    else if(report.critical_count>0||report.high_count>3) report.nist_readiness="not-started";
    else if(report.high_count>0||report.medium_count>5)   report.nist_readiness="in-progress";
    else report.nist_readiness="near-compliant";
    return report;
}
nlohmann::json FileRiskSummary::to_json() const {
    nlohmann::json j;
    j["file_path"]=file_path; j["finding_count"]=finding_count;
    j["max_risk_score"]=max_score; j["avg_risk_score"]=avg_score;
    j["overall_priority"]=priority_str(overall_priority);
    j["functions"]=function_names; return j;
}
nlohmann::json RiskReport::to_json() const {
    nlohmann::json j;
    j["overall_risk_score"]=overall_risk_score;
    j["nist_readiness"]=nist_readiness;
    j["summary"]={{"critical",critical_count},{"high",high_count},
                  {"medium",medium_count},{"low",low_count}};
    nlohmann::json mp=nlohmann::json::array();
    for(auto& a:migration_plan){
        nlohmann::json aj;
        aj["migration_order"]=a.migration_order;
        aj["priority"]=priority_str(a.priority);
        aj["file_path"]=a.file_path; aj["line_number"]=a.line_number;
        aj["current_function"]=a.current_function; aj["current_library"]=a.current_library;
        aj["replacement"]={{"function",a.replacement_function},{"library",a.replacement_library},
            {"standard",a.replacement_standard},{"algorithm",a.replacement_algorithm},
            {"type",a.replacement_type}};
        aj["example_code"]=a.example_code; aj["migration_notes"]=a.migration_notes;
        aj["nist_reference"]=a.nist_reference; aj["tc26_note"]=a.tc26_note;
        aj["risk"]={{"base_score",a.risk.base_score},{"context_multiplier",a.risk.context_multiplier},
            {"final_score",a.risk.final_score},{"rationale",a.risk.rationale}};
        aj["context"]={{"function",a.risk.factors.data_classification},
            {"network_facing",a.risk.factors.is_network_facing},
            {"persistent_data",a.risk.factors.is_persistent_data},
            {"key_material",a.risk.factors.is_key_material},
            {"test_code",a.risk.factors.is_test_code}};
        mp.push_back(aj);
    }
    j["migration_plan"]=mp;
    nlohmann::json fs_j=nlohmann::json::object();
    for(auto& [k,v]:file_summaries) fs_j[k]=v.to_json();
    j["file_risk_summaries"]=fs_j;
    return j;
}
} // namespace pqc
