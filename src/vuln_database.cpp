#include "pqc/vuln_database.hpp"
#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <iostream>
namespace pqc {
std::string VulnDatabase::to_lower(std::string s){
    std::transform(s.begin(),s.end(),s.begin(),::tolower); return s;
}
void VulnDatabase::rebuild_index(){
    name_index_.clear();
    for(size_t i=0;i<functions_.size();++i){
        name_index_[to_lower(functions_[i].name)]=i;
        for(auto& a:functions_[i].aliases) name_index_[to_lower(a)]=i;
    }
}
void VulnDatabase::load(const std::string& path){
    std::ifstream ifs(path);
    if(!ifs.is_open()) throw std::runtime_error("Cannot open vulnerability database: "+path);
    nlohmann::json j; ifs>>j; merge_json(j);
}
void VulnDatabase::merge_json(const nlohmann::json& j){
    if(j.contains("version") && version_.empty()) version_=j["version"].get<std::string>();
    if(j.contains("last_updated") && last_updated_.empty()) last_updated_=j["last_updated"].get<std::string>();
    auto& libs=j["libraries"];
    for(auto it=libs.begin();it!=libs.end();++it){
        std::string lib_name=it.key();
        auto& lib=it.value();
        auto& fns=lib["functions"];
        for(auto& fn:fns){
            VulnerableFunction vf;
            vf.id=fn.value("id","");
            vf.name=fn.value("name","");
            if(vf.name.empty()) continue;
            vf.library_name=lib_name;
            vf.category=fn.value("category","");
            vf.algorithm=fn.value("algorithm","");
            vf.quantum_vulnerability=fn.value("quantum_vulnerability","high");
            vf.risk_score=fn.value("risk_score",8.0);
            vf.description=fn.value("description","");
            vf.nist_reference=fn.value("nist_reference","");
            vf.tc26_reference=fn.value("tc26_reference","");
            vf.deprecation_url=fn.value("deprecation_url","");
            if(fn.contains("aliases")) for(auto& a:fn["aliases"]) vf.aliases.push_back(a.get<std::string>());
            if(fn.contains("patterns")) for(auto& p:fn["patterns"]) vf.patterns.push_back(p.get<std::string>());
            if(fn.contains("context_keywords")) for(auto& k:fn["context_keywords"]) vf.context_keywords.push_back(k.get<std::string>());
            if(fn.contains("replacements")){
                for(auto& rep:fn["replacements"]){
                    ReplacementInfo ri;
                    // Accept both new canonical field names and legacy aliases.
                    ri.function_name = rep.contains("function_name") ? rep.value("function_name","")
                                                                      : rep.value("function","");
                    ri.library       = rep.value("library","");
                    ri.standard      = rep.value("standard","");
                    ri.algorithm     = rep.value("algorithm","");
                    ri.type          = rep.value("type","");
                    ri.migration_notes = rep.contains("migration_notes") ? rep.value("migration_notes","")
                                                                         : rep.value("notes","");
                    ri.example_code  = rep.value("example_code","");
                    ri.tc26_note     = rep.value("tc26_note","");
                    vf.replacements.push_back(ri);
                }
            }
            // Update if exists (by name), else add
            auto it2=name_index_.find(to_lower(vf.name));
            if(it2!=name_index_.end()) functions_[it2->second]=vf;
            else functions_.push_back(vf);
        }
    }
    rebuild_index();
}
std::optional<VulnerableFunction> VulnDatabase::find_by_name(const std::string& name) const {
    auto it=name_index_.find(to_lower(name));
    if(it==name_index_.end()) return std::nullopt;
    return functions_[it->second];
}
std::vector<VulnerableFunction> VulnDatabase::by_library(const std::string& lib) const {
    std::vector<VulnerableFunction> r;
    for(auto& f:functions_) if(f.library_name==lib) r.push_back(f);
    return r;
}
} // namespace pqc
