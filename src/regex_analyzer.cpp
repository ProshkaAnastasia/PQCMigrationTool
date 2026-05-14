#include "pqc/regex_analyzer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <set>

namespace pqc {
RegexAnalyzer::RegexAnalyzer(const VulnDatabase& db) : db_(db){ compile_patterns(); }
void RegexAnalyzer::compile_patterns(){
    for(auto& fn:db_.all()){
        for(auto& pat:fn.patterns){
            try { patterns_.push_back({std::regex(pat, std::regex_constants::ECMAScript), &fn}); }
            catch(std::exception& e){ std::cerr<<"[WARN] Bad regex '"<<pat<<"': "<<e.what()<<"\n"; }
        }
        // Always add plain function name pattern as fallback
        try { std::string p="\\b"+fn.name+"\\s*\\(";
              patterns_.push_back({std::regex(p, std::regex_constants::ECMAScript), &fn}); }
        catch(...) {}
    }
}
std::string RegexAnalyzer::extract_context_function(const std::vector<std::string>& lines, int idx){
    for(int i=idx;i>=0&&i>idx-80;--i){
        const auto& l=lines[i];
        // Look for: rettype funcname(  without ; at end (definition)
        auto pos=l.find('(');
        if(pos==std::string::npos) continue;
        if(l.find(';')!=std::string::npos&&l.find(';')<pos) continue;
        if(l.find("if(")!=std::string::npos||l.find("if (")!=std::string::npos) continue;
        if(l.find("for(")!=std::string::npos||l.find("for (")!=std::string::npos) continue;
        if(l.find("while(")!=std::string::npos||l.find("while (")!=std::string::npos) continue;
        // extract identifier before (
        size_t ep=pos; while(ep>0&&std::isspace((unsigned char)l[ep-1])) --ep;
        if(ep==0) continue;
        size_t sp=ep;
        while(sp>0&&(std::isalnum((unsigned char)l[sp-1])||l[sp-1]=='_')) --sp;
        std::string name=l.substr(sp,ep-sp);
        if(name.size()>=2) return name;
    }
    return "<global>";
}
std::vector<Finding> RegexAnalyzer::analyze_file(const std::filesystem::path& p) const {
    std::ifstream ifs(p); if(!ifs.is_open()) return {};
    std::vector<std::string> lines; std::string l;
    while(std::getline(ifs,l)) lines.push_back(l);
    std::vector<Finding> findings;
    std::set<std::pair<std::string,int>> seen; // deduplicate by (name, line)
    for(int li=0;li<(int)lines.size();++li){
        const auto& line=lines[li];
        // Skip full-line comments
        std::string trimmed=line; auto it=trimmed.begin();
        while(it!=trimmed.end()&&std::isspace((unsigned char)*it)) ++it;
        if(it!=trimmed.end()&&*it=='/'&&(it+1)!=trimmed.end()&&*(it+1)=='/') continue;
        for(auto& cp:patterns_){
            std::sregex_iterator rit(line.begin(),line.end(),cp.re);
            std::sregex_iterator rend;
            while(rit!=rend){
                auto match=*rit;
                int col=(int)match.position()+1;
                auto key=std::make_pair(cp.func->name,li+1);
                if(!seen.count(key)){
                    seen.insert(key);
                    Finding f;
                    f.function_name=cp.func->name; f.file_path=p.string();
                    f.line_number=li+1; f.column=col;
                    f.library=cp.func->library_name; f.algorithm=cp.func->algorithm;
                    f.category=cp.func->category; f.quantum_vulnerability=cp.func->quantum_vulnerability;
                    f.base_risk_score=cp.func->risk_score; f.analyzer_mode="regex";
                    f.vuln_id=cp.func->id; f.nist_reference=cp.func->nist_reference;
                    f.tc26_reference=cp.func->tc26_reference;
                    f.raw_line=line;
                    f.context_function=extract_context_function(lines,li);
                    findings.push_back(f);
                }
                ++rit;
            }
        }
    }
    return findings;
}
std::vector<Finding> RegexAnalyzer::analyze(const ProjectInventory& inv) const {
    std::vector<Finding> all;
    for(auto* fe:inv.get_source_files()){
        auto r=analyze_file(fe->path);
        all.insert(all.end(),r.begin(),r.end());
    }
    return all;
}
} // namespace pqc
