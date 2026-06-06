#include "pqc/regex_analyzer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <set>

namespace pqc {

RegexAnalyzer::RegexAnalyzer(const VulnDatabase& db) : db_(db)
{
    compile_patterns();
}

void RegexAnalyzer::compile_patterns()
{
    for (auto& fn : db_.all()) {
        for (auto& pat : fn.patterns) {
            try {
                patterns_.push_back({std::regex(pat, std::regex_constants::ECMAScript), &fn});
            } catch (std::exception& e) {
                std::cerr << "[WARN] Bad regex '" << pat << "': " << e.what() << "\n";
            }
        }
        auto add_name_pattern = [&](const std::string& name) {
            try {
                std::string p = "\\b" + name + "\\s*\\(";
                patterns_.push_back({std::regex(p, std::regex_constants::ECMAScript), &fn});
            } catch (...) {
            }
        };
        add_name_pattern(fn.name);
        for (const auto& alias : fn.aliases)
            add_name_pattern(alias);
    }
}

std::string RegexAnalyzer::extract_context_function(const std::vector<std::string>& lines, int idx)
{
    for (int i = idx; i >= 0 && i > idx - 80; --i) {
        const auto& l = lines[i];
        auto pos = l.find('(');
        if (pos == std::string::npos) {
            continue;
        }
        if (l.find(';') != std::string::npos && l.find(';') < pos) {
            continue;
        }
        if (l.find("if(") != std::string::npos || l.find("if (") != std::string::npos) {
            continue;
        }
        if (l.find("for(") != std::string::npos || l.find("for (") != std::string::npos) {
            continue;
        }
        if (l.find("while(") != std::string::npos || l.find("while (") != std::string::npos) {
            continue;
        }

        size_t ep = pos;
        while (ep > 0 && std::isspace((unsigned char)l[ep - 1])) {
            --ep;
        }
        if (ep == 0) {
            continue;
        }

        size_t sp = ep;
        while (sp > 0 && (std::isalnum((unsigned char)l[sp - 1]) || l[sp - 1] == '_')) {
            --sp;
        }

        std::string name = l.substr(sp, ep - sp);
        if (name.size() >= 2) {
            return name;
        }
    }
    return "<global>";
}

std::vector<Finding> RegexAnalyzer::analyze_file(const std::filesystem::path& p) const
{
    std::ifstream ifs(p);
    if (!ifs.is_open())
        return {};

    std::vector<std::string> lines;
    std::string l;
    while (std::getline(ifs, l)) {
        lines.push_back(l);
    }

    std::vector<Finding> findings;
    std::set<std::pair<std::string, int>> seen;

    bool in_block_comment = false;
    for (int li = 0; li < (int)lines.size(); ++li) {
        const auto& line = lines[li];

        std::string stripped;
        stripped.reserve(line.size());
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (in_block_comment) {
                if (i + 1 < line.size() && line[i] == '*' && line[i + 1] == '/') {
                    in_block_comment = false;
                    ++i;  // skip '/'
                }
                stripped += ' ';
            } else {
                if (i + 1 < line.size() && line[i] == '/' && line[i + 1] == '*') {
                    in_block_comment = true;
                    stripped += ' ';
                    ++i;  // skip '*'
                } else if (i + 1 < line.size() && line[i] == '/' && line[i + 1] == '/') {
                    break;
                } else {
                    stripped += line[i];
                }
            }
        }

        bool all_space = true;
        for (char c : stripped)
            if (!std::isspace((unsigned char)c)) {
                all_space = false;
                break;
            }
        if (all_space)
            continue;

        for (auto& cp : patterns_) {
            std::sregex_iterator rit(stripped.begin(), stripped.end(), cp.re);
            std::sregex_iterator rend;

            while (rit != rend) {
                auto match = *rit;
                int col = (int)match.position() + 1;
                auto key = std::make_pair(cp.func->name, li + 1);

                if (!seen.count(key)) {
                    seen.insert(key);

                    std::string actual_name;
                    std::string ms = match.str();
                    for (char c : ms) {
                        if (c == '(' || std::isspace((unsigned char)c))
                            break;
                        actual_name += c;
                    }
                    if (actual_name.empty())
                        actual_name = cp.func->name;

                    Finding f;
                    f.function_name = actual_name;
                    f.file_path = p.string();
                    f.line_number = li + 1;
                    f.column = col;
                    f.library = cp.func->library_name;
                    f.algorithm = cp.func->algorithm;
                    f.category = cp.func->category;
                    f.quantum_vulnerability = cp.func->quantum_vulnerability;
                    f.base_risk_score = cp.func->risk_score;
                    f.analyzer_mode = "regex";
                    f.vuln_id = cp.func->id;
                    f.nist_reference = cp.func->nist_reference;
                    f.tc26_reference = cp.func->tc26_reference;
                    f.raw_line = line;
                    f.context_function = extract_context_function(lines, li);

                    findings.push_back(f);
                }
                ++rit;
            }
        }
    }
    return findings;
}

std::vector<Finding> RegexAnalyzer::analyze(const ProjectInventory& inv) const
{
    std::vector<Finding> all;

    for (auto* fe : inv.get_source_files()) {
        auto r = analyze_file(fe->path);
        all.insert(all.end(), r.begin(), r.end());
    }

    return all;
}

}  // namespace pqc
