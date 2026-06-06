#include "pqc/token_analyzer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
namespace pqc {
TokenAnalyzer::TokenAnalyzer(const VulnDatabase& db) : db_(db) {}
std::string TokenAnalyzer::strip_comments(const std::string& src)
{
    std::string r;
    r.reserve(src.size());
    size_t i = 0, n = src.size();
    while (i < n) {
        if (i + 1 < n && src[i] == '/' && src[i + 1] == '/') {
            while (i < n && src[i] != '\n') {
                r += ' ';
                ++i;
            }
        } else if (i + 1 < n && src[i] == '/' && src[i + 1] == '*') {
            r += ' ';
            r += ' ';
            i += 2;
            while (i + 1 < n && !(src[i] == '*' && src[i + 1] == '/')) {
                r += (src[i] == '\n' ? '\n' : ' ');
                ++i;
            }
            if (i + 1 < n) {
                r += ' ';
                r += ' ';
                i += 2;
            }
        } else {
            r += src[i];
            ++i;
        }
    }
    return r;
}
std::string TokenAnalyzer::strip_strings(const std::string& src)
{
    std::string r;
    r.reserve(src.size());
    size_t i = 0, n = src.size();
    while (i < n) {
        if (src[i] == '"') {
            r += '"';
            ++i;
            while (i < n && src[i] != '"') {
                r += (src[i] == '\n' ? '\n' : ' ');
                if (src[i] == '\\') {
                    ++i;
                    r += ' ';
                }
                ++i;
            }
            if (i < n) {
                r += '"';
                ++i;
            }
        } else if (src[i] == '\'') {
            r += '\'';
            ++i;
            while (i < n && src[i] != '\'') {
                r += ' ';
                if (src[i] == '\\') {
                    ++i;
                    r += ' ';
                }
                ++i;
            }
            if (i < n) {
                r += '\'';
                ++i;
            }
        } else {
            r += src[i];
            ++i;
        }
    }
    return r;
}
std::vector<TokenAnalyzer::Token> TokenAnalyzer::tokenize(const std::string& s)
{
    std::vector<Token> toks;
    int line = 1, col = 1;
    for (size_t i = 0; i < s.size();) {
        char c = s[i];
        if (c == '\n') {
            ++line;
            col = 1;
            ++i;
            continue;
        }
        if (std::isspace((unsigned char)c)) {
            ++col;
            ++i;
            continue;
        }
        if (c == '#') {
            while (i < s.size() && s[i] != '\n') ++i;
            continue;
        }
        if (std::isalpha((unsigned char)c) || c == '_') {
            std::string v;
            int sc = col;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) {
                v += s[i++];
                ++col;
            }
            while (i + 1 < s.size() && s[i] == ':' && s[i + 1] == ':') {
                v += "::";
                i += 2;
                col += 2;
                while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_')) {
                    v += s[i++];
                    ++col;
                }
            }
            toks.push_back({TokType::IDENT, v, line, sc});
        } else if (std::isdigit((unsigned char)c)) {
            std::string v;
            int sc = col;
            while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '.' ||
                                    s[i] == 'x' || s[i] == 'X')) {
                v += s[i++];
                ++col;
            }
            toks.push_back({TokType::NUMBER, v, line, sc});
        } else {
            toks.push_back({TokType::PUNCT, std::string(1, c), line, col});
            ++i;
            ++col;
        }
    }
    toks.push_back({TokType::END, "", line, col});
    return toks;
}
std::string TokenAnalyzer::extract_call_args(const std::vector<Token>& toks, size_t sp) const
{
    std::string r;
    int depth = 0;
    size_t i = sp;
    while (i < toks.size()) {
        if (toks[i].type == TokType::PUNCT && toks[i].val == "(") {
            ++depth;
            if (depth > 1)
                r += toks[i].val;
            ++i;
            continue;
        }
        if (toks[i].type == TokType::PUNCT && toks[i].val == ")") {
            --depth;
            if (depth <= 0)
                break;
            r += toks[i].val;
            ++i;
            continue;
        }
        if (toks[i].type != TokType::END)
            r += toks[i].val + " ";
        ++i;
    }
    return r;
}
std::vector<Finding> TokenAnalyzer::extract_findings(const std::vector<Token>& toks,
                                                     const std::string& fpath,
                                                     const std::vector<std::string>& lines) const
{
    std::vector<Finding> findings;
    struct Scope {
        std::string kind, name;
    };
    std::vector<Scope> scopes;
    for (size_t i = 0; i < toks.size(); ++i) {
        auto& t = toks[i];
        if (t.type == TokType::PUNCT) {
            if (t.val == "{") {
                bool pushed = false;
                for (int back = (int)i - 1; back >= std::max(0, (int)i - 60) && !pushed; --back) {
                    if (toks[back].type != TokType::IDENT)
                        continue;
                    auto& bt = toks[back];
                    if (bt.val == "namespace" && back + 1 < (int)i &&
                        toks[back + 1].type == TokType::IDENT) {
                        scopes.push_back({"namespace", toks[back + 1].val});
                        pushed = true;
                    } else if ((bt.val == "class" || bt.val == "struct") && back + 1 < (int)i &&
                               toks[back + 1].type == TokType::IDENT) {
                        scopes.push_back({"class", toks[back + 1].val});
                        pushed = true;
                    }
                }
                if (!pushed) {
                    std::string fn_name;
                    for (int back = (int)i - 1; back >= std::max(0, (int)i - 80) && fn_name.empty();
                         --back) {
                        if (toks[back].type == TokType::PUNCT && toks[back].val == ")") {
                            int d2 = 1;
                            for (int j = back - 1; j >= std::max(0, back - 60); --j) {
                                if (toks[j].type == TokType::PUNCT && toks[j].val == ")")
                                    ++d2;
                                else if (toks[j].type == TokType::PUNCT && toks[j].val == "(") {
                                    --d2;
                                    if (d2 == 0 && j > 0 && toks[j - 1].type == TokType::IDENT) {
                                        static const std::vector<std::string> kw = {
                                            "if", "for", "while", "switch", "catch", "return"};
                                        if (std::find(kw.begin(), kw.end(), toks[j - 1].val) ==
                                            kw.end())
                                            fn_name = toks[j - 1].val;
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    scopes.push_back({"function", fn_name.empty() ? "<anonymous>" : fn_name});
                }
            } else if (t.val == "}") {
                if (!scopes.empty())
                    scopes.pop_back();
            }
        } else if (t.type == TokType::IDENT && i + 1 < toks.size() &&
                   toks[i + 1].type == TokType::PUNCT && toks[i + 1].val == "(") {
            auto opt = db_.find_by_name(t.val);
            if (!opt)
                continue;
            Finding f;
            f.function_name = opt->name;
            f.file_path = fpath;
            f.line_number = t.line;
            f.column = t.col;
            f.library = opt->library_name;
            f.algorithm = opt->algorithm;
            f.category = opt->category;
            f.quantum_vulnerability = opt->quantum_vulnerability;
            f.base_risk_score = opt->risk_score;
            f.analyzer_mode = "token";
            f.vuln_id = opt->id;
            f.nist_reference = opt->nist_reference;
            f.tc26_reference = opt->tc26_reference;
            if (t.line > 0 && t.line <= (int)lines.size())
                f.raw_line = lines[t.line - 1];
            for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
                if (it->kind == "function" && f.context_function.empty())
                    f.context_function = it->name;
                else if (it->kind == "class" && f.context_class.empty())
                    f.context_class = it->name;
                else if (it->kind == "namespace" && f.context_namespace.empty())
                    f.context_namespace = it->name;
            }
            if (f.context_function.empty())
                f.context_function = "<global>";
            std::string args = extract_call_args(toks, i + 1);
            if (!args.empty())
                f.arguments.push_back(args);
            findings.push_back(std::move(f));
        }
    }
    return findings;
}
std::vector<Finding> TokenAnalyzer::analyze_file(const std::filesystem::path& p) const
{
    std::ifstream ifs(p);
    if (!ifs.is_open())
        return {};
    std::string src((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    std::vector<std::string> lines;
    std::istringstream ss(src);
    std::string l;
    while (std::getline(ss, l)) lines.push_back(l);
    auto clean = strip_strings(strip_comments(src));
    auto toks = tokenize(clean);
    return extract_findings(toks, p.string(), lines);
}
std::vector<Finding> TokenAnalyzer::analyze(const ProjectInventory& inv) const
{
    std::vector<Finding> all;
    for (auto* fe : inv.get_source_files()) {
        auto r = analyze_file(fe->path);
        all.insert(all.end(), r.begin(), r.end());
    }
    return all;
}
}  // namespace pqc
