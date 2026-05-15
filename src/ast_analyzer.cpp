#include "pqc/ast_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef PQC_HAS_LIBCLANG
#  include <clang-c/Index.h>
#endif

#ifndef PQC_AST_DEBUG
#  define PQC_AST_DEBUG 0
#endif

namespace pqc {

ASTAnalyzer::ASTAnalyzer(const VulnDatabase& db)
    : db_(db), fallback_(std::make_unique<TokenAnalyzer>(db))
{
#ifdef PQC_HAS_LIBCLANG
    has_libclang_ = true;
#else
    has_libclang_ = false;
#endif
}

ASTAnalyzer::~ASTAnalyzer() = default;

void ASTAnalyzer::set_include_dirs(const std::vector<std::string>& dirs) {
    include_dirs_ = dirs;

#ifdef PQC_OPENSSL_INCLUDE_DIR
    include_dirs_.push_back(PQC_OPENSSL_INCLUDE_DIR);
#endif

    std::vector<std::string> unique_dirs;
    for (const auto& d : include_dirs_) {
        if (d.empty()) continue;
        bool exists = false;
        for (const auto& u : unique_dirs) {
            std::error_code ec1, ec2;
            auto p1 = std::filesystem::weakly_canonical(d, ec1);
            auto p2 = std::filesystem::weakly_canonical(u, ec2);
            if (!ec1 && !ec2 && p1 == p2) {
                exists = true;
                break;
            }
            if ((ec1 || ec2) && d == u) {
                exists = true;
                break;
            }
        }
        if (!exists) unique_dirs.push_back(d);
    }
    include_dirs_.swap(unique_dirs);
}

std::vector<Finding> ASTAnalyzer::analyze(const ProjectInventory& inv) const {
#ifdef PQC_HAS_LIBCLANG
    if (!has_libclang_) {
        return {};
    }

    std::vector<Finding> all;
    auto& dirs = const_cast<std::vector<std::string>&>(include_dirs_);

    auto add_dir_if_missing = [&](const std::filesystem::path& p) {
        if (p.empty()) return;
        std::error_code ecx;
        if (!std::filesystem::exists(p, ecx)) return;

        bool exists = false;
        for (const auto& d : dirs) {
            std::error_code ec1, ec2;
            auto p1 = std::filesystem::weakly_canonical(d, ec1);
            auto p2 = std::filesystem::weakly_canonical(p, ec2);
            if (!ec1 && !ec2 && p1 == p2) {
                exists = true;
                break;
            }
            if ((ec1 || ec2) && d == p.string()) {
                exists = true;
                break;
            }
        }
        if (!exists) dirs.push_back(p.string());
    };

    add_dir_if_missing(inv.project_path);
    add_dir_if_missing(std::filesystem::path(inv.project_path) / "include");
    add_dir_if_missing(std::filesystem::path(inv.project_path) / "src");

    for (const auto* fe : inv.get_by_category(FileCategory::HEADER)) {
        if (!fe) continue;
        add_dir_if_missing(fe->path.parent_path());
    }

#if PQC_AST_DEBUG
    std::cerr << "[AST][debug] analyze(project=" << inv.project_path << ")\n";
    std::cerr << "[AST][debug] final include dirs:\n";
    for (const auto& d : dirs) {
        std::cerr << "  - " << d << "\n";
    }
#endif

    for (const auto* fe : inv.get_by_category(FileCategory::SOURCE)) {
        if (!fe) continue;
#if PQC_AST_DEBUG
        std::cerr << "[AST][debug] analyzing TU: " << fe->path.string() << "\n";
#endif
        auto r = analyze_file(fe->path);
#if PQC_AST_DEBUG
        std::cerr << "[AST][debug] TU findings: " << r.size() << "\n";
#endif
        all.insert(all.end(), r.begin(), r.end());
    }

    return all;
#else
    (void)inv;
    return {};
#endif
}

std::vector<Finding> ASTAnalyzer::analyze_file(const std::filesystem::path& p) const {
    std::vector<Finding> out;
#ifdef PQC_HAS_LIBCLANG
    if (has_libclang_) {
        if (!try_libclang(p, out)) {
            return {};
        }
        return out;
    }
#endif
    return {};
}

#ifdef PQC_HAS_LIBCLANG
namespace {

static constexpr int kMaxResolveDepth = 3;
static constexpr std::size_t kMaxResolvedText = 240;

static std::string to_string_and_dispose(CXString s) {
    const char* c = clang_getCString(s);
    std::string out = c ? c : "";
    clang_disposeString(s);
    return out;
}

static std::string trim_copy(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    return s;
}

static std::string squash_spaces(std::string s) {
    std::string out;
    out.reserve(s.size());
    bool prev_space = false;
    for (char ch : s) {
        const bool is_sp = std::isspace(static_cast<unsigned char>(ch)) != 0;
        if (is_sp) {
            if (!prev_space) out.push_back(' ');
        } else {
            out.push_back(ch);
        }
        prev_space = is_sp;
    }
    return trim_copy(out);
}

static std::string clip_text(std::string s, std::size_t max_len = kMaxResolvedText) {
    s = squash_spaces(std::move(s));
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len - 3) + "...";
}

static bool same_path(const std::string& a, const std::string& b) {
    std::error_code ec1, ec2;
    auto p1 = std::filesystem::weakly_canonical(a, ec1);
    auto p2 = std::filesystem::weakly_canonical(b, ec2);
    if (!ec1 && !ec2) return p1 == p2;
    return a == b;
}

static std::string get_cursor_text(CXCursor cursor, CXTranslationUnit tu) {
    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken* tokens = nullptr;
    unsigned n_tokens = 0;
    clang_tokenize(tu, range, &tokens, &n_tokens);

    std::string text;
    for (unsigned i = 0; i < n_tokens; ++i) {
        auto ts = to_string_and_dispose(clang_getTokenSpelling(tu, tokens[i]));
        if (!ts.empty()) {
            if (!text.empty()) text += ' ';
            text += ts;
        }
    }

    if (tokens) clang_disposeTokens(tu, tokens, n_tokens);
    return clip_text(text);
}

static std::string evaluate_cursor_value(CXCursor cursor, CXTranslationUnit tu) {
    CXEvalResult eval = clang_Cursor_Evaluate(cursor);
    if (eval) {
        CXEvalResultKind kind = clang_EvalResult_getKind(eval);
        std::string result;

        switch (kind) {
            case CXEval_Int:
                result = std::to_string(clang_EvalResult_getAsLongLong(eval));
                break;

            case CXEval_Float: {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%g", clang_EvalResult_getAsDouble(eval));
                result = buf;
                break;
            }

            case CXEval_StrLiteral:
            case CXEval_CFStr:
            case CXEval_ObjCStrLiteral:
            case CXEval_Other: {
                const char* str = clang_EvalResult_getAsStr(eval);
                if (str) result = std::string("\"") + str + "\"";
                break;
            }

            default:
                break;
        }

        clang_EvalResult_dispose(eval);
        if (!result.empty()) return clip_text(result);
    }

    (void)tu;
    return {};
}

static bool cursor_is_from_file(CXCursor cursor, const std::string& file_path) {
    CXSourceLocation loc = clang_getCursorLocation(cursor);
    if (clang_Location_isInSystemHeader(loc)) return false;

    CXFile cf;
    unsigned line = 0, col = 0;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    (void)line;
    (void)col;

    if (!cf) return false;

    std::string fname = to_string_and_dispose(clang_getFileName(cf));
    if (fname.empty()) return false;

    return same_path(fname, file_path);
}

static std::string extract_name_from_tokens_before_paren(CXCursor cursor, CXTranslationUnit tu) {
    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken* tokens = nullptr;
    unsigned n_tokens = 0;
    clang_tokenize(tu, range, &tokens, &n_tokens);

    std::string last_ident;
    for (unsigned i = 0; i < n_tokens; ++i) {
        auto kind = clang_getTokenKind(tokens[i]);
        auto text = to_string_and_dispose(clang_getTokenSpelling(tu, tokens[i]));
        if (text == "(") break;
        if (kind == CXToken_Identifier) last_ident = text;
    }

    if (tokens) clang_disposeTokens(tu, tokens, n_tokens);
    return last_ident;
}

static std::string get_best_cursor_spelling(CXCursor c) {
    std::string s = to_string_and_dispose(clang_getCursorSpelling(c));
    if (!s.empty()) return s;
    return to_string_and_dispose(clang_getCursorDisplayName(c));
}

static std::string extract_callee_name_from_children(CXCursor cursor, CXTranslationUnit tu) {
    struct ChildData {
        CXTranslationUnit tu;
        std::string name;
    } cd{tu, ""};

    clang_visitChildren(
        cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* cd = static_cast<ChildData*>(data);
            auto ck = clang_getCursorKind(child);

            if (ck == CXCursor_DeclRefExpr ||
                ck == CXCursor_MemberRefExpr ||
                ck == CXCursor_UnexposedExpr ||
                ck == CXCursor_OverloadedDeclRef) {

                std::string name = get_best_cursor_spelling(child);
                if (name.empty()) {
                    CXCursor ref = clang_getCursorReferenced(child);
                    if (!clang_Cursor_isNull(ref)) {
                        name = get_best_cursor_spelling(ref);
                    }
                }
                if (!name.empty()) {
                    cd->name = name;
                    return CXChildVisit_Break;
                }
            }

            return CXChildVisit_Recurse;
        },
        &cd
    );

    if (!cd.name.empty()) return cd.name;
    return extract_name_from_tokens_before_paren(cursor, tu);
}

static std::string get_callee_name(CXCursor call_cursor, CXTranslationUnit tu) {
    std::string fname;

    CXCursor ref = clang_getCursorReferenced(call_cursor);
    if (!clang_Cursor_isNull(ref) && !clang_equalCursors(ref, call_cursor)) {
        fname = get_best_cursor_spelling(ref);
    }

    if (fname.empty()) {
        fname = get_best_cursor_spelling(call_cursor);
    }

    if (fname.empty()) {
        fname = extract_callee_name_from_children(call_cursor, tu);
    }

    return fname;
}

struct ResolvedValue {
    std::string text;
    unsigned line = 0;
    bool known = false;
};

struct FunctionFrame {
    std::string qualified_name;
    std::unordered_map<std::string, ResolvedValue> locals;
};

struct PendingCall {
    unsigned line = 0;
    unsigned col = 0;
    std::string file_path;
    std::string context_function;
    std::string context_class;
    std::string context_namespace;

    std::string callee_name;
    std::string raw_line;
    std::vector<std::string> arguments;
};

struct VisitData {
    const VulnDatabase& db;
    std::vector<Finding>& findings;
    const std::string& file_path;
    const std::vector<std::string>& lines;
    CXTranslationUnit tu;

    std::string cur_fn;
    std::string cur_cls;
    std::string cur_ns;

    std::vector<PendingCall> pending_calls;
};

static std::string current_qualified_function(const VisitData& vd) {
    std::string q;
    if (!vd.cur_ns.empty()) q += vd.cur_ns + "::";
    if (!vd.cur_cls.empty()) q += vd.cur_cls + "::";
    if (!vd.cur_fn.empty()) q += vd.cur_fn;
    return q.empty() ? "<global>" : q;
}

static bool is_function_like_cursor(CXCursorKind kind) {
    return kind == CXCursor_FunctionDecl ||
           kind == CXCursor_CXXMethod ||
           kind == CXCursor_Constructor ||
           kind == CXCursor_Destructor ||
           kind == CXCursor_FunctionTemplate;
}

static bool is_literal_like(CXCursorKind kind) {
    return kind == CXCursor_IntegerLiteral ||
           kind == CXCursor_FloatingLiteral ||
           kind == CXCursor_StringLiteral ||
           kind == CXCursor_CharacterLiteral ||
           kind == CXCursor_CXXBoolLiteralExpr ||
           kind == CXCursor_ImaginaryLiteral;
}

static std::string join_children_text(CXCursor cursor, CXTranslationUnit tu) {
    std::vector<std::string> parts;
    clang_visitChildren(
        cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* parts = static_cast<std::vector<std::string>*>(data);
            parts->push_back(get_cursor_text(child, clang_Cursor_getTranslationUnit(child)));
            return CXChildVisit_Continue;
        },
        &parts
    );

    std::ostringstream oss;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) oss << ", ";
        oss << parts[i];
    }
    if (!parts.empty()) return clip_text(oss.str());
    return get_cursor_text(cursor, tu);
}

static std::vector<CXCursor> get_children(CXCursor cursor) {
    std::vector<CXCursor> children;
    clang_visitChildren(
        cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* vec = static_cast<std::vector<CXCursor>*>(data);
            vec->push_back(child);
            return CXChildVisit_Continue;
        },
        &children
    );
    return children;
}

static std::string resolve_expr(CXCursor cursor,
                                CXTranslationUnit tu,
                                FunctionFrame& frame,
                                unsigned line_limit,
                                int depth);

static std::string lookup_local(FunctionFrame& frame,
                                const std::string& name,
                                unsigned line_limit,
                                int depth)
{
    auto it = frame.locals.find(name);
    if (it == frame.locals.end()) return {};
    if (!it->second.known) return {};
    if (it->second.line > line_limit) return {};
    if (depth <= 0) return name;
    return it->second.text;
}

static std::string resolve_decl_ref(CXCursor ref_cursor,
                                    CXTranslationUnit tu,
                                    FunctionFrame& frame,
                                    unsigned line_limit,
                                    int depth)
{
    std::string name = to_string_and_dispose(clang_getCursorSpelling(ref_cursor));
    if (name.empty()) return {};

    std::string local = lookup_local(frame, name, line_limit, depth - 1);
    if (!local.empty()) {
        if (local == name) return name;
        return clip_text(name + "=" + local);
    }

    CXCursor decl = clang_getCursorReferenced(ref_cursor);
    if (clang_Cursor_isNull(decl)) return name;

    CXCursorKind dk = clang_getCursorKind(decl);

    if (dk == CXCursor_ParmDecl) {
        return name;
    }

    if (dk == CXCursor_EnumConstantDecl) {
        std::string val = evaluate_cursor_value(decl, tu);
        if (!val.empty()) return clip_text(name + "=" + val);
        return name;
    }

    if (dk == CXCursor_FieldDecl) {
        CXCursor parent = clang_getCursorSemanticParent(decl);
        std::string owner = to_string_and_dispose(clang_getCursorSpelling(parent));
        if (!owner.empty()) return owner + "::" + name;
        return name;
    }

    if (dk == CXCursor_VarDecl) {
        auto ch = get_children(decl);
        for (const auto& c : ch) {
            std::string rv = resolve_expr(c, tu, frame, line_limit, depth - 1);
            if (!rv.empty() && rv != name) {
                return clip_text(name + "=" + rv);
            }
        }

        std::string val = evaluate_cursor_value(decl, tu);
        if (!val.empty() && val != name) return clip_text(name + "=" + val);
    }

    return name;
}

static std::string resolve_member_ref(CXCursor cursor,
                                      CXTranslationUnit tu,
                                      FunctionFrame& frame,
                                      unsigned line_limit,
                                      int depth)
{
    std::string name = to_string_and_dispose(clang_getCursorSpelling(cursor));
    if (name.empty()) {
        return get_cursor_text(cursor, tu);
    }

    auto children = get_children(cursor);
    if (!children.empty()) {
        std::string base = resolve_expr(children.front(), tu, frame, line_limit, depth - 1);
        if (!base.empty()) {
            return clip_text(base + "." + name);
        }
    }

    CXCursor ref = clang_getCursorReferenced(cursor);
    if (!clang_Cursor_isNull(ref) && clang_getCursorKind(ref) == CXCursor_FieldDecl) {
        CXCursor parent = clang_getCursorSemanticParent(ref);
        std::string owner = to_string_and_dispose(clang_getCursorSpelling(parent));
        if (!owner.empty()) return owner + "::" + name;
    }

    return name;
}

static std::string resolve_call_expr(CXCursor cursor,
                                     CXTranslationUnit tu,
                                     FunctionFrame& frame,
                                     unsigned line_limit,
                                     int depth)
{
    std::string callee = get_callee_name(cursor, tu);
    if (callee.empty()) callee = "<call>";

    int na = clang_Cursor_getNumArguments(cursor);
    std::ostringstream oss;
    oss << callee << "(";
    for (int i = 0; i < na; ++i) {
        if (i) oss << ", ";
        CXCursor arg = clang_Cursor_getArgument(cursor, i);
        std::string a = resolve_expr(arg, tu, frame, line_limit, depth - 1);
        if (a.empty()) a = get_cursor_text(arg, tu);
        oss << a;
    }
    oss << ")";
    return clip_text(oss.str());
}

static std::string resolve_expr(CXCursor cursor,
                                CXTranslationUnit tu,
                                FunctionFrame& frame,
                                unsigned line_limit,
                                int depth)
{
    if (clang_Cursor_isNull(cursor)) return {};
    if (depth <= 0) return get_cursor_text(cursor, tu);

    CXCursorKind kind = clang_getCursorKind(cursor);

    if (is_literal_like(kind)) {
        std::string eval = evaluate_cursor_value(cursor, tu);
        if (!eval.empty()) return eval;
        return get_cursor_text(cursor, tu);
    }

    switch (kind) {
        case CXCursor_DeclRefExpr:
            return resolve_decl_ref(cursor, tu, frame, line_limit, depth);

        case CXCursor_MemberRefExpr:
        case CXCursor_MemberRef:
            return resolve_member_ref(cursor, tu, frame, line_limit, depth);

        case CXCursor_ParenExpr: {
            auto children = get_children(cursor);
            if (!children.empty()) return resolve_expr(children.front(), tu, frame, line_limit, depth - 1);
            return get_cursor_text(cursor, tu);
        }

        case CXCursor_UnaryOperator:
        case CXCursor_BinaryOperator:
        case CXCursor_ConditionalOperator:
        case CXCursor_CStyleCastExpr:
        case CXCursor_CXXStaticCastExpr:
        case CXCursor_CXXFunctionalCastExpr:
        case CXCursor_InitListExpr:
        case CXCursor_ArraySubscriptExpr: {
            std::string eval = evaluate_cursor_value(cursor, tu);
            if (!eval.empty()) return eval;

            auto children = get_children(cursor);
            if (children.empty()) return get_cursor_text(cursor, tu);

            std::string raw = get_cursor_text(cursor, tu);
            if (!raw.empty()) return raw;

            std::ostringstream oss;
            for (std::size_t i = 0; i < children.size(); ++i) {
                if (i) oss << ", ";
                oss << resolve_expr(children[i], tu, frame, line_limit, depth - 1);
            }
            return clip_text(oss.str());
        }

        case CXCursor_CallExpr:
            return resolve_call_expr(cursor, tu, frame, line_limit, depth);

        case CXCursor_UnexposedExpr: {
            auto children = get_children(cursor);
            if (children.size() == 1) {
                return resolve_expr(children.front(), tu, frame, line_limit, depth - 1);
            }
            std::string eval = evaluate_cursor_value(cursor, tu);
            if (!eval.empty()) return eval;
            return get_cursor_text(cursor, tu);
        }

        default: {
            std::string eval = evaluate_cursor_value(cursor, tu);
            if (!eval.empty()) return eval;
            return get_cursor_text(cursor, tu);
        }
    }
}

static std::string extract_assignment_lhs_name(CXCursor cursor) {
    CXCursorKind kind = clang_getCursorKind(cursor);
    if (kind == CXCursor_DeclRefExpr) {
        return to_string_and_dispose(clang_getCursorSpelling(cursor));
    }
    if (kind == CXCursor_UnexposedExpr || kind == CXCursor_ParenExpr) {
        auto children = get_children(cursor);
        if (!children.empty()) return extract_assignment_lhs_name(children.front());
    }
    return {};
}

static void collect_definitions_recursive(CXCursor cursor,
                                          const std::string& file_path,
                                          CXTranslationUnit tu,
                                          FunctionFrame& frame)
{
    if (!cursor_is_from_file(cursor, file_path)) return;

    CXSourceLocation loc = clang_getCursorLocation(cursor);
    CXFile cf;
    unsigned line = 0, col = 0;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    (void)cf;
    (void)col;

    CXCursorKind kind = clang_getCursorKind(cursor);

    if (kind == CXCursor_VarDecl) {
        std::string var_name = to_string_and_dispose(clang_getCursorSpelling(cursor));
        if (!var_name.empty()) {
            auto children = get_children(cursor);
            std::string init_value;
            for (const auto& c : children) {
                init_value = resolve_expr(c, tu, frame, line, kMaxResolveDepth);
                if (!init_value.empty()) break;
            }
            if (init_value.empty()) {
                init_value = evaluate_cursor_value(cursor, tu);
            }
            if (init_value.empty()) {
                std::string text = get_cursor_text(cursor, tu);
                auto pos = text.find('=');
                if (pos != std::string::npos) {
                    init_value = trim_copy(text.substr(pos + 1));
                    if (!init_value.empty() && init_value.back() == ';') {
                        init_value.pop_back();
                        init_value = trim_copy(init_value);
                    }
                }
            }

            if (!init_value.empty()) {
                frame.locals[var_name] = ResolvedValue{clip_text(init_value), line, true};
#if PQC_AST_DEBUG
                std::cerr << "[AST][debug] var init " << var_name << "="
                          << frame.locals[var_name].text << " at line " << line << "\n";
#endif
            }
        }
    } else if (kind == CXCursor_BinaryOperator) {
        auto children = get_children(cursor);
        if (children.size() >= 2) {
            std::string lhs = extract_assignment_lhs_name(children[0]);
            if (!lhs.empty()) {
                std::string rhs = resolve_expr(children[1], tu, frame, line, kMaxResolveDepth);
                if (!rhs.empty()) {
                    frame.locals[lhs] = ResolvedValue{clip_text(rhs), line, true};
#if PQC_AST_DEBUG
                    std::cerr << "[AST][debug] assign " << lhs << "="
                              << frame.locals[lhs].text << " at line " << line << "\n";
#endif
                }
            }
        }
    }

    clang_visitChildren(
        cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* payload = static_cast<std::tuple<const std::string*, CXTranslationUnit, FunctionFrame*>*>(data);
            collect_definitions_recursive(child, *std::get<0>(*payload), std::get<1>(*payload), *std::get<2>(*payload));
            return CXChildVisit_Continue;
        },
        new std::tuple<const std::string*, CXTranslationUnit, FunctionFrame*>(&file_path, tu, &frame)
    );
}

static void collect_definitions(CXCursor function_cursor,
                                const std::string& file_path,
                                CXTranslationUnit tu,
                                FunctionFrame& frame)
{
    auto payload = std::tuple<const std::string*, CXTranslationUnit, FunctionFrame*>(&file_path, tu, &frame);
    clang_visitChildren(
        function_cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* payload = static_cast<std::tuple<const std::string*, CXTranslationUnit, FunctionFrame*>*>(data);
            collect_definitions_recursive(child, *std::get<0>(*payload), std::get<1>(*payload), *std::get<2>(*payload));
            return CXChildVisit_Continue;
        },
        &payload
    );
}

static void emit_pending_call(const PendingCall& pc, VisitData* vd) {
    std::string fname = pc.callee_name;
    if (fname.empty()) {
#if PQC_AST_DEBUG
        std::cerr << "[AST][debug] emit skip: empty callee at "
                  << pc.file_path << ":" << pc.line << ":" << pc.col
                  << " raw='" << pc.raw_line << "'\n";
#endif
        return;
    }

    auto opt = vd->db.find_by_name(fname);
    if (!opt) {
#if PQC_AST_DEBUG
        std::cerr << "[AST][debug] db MISS: callee='" << fname
                  << "' raw='" << pc.raw_line << "'\n";
#endif
        return;
    }

#if PQC_AST_DEBUG
    std::cerr << "[AST][debug] db HIT: callee='" << fname
              << "' vuln_id='" << opt->id << "' at "
              << pc.file_path << ":" << pc.line << ":" << pc.col << "\n";
#endif

    Finding f;
    f.function_name         = opt->name;
    f.file_path             = pc.file_path;
    f.line_number           = static_cast<int>(pc.line);
    f.column                = static_cast<int>(pc.col);
    f.library               = opt->library_name;
    f.algorithm             = opt->algorithm;
    f.category              = opt->category;
    f.quantum_vulnerability = opt->quantum_vulnerability;
    f.base_risk_score       = opt->risk_score;
    f.analyzer_mode         = "ast";
    f.vuln_id               = opt->id;
    f.nist_reference        = opt->nist_reference;
    f.tc26_reference        = opt->tc26_reference;
    f.context_function      = pc.context_function.empty() ? "<global>" : pc.context_function;
    f.context_class         = pc.context_class;
    f.context_namespace     = pc.context_namespace;
    f.raw_line              = pc.raw_line;
    f.arguments             = pc.arguments;

#if PQC_AST_DEBUG
    for (size_t i = 0; i < f.arguments.size(); ++i) {
        std::cerr << "[AST][debug]   arg[" << i << "]='" << f.arguments[i] << "'\n";
    }
#endif

    vd->findings.push_back(std::move(f));
}

static void collect_calls_recursive(CXCursor cursor,
                                    VisitData* vd,
                                    FunctionFrame& frame)
{
    if (!cursor_is_from_file(cursor, vd->file_path)) return;

    CXSourceLocation loc = clang_getCursorLocation(cursor);
    CXFile cf;
    unsigned line = 0, col = 0;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    (void)cf;

    CXCursorKind kind = clang_getCursorKind(cursor);

    if (kind == CXCursor_CallExpr) {
        PendingCall pc;
        pc.line = line;
        pc.col = col;
        pc.file_path = vd->file_path;
        pc.context_function = vd->cur_fn.empty() ? "<global>" : vd->cur_fn;
        pc.context_class = vd->cur_cls;
        pc.context_namespace = vd->cur_ns;
        pc.callee_name = get_callee_name(cursor, vd->tu);

        if (line > 0 && line <= vd->lines.size()) {
            pc.raw_line = vd->lines[line - 1];
        }

        int na = clang_Cursor_getNumArguments(cursor);
        for (int i = 0; i < na; ++i) {
            CXCursor arg = clang_Cursor_getArgument(cursor, i);
            std::string resolved = resolve_expr(arg, vd->tu, frame, line, kMaxResolveDepth);
            if (resolved.empty()) resolved = get_cursor_text(arg, vd->tu);
            pc.arguments.push_back(clip_text(resolved));
        }

        vd->pending_calls.push_back(std::move(pc));
    }

    std::pair<VisitData*, FunctionFrame*> payload{vd, &frame};
    clang_visitChildren(
        cursor,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* payload = static_cast<std::pair<VisitData*, FunctionFrame*>*>(data);
            collect_calls_recursive(child, payload->first, *payload->second);
            return CXChildVisit_Continue;
        },
        &payload
    );
}

static void process_function_cursor(CXCursor cursor, VisitData* vd) {
    if (!clang_isCursorDefinition(cursor)) return;

    std::string saved_fn = vd->cur_fn;
    vd->cur_fn = to_string_and_dispose(clang_getCursorSpelling(cursor));

#if PQC_AST_DEBUG
    std::cerr << "[AST][debug] entering function: " << vd->cur_fn << "\n";
#endif

    FunctionFrame frame;
    frame.qualified_name = current_qualified_function(*vd);

    collect_definitions(cursor, vd->file_path, vd->tu, frame);
    collect_calls_recursive(cursor, vd, frame);

    std::vector<PendingCall> remain;
    remain.reserve(vd->pending_calls.size());

    std::set<std::tuple<std::string, unsigned, unsigned, std::string>> seen;

    for (const auto& pc : vd->pending_calls) {
        if (pc.context_function == (vd->cur_fn.empty() ? "<global>" : vd->cur_fn) &&
            same_path(pc.file_path, vd->file_path)) {

            auto key = std::make_tuple(pc.file_path, pc.line, pc.col, pc.callee_name);
            if (seen.insert(key).second) {
                emit_pending_call(pc, vd);
            }
        } else {
            remain.push_back(pc);
        }
    }

    vd->pending_calls.swap(remain);
    vd->cur_fn = saved_fn;
}

static CXChildVisitResult ast_visitor(CXCursor cursor, CXCursor /*parent*/, CXClientData data) {
    auto* vd = static_cast<VisitData*>(data);

    if (!cursor_is_from_file(cursor, vd->file_path)) {
        return CXChildVisit_Continue;
    }

    CXCursorKind kind = clang_getCursorKind(cursor);

    std::string saved_cls = vd->cur_cls;
    std::string saved_ns = vd->cur_ns;
    bool changed_cls = false;
    bool changed_ns = false;

    if (kind == CXCursor_ClassDecl || kind == CXCursor_StructDecl || kind == CXCursor_ClassTemplate) {
        vd->cur_cls = to_string_and_dispose(clang_getCursorSpelling(cursor));
        changed_cls = true;
    } else if (kind == CXCursor_Namespace) {
        std::string ns = to_string_and_dispose(clang_getCursorSpelling(cursor));
        if (!ns.empty()) {
            if (!vd->cur_ns.empty()) vd->cur_ns += "::";
            vd->cur_ns += ns;
            changed_ns = true;
        }
    } else if (is_function_like_cursor(kind)) {
        process_function_cursor(cursor, vd);
        return CXChildVisit_Continue;
    }

    clang_visitChildren(cursor, ast_visitor, data);

    if (changed_cls) vd->cur_cls = saved_cls;
    if (changed_ns) vd->cur_ns = saved_ns;

    return CXChildVisit_Continue;
}

} // anonymous namespace

bool ASTAnalyzer::try_libclang(const std::filesystem::path& path,
                               std::vector<Finding>& out) const
{
    std::error_code ec;
    auto canon = std::filesystem::weakly_canonical(path, ec);
    std::filesystem::path real_path = ec ? std::filesystem::absolute(path) : canon;

    std::vector<std::string> lines;
    {
        std::ifstream ifs(real_path);
        if (!ifs.is_open()) {
            return false;
        }
        std::string l;
        while (std::getline(ifs, l)) lines.push_back(l);
    }

    CXIndex index = clang_createIndex(/*excludeDeclarationsFromPCH=*/0,
                                      /*displayDiagnostics=*/0);

    std::vector<std::string> args_str = {
        "-x", "c++",
        "-std=c++17",
        "-w",
        "-ferror-limit=0",
    };

#ifdef PQC_MACOS_SDKROOT
    args_str.push_back("-isysroot");
    args_str.push_back(PQC_MACOS_SDKROOT);
#endif

    for (const auto& d : include_dirs_) {
        if (d.empty()) continue;
        args_str.push_back("-I");
        args_str.push_back(d);
    }

    auto parent = real_path.parent_path();
    auto root   = parent.parent_path();

    if (!parent.empty()) {
        args_str.push_back("-I");
        args_str.push_back(parent.string());
    }
    if (!root.empty() && root != parent) {
        args_str.push_back("-I");
        args_str.push_back(root.string());
    }

    auto root_include = root / "include";
    if (!root.empty() && std::filesystem::exists(root_include, ec)) {
        args_str.push_back("-I");
        args_str.push_back(root_include.string());
    }

    std::vector<const char*> cargs;
    cargs.reserve(args_str.size());
    for (auto& s : args_str) cargs.push_back(s.c_str());

    unsigned tu_flags =
        CXTranslationUnit_DetailedPreprocessingRecord |
        CXTranslationUnit_KeepGoing;

    CXTranslationUnit tu = clang_parseTranslationUnit(
        index,
        real_path.string().c_str(),
        cargs.data(), static_cast<int>(cargs.size()),
        nullptr, 0,
        tu_flags
    );

    if (!tu) {
        clang_disposeIndex(index);
        return false;
    }

#if PQC_AST_DEBUG
    unsigned n_diags = clang_getNumDiagnostics(tu);
    unsigned n_errors = 0, n_warnings = 0;
    for (unsigned i = 0; i < n_diags; ++i) {
        CXDiagnostic diag = clang_getDiagnostic(tu, i);
        CXDiagnosticSeverity sev = clang_getDiagnosticSeverity(diag);
        if (sev >= CXDiagnostic_Error) ++n_errors;
        else if (sev == CXDiagnostic_Warning) ++n_warnings;
        clang_disposeDiagnostic(diag);
    }
    std::cerr << "[AST][debug] TU diagnostics: " << n_errors << " errors, "
              << n_warnings << " warnings\n";
#endif

    VisitData vd{db_, out, real_path.string(), lines, tu, "", "", "", {}};
    clang_visitChildren(clang_getTranslationUnitCursor(tu), ast_visitor, &vd);

    for (const auto& pc : vd.pending_calls) {
        emit_pending_call(pc, &vd);
    }

    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return true;
}

#endif // PQC_HAS_LIBCLANG

} // namespace pqc