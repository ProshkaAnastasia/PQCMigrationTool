// src/ast_analyzer.cpp
#include "pqc/ast_analyzer.hpp"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
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

#ifdef PQC_EXTRA_CLANG_INCLUDE_1
    include_dirs_.push_back(PQC_EXTRA_CLANG_INCLUDE_1);
#endif
#ifdef PQC_EXTRA_CLANG_INCLUDE_2
    include_dirs_.push_back(PQC_EXTRA_CLANG_INCLUDE_2);
#endif
#ifdef PQC_EXTRA_CLANG_INCLUDE_3
    include_dirs_.push_back(PQC_EXTRA_CLANG_INCLUDE_3);
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
        // Note: try_libclang must NOT push findings into `out` before deciding
        // it cannot parse the TU. On `false` we still return whatever was
        // safely produced (currently nothing, but this is defensive).
        if (!try_libclang(p, out)) {
            return out;
        }
        return out;
    }
#endif
    return {};
}

#ifdef PQC_HAS_LIBCLANG
namespace {

// =============================================================================
// Tunables
// =============================================================================
static constexpr int         kMaxResolveDepth          = 12;
static constexpr int         kMaxInlineExpansionDepth  = 6;
static constexpr int         kMaxCallGraphDepth        = 8;   // depth of inter-procedural propagation
static constexpr std::size_t kMaxResolvedText          = 512;

// Risk multiplier applied to findings located in functions that are NOT
// reachable from the call-graph roots (main + external-linkage functions).
// 1.0 = no penalty, 0.0 = effectively suppressed.
static constexpr double      kUnreachableRiskFactor    = 0.3;

// =============================================================================
// Small string helpers
// =============================================================================
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

// =============================================================================
// Cursor → text / value
// =============================================================================
// -----------------------------------------------------------------------------
// Token-stream → readable text with C++-aware spacing rules.
//
// libclang gives us tokens but no whitespace, so we have to decide spacing
// ourselves. The rules below avoid the usual artifacts:
//   `& pkey_`   →  `&pkey_`
//   `a -> b`    →  `a->b`
//   `a . b`     →  `a.b`
//   `ns :: T`   →  `ns::T`
//   `arr [ 0 ]` →  `arr[0]`
//   `f ( x )`   →  `f(x)`
//   `EVP_PKEY_CTX * ctx` → `EVP_PKEY_CTX* ctx`
//
// We treat `*` and `&` as prefix unary operators when the previous token is
// not an identifier/literal/closing bracket; otherwise they are binary and
// kept with surrounding spaces.
// -----------------------------------------------------------------------------
static bool token_is_word_like(CXTokenKind k) {
    return k == CXToken_Identifier || k == CXToken_Literal || k == CXToken_Keyword;
}

static bool is_open_bracket(const std::string& t)  { return t == "(" || t == "["; }
static bool is_close_bracket(const std::string& t) { return t == ")" || t == "]"; }
static bool is_unary_punct(const std::string& t) {
    return t == "!" || t == "~" || t == "++" || t == "--";
}
static bool is_no_space_glue(const std::string& t) {
    // Punctuation that should never have spaces on either side.
    return t == "." || t == "->" || t == "::" || t == ".*" || t == "->*";
}
static bool prev_allows_binary(CXTokenKind k, const std::string& t) {
    if (token_is_word_like(k)) return true;
    if (k == CXToken_Punctuation && (is_close_bracket(t) || t == "++" || t == "--")) return true;
    return false;
}

static std::string get_cursor_text(CXCursor cursor, CXTranslationUnit tu) {
    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken* tokens = nullptr;
    unsigned n_tokens = 0;
    clang_tokenize(tu, range, &tokens, &n_tokens);

    std::string text;
    CXTokenKind prev_kind = CXToken_Comment;  // sentinel: definitely not word-like
    std::string prev_text;
    bool prev_amp_or_star_was_unary = false;  // set when we emit `&`/`*` as prefix

    auto last_non_space_char = [&]() -> char {
        for (auto it = text.rbegin(); it != text.rend(); ++it) {
            if (*it != ' ') return *it;
        }
        return '\0';
    };

    for (unsigned i = 0; i < n_tokens; ++i) {
        CXTokenKind kind = clang_getTokenKind(tokens[i]);
        std::string ts = to_string_and_dispose(clang_getTokenSpelling(tu, tokens[i]));
        if (ts.empty()) continue;

        bool need_space = false;
        bool this_amp_or_star_is_unary = false;

        if (text.empty()) {
            need_space = false;
            // First token: still mark `&`/`*` as unary so the next iteration
            // (when it processes the following identifier) knows not to insert
            // a separating space (e.g. `&pkey_` rendered from a UnaryOperator).
            if (kind == CXToken_Punctuation && (ts == "&" || ts == "*")) {
                this_amp_or_star_is_unary = true;
            }
        } else if (is_no_space_glue(ts) || is_no_space_glue(prev_text)) {
            need_space = false;
        } else if (kind == CXToken_Punctuation) {
            if (is_open_bracket(ts)) {
                if (token_is_word_like(prev_kind) || is_close_bracket(prev_text)) {
                    need_space = false;
                } else if (prev_kind == CXToken_Punctuation &&
                           (prev_text == "*" || prev_text == "&") &&
                           prev_amp_or_star_was_unary) {
                    need_space = false;
                } else {
                    need_space = true;
                }
            } else if (is_close_bracket(ts) || ts == "," || ts == ";") {
                need_space = false;
            } else if (ts == "*" || ts == "&") {
                // Decide unary vs binary by looking at what immediately precedes.
                // Unary: at start, or after an open bracket / `,` / `=` /
                // assignment-like punctuation / another operator.
                bool prev_makes_unary =
                    text.empty() ||
                    (prev_kind == CXToken_Punctuation &&
                     (is_open_bracket(prev_text) || prev_text == "," ||
                      prev_text == "=" || prev_text == "==" || prev_text == "!=" ||
                      prev_text == "<" || prev_text == ">" || prev_text == "<=" ||
                      prev_text == ">=" || prev_text == "&&" || prev_text == "||" ||
                      prev_text == "+" || prev_text == "-" || prev_text == "*" ||
                      prev_text == "/" || prev_text == "%" || prev_text == "!" ||
                      prev_text == "~" || prev_text == "?" || prev_text == ":" ||
                      prev_text == ";" || prev_text == "return")) ||
                    (prev_kind == CXToken_Keyword && prev_text == "return");

                if (prev_makes_unary) {
                    need_space = (prev_kind == CXToken_Keyword);  // `return &x` needs a space after return
                    this_amp_or_star_is_unary = true;
                } else if (token_is_word_like(prev_kind)) {
                    // `T* x` / `T& x` (declaration) or `a * b` (binary). Without
                    // semantic info we choose the declaration style: glue to type.
                    need_space = false;
                } else if (is_close_bracket(prev_text)) {
                    // `f() * g()` — binary; keep a space.
                    need_space = true;
                } else {
                    need_space = false;
                }
            } else if (is_unary_punct(ts) && !prev_allows_binary(prev_kind, prev_text)) {
                need_space = false;
            } else {
                // Generic punctuation — keep a space if previous is word-like.
                need_space = token_is_word_like(prev_kind) || is_close_bracket(prev_text);
            }
        } else {
            // word-like token (identifier / keyword / literal)
            if (prev_kind == CXToken_Punctuation) {
                if (is_open_bracket(prev_text)) {
                    need_space = false;
                } else if ((prev_text == "*" || prev_text == "&")) {
                    // After `*`/`&`: no space if it was unary, space if it was
                    // glued to a type identifier (declaration style).
                    need_space = !prev_amp_or_star_was_unary;
                } else if (prev_text == "!" || prev_text == "~" ||
                           prev_text == "++" || prev_text == "--") {
                    need_space = false;
                } else if (prev_text == "," || prev_text == ";") {
                    need_space = true;
                } else {
                    need_space = true;
                }
            } else {
                need_space = true;
            }
        }

        // Override: never emit duplicate or leading whitespace.
        if (need_space && (text.empty() || last_non_space_char() == '\0')) need_space = false;

        if (need_space) text.push_back(' ');
        text += ts;
        prev_kind = kind;
        prev_text = ts;
        prev_amp_or_star_was_unary = this_amp_or_star_is_unary;
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

// =============================================================================
// Source-location predicates
// =============================================================================
static bool cursor_is_from_file_or_header(CXCursor cursor, const std::string& main_file_path) {
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

    if (same_path(fname, main_file_path)) return true;

    std::filesystem::path mainp(main_file_path);
    auto root = mainp.parent_path().parent_path();
    if (!root.empty()) {
        std::error_code ec1, ec2;
        auto croot = std::filesystem::weakly_canonical(root, ec1);
        auto cfile = std::filesystem::weakly_canonical(fname, ec2);
        if (!ec1 && !ec2) {
            auto root_s = croot.string();
            auto file_s = cfile.string();
            if (file_s.rfind(root_s, 0) == 0) return true;
        }
    }
    return false;
}

// =============================================================================
// Callee-name extraction
// =============================================================================
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
        std::string name;
    } cd{""};

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

static std::string get_qualified_cursor_name(CXCursor cursor) {
    std::vector<std::string> parts;
    CXCursor cur = cursor;
    while (!clang_Cursor_isNull(cur)) {
        CXCursorKind k = clang_getCursorKind(cur);
        if (k == CXCursor_FunctionDecl || k == CXCursor_CXXMethod ||
            k == CXCursor_Constructor || k == CXCursor_Destructor ||
            k == CXCursor_FunctionTemplate || k == CXCursor_Namespace ||
            k == CXCursor_ClassDecl || k == CXCursor_StructDecl ||
            k == CXCursor_ClassTemplate) {
            std::string s = to_string_and_dispose(clang_getCursorSpelling(cur));
            if (!s.empty()) parts.push_back(s);
        }
        cur = clang_getCursorSemanticParent(cur);
    }

    std::reverse(parts.begin(), parts.end());

    std::ostringstream oss;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) oss << "::";
        oss << parts[i];
    }
    return oss.str();
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

static std::string format_type_placeholder(CXType t) {
    std::string ts = to_string_and_dispose(clang_getTypeSpelling(t));
    ts = clip_text(trim_copy(ts));
    if (ts.empty()) ts = "unknown";
    return "<type: " + ts + ">";
}

// Render an unresolved variable reference as `name (<type: T>)` so the user
// sees both the source-level identifier and its static type. Falls back to
// just the placeholder when the name is empty.
static std::string format_named_type_placeholder(const std::string& name, CXType t) {
    std::string ph = format_type_placeholder(t);
    if (name.empty()) return ph;
    return clip_text(name + " (" + ph + ")");
}

// =============================================================================
// Assignment detection: distinguishes `a = b` from `a + b`, `a == b`, etc.
// We look at tokens between the LHS extent and the RHS extent: if any of them
// is exactly one of the assignment operators, it's an assignment. For compound
// operators (+=, -=, *=, /=, %=, <<=, >>=, &=, |=, ^=) the resulting value
// depends on the prior value, so we conservatively mark it as opaque (type
// placeholder), not as the RHS.
// =============================================================================
enum class AssignKind { None, Pure, Compound };

static AssignKind detect_assignment_between(CXCursor bin_op,
                                            CXCursor lhs,
                                            CXCursor rhs,
                                            CXTranslationUnit tu)
{
    // Get the source range that contains both children, then look at tokens
    // strictly between lhs end and rhs start.
    CXSourceRange whole = clang_getCursorExtent(bin_op);
    CXSourceLocation lhs_end = clang_getRangeEnd(clang_getCursorExtent(lhs));
    CXSourceLocation rhs_start = clang_getRangeStart(clang_getCursorExtent(rhs));

    unsigned lhs_end_off = 0, rhs_start_off = 0;
    CXFile dummy;
    clang_getExpansionLocation(lhs_end, &dummy, nullptr, nullptr, &lhs_end_off);
    clang_getExpansionLocation(rhs_start, &dummy, nullptr, nullptr, &rhs_start_off);

    CXToken* tokens = nullptr;
    unsigned n_tokens = 0;
    clang_tokenize(tu, whole, &tokens, &n_tokens);

    AssignKind result = AssignKind::None;

    for (unsigned i = 0; i < n_tokens; ++i) {
        CXSourceLocation tloc = clang_getTokenLocation(tu, tokens[i]);
        unsigned toff = 0;
        clang_getExpansionLocation(tloc, &dummy, nullptr, nullptr, &toff);
        if (toff < lhs_end_off) continue;
        if (toff >= rhs_start_off) break;

        auto kind = clang_getTokenKind(tokens[i]);
        if (kind != CXToken_Punctuation) continue;

        auto text = to_string_and_dispose(clang_getTokenSpelling(tu, tokens[i]));
        if (text == "=") {
            result = AssignKind::Pure;
            break;
        }
        if (text == "+="  || text == "-="  || text == "*="  || text == "/="  ||
            text == "%="  || text == "<<=" || text == ">>=" || text == "&="  ||
            text == "|="  || text == "^=") {
            result = AssignKind::Compound;
            break;
        }
    }

    if (tokens) clang_disposeTokens(tu, tokens, n_tokens);
    return result;
}

// =============================================================================
// Resolution model
// =============================================================================
//
// LocalValue:
//   A single recorded value of a variable at a specific line. We keep a vector
//   per name (history), so `int x=1; f(x); x=2; g(x);` resolves correctly.
//
// ResolvedValue (legacy name) is retained as an alias for clarity in places
// where only one entry is needed.
// =============================================================================
struct LocalValue {
    std::string text;
    unsigned    line = 0;
    bool        known = false;
};
using ResolvedValue = LocalValue;

struct FunctionFrame {
    std::string qualified_name;
    std::unordered_map<std::string, std::vector<LocalValue>> locals;  // name → history
};

struct PendingCall {
    unsigned line = 0;
    unsigned col = 0;
    std::string file_path;
    std::string context_function;  // qualified
    std::string context_class;
    std::string context_namespace;

    std::string callee_name;       // simple (db lookup is by simple name)
    std::string callee_qualified;  // qualified, used for graph edges

    std::string raw_line;
    std::vector<std::string> arguments;

    // True when the enclosing caller is reachable from a call-graph root
    // (main or any external-linkage function). When false, the finding is
    // still emitted but its base_risk_score is scaled down.
    bool reachable_from_root = true;
};

struct FunctionSummary {
    std::string qualified_name;
    std::string simple_name;
    std::string file_path;
    CXCursor    cursor{};
    bool        has_cursor = false;

    bool        is_static = false;        // internal linkage
    bool        in_anon_ns = false;
    bool        is_definition = false;

    std::vector<std::string> param_names;
    std::vector<std::string> param_types;

    // Locals seen at definition-collection time (no caller context).
    // history per name.
    std::unordered_map<std::string, std::vector<LocalValue>> locals;

    // For inter-procedural inlining of return values we keep the cursor of the
    // return expression itself (preferred over textual return_expr).
    CXCursor return_cursor{};
    bool     has_return_cursor = false;

    // Outgoing calls discovered in this function (qualified name when we could
    // resolve it, otherwise simple name). Used to build the call graph.
    std::vector<std::string> callees;
};

// Class field registry — populated in phase 2.5 (between body collection and
// reachability). For each class, stores per-field type spelling and a best-
// guess resolved initializer value (from inline default member initializer
// and/or constructor member-init list).
struct FieldInfo {
    std::string type_spelling;          // e.g. "EVP_PKEY *"
    std::string resolved_value;         // resolved initializer text, possibly empty
    bool has_value = false;             // true if resolved_value is meaningful
};
using ClassFieldMap = std::unordered_map<std::string /*field name*/, FieldInfo>;
using ClassFieldRegistry = std::unordered_map<std::string /*class qualified*/, ClassFieldMap>;

// A single mutation of a class field discovered statically inside one method.
// Used by the inter-procedural field-state engine.
struct FieldEffect {
    enum class Kind {
        DirectAssign,   // this->field = expr;   (or field = expr;)
        AddressOfArg,   // some_call(…, &field, …)
    };
    Kind        kind        = Kind::DirectAssign;
    std::string field_name;            // mutated field
    std::string class_qualified;       // class that owns the field
    unsigned    line        = 0;       // location inside the method
    std::string assigned_value;        // resolved RHS (for DirectAssign) or call render (for AddressOfArg)
};

// One "event" in a method's body that the inter-procedural engine cares about:
// either a mutation of the enclosing class's field, or a call into another
// method of the same class. We keep them ordered by source line so the engine
// can replay them sequentially.
struct MethodEvent {
    enum class Kind { Mutation, IntraClassCall };
    Kind        kind         = Kind::Mutation;
    unsigned    line         = 0;
    FieldEffect mutation{};            // valid when kind == Mutation
    std::string call_qualified;        // valid when kind == IntraClassCall
};

struct MethodEffects {
    std::string class_qualified;
    std::vector<MethodEvent> events;   // ordered by source line
};

using MethodEffectsMap = std::unordered_map<std::string /*method qualified*/, MethodEffects>;

// Mapping field_name -> current resolved value, scoped to the current class
// and "point in time" during a call-graph walk. The walker mutates this map
// as it replays method events in source order.
using FieldStateMap = std::unordered_map<std::string, std::string>;

struct ResolutionContext {
    FunctionFrame* frame = nullptr;
    const std::unordered_map<std::string, FunctionSummary>* summaries = nullptr;

    // Parameter bindings of the *current* function, supplied by the caller.
    // Values are already-resolved strings (concrete value or "<type: T>").
    std::unordered_map<std::string, std::string> param_bindings;

    // Recursion guard for inlining.
    std::unordered_set<std::string> active_functions;

    // Class context for member references through implicit `this`.
    const ClassFieldRegistry* field_registry = nullptr;
    std::string current_class_qualified;   // qualified name of the enclosing class, if any
    std::string current_class_simple;      // simple name, used for rendering Class::field

    // Inter-procedural field state: for the currently-walked method, this maps
    // field name -> latest-known resolved value at the current point in the
    // method's body. Looked up by resolve_member_ref / resolve_decl_ref
    // BEFORE falling back to the static field registry (inline / ctor init).
    const FieldStateMap* dynamic_field_state = nullptr;
};

// =============================================================================
// Forward declarations
// =============================================================================
static std::string resolve_expr(CXCursor cursor,
                                CXTranslationUnit tu,
                                ResolutionContext& rc,
                                unsigned line_limit,
                                int depth);

// =============================================================================
// Local lookup honoring scope by line: returns the most recent assignment
// with line ≤ line_limit. Falls back to param_bindings.
// =============================================================================
static std::string lookup_local(const ResolutionContext& rc,
                                const std::string& name,
                                unsigned line_limit)
{
    if (rc.frame) {
        auto it = rc.frame->locals.find(name);
        if (it != rc.frame->locals.end()) {
            const auto& hist = it->second;
            const LocalValue* best = nullptr;
            for (const auto& v : hist) {
                if (!v.known) continue;
                if (v.line <= line_limit) {
                    if (!best || v.line >= best->line) best = &v;
                }
            }
            if (best) return best->text;
        }
    }

    auto pit = rc.param_bindings.find(name);
    if (pit != rc.param_bindings.end() && !pit->second.empty()) {
        return pit->second;
    }

    return {};
}

static const FunctionSummary* find_function_summary(const ResolutionContext& rc,
                                                    const std::string& callee_simple,
                                                    const std::string& callee_qualified = {})
{
    if (!rc.summaries) return nullptr;

    if (!callee_qualified.empty()) {
        auto it = rc.summaries->find(callee_qualified);
        if (it != rc.summaries->end()) return &it->second;
    }

    auto it = rc.summaries->find(callee_simple);
    if (it != rc.summaries->end()) return &it->second;

    const FunctionSummary* fallback = nullptr;
    int matches = 0;
    for (const auto& kv : *rc.summaries) {
        if (kv.second.simple_name == callee_simple) {
            fallback = &kv.second;
            ++matches;
            if (matches > 1) break;
        }
    }
    // If multiple overloads share the simple name we can't pick safely;
    // give up on inlining (caller will keep "<type: …>").
    return matches == 1 ? fallback : nullptr;
}

// =============================================================================
// resolve_decl_ref / resolve_member_ref / resolve_call_expr / resolve_expr
// =============================================================================
static std::string resolve_decl_ref(CXCursor ref_cursor,
                                    CXTranslationUnit tu,
                                    ResolutionContext& rc,
                                    unsigned line_limit,
                                    int depth)
{
    std::string name = to_string_and_dispose(clang_getCursorSpelling(ref_cursor));
    if (name.empty()) return {};

    std::string local = lookup_local(rc, name, line_limit);
    if (!local.empty()) {
        return clip_text(local);
    }

    CXCursor decl = clang_getCursorReferenced(ref_cursor);
    if (clang_Cursor_isNull(decl)) {
        return format_named_type_placeholder(name, clang_getCursorType(ref_cursor));
    }

    CXCursorKind dk = clang_getCursorKind(decl);

    if (dk == CXCursor_ParmDecl) {
        auto pit = rc.param_bindings.find(name);
        if (pit != rc.param_bindings.end() && !pit->second.empty()) {
            return clip_text(pit->second);
        }
        return format_named_type_placeholder(name, clang_getCursorType(decl));
    }

    if (dk == CXCursor_EnumConstantDecl) {
        std::string val = evaluate_cursor_value(decl, tu);
        if (!val.empty()) return clip_text(val);
        return format_named_type_placeholder(name, clang_getCursorType(decl));
    }

    if (dk == CXCursor_FieldDecl) {
        // Field access via implicit `this`. Render as `Class::field` and
        // (when known) substitute a value from the field registry; otherwise
        // fall back to `Class::field (<type: T>)`.
        std::string cls;
        {
            CXCursor parent = clang_getCursorSemanticParent(decl);
            if (!clang_Cursor_isNull(parent)) {
                CXCursorKind pk = clang_getCursorKind(parent);
                if (pk == CXCursor_ClassDecl || pk == CXCursor_StructDecl ||
                    pk == CXCursor_ClassTemplate) {
                    cls = to_string_and_dispose(clang_getCursorSpelling(parent));
                }
            }
        }
        std::string qualified_field;
        if (!cls.empty()) qualified_field = cls + "::" + name;
        else              qualified_field = name;

        // 1) Dynamic field state (last-seen value at current source position).
        if (rc.dynamic_field_state) {
            auto dit = rc.dynamic_field_state->find(name);
            if (dit != rc.dynamic_field_state->end() && !dit->second.empty()) {
                return clip_text(dit->second);
            }
        }
        // 2) Static field registry (inline / ctor init).
        if (rc.field_registry) {
            std::string cls_qual = get_qualified_cursor_name(
                clang_getCursorSemanticParent(decl));
            auto cit = rc.field_registry->find(cls_qual);
            if (cit != rc.field_registry->end()) {
                auto fit = cit->second.find(name);
                if (fit != cit->second.end() && fit->second.has_value &&
                    !fit->second.resolved_value.empty())
                {
                    return clip_text(fit->second.resolved_value);
                }
            }
        }
        return format_named_type_placeholder(qualified_field, clang_getCursorType(decl));
    }

    if (dk == CXCursor_VarDecl && depth > 0) {
        // First try a compile-time evaluation — covers true constants.
        std::string val = evaluate_cursor_value(decl, tu);
        if (!val.empty()) return clip_text(val);

        // Collect non-type initializer children. We only "unfold" a VarDecl into
        // its initializer when that initializer is a *simple* expression
        // (a literal, a single decl-ref, a single member-ref). For anything
        // resembling a constructor call, multi-arg list, or compound expression,
        // we keep the variable name with its type placeholder — otherwise we
        // produce mangled text like `vector(begin(), end())` instead of `dv`.
        auto ch = get_children(decl);
        std::vector<CXCursor> init_children;
        for (const auto& c : ch) {
            CXCursorKind ck = clang_getCursorKind(c);
            if (ck == CXCursor_TypeRef || ck == CXCursor_NamespaceRef ||
                ck == CXCursor_TemplateRef) continue;
            init_children.push_back(c);
        }

        auto is_simple_init_kind = [](CXCursorKind ck) {
            return ck == CXCursor_IntegerLiteral ||
                   ck == CXCursor_FloatingLiteral ||
                   ck == CXCursor_StringLiteral ||
                   ck == CXCursor_CharacterLiteral ||
                   ck == CXCursor_CXXBoolLiteralExpr ||
                   ck == CXCursor_ImaginaryLiteral ||
                   ck == CXCursor_DeclRefExpr ||
                   ck == CXCursor_MemberRefExpr ||
                   ck == CXCursor_MemberRef ||
                   ck == CXCursor_UnexposedExpr ||
                   ck == CXCursor_ParenExpr;
        };

        if (init_children.size() == 1 && is_simple_init_kind(clang_getCursorKind(init_children.front()))) {
            CXCursor init = init_children.front();
            // Recurse, but if the resolved text differs from the variable name
            // and looks like a complex expression (contains '(' or ','), prefer
            // the typed name to keep the rendering close to the user's source.
            std::string rv = resolve_expr(init, tu, rc, line_limit, depth - 1);
            if (!rv.empty()) {
                bool complex = rv.find('(') != std::string::npos ||
                               rv.find(',') != std::string::npos;
                if (!complex) return clip_text(rv);
            }
        }

        return format_named_type_placeholder(name, clang_getCursorType(decl));
    }

    return format_named_type_placeholder(name, clang_getCursorType(decl));
}

static std::string resolve_member_ref(CXCursor cursor,
                                      CXTranslationUnit tu,
                                      ResolutionContext& rc,
                                      unsigned line_limit,
                                      int depth)
{
    std::string name = to_string_and_dispose(clang_getCursorSpelling(cursor));
    if (name.empty()) {
        return get_cursor_text(cursor, tu);
    }

    auto children = get_children(cursor);

    // Filter children: skip CXXThisExpr (we render implicit `this` access
    // as just the field name, not `this->field`) and type-related cursors.
    CXCursor explicit_base{};
    bool has_explicit_base = false;
    for (const auto& c : children) {
        CXCursorKind ck = clang_getCursorKind(c);
        // CXCursor_CXXThisExpr is exposed in libclang; some versions report it
        // as UnexposedExpr wrapping nothing. We treat any single-child
        // UnexposedExpr that resolves to empty text as implicit-this too.
        if (ck == CXCursor_TypeRef || ck == CXCursor_NamespaceRef ||
            ck == CXCursor_TemplateRef) continue;
        explicit_base = c;
        has_explicit_base = true;
        break;
    }

    if (has_explicit_base) {
        std::string base = resolve_expr(explicit_base, tu, rc, line_limit, depth - 1);
        // Drop trivial bases like `this` or empty text — render `field` alone.
        if (!base.empty() && base != "this") {
            return clip_text(base + "." + name);
        }
    }

    // Implicit-this or could-not-resolve base: render `Class::field` with type
    // or, when available, the resolved field initializer value.
    CXCursor ref = clang_getCursorReferenced(cursor);
    std::string field_name = name;
    CXType field_type = clang_getCursorType(cursor);
    std::string cls_simple;
    std::string cls_qualified;
    if (!clang_Cursor_isNull(ref)) {
        std::string ref_name = to_string_and_dispose(clang_getCursorSpelling(ref));
        if (!ref_name.empty()) field_name = ref_name;
        field_type = clang_getCursorType(ref);
        CXCursor parent = clang_getCursorSemanticParent(ref);
        if (!clang_Cursor_isNull(parent)) {
            CXCursorKind pk = clang_getCursorKind(parent);
            if (pk == CXCursor_ClassDecl || pk == CXCursor_StructDecl ||
                pk == CXCursor_ClassTemplate) {
                cls_simple = to_string_and_dispose(clang_getCursorSpelling(parent));
                cls_qualified = get_qualified_cursor_name(parent);
            }
        }
    }
    if (cls_simple.empty()) cls_simple = rc.current_class_simple;
    if (cls_qualified.empty()) cls_qualified = rc.current_class_qualified;

    // 1) Dynamic field state — latest-known value for this field inside the
    //    currently-walked method.
    if (rc.dynamic_field_state) {
        auto dit = rc.dynamic_field_state->find(field_name);
        if (dit != rc.dynamic_field_state->end() && !dit->second.empty()) {
            return clip_text(dit->second);
        }
    }
    // 2) Static field registry (inline / ctor init).
    if (rc.field_registry && !cls_qualified.empty()) {
        auto cit = rc.field_registry->find(cls_qualified);
        if (cit != rc.field_registry->end()) {
            auto fit = cit->second.find(field_name);
            if (fit != cit->second.end() && fit->second.has_value &&
                !fit->second.resolved_value.empty())
            {
                return clip_text(fit->second.resolved_value);
            }
        }
    }

    std::string qualified_field =
        cls_simple.empty() ? field_name : (cls_simple + "::" + field_name);
    return format_named_type_placeholder(qualified_field, field_type);
}

static std::string resolve_call_expr(CXCursor cursor,
                                     CXTranslationUnit tu,
                                     ResolutionContext& rc,
                                     unsigned line_limit,
                                     int depth)
{
    std::string callee_simple = get_callee_name(cursor, tu);
    if (callee_simple.empty()) callee_simple = "<call>";

    std::string callee_qualified;
    {
        CXCursor ref = clang_getCursorReferenced(cursor);
        if (!clang_Cursor_isNull(ref) && is_function_like_cursor(clang_getCursorKind(ref))) {
            callee_qualified = get_qualified_cursor_name(ref);
        }
    }

    // For method calls (CallExpr whose first child is a MemberRefExpr) we want
    // to reconstruct `base.method` instead of dropping the receiver.
    // The MemberRefExpr's children give us the receiver expression; the
    // MemberRefExpr's own spelling is the method name.
    std::string callee_display = callee_simple;
    {
        auto call_children = get_children(cursor);
        for (const auto& c : call_children) {
            CXCursorKind ck = clang_getCursorKind(c);
            if (ck == CXCursor_MemberRefExpr || ck == CXCursor_MemberRef) {
                // Find the receiver among the MemberRefExpr's own children,
                // skipping pure type cursors.
                auto mch = get_children(c);
                CXCursor recv{};
                bool has_recv = false;
                for (const auto& mc : mch) {
                    CXCursorKind mck = clang_getCursorKind(mc);
                    if (mck == CXCursor_TypeRef || mck == CXCursor_NamespaceRef ||
                        mck == CXCursor_TemplateRef) continue;
                    recv = mc;
                    has_recv = true;
                    break;
                }
                if (has_recv) {
                    std::string base = resolve_expr(recv, tu, rc, line_limit, depth - 1);
                    if (!base.empty() && base != "this") {
                        callee_display = base + "." + callee_simple;
                    }
                }
                break; // only first member-ref child matters
            }
            if (ck == CXCursor_DeclRefExpr || ck == CXCursor_CallExpr ||
                ck == CXCursor_UnexposedExpr) {
                // The callee position has already been resolved by
                // get_callee_name; we don't need to rebuild it here.
                break;
            }
        }
    }

    std::vector<std::string> actuals;
    int na = clang_Cursor_getNumArguments(cursor);
    for (int i = 0; i < na; ++i) {
        CXCursor arg = clang_Cursor_getArgument(cursor, i);
        std::string a = resolve_expr(arg, tu, rc, line_limit, depth - 1);
        if (a.empty()) a = format_type_placeholder(clang_getCursorType(arg));
        actuals.push_back(clip_text(a));
    }

    // Try to inline the callee's return expression by recursively re-resolving
    // it under a context whose param_bindings are the actuals computed above.
    // This replaces the previous textual substitute_bindings approach.
    if (depth > 1) {
        if (const auto* summary = find_function_summary(rc, callee_simple, callee_qualified)) {
            const std::string summary_key =
                summary->qualified_name.empty() ? summary->simple_name : summary->qualified_name;
            if (!summary_key.empty() &&
                summary->has_return_cursor &&
                rc.active_functions.find(summary_key) == rc.active_functions.end())
            {
                ResolutionContext nested;
                nested.frame = nullptr;                       // no caller locals visible inside callee
                nested.summaries = rc.summaries;
                nested.active_functions = rc.active_functions;
                nested.active_functions.insert(summary_key);

                for (std::size_t i = 0; i < summary->param_names.size(); ++i) {
                    std::string bound;
                    if (i < actuals.size()) bound = actuals[i];
                    if (bound.empty() && i < summary->param_types.size()) {
                        bound = "<type: " + summary->param_types[i] + ">";
                    }
                    nested.param_bindings[summary->param_names[i]] = clip_text(bound);
                }

                // Also expose callee's pre-collected locals as last-resort bindings.
                for (const auto& kv : summary->locals) {
                    if (kv.first.empty() || kv.second.empty()) continue;
                    const auto& hist = kv.second;
                    const LocalValue* latest = nullptr;
                    for (const auto& v : hist) {
                        if (!v.known) continue;
                        if (!latest || v.line >= latest->line) latest = &v;
                    }
                    if (latest && nested.param_bindings.find(kv.first) == nested.param_bindings.end()) {
                        nested.param_bindings[kv.first] = latest->text;
                    }
                }

                std::string rr = resolve_expr(summary->return_cursor, tu, nested,
                                              UINT_MAX, kMaxInlineExpansionDepth);
                if (!rr.empty()) return clip_text(rr);
            }
        }
    }

    std::ostringstream oss;
    oss << callee_display << "(";
    for (std::size_t i = 0; i < actuals.size(); ++i) {
        if (i) oss << ", ";
        oss << actuals[i];
    }
    oss << ")";
    return clip_text(oss.str());
}

static std::string resolve_expr(CXCursor cursor,
                                CXTranslationUnit tu,
                                ResolutionContext& rc,
                                unsigned line_limit,
                                int depth)
{
    if (clang_Cursor_isNull(cursor)) return {};
    if (depth <= 0) {
        std::string eval = evaluate_cursor_value(cursor, tu);
        if (!eval.empty()) return eval;
        return get_cursor_text(cursor, tu);
    }

    CXCursorKind kind = clang_getCursorKind(cursor);

    if (is_literal_like(kind)) {
        std::string eval = evaluate_cursor_value(cursor, tu);
        if (!eval.empty()) return eval;
        return get_cursor_text(cursor, tu);
    }

    switch (kind) {
        case CXCursor_DeclRefExpr:
            return resolve_decl_ref(cursor, tu, rc, line_limit, depth);

        case CXCursor_MemberRefExpr:
        case CXCursor_MemberRef:
            return resolve_member_ref(cursor, tu, rc, line_limit, depth);

        case CXCursor_ParenExpr: {
            auto children = get_children(cursor);
            if (!children.empty()) return resolve_expr(children.front(), tu, rc, line_limit, depth - 1);
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
            return get_cursor_text(cursor, tu);
        }

        case CXCursor_CallExpr:
            return resolve_call_expr(cursor, tu, rc, line_limit, depth);

        case CXCursor_UnexposedExpr: {
            auto children = get_children(cursor);
            if (children.size() == 1) {
                return resolve_expr(children.front(), tu, rc, line_limit, depth - 1);
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

// =============================================================================
// Collect local definitions and assignments within a function body, stopping
// at nested function/lambda/class boundaries.
//
// The collection populates `frame.locals` as a *history* per variable name.
// =============================================================================
static void record_local(FunctionFrame& frame,
                         const std::string& name,
                         const std::string& value,
                         unsigned line)
{
    if (name.empty() || value.empty()) return;
    LocalValue lv;
    lv.text = clip_text(value);
    lv.line = line;
    lv.known = true;
    frame.locals[name].push_back(std::move(lv));
}

static bool is_scope_boundary(CXCursorKind k) {
    if (is_function_like_cursor(k)) return true;
    switch (k) {
        case CXCursor_LambdaExpr:
        case CXCursor_ClassDecl:
        case CXCursor_StructDecl:
        case CXCursor_ClassTemplate:
            return true;
        default:
            return false;
    }
}

struct DefCollectPayload {
    const std::string* file_path;
    CXTranslationUnit tu;
    FunctionFrame* frame;
    const std::unordered_map<std::string, FunctionSummary>* summaries;
    bool stop_at_nested;  // true when walking inside an outer function body
};

static void collect_definitions_recursive(CXCursor cursor,
                                          const std::string& file_path,
                                          CXTranslationUnit tu,
                                          FunctionFrame& frame,
                                          const std::unordered_map<std::string, FunctionSummary>& summaries,
                                          bool stop_at_nested);

static void visit_for_defs(CXCursor parent,
                           const std::string& file_path,
                           CXTranslationUnit tu,
                           FunctionFrame& frame,
                           const std::unordered_map<std::string, FunctionSummary>& summaries,
                           bool stop_at_nested)
{
    DefCollectPayload payload{&file_path, tu, &frame, &summaries, stop_at_nested};
    clang_visitChildren(
        parent,
        [](CXCursor child, CXCursor, CXClientData data) -> CXChildVisitResult {
            auto* p = static_cast<DefCollectPayload*>(data);
            collect_definitions_recursive(child, *p->file_path, p->tu, *p->frame,
                                          *p->summaries, p->stop_at_nested);
            return CXChildVisit_Continue;
        },
        &payload
    );
}

static void collect_definitions_recursive(CXCursor cursor,
                                          const std::string& file_path,
                                          CXTranslationUnit tu,
                                          FunctionFrame& frame,
                                          const std::unordered_map<std::string, FunctionSummary>& summaries,
                                          bool stop_at_nested)
{
    if (!cursor_is_from_file_or_header(cursor, file_path)) return;

    CXCursorKind kind = clang_getCursorKind(cursor);

    // Stop walking into nested function / lambda / class bodies — their locals
    // must not pollute the outer function's frame.
    if (stop_at_nested && is_scope_boundary(kind)) return;

    CXSourceLocation loc = clang_getCursorLocation(cursor);
    CXFile cf;
    unsigned line = 0, col = 0;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    (void)cf; (void)col;

    ResolutionContext rc;
    rc.frame = &frame;
    rc.summaries = &summaries;

    if (kind == CXCursor_VarDecl) {
        std::string var_name = to_string_and_dispose(clang_getCursorSpelling(cursor));
        if (!var_name.empty()) {
            auto children = get_children(cursor);
            std::string init_value;
            for (const auto& c : children) {
                // Skip type-related children (they are not initializers).
                CXCursorKind ck = clang_getCursorKind(c);
                if (ck == CXCursor_TypeRef || ck == CXCursor_NamespaceRef ||
                    ck == CXCursor_TemplateRef) continue;
                init_value = resolve_expr(c, tu, rc, line, kMaxResolveDepth);
                if (!init_value.empty()) break;
            }
            if (init_value.empty()) {
                init_value = evaluate_cursor_value(cursor, tu);
            }
            if (init_value.empty()) {
                init_value = format_type_placeholder(clang_getCursorType(cursor));
            }
            record_local(frame, var_name, init_value, line);
#if PQC_AST_DEBUG
            std::cerr << "[AST][debug] var init " << var_name << " -> "
                      << clip_text(init_value) << " at line " << line << "\n";
#endif
        }
    } else if (kind == CXCursor_BinaryOperator) {
        auto children = get_children(cursor);
        if (children.size() >= 2) {
            AssignKind ak = detect_assignment_between(cursor, children[0], children[1], tu);
            if (ak != AssignKind::None) {
                std::string lhs = extract_assignment_lhs_name(children[0]);
                if (!lhs.empty()) {
                    std::string value;
                    if (ak == AssignKind::Pure) {
                        value = resolve_expr(children[1], tu, rc, line, kMaxResolveDepth);
                        if (value.empty()) {
                            value = format_type_placeholder(clang_getCursorType(children[1]));
                        }
                    } else {
                        // Compound assignment: result depends on prior value of lhs.
                        // Mark as opaque to avoid stale concrete substitution.
                        value = format_type_placeholder(clang_getCursorType(cursor));
                    }
                    record_local(frame, lhs, value, line);
#if PQC_AST_DEBUG
                    std::cerr << "[AST][debug] assign " << lhs << " -> "
                              << clip_text(value) << " at line " << line << "\n";
#endif
                }
            }
        }
    } else if (kind == CXCursor_CompoundAssignOperator) {
        // libclang sometimes exposes this explicitly.
        auto children = get_children(cursor);
        if (children.size() >= 1) {
            std::string lhs = extract_assignment_lhs_name(children[0]);
            if (!lhs.empty()) {
                record_local(frame, lhs,
                             format_type_placeholder(clang_getCursorType(cursor)),
                             line);
            }
        }
    }

    // Recurse into children, still respecting scope boundaries.
    visit_for_defs(cursor, file_path, tu, frame, summaries, stop_at_nested);
}

static void collect_definitions(CXCursor function_cursor,
                                const std::string& file_path,
                                CXTranslationUnit tu,
                                FunctionFrame& frame,
                                const std::unordered_map<std::string, FunctionSummary>& summaries)
{
    // The top-level is the function body itself; from here we forbid descending
    // into nested function-like / lambda / class scopes.
    visit_for_defs(function_cursor, file_path, tu, frame, summaries, /*stop_at_nested=*/true);
}

// =============================================================================
// Find the first return-statement cursor inside a function body (last-wins).
// =============================================================================
static void find_return_cursor(CXCursor cursor,
                               const std::string& file_path,
                               FunctionSummary& summary)
{
    if (!cursor_is_from_file_or_header(cursor, file_path)) return;

    CXCursorKind kind = clang_getCursorKind(cursor);
    if (is_scope_boundary(kind) && !clang_equalCursors(cursor, summary.cursor)) return;

    if (kind == CXCursor_ReturnStmt) {
        auto children = get_children(cursor);
        if (!children.empty()) {
            summary.return_cursor = children.front();
            summary.has_return_cursor = true;
        }
    }

    for (const auto& ch : get_children(cursor)) {
        find_return_cursor(ch, file_path, summary);
    }
}

// =============================================================================
// Collect outgoing call edges from a function body (for call-graph building).
// =============================================================================
static void collect_callees_recursive(CXCursor cursor,
                                      const std::string& file_path,
                                      CXTranslationUnit tu,
                                      const CXCursor& outer_fn,
                                      std::vector<std::string>& out)
{
    if (!cursor_is_from_file_or_header(cursor, file_path)) return;

    CXCursorKind kind = clang_getCursorKind(cursor);
    if (is_scope_boundary(kind) && !clang_equalCursors(cursor, outer_fn)) {
        // Don't descend into nested functions/lambdas/classes.
        return;
    }

    if (kind == CXCursor_CallExpr) {
        CXCursor ref = clang_getCursorReferenced(cursor);
        std::string key;
        if (!clang_Cursor_isNull(ref) && is_function_like_cursor(clang_getCursorKind(ref))) {
            key = get_qualified_cursor_name(ref);
        }
        if (key.empty()) key = get_callee_name(cursor, tu);
        if (!key.empty()) out.push_back(key);
    }

    for (const auto& ch : get_children(cursor)) {
        collect_callees_recursive(ch, file_path, tu, outer_fn, out);
    }
}

// =============================================================================
// Emission
// =============================================================================
struct VisitData {
    const VulnDatabase& db;
    std::vector<Finding>& findings;
    const std::string& file_path;
    const std::vector<std::string>& lines;
    CXTranslationUnit tu;

    // Built during phase 1 (precollect) and phase 2 (bodies):
    std::unordered_map<std::string, FunctionSummary> function_summaries;

    // Built during phase 2.5 (after bodies, before reachability):
    ClassFieldRegistry class_fields;

    // Built during phase 2.6 (after class_fields):
    //   method_qualified -> ordered list of field-mutations and intra-class calls
    MethodEffectsMap method_effects;

    // Built during phase 3 (call-graph reachability):
    std::unordered_set<std::string> reachable;
};

static void emit_finding(const PendingCall& pc, VisitData* vd) {
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
              << pc.file_path << ":" << pc.line << ":" << pc.col
              << (pc.reachable_from_root ? " [reachable]" : " [UNREACHABLE]")
              << "\n";
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
    // Apply the unreachable-call risk discount in-place. The schema stays the
    // same; downstream sorting by base_risk_score naturally deprioritizes
    // findings whose enclosing function is not called from any root.
    f.base_risk_score       = pc.reachable_from_root
                                ? opt->risk_score
                                : opt->risk_score * kUnreachableRiskFactor;
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

// =============================================================================
// Call-graph traversal: visit a function with a given set of param_bindings,
// emit findings for every CallExpr in its body, and recurse into callees with
// updated bindings.
// =============================================================================
struct CallSiteVisitState {
    VisitData* vd;
    FunctionFrame* frame;
    ResolutionContext* rc;
    // Pointed-to strings owned by walk_call_graph:
    const std::string* caller_simple;     // emitted as context_function
    const std::string* caller_qualified;  // used for reachability lookup
    const std::string* caller_class;
    const std::string* caller_namespace;
    int depth_left;
    // Out: pending calls discovered at this function (used to recurse).
    std::vector<std::pair<std::string /*qualified or simple*/,
                          std::vector<std::string> /*actuals*/>>* outgoing;
    // Dedup key set for emissions, scoped per top-level walk.
    std::set<std::tuple<std::string, unsigned, unsigned,
                        std::string, std::string>>* seen;
    CXCursor outer_fn;
    // Mutable field-state for the current method body. After each intra-class
    // call we replay its effects so subsequent sibling expressions see the
    // up-to-date field values.
    FieldStateMap* mutable_field_state;
    // Qualified name of the enclosing class (empty if free function). Used to
    // recognise intra-class call targets and gate replay.
    const std::string* enclosing_class_qualified;
};

static void walk_calls_in_function(CXCursor cursor, CallSiteVisitState* st);

// Forward declarations — these functions are defined later (phase 2.6) but the
// call-graph walker (phase 4) uses them to keep field state up-to-date as it
// visits each CallExpr in source order.
static FieldStateMap initial_field_state(const VisitData* vd,
                                         const std::string& cls_qual);
static void replay_method_effects(const VisitData* vd,
                                  const std::string& method_qual,
                                  FieldStateMap& state,
                                  std::unordered_set<std::string>& active,
                                  int depth_left);

static CXChildVisitResult walk_calls_visitor(CXCursor child, CXCursor, CXClientData data) {
    auto* st = static_cast<CallSiteVisitState*>(data);
    walk_calls_in_function(child, st);
    return CXChildVisit_Continue;
}

static void walk_calls_in_function(CXCursor cursor, CallSiteVisitState* st) {
    VisitData* vd = st->vd;
    if (!cursor_is_from_file_or_header(cursor, vd->file_path)) return;

    CXCursorKind kind = clang_getCursorKind(cursor);
    if (is_scope_boundary(kind) && !clang_equalCursors(cursor, st->outer_fn)) {
        return;
    }

    if (kind == CXCursor_CallExpr) {
        CXSourceLocation loc = clang_getCursorLocation(cursor);
        CXFile cf;
        unsigned line = 0, col = 0;
        clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
        (void)cf;

        std::string callee_simple = get_callee_name(cursor, vd->tu);
        std::string callee_qualified;
        {
            CXCursor ref = clang_getCursorReferenced(cursor);
            if (!clang_Cursor_isNull(ref) && is_function_like_cursor(clang_getCursorKind(ref))) {
                callee_qualified = get_qualified_cursor_name(ref);
            }
        }

        std::vector<std::string> actuals;
        int na = clang_Cursor_getNumArguments(cursor);
        for (int i = 0; i < na; ++i) {
            CXCursor arg = clang_Cursor_getArgument(cursor, i);
            std::string resolved = resolve_expr(arg, vd->tu, *st->rc, line, kMaxResolveDepth);
            if (resolved.empty()) {
                resolved = format_type_placeholder(clang_getCursorType(arg));
            }
            actuals.push_back(clip_text(resolved));
        }

        // Emit regardless of reachability; the unreachable case is reflected
        // via a discounted base_risk_score (see emit_finding).
        const bool reachable = vd->reachable.count(*st->caller_qualified) > 0;

        PendingCall pc;
        pc.line = line;
        pc.col = col;
        pc.file_path = vd->file_path;
        pc.context_function = *st->caller_simple;
        pc.context_class = *st->caller_class;
        pc.context_namespace = *st->caller_namespace;
        pc.callee_name = callee_simple;
        pc.callee_qualified = callee_qualified;
        if (line > 0 && line <= vd->lines.size()) {
            pc.raw_line = vd->lines[line - 1];
        }
        pc.arguments = actuals;
        pc.reachable_from_root = reachable;

        // Dedup key now includes a joined-arguments digest so two distinct
        // call sites on the same line aren't collapsed.
        std::ostringstream args_join;
        for (size_t i = 0; i < actuals.size(); ++i) {
            if (i) args_join << "|";
            args_join << actuals[i];
        }
        auto key = std::make_tuple(pc.file_path, pc.line, pc.col,
                                   pc.callee_name, args_join.str());
        if (st->seen->insert(key).second) {
            emit_finding(pc, vd);
        }

        // Queue for recursive descent regardless of reachability filter — the
        // outer driver decides what to do with callees.
        st->outgoing->emplace_back(
            callee_qualified.empty() ? callee_simple : callee_qualified,
            actuals
        );

        // Inter-procedural field-state replay: if this CallExpr resolves to a
        // method of the same enclosing class (and we have collected its
        // effects), apply those effects to the mutable field state so the
        // *next* CallExpr in this body sees the updated field values.
        if (st->mutable_field_state && st->enclosing_class_qualified &&
            !st->enclosing_class_qualified->empty() &&
            !callee_qualified.empty())
        {
            auto mit = vd->method_effects.find(callee_qualified);
            if (mit != vd->method_effects.end() &&
                mit->second.class_qualified == *st->enclosing_class_qualified)
            {
                std::unordered_set<std::string> active;
                replay_method_effects(vd, callee_qualified,
                                      *st->mutable_field_state,
                                      active, kMaxCallGraphDepth);
            }
        }
    }

    clang_visitChildren(cursor, walk_calls_visitor, st);
}

// =============================================================================
// Recursive call-graph walk with parameter propagation.
// =============================================================================
struct WalkKey {
    std::string qualified_name;
    std::vector<std::string> bindings;  // values for each param (ordered)
    bool operator==(const WalkKey& o) const {
        return qualified_name == o.qualified_name && bindings == o.bindings;
    }
};
struct WalkKeyHash {
    std::size_t operator()(const WalkKey& k) const noexcept {
        std::size_t h = std::hash<std::string>{}(k.qualified_name);
        for (const auto& b : k.bindings) {
            h ^= std::hash<std::string>{}(b) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        }
        return h;
    }
};

static void walk_call_graph(const FunctionSummary& fn,
                            const std::vector<std::string>& actuals_from_caller,
                            VisitData* vd,
                            std::unordered_set<WalkKey, WalkKeyHash>& visited,
                            std::set<std::tuple<std::string, unsigned, unsigned,
                                                std::string, std::string>>& seen,
                            int depth_left)
{
    if (depth_left <= 0) return;
    if (!fn.has_cursor) return;

    WalkKey key{fn.qualified_name, actuals_from_caller};
    if (!visited.insert(key).second) return;

    // Build the frame for this function. Start from definition-time locals
    // (already collected during phase 2), then bind params from caller.
    FunctionFrame frame;
    frame.qualified_name = fn.qualified_name;
    frame.locals = fn.locals;

    ResolutionContext rc;
    rc.frame = &frame;
    rc.summaries = &vd->function_summaries;
    rc.field_registry = &vd->class_fields;

    for (std::size_t i = 0; i < fn.param_names.size(); ++i) {
        std::string bound;
        if (i < actuals_from_caller.size()) bound = actuals_from_caller[i];
        if (bound.empty()) {
            if (i < fn.param_types.size() && !fn.param_types[i].empty()) {
                bound = "<type: " + fn.param_types[i] + ">";
            } else {
                bound = "<type: unknown>";
            }
        }
        rc.param_bindings[fn.param_names[i]] = clip_text(bound);
    }

    // Derive class / namespace from the cursor's semantic parents. This is the
    // *only* reliable way — the qualified-name string mixes class and
    // namespace segments together with no marker to tell them apart.
    std::string ns, cls, fn_simple = fn.simple_name;
    {
        std::vector<std::string> ns_parts;
        CXCursor cur = clang_getCursorSemanticParent(fn.cursor);
        while (!clang_Cursor_isNull(cur)) {
            CXCursorKind k = clang_getCursorKind(cur);
            std::string name = to_string_and_dispose(clang_getCursorSpelling(cur));
            if (k == CXCursor_Namespace) {
                if (!name.empty()) ns_parts.push_back(name);
            } else if (k == CXCursor_ClassDecl || k == CXCursor_StructDecl ||
                       k == CXCursor_ClassTemplate) {
                if (cls.empty() && !name.empty()) cls = name;
            } else if (k == CXCursor_TranslationUnit) {
                break;
            }
            cur = clang_getCursorSemanticParent(cur);
        }
        std::reverse(ns_parts.begin(), ns_parts.end());
        for (const auto& p : ns_parts) {
            if (!ns.empty()) ns += "::";
            ns += p;
        }
    }

    // Propagate enclosing class info into the resolution context so member
    // references through implicit `this` can be rendered with the correct
    // class prefix and substituted with field-registry values.
    {
        CXCursor cur = clang_getCursorSemanticParent(fn.cursor);
        while (!clang_Cursor_isNull(cur)) {
            CXCursorKind k = clang_getCursorKind(cur);
            if (k == CXCursor_ClassDecl || k == CXCursor_StructDecl ||
                k == CXCursor_ClassTemplate) {
                rc.current_class_simple = to_string_and_dispose(clang_getCursorSpelling(cur));
                rc.current_class_qualified = get_qualified_cursor_name(cur);
                break;
            }
            if (k == CXCursor_TranslationUnit) break;
            cur = clang_getCursorSemanticParent(cur);
        }
    }

    // Inter-procedural field state for *this* invocation of the method. Seed
    // from the class's static initializers (inline + ctor); subsequent
    // intra-class calls in the body mutate it via replay_method_effects.
    FieldStateMap current_state;
    if (!rc.current_class_qualified.empty()) {
        current_state = initial_field_state(vd, rc.current_class_qualified);
    }
    rc.dynamic_field_state = &current_state;

    std::vector<std::pair<std::string, std::vector<std::string>>> outgoing;
    CallSiteVisitState st;
    st.vd = vd;
    st.frame = &frame;
    st.rc = &rc;
    // Emit the *simple* name as context_function; class and namespace are
    // exposed in their own Finding fields. Reachability lookup uses the
    // qualified name (matches keys stored in vd->reachable).
    st.caller_simple = &fn_simple;
    st.caller_qualified = &fn.qualified_name;
    st.caller_class = &cls;
    st.caller_namespace = &ns;
    st.depth_left = depth_left;
    st.outgoing = &outgoing;
    st.seen = &seen;
    st.outer_fn = fn.cursor;
    st.mutable_field_state = &current_state;
    st.enclosing_class_qualified = &rc.current_class_qualified;

    clang_visitChildren(fn.cursor, walk_calls_visitor, &st);

    // Recurse into callees that we have summaries for.
    for (const auto& kv : outgoing) {
        const std::string& callee_key = kv.first;
        const auto& callee_actuals = kv.second;

        ResolutionContext tmp;
        tmp.summaries = &vd->function_summaries;
        const FunctionSummary* sub = nullptr;
        // Try qualified, then simple (find_function_summary handles both).
        if (!callee_key.empty()) {
            auto it = vd->function_summaries.find(callee_key);
            if (it != vd->function_summaries.end()) sub = &it->second;
            else sub = find_function_summary(tmp, callee_key);
        }
        if (!sub) continue;
        walk_call_graph(*sub, callee_actuals, vd, visited, seen, depth_left - 1);
    }
}

// =============================================================================
// Phase 2.5 — collect class fields with their inline / ctor initializer values.
// =============================================================================
static void resolve_field_initializer(CXCursor init_cursor,
                                      CXTranslationUnit tu,
                                      VisitData* vd,
                                      FieldInfo& out)
{
    // Use a minimal ResolutionContext: no frame, no param bindings, but with
    // access to function summaries (so a ctor-init expression that calls a
    // pure function with literal args can still be inlined). Field registry
    // is intentionally NOT yet wired — we're building it.
    ResolutionContext rc;
    rc.summaries = &vd->function_summaries;
    rc.field_registry = &vd->class_fields;

    std::string resolved = resolve_expr(init_cursor, tu, rc, UINT_MAX, kMaxResolveDepth);
    if (!resolved.empty()) {
        out.resolved_value = resolved;
        out.has_value = true;
    }
}

static void collect_class_fields(VisitData* vd) {
    // Visit every ClassDecl / StructDecl reachable from the TU root and walk
    // its immediate declarations.
    auto tu_cursor = clang_getTranslationUnitCursor(vd->tu);

    // We need a stateful recursive walk; use a free helper that re-enters on
    // nested namespaces / classes.
    std::function<void(CXCursor)> walk_decl = [&](CXCursor c) {
        CXCursorKind kind = clang_getCursorKind(c);
        // TU root has no file location; allow descent unconditionally.
        if (kind != CXCursor_TranslationUnit &&
            !cursor_is_from_file_or_header(c, vd->file_path)) return;

        if (kind == CXCursor_ClassDecl || kind == CXCursor_StructDecl ||
            kind == CXCursor_ClassTemplate)
        {
            std::string class_qual = get_qualified_cursor_name(c);
            if (!class_qual.empty()) {
                auto& fields = vd->class_fields[class_qual];

                // Walk class members.
                for (const auto& member : get_children(c)) {
                    CXCursorKind mk = clang_getCursorKind(member);

                    if (mk == CXCursor_FieldDecl) {
                        std::string fname = to_string_and_dispose(
                            clang_getCursorSpelling(member));
                        if (fname.empty()) continue;
                        FieldInfo& fi = fields[fname];
                        if (fi.type_spelling.empty()) {
                            fi.type_spelling = to_string_and_dispose(
                                clang_getTypeSpelling(clang_getCursorType(member)));
                        }

                        // Look for an in-class default member initializer.
                        // libclang exposes it as a child expression of the
                        // FieldDecl (filtering out type / namespace cursors).
                        for (const auto& fc : get_children(member)) {
                            CXCursorKind fck = clang_getCursorKind(fc);
                            if (fck == CXCursor_TypeRef ||
                                fck == CXCursor_NamespaceRef ||
                                fck == CXCursor_TemplateRef) continue;
                            if (!fi.has_value) {
                                resolve_field_initializer(fc, vd->tu, vd, fi);
                            }
                            break;
                        }
                    }
                }

                // Second sub-pass over constructors of this class to pick up
                // their member-init lists. We only consume an initializer if
                // the field has no inline value yet (avoid overwriting), and
                // we accept it unconditionally when there is exactly one ctor.
                int ctor_count = 0;
                for (const auto& member : get_children(c)) {
                    if (clang_getCursorKind(member) == CXCursor_Constructor &&
                        clang_isCursorDefinition(member)) {
                        ++ctor_count;
                    }
                }
                const bool single_ctor = (ctor_count == 1);

                for (const auto& member : get_children(c)) {
                    if (clang_getCursorKind(member) != CXCursor_Constructor) continue;
                    if (!clang_isCursorDefinition(member)) continue;

                    for (const auto& mi : get_children(member)) {
                        if (clang_getCursorKind(mi) != CXCursor_MemberRef) continue;
                        // The MemberRef inside a constructor declaration is
                        // the member-init-list entry. Its spelling is the
                        // field name; its siblings (next children of the
                        // ctor cursor, with matching extent) carry the init
                        // expression — but libclang here gives us the init
                        // expression as a child of the MemberRef itself in
                        // most versions. Try children first.
                        std::string fname = to_string_and_dispose(
                            clang_getCursorSpelling(mi));
                        if (fname.empty()) continue;

                        auto fit = fields.find(fname);
                        if (fit == fields.end()) continue;
                        // Skip if we already have an inline value, unless
                        // there's exactly one ctor (then ctor wins).
                        if (fit->second.has_value && !single_ctor) continue;

                        // The initializer expression follows the MemberRef in
                        // the ctor's child list. Find it by extent.
                        bool found_init = false;
                        auto ctor_children = get_children(member);
                        for (std::size_t i = 0; i + 1 < ctor_children.size(); ++i) {
                            if (clang_equalCursors(ctor_children[i], mi)) {
                                CXCursor init = ctor_children[i + 1];
                                CXCursorKind ik = clang_getCursorKind(init);
                                if (ik != CXCursor_TypeRef &&
                                    ik != CXCursor_NamespaceRef &&
                                    ik != CXCursor_TemplateRef &&
                                    ik != CXCursor_MemberRef &&
                                    ik != CXCursor_ParmDecl &&
                                    ik != CXCursor_CompoundStmt)
                                {
                                    FieldInfo tmp = fit->second;
                                    resolve_field_initializer(init, vd->tu, vd, tmp);
                                    if (tmp.has_value) {
                                        fit->second = tmp;
                                    }
                                    found_init = true;
                                }
                                break;
                            }
                        }
                        (void)found_init;
                    }
                }
            }
        }

        // Recurse into namespaces and nested classes.
        if (kind == CXCursor_Namespace || kind == CXCursor_TranslationUnit ||
            kind == CXCursor_ClassDecl || kind == CXCursor_StructDecl ||
            kind == CXCursor_ClassTemplate ||
            kind == CXCursor_LinkageSpec || kind == CXCursor_UnexposedDecl)
        {
            for (const auto& ch : get_children(c)) {
                walk_decl(ch);
            }
        }
    };

    walk_decl(tu_cursor);
}

// =============================================================================
// Phase 2.6 — inter-procedural field-effect collection.
//
// For every method definition that belongs to a class, walk its body and emit
// an ordered list of "events":
//   • Mutation     — the method assigns to a field of its own class
//                    (this->field = expr;  or  field = expr;
//                     or  some_call(…, &field, …)).
//   • IntraClassCall — the method calls another method of the same class on
//                      the implicit `this` (e.g. this->foo() or just foo()).
//
// The walk_call_graph phase later replays these events in source order to
// maintain a dynamic field-state map that drives field resolution.
// =============================================================================

// Helper: is `cursor` a reference to a field that belongs to class `cls_qual`?
// If yes, fill out `field_name`. Accepts both DeclRefExpr to a FieldDecl and
// MemberRefExpr whose canonical referenced decl is a FieldDecl in the class.
static bool cursor_is_own_field_ref(CXCursor cursor,
                                    const std::string& cls_qual,
                                    std::string& out_field_name)
{
    CXCursor ref = clang_getCursorReferenced(cursor);
    if (clang_Cursor_isNull(ref)) return false;
    if (clang_getCursorKind(ref) != CXCursor_FieldDecl) return false;
    CXCursor parent = clang_getCursorSemanticParent(ref);
    if (clang_Cursor_isNull(parent)) return false;
    CXCursorKind pk = clang_getCursorKind(parent);
    if (pk != CXCursor_ClassDecl && pk != CXCursor_StructDecl &&
        pk != CXCursor_ClassTemplate) return false;
    std::string parent_qual = get_qualified_cursor_name(parent);
    if (parent_qual != cls_qual) return false;
    out_field_name = to_string_and_dispose(clang_getCursorSpelling(ref));
    return !out_field_name.empty();
}

// Helper: is `cursor` a CXXMethod whose semantic parent is class `cls_qual`?
static bool cursor_is_own_method_call(CXCursor call_cursor,
                                      const std::string& cls_qual,
                                      std::string& out_method_qualified)
{
    CXCursor ref = clang_getCursorReferenced(call_cursor);
    if (clang_Cursor_isNull(ref)) return false;
    CXCursorKind rk = clang_getCursorKind(ref);
    if (rk != CXCursor_CXXMethod && rk != CXCursor_Constructor &&
        rk != CXCursor_Destructor) return false;
    CXCursor parent = clang_getCursorSemanticParent(ref);
    if (clang_Cursor_isNull(parent)) return false;
    CXCursorKind pk = clang_getCursorKind(parent);
    if (pk != CXCursor_ClassDecl && pk != CXCursor_StructDecl &&
        pk != CXCursor_ClassTemplate) return false;
    if (get_qualified_cursor_name(parent) != cls_qual) return false;
    out_method_qualified = get_qualified_cursor_name(ref);
    return !out_method_qualified.empty();
}

// Helper: render a call-expression as text by re-resolving its callee + args
// in a neutral context (no caller frame, no dynamic state, just static
// summaries + field registry). Used to label AddressOfArg effects.
static std::string render_call_for_effect(CXCursor call_cursor,
                                          VisitData* vd)
{
    ResolutionContext rc;
    rc.summaries = &vd->function_summaries;
    rc.field_registry = &vd->class_fields;
    std::string out = resolve_expr(call_cursor, vd->tu, rc, UINT_MAX, kMaxInlineExpansionDepth);
    return clip_text(out);
}

static CXChildVisitResult method_event_visitor(CXCursor cursor, CXCursor /*parent*/, CXClientData data);

struct MethodEventCtx {
    VisitData* vd;
    MethodEffects* out;
    CXCursor outer_method;
    std::string cls_qual;
};

static CXChildVisitResult method_event_visitor(CXCursor cursor, CXCursor /*parent*/, CXClientData data) {
    auto* ctx = static_cast<MethodEventCtx*>(data);
    VisitData* vd = ctx->vd;

    if (!cursor_is_from_file_or_header(cursor, vd->file_path)) {
        return CXChildVisit_Continue;
    }

    CXCursorKind kind = clang_getCursorKind(cursor);
    // Don't descend into nested functions / lambdas / classes.
    if (is_scope_boundary(kind) && !clang_equalCursors(cursor, ctx->outer_method)) {
        return CXChildVisit_Continue;
    }

    auto get_line = [&](CXCursor c) -> unsigned {
        CXSourceLocation loc = clang_getCursorLocation(c);
        unsigned ln = 0;
        clang_getExpansionLocation(loc, nullptr, &ln, nullptr, nullptr);
        return ln;
    };

    // ----- 1) Direct field assignment: BinaryOperator '=' with LHS being
    //          a reference to one of our class's fields.
    if (kind == CXCursor_BinaryOperator) {
        auto children = get_children(cursor);
        if (children.size() >= 2) {
            CXCursor lhs = children.front();
            CXCursor rhs = children.back();
            AssignKind ak = detect_assignment_between(cursor, lhs, rhs, vd->tu);
            if (ak == AssignKind::Pure) {
                std::string field_name;
                if (cursor_is_own_field_ref(lhs, ctx->cls_qual, field_name)) {
                    // Resolve RHS in a neutral-ish context (with current field
                    // registry as fallback; but the engine then replays this
                    // event so we don't need dynamic state here).
                    ResolutionContext rc;
                    rc.summaries = &vd->function_summaries;
                    rc.field_registry = &vd->class_fields;
                    rc.current_class_qualified = ctx->cls_qual;
                    std::string rhs_value = resolve_expr(rhs, vd->tu, rc, UINT_MAX, kMaxResolveDepth);
                    if (rhs_value.empty()) {
                        rhs_value = format_type_placeholder(clang_getCursorType(rhs));
                    }
                    MethodEvent ev;
                    ev.kind = MethodEvent::Kind::Mutation;
                    ev.line = get_line(cursor);
                    ev.mutation.kind = FieldEffect::Kind::DirectAssign;
                    ev.mutation.field_name = field_name;
                    ev.mutation.class_qualified = ctx->cls_qual;
                    ev.mutation.line = ev.line;
                    ev.mutation.assigned_value = clip_text(rhs_value);
                    ctx->out->events.push_back(std::move(ev));
                }
            }
        }
    }

    // ----- 2) CallExpr handling:
    //          (a) any &field argument — register AddressOfArg mutation;
    //          (b) intra-class call — register IntraClassCall event.
    if (kind == CXCursor_CallExpr) {
        // (a) AddressOfArg
        int na = clang_Cursor_getNumArguments(cursor);
        for (int i = 0; i < na; ++i) {
            CXCursor arg = clang_Cursor_getArgument(cursor, i);
            CXCursorKind ak = clang_getCursorKind(arg);
            CXCursor inner = arg;
            // Peel UnexposedExpr / ParenExpr.
            for (int peel = 0; peel < 3; ++peel) {
                if (clang_getCursorKind(inner) != CXCursor_UnexposedExpr &&
                    clang_getCursorKind(inner) != CXCursor_ParenExpr) break;
                auto ch = get_children(inner);
                if (ch.empty()) break;
                inner = ch.front();
            }
            (void)ak;
            if (clang_getCursorKind(inner) == CXCursor_UnaryOperator) {
                // Tokenize first token to confirm it's '&'.
                CXSourceRange ext = clang_getCursorExtent(inner);
                CXToken* toks = nullptr;
                unsigned ntok = 0;
                clang_tokenize(vd->tu, ext, &toks, &ntok);
                bool is_addr_of = false;
                if (ntok > 0) {
                    std::string t = to_string_and_dispose(clang_getTokenSpelling(vd->tu, toks[0]));
                    if (t == "&") is_addr_of = true;
                }
                if (toks) clang_disposeTokens(vd->tu, toks, ntok);

                if (is_addr_of) {
                    auto uch = get_children(inner);
                    if (!uch.empty()) {
                        CXCursor target = uch.front();
                        // Look through casts/unexposed.
                        for (int peel = 0; peel < 3; ++peel) {
                            if (clang_getCursorKind(target) != CXCursor_UnexposedExpr &&
                                clang_getCursorKind(target) != CXCursor_ParenExpr) break;
                            auto tch = get_children(target);
                            if (tch.empty()) break;
                            target = tch.front();
                        }
                        std::string field_name;
                        if (cursor_is_own_field_ref(target, ctx->cls_qual, field_name)) {
                            MethodEvent ev;
                            ev.kind = MethodEvent::Kind::Mutation;
                            ev.line = get_line(cursor);
                            ev.mutation.kind = FieldEffect::Kind::AddressOfArg;
                            ev.mutation.field_name = field_name;
                            ev.mutation.class_qualified = ctx->cls_qual;
                            ev.mutation.line = ev.line;
                            ev.mutation.assigned_value = render_call_for_effect(cursor, vd);
                            ctx->out->events.push_back(std::move(ev));
                        }
                    }
                }
            }
        }

        // (b) IntraClassCall — only register if the receiver is implicit-this
        //     (we don't track other objects' state).
        std::string method_qual;
        if (cursor_is_own_method_call(cursor, ctx->cls_qual, method_qual)) {
            // Check whether the call is on implicit `this` (no explicit base
            // among children that resolves to anything other than `this`).
            bool implicit_this = true;
            for (const auto& c : get_children(cursor)) {
                CXCursorKind ck = clang_getCursorKind(c);
                if (ck == CXCursor_MemberRefExpr || ck == CXCursor_MemberRef) {
                    for (const auto& mc : get_children(c)) {
                        CXCursorKind mck = clang_getCursorKind(mc);
                        if (mck == CXCursor_TypeRef || mck == CXCursor_NamespaceRef ||
                            mck == CXCursor_TemplateRef) continue;
                        // Any non-trivial base disqualifies.
                        implicit_this = false;
                        break;
                    }
                    break;
                }
            }
            if (implicit_this) {
                MethodEvent ev;
                ev.kind = MethodEvent::Kind::IntraClassCall;
                ev.line = get_line(cursor);
                ev.call_qualified = method_qual;
                ctx->out->events.push_back(std::move(ev));
            }
        }
    }

    return CXChildVisit_Recurse;
}

static void collect_method_effects(VisitData* vd) {
    for (auto& kv : vd->function_summaries) {
        FunctionSummary& s = kv.second;
        if (!s.has_cursor) continue;
        CXCursorKind ck = clang_getCursorKind(s.cursor);
        if (ck != CXCursor_CXXMethod && ck != CXCursor_Constructor &&
            ck != CXCursor_Destructor) continue;

        // Find the enclosing class.
        std::string cls_qual;
        {
            CXCursor parent = clang_getCursorSemanticParent(s.cursor);
            if (!clang_Cursor_isNull(parent)) {
                CXCursorKind pk = clang_getCursorKind(parent);
                if (pk == CXCursor_ClassDecl || pk == CXCursor_StructDecl ||
                    pk == CXCursor_ClassTemplate) {
                    cls_qual = get_qualified_cursor_name(parent);
                }
            }
        }
        if (cls_qual.empty()) continue;

        MethodEffects me;
        me.class_qualified = cls_qual;

        MethodEventCtx ctx{vd, &me, s.cursor, cls_qual};
        clang_visitChildren(s.cursor, method_event_visitor, &ctx);

        // Sort events by line just in case AST visitation order isn't strictly
        // source-order (it usually is, but defensive).
        std::sort(me.events.begin(), me.events.end(),
                  [](const MethodEvent& a, const MethodEvent& b) {
                      return a.line < b.line;
                  });

        if (!me.events.empty()) {
            vd->method_effects[s.qualified_name] = std::move(me);
        }
    }
}

// Apply the static (inline / ctor) field initializers as the starting field
// state for a class.
static FieldStateMap initial_field_state(const VisitData* vd,
                                         const std::string& cls_qual)
{
    FieldStateMap out;
    auto it = vd->class_fields.find(cls_qual);
    if (it == vd->class_fields.end()) return out;
    for (const auto& kv : it->second) {
        if (kv.second.has_value && !kv.second.resolved_value.empty()) {
            out[kv.first] = kv.second.resolved_value;
        }
    }
    return out;
}

// Recursively replay the effects of `method_qual` on `state`. `active` guards
// against direct/indirect recursion through the call graph.
static void replay_method_effects(const VisitData* vd,
                                  const std::string& method_qual,
                                  FieldStateMap& state,
                                  std::unordered_set<std::string>& active,
                                  int depth_left)
{
    if (depth_left <= 0) return;
    auto mit = vd->method_effects.find(method_qual);
    if (mit == vd->method_effects.end()) return;
    if (!active.insert(method_qual).second) return;

    for (const auto& ev : mit->second.events) {
        if (ev.kind == MethodEvent::Kind::Mutation) {
            if (!ev.mutation.field_name.empty() && !ev.mutation.assigned_value.empty()) {
                state[ev.mutation.field_name] = ev.mutation.assigned_value;
            }
        } else if (ev.kind == MethodEvent::Kind::IntraClassCall) {
            replay_method_effects(vd, ev.call_qualified, state, active, depth_left - 1);
        }
    }

    active.erase(method_qual);
}

// =============================================================================
// Phase 1 — precollect signatures + linkage flags for *every* defined function.
// =============================================================================
static bool is_in_anonymous_namespace(CXCursor c) {
    CXCursor cur = clang_getCursorSemanticParent(c);
    while (!clang_Cursor_isNull(cur)) {
        if (clang_getCursorKind(cur) == CXCursor_Namespace) {
            std::string name = to_string_and_dispose(clang_getCursorSpelling(cur));
            if (name.empty()) return true;
        }
        cur = clang_getCursorSemanticParent(cur);
    }
    return false;
}

static void build_function_summary(CXCursor cursor, VisitData* vd) {
    if (!clang_isCursorDefinition(cursor)) return;

    FunctionSummary summary;
    summary.qualified_name = get_qualified_cursor_name(cursor);
    summary.simple_name = to_string_and_dispose(clang_getCursorSpelling(cursor));
    summary.file_path = vd->file_path;
    summary.cursor = cursor;
    summary.has_cursor = true;
    summary.is_definition = true;
    summary.in_anon_ns = is_in_anonymous_namespace(cursor);

    CX_StorageClass sc = clang_Cursor_getStorageClass(cursor);
    summary.is_static = (sc == CX_SC_Static);

    int argc = clang_Cursor_getNumArguments(cursor);
    for (int i = 0; i < argc; ++i) {
        CXCursor arg = clang_Cursor_getArgument(cursor, i);
        summary.param_names.push_back(to_string_and_dispose(clang_getCursorSpelling(arg)));
        summary.param_types.push_back(
            to_string_and_dispose(clang_getTypeSpelling(clang_getCursorType(arg)))
        );
    }

    // Locals will be (re-)collected in phase 2 once all signatures are known.
    vd->function_summaries[summary.qualified_name] = std::move(summary);
}

static CXChildVisitResult precollect_visitor(CXCursor cursor, CXCursor, CXClientData data) {
    auto* vd = static_cast<VisitData*>(data);

    if (!cursor_is_from_file_or_header(cursor, vd->file_path)) {
        return CXChildVisit_Continue;
    }

    CXCursorKind kind = clang_getCursorKind(cursor);
    if (is_function_like_cursor(kind) && clang_isCursorDefinition(cursor)) {
        build_function_summary(cursor, vd);
    }

    clang_visitChildren(cursor, precollect_visitor, data);
    return CXChildVisit_Continue;
}

// =============================================================================
// Phase 2 — for every collected summary, populate locals + return cursor +
// outgoing callee names (for the graph).
// =============================================================================
static void populate_function_bodies(VisitData* vd) {
    // Copy keys first because we'll mutate values in the map.
    std::vector<std::string> keys;
    keys.reserve(vd->function_summaries.size());
    for (const auto& kv : vd->function_summaries) keys.push_back(kv.first);

    for (const auto& key : keys) {
        auto it = vd->function_summaries.find(key);
        if (it == vd->function_summaries.end()) continue;
        FunctionSummary& s = it->second;
        if (!s.has_cursor) continue;

        FunctionFrame frame;
        frame.qualified_name = s.qualified_name;
        collect_definitions(s.cursor, vd->file_path, vd->tu, frame, vd->function_summaries);
        s.locals = std::move(frame.locals);

        find_return_cursor(s.cursor, vd->file_path, s);

        s.callees.clear();
        collect_callees_recursive(s.cursor, vd->file_path, vd->tu, s.cursor, s.callees);
    }
}

// =============================================================================
// Phase 3 — build reachability set from roots:
//   roots = main + all functions with external linkage (i.e. non-static,
//           not in an anonymous namespace), per user's choice.
//
// We additionally mark *every* defined function as analyzable, but the
// emission step filters by reachability.
// =============================================================================
static void compute_reachability(VisitData* vd) {
    std::deque<std::string> frontier;
    auto add_root = [&](const std::string& key) {
        if (vd->reachable.insert(key).second) frontier.push_back(key);
    };

    for (const auto& kv : vd->function_summaries) {
        const auto& s = kv.second;
        if (s.simple_name == "main") {
            add_root(s.qualified_name);
        } else if (!s.is_static && !s.in_anon_ns) {
            add_root(s.qualified_name);
        }
    }

    while (!frontier.empty()) {
        std::string cur = std::move(frontier.front());
        frontier.pop_front();
        auto it = vd->function_summaries.find(cur);
        if (it == vd->function_summaries.end()) continue;
        for (const auto& callee_key : it->second.callees) {
            // callee_key may be qualified or simple; try both.
            if (vd->function_summaries.count(callee_key)) {
                if (vd->reachable.insert(callee_key).second) frontier.push_back(callee_key);
                continue;
            }
            // Simple-name fallback (single match only, to avoid wrong unions).
            const FunctionSummary* unique = nullptr;
            int matches = 0;
            for (const auto& kv2 : vd->function_summaries) {
                if (kv2.second.simple_name == callee_key) {
                    unique = &kv2.second;
                    ++matches;
                    if (matches > 1) break;
                }
            }
            if (matches == 1 && unique) {
                if (vd->reachable.insert(unique->qualified_name).second) {
                    frontier.push_back(unique->qualified_name);
                }
            }
        }
    }
}

// =============================================================================
// Phase 4 — drive emission by walking every defined function with empty
// caller bindings. This guarantees stand-alone analysis for unreachable
// functions too (kept analyzed, but their findings are filtered out in
// emit_finding's reachability check). At the same time, reachable roots get
// proper inter-procedural propagation of param values.
// =============================================================================
static void drive_emission(VisitData* vd) {
    std::unordered_set<WalkKey, WalkKeyHash> visited;
    std::set<std::tuple<std::string, unsigned, unsigned,
                        std::string, std::string>> seen;

    // 1) Walk from reachable roots first so propagated values win over
    //    plain "<type: T>" fallbacks. Top-level walks use empty actuals
    //    (because main has none meaningful for our purposes, and other roots
    //    are external entry points whose callers we don't see).
    for (const auto& root_key : vd->reachable) {
        auto it = vd->function_summaries.find(root_key);
        if (it == vd->function_summaries.end()) continue;
        const FunctionSummary& fn = it->second;
        // Only start from roots (functions with no caller in our graph that
        // are themselves in the reachable set). Practically: every reachable
        // function is walked anyway via recursion, but starting from each
        // reachable function ensures unreached overloads of public APIs are
        // still covered.
        walk_call_graph(fn, /*actuals*/ {}, vd, visited, seen, kMaxCallGraphDepth);
    }

    // 2) For *unreachable* functions: we still want to analyze them
    //    standalone (their findings will be dropped by emit_finding, but the
    //    user asked us to keep them analyzable). Walk with empty bindings.
    //
    //    Note: emit_finding currently gates on reachability via vd->reachable.
    //    If you want unreachable functions to also produce findings (e.g. for
    //    a "reachable" flag in Finding), flip the gate in emit_finding.
    for (const auto& kv : vd->function_summaries) {
        if (vd->reachable.count(kv.first)) continue;
        walk_call_graph(kv.second, /*actuals*/ {}, vd, visited, seen, kMaxCallGraphDepth);
    }
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

    VisitData vd{db_, out, real_path.string(), lines, tu, {}, {}, {}, {}};

    // Phase 1: precollect signatures of every defined function.
    clang_visitChildren(clang_getTranslationUnitCursor(tu), precollect_visitor, &vd);

    // Phase 2: collect bodies (locals, return cursors, outgoing edges).
    populate_function_bodies(&vd);

    // Phase 2.5: collect class fields with inline / ctor initializer values.
    collect_class_fields(&vd);

    // Phase 2.6: collect per-method field effects (mutations + intra-class
    // calls) for inter-procedural field-state propagation in phase 4.
    collect_method_effects(&vd);

    // Phase 3: compute reachability from main + external-linkage roots.
    compute_reachability(&vd);

#if PQC_AST_DEBUG
    std::cerr << "[AST][debug] reachable functions (" << vd.reachable.size() << "):\n";
    for (const auto& q : vd.reachable) std::cerr << "  - " << q << "\n";
#endif

    // Phase 4: walk call-graph and emit findings.
    drive_emission(&vd);

    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return true;
}

#endif // PQC_HAS_LIBCLANG

} // namespace pqc
