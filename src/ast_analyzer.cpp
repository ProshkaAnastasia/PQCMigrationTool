// src/ast_analyzer.cpp
#include "pqc/ast_analyzer.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>

#ifdef PQC_HAS_LIBCLANG
#  include <clang-c/Index.h>
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
}

std::vector<Finding> ASTAnalyzer::analyze(const ProjectInventory& inv) const {
    std::vector<Finding> all;
    if (has_libclang_) {
        std::cout << "[AST] Using libclang for analysis\n";
    } else {
        std::cout << "[AST] libclang unavailable — using token-based fallback\n";
    }
    for (auto* fe : inv.get_source_files()) {
        auto r = analyze_file(fe->path);
        all.insert(all.end(), r.begin(), r.end());
    }
    return all;
}

std::vector<Finding> ASTAnalyzer::analyze_file(const std::filesystem::path& p) const {
    std::vector<Finding> out;
#ifdef PQC_HAS_LIBCLANG
    if (has_libclang_) {
        if (!try_libclang(p, out)) {
            out = fallback_->analyze_file(p);
        }
        return out;
    }
#endif
    return fallback_->analyze_file(p);
}

#ifdef PQC_HAS_LIBCLANG
namespace {

static std::string evaluate_cursor_value(CXCursor cursor, CXTranslationUnit tu) {
    CXEvalResult eval = clang_Cursor_Evaluate(cursor);
    if (eval) {
        CXEvalResultKind kind = clang_EvalResult_getKind(eval);
        std::string result;
        switch (kind) {
            case CXEval_Int: {
                long long val = clang_EvalResult_getAsLongLong(eval);
                result = std::to_string(val);
                break;
            }
            case CXEval_Float: {
                double val = clang_EvalResult_getAsDouble(eval);
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%g", val);
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
        if (!result.empty()) return result;
    }

    CXSourceRange range = clang_getCursorExtent(cursor);
    CXToken* tokens = nullptr;
    unsigned n_tokens = 0;
    clang_tokenize(tu, range, &tokens, &n_tokens);

    std::string text;
    for (unsigned i = 0; i < n_tokens; ++i) {
        CXString ts = clang_getTokenSpelling(tu, tokens[i]);
        const char* s = clang_getCString(ts);
        if (s && *s) {
            if (!text.empty()) text += ' ';
            text += s;
        }
        clang_disposeString(ts);
    }
    if (tokens) clang_disposeTokens(tu, tokens, n_tokens);

    return text;
}

static std::string resolve_decl_ref(CXCursor ref_cursor, CXTranslationUnit tu) {
    CXCursor decl = clang_getCursorReferenced(ref_cursor);
    if (clang_Cursor_isNull(decl)) return {};

    CXCursorKind dk = clang_getCursorKind(decl);
    if (dk == CXCursor_VarDecl || dk == CXCursor_FieldDecl ||
        dk == CXCursor_EnumConstantDecl || dk == CXCursor_ParmDecl) {

        std::string val = evaluate_cursor_value(decl, tu);
        if (!val.empty()) return val;

        struct InitData {
            std::string value;
            CXTranslationUnit tu;
        } idata{"", tu};

        clang_visitChildren(
            decl,
            [](CXCursor child, CXCursor, CXClientData cd) -> CXChildVisitResult {
                auto* id = static_cast<InitData*>(cd);
                CXCursorKind ck = clang_getCursorKind(child);
                if (ck == CXCursor_IntegerLiteral || ck == CXCursor_FloatingLiteral ||
                    ck == CXCursor_StringLiteral  || ck == CXCursor_CharacterLiteral ||
                    ck == CXCursor_UnaryOperator  || ck == CXCursor_BinaryOperator   ||
                    ck == CXCursor_DeclRefExpr) {
                    id->value = evaluate_cursor_value(child, id->tu);
                    if (!id->value.empty()) return CXChildVisit_Break;
                }
                return CXChildVisit_Continue;
            },
            &idata
        );

        if (!idata.value.empty()) return idata.value;
    }
    return {};
}

static std::string resolve_arg_value(CXCursor arg_cursor, CXTranslationUnit tu) {
    CXCursorKind kind = clang_getCursorKind(arg_cursor);

    if (kind == CXCursor_IntegerLiteral || kind == CXCursor_FloatingLiteral ||
        kind == CXCursor_StringLiteral  || kind == CXCursor_CharacterLiteral) {
        return evaluate_cursor_value(arg_cursor, tu);
    }

    if (kind == CXCursor_DeclRefExpr) {
        std::string resolved = resolve_decl_ref(arg_cursor, tu);
        if (!resolved.empty()) {
            CXString sp = clang_getCursorSpelling(arg_cursor);
            std::string name = clang_getCString(sp);
            clang_disposeString(sp);
            if (!name.empty() && resolved != name)
                return name + "=" + resolved;
            return resolved;
        }
        CXString sp = clang_getCursorSpelling(arg_cursor);
        std::string name = clang_getCString(sp);
        clang_disposeString(sp);
        return name;
    }

    if (kind == CXCursor_UnaryOperator ||
        kind == CXCursor_BinaryOperator ||
        kind == CXCursor_ConditionalOperator ||
        kind == CXCursor_ParenExpr) {
        return evaluate_cursor_value(arg_cursor, tu);
    }

    return evaluate_cursor_value(arg_cursor, tu);
}

struct VisitData {
    const VulnDatabase&              db;
    std::vector<Finding>&            findings;
    const std::string&               file_path;
    const std::vector<std::string>&  lines;
    CXTranslationUnit                tu;
    std::string                      cur_fn;
    std::string                      cur_cls;
    std::string                      cur_ns;
};

CXChildVisitResult ast_visitor(CXCursor cursor, CXCursor /*parent*/, CXClientData data) {
    auto* vd = static_cast<VisitData*>(data);

    CXSourceLocation loc = clang_getCursorLocation(cursor);
    if (clang_Location_isInSystemHeader(loc)) return CXChildVisit_Continue;

    CXFile cf;
    unsigned line = 0, col = 0;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    if (cf) {
        CXString cfn = clang_getFileName(cf);
        std::string fname = clang_getCString(cfn);
        clang_disposeString(cfn);
        if (!fname.empty() && fname != vd->file_path) {
            std::error_code ec;
            auto p1 = std::filesystem::canonical(fname, ec);
            auto p2 = std::filesystem::canonical(vd->file_path, ec);
            if (!ec && p1 != p2) return CXChildVisit_Continue;
            if (ec && fname != vd->file_path) return CXChildVisit_Continue;
        }
    }

    CXCursorKind kind = clang_getCursorKind(cursor);

    std::string sf = vd->cur_fn;
    std::string sc = vd->cur_cls;
    std::string sn = vd->cur_ns;
    bool scope_changed = false;

    if (kind == CXCursor_FunctionDecl   || kind == CXCursor_CXXMethod     ||
        kind == CXCursor_Constructor    || kind == CXCursor_Destructor    ||
        kind == CXCursor_FunctionTemplate) {
        CXString s = clang_getCursorSpelling(cursor);
        vd->cur_fn = clang_getCString(s);
        clang_disposeString(s);
        scope_changed = true;
    } else if (kind == CXCursor_ClassDecl || kind == CXCursor_StructDecl ||
               kind == CXCursor_ClassTemplate) {
        CXString s = clang_getCursorSpelling(cursor);
        vd->cur_cls = clang_getCString(s);
        clang_disposeString(s);
        scope_changed = true;
    } else if (kind == CXCursor_Namespace) {
        CXString s = clang_getCursorSpelling(cursor);
        std::string ns = clang_getCString(s);
        clang_disposeString(s);
        if (!ns.empty()) {
            if (!vd->cur_ns.empty()) vd->cur_ns += "::";
            vd->cur_ns += ns;
            scope_changed = true;
        }
    }

    if (kind == CXCursor_CallExpr) {
        std::string fname;
        CXCursor ref = clang_getCursorReferenced(cursor);
        if (!clang_Cursor_isNull(ref) && !clang_equalCursors(ref, cursor)) {
            CXString rs = clang_getCursorSpelling(ref);
            fname = clang_getCString(rs);
            clang_disposeString(rs);
        }
        if (fname.empty()) {
            CXString cs = clang_getCursorSpelling(cursor);
            fname = clang_getCString(cs);
            clang_disposeString(cs);
        }

        if (!fname.empty()) {
            auto opt = vd->db.find_by_name(fname);
            if (opt) {
                Finding f;
                f.function_name         = opt->name;
                f.file_path             = vd->file_path;
                f.line_number           = static_cast<int>(line);
                f.column                = static_cast<int>(col);
                f.library               = opt->library_name;
                f.algorithm             = opt->algorithm;
                f.category              = opt->category;
                f.quantum_vulnerability = opt->quantum_vulnerability;
                f.base_risk_score       = opt->risk_score;
                f.analyzer_mode         = "ast";
                f.vuln_id               = opt->id;
                f.nist_reference        = opt->nist_reference;
                f.tc26_reference        = opt->tc26_reference;
                f.context_function      = vd->cur_fn.empty() ? "<global>" : vd->cur_fn;
                f.context_class         = vd->cur_cls;
                f.context_namespace     = vd->cur_ns;
                if (line > 0 && line <= (unsigned)vd->lines.size())
                    f.raw_line = vd->lines[line - 1];

                int na = clang_Cursor_getNumArguments(cursor);
                for (int i = 0; i < na; ++i) {
                    CXCursor arg = clang_Cursor_getArgument(cursor, i);
                    std::string resolved = resolve_arg_value(arg, vd->tu);
                    if (!resolved.empty()) {
                        f.arguments.push_back(resolved);
                    } else {
                        CXString as = clang_getCursorSpelling(arg);
                        std::string av = clang_getCString(as);
                        clang_disposeString(as);
                        if (!av.empty()) f.arguments.push_back(av);
                    }
                }

                vd->findings.push_back(std::move(f));
            }
        }
    }

    clang_visitChildren(cursor, ast_visitor, data);

    if (scope_changed) {
        vd->cur_fn  = sf;
        vd->cur_cls = sc;
        vd->cur_ns  = sn;
    }

    return CXChildVisit_Continue;
}

}

bool ASTAnalyzer::try_libclang(const std::filesystem::path& path,
                               std::vector<Finding>& out) const
{
    constexpr bool kAstDebug = true; // потом можно сделать через cfg.verbose / env

    auto dbg = [&](const std::string& msg) {
        if (kAstDebug) std::cerr << "[ASTDBG] " << msg << "\n";
    };

    std::error_code ec;
    auto canon = std::filesystem::weakly_canonical(path, ec);
    std::filesystem::path real_path = ec ? std::filesystem::absolute(path) : canon;

    dbg("input path      = " + path.string());
    dbg("resolved path   = " + real_path.string());

    std::vector<std::string> lines;
    {
        std::ifstream ifs(real_path);
        if (!ifs.is_open()) {
            dbg("cannot open file for reading: " + real_path.string());
            return false;
        }
        std::string l;
        while (std::getline(ifs, l)) lines.push_back(l);
    }

    dbg("source lines    = " + std::to_string(lines.size()));

    CXIndex index = clang_createIndex(/*excludeDeclarationsFromPCH=*/0,
                                      /*displayDiagnostics=*/0);

    std::vector<std::string> args_str = {
        "-std=c++17",
        "-w",
        "-ferror-limit=0",
    };

    for (const auto& d : include_dirs_) {
        args_str.push_back("-I");
        args_str.push_back(d);
    }

    auto parent = real_path.parent_path().string();
    auto root   = real_path.parent_path().parent_path().string();

    if (!parent.empty()) {
        args_str.push_back("-I");
        args_str.push_back(parent);
    }
    if (!root.empty() && root != parent) {
        args_str.push_back("-I");
        args_str.push_back(root);
    }

    if (kAstDebug) {
        dbg("clang args:");
        for (std::size_t i = 0; i < args_str.size(); ++i) {
            std::cerr << "  [ARG " << i << "] " << args_str[i] << "\n";
        }
    }

    std::vector<const char*> cargs;
    cargs.reserve(args_str.size());
    for (auto& s : args_str) cargs.push_back(s.c_str());

    unsigned tu_flags =
        CXTranslationUnit_DetailedPreprocessingRecord |
        CXTranslationUnit_KeepGoing;

    dbg("parsing translation unit...");

    CXTranslationUnit tu = clang_parseTranslationUnit(
        index,
        real_path.string().c_str(),
        cargs.data(), static_cast<int>(cargs.size()),
        nullptr, 0,
        tu_flags);

    if (!tu) {
        dbg("clang_parseTranslationUnit returned null");
        clang_disposeIndex(index);
        return false;
    }

    unsigned nd = clang_getNumDiagnostics(tu);
    dbg("diagnostics count = " + std::to_string(nd));

    unsigned err_count = 0;
    unsigned fatal_count = 0;

    for (unsigned i = 0; i < nd; ++i) {
        CXDiagnostic d = clang_getDiagnostic(tu, i);
        CXDiagnosticSeverity sev = clang_getDiagnosticSeverity(d);

        if (sev == CXDiagnostic_Error) ++err_count;
        if (sev == CXDiagnostic_Fatal) ++fatal_count;

        CXString ds = clang_formatDiagnostic(d, clang_defaultDiagnosticDisplayOptions());
        std::cerr << "[CLANG] " << clang_getCString(ds) << "\n";
        clang_disposeString(ds);
        clang_disposeDiagnostic(d);
    }

    dbg("errors           = " + std::to_string(err_count));
    dbg("fatal errors     = " + std::to_string(fatal_count));

    const std::size_t before = out.size();

    VisitData vd{db_, out, real_path.string(), lines, tu, "", "", ""};

    dbg("starting AST traversal...");
    clang_visitChildren(clang_getTranslationUnitCursor(tu), ast_visitor, &vd);
    dbg("finished AST traversal");

    const std::size_t added = out.size() - before;
    dbg("AST findings added = " + std::to_string(added));

    if (added == 0) {
        dbg("no findings added for file: " + real_path.string());
    }

    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return true;
}

#endif 

} 