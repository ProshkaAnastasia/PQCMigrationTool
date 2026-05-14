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
    if(has_libclang_) {
        std::cout << "[AST] Using libclang for analysis\n";
    } else {
        std::cout << "[AST] libclang unavailable — using token-based fallback\n";
    }
    for(auto* fe : inv.get_source_files()) {
        auto r = analyze_file(fe->path);
        all.insert(all.end(), r.begin(), r.end());
    }
    return all;
}

std::vector<Finding> ASTAnalyzer::analyze_file(const std::filesystem::path& p) const {
    std::vector<Finding> out;
#ifdef PQC_HAS_LIBCLANG
    if(has_libclang_) {
        if(!try_libclang(p, out)) {
            // parse failed — fall back silently
            out = fallback_->analyze_file(p);
        }
        return out;
    }
#endif
    return fallback_->analyze_file(p);
}

// ─────────────────────────────────────────────────────────────────────────────
#ifdef PQC_HAS_LIBCLANG
namespace {

struct VisitData {
    const VulnDatabase& db;
    std::vector<Finding>& findings;
    const std::string& file_path;
    const std::vector<std::string>& lines;
    CXTranslationUnit tu;
    // Mutable scope context, updated during traversal
    std::string cur_fn, cur_cls, cur_ns;
};

// Manual-recursion visitor that maintains scope state correctly.
// Returns CXChildVisit_Continue so parent caller won't recurse again.
CXChildVisitResult ast_visitor(CXCursor cursor, CXCursor /*parent*/, CXClientData data) {
    auto* vd = static_cast<VisitData*>(data);

    // Skip system headers (performance + accuracy)
    CXSourceLocation loc = clang_getCursorLocation(cursor);
    if(clang_Location_isInSystemHeader(loc)) return CXChildVisit_Continue;

    // Only process cursors that belong to our file
    CXFile cf;
    unsigned line, col;
    clang_getExpansionLocation(loc, &cf, &line, &col, nullptr);
    if(cf) {
        CXString cfn = clang_getFileName(cf);
        std::string fname = clang_getCString(cfn);
        clang_disposeString(cfn);
        if(!fname.empty() && fname != vd->file_path) {
            // Try canonical path comparison
            std::error_code ec;
            auto p1 = std::filesystem::canonical(fname, ec);
            auto p2 = std::filesystem::canonical(vd->file_path, ec);
            if(!ec && p1 != p2) return CXChildVisit_Continue;
            if(ec && fname != vd->file_path) return CXChildVisit_Continue;
        }
    }

    CXCursorKind kind = clang_getCursorKind(cursor);

    // ── Save scope state before potentially updating it ─────────────────────
    std::string sf = vd->cur_fn, sc = vd->cur_cls, sn = vd->cur_ns;
    bool scope_changed = false;

    if(kind == CXCursor_FunctionDecl   || kind == CXCursor_CXXMethod      ||
       kind == CXCursor_Constructor    || kind == CXCursor_Destructor      ||
       kind == CXCursor_FunctionTemplate) {
        CXString s = clang_getCursorSpelling(cursor);
        vd->cur_fn = clang_getCString(s); clang_disposeString(s);
        scope_changed = true;
    } else if(kind == CXCursor_ClassDecl  || kind == CXCursor_StructDecl   ||
              kind == CXCursor_ClassTemplate) {
        CXString s = clang_getCursorSpelling(cursor);
        vd->cur_cls = clang_getCString(s); clang_disposeString(s);
        scope_changed = true;
    } else if(kind == CXCursor_Namespace) {
        CXString s = clang_getCursorSpelling(cursor);
        std::string ns = clang_getCString(s); clang_disposeString(s);
        if(!ns.empty()) {
            if(!vd->cur_ns.empty()) vd->cur_ns += "::";
            vd->cur_ns += ns;
            scope_changed = true;
        }
    }

    // ── Detect function calls ────────────────────────────────────────────────
    if(kind == CXCursor_CallExpr) {
        // Primary: get the referenced declaration (most reliable)
        std::string fname;
        CXCursor ref = clang_getCursorReferenced(cursor);
        if(!clang_Cursor_isNull(ref) && !clang_equalCursors(ref, cursor)) {
            CXString rs = clang_getCursorSpelling(ref);
            fname = clang_getCString(rs); clang_disposeString(rs);
        }
        // Fallback: spelling of the call expression itself
        if(fname.empty()) {
            CXString cs = clang_getCursorSpelling(cursor);
            fname = clang_getCString(cs); clang_disposeString(cs);
        }

        if(!fname.empty()) {
            auto opt = vd->db.find_by_name(fname);
            if(opt) {
                Finding f;
                f.function_name = opt->name;
                f.file_path     = vd->file_path;
                f.line_number   = (int)line;
                f.column        = (int)col;
                f.library       = opt->library_name;
                f.algorithm     = opt->algorithm;
                f.category      = opt->category;
                f.quantum_vulnerability = opt->quantum_vulnerability;
                f.base_risk_score = opt->risk_score;
                f.analyzer_mode = "ast";
                f.vuln_id       = opt->id;
                f.nist_reference = opt->nist_reference;
                f.tc26_reference = opt->tc26_reference;
                f.context_function = vd->cur_fn.empty() ? "<global>" : vd->cur_fn;
                f.context_class    = vd->cur_cls;
                f.context_namespace = vd->cur_ns;
                if(line > 0 && line <= (unsigned)vd->lines.size())
                    f.raw_line = vd->lines[line - 1];

                // Extract call arguments via libclang API
                int na = clang_Cursor_getNumArguments(cursor);
                for(int i = 0; i < na; ++i) {
                    CXCursor arg = clang_Cursor_getArgument(cursor, i);
                    CXString as  = clang_getCursorSpelling(arg);
                    std::string av = clang_getCString(as); clang_disposeString(as);
                    if(!av.empty()) f.arguments.push_back(av);
                }

                vd->findings.push_back(std::move(f));
            }
        }
    }

    // ── Recurse manually so we can restore scope afterward ──────────────────
    clang_visitChildren(cursor, ast_visitor, data);

    // Restore saved scope (unwind after leaving this scope context)
    if(scope_changed) {
        vd->cur_fn = sf; vd->cur_cls = sc; vd->cur_ns = sn;
    }

    return CXChildVisit_Continue;
}

} // anonymous namespace

bool ASTAnalyzer::try_libclang(const std::filesystem::path& path,
                                std::vector<Finding>& out) const {
    // Read source lines for raw_line extraction
    std::vector<std::string> lines;
    {
        std::ifstream ifs(path);
        if(!ifs.is_open()) return false;
        std::string l;
        while(std::getline(ifs, l)) lines.push_back(l);
    }

    CXIndex index = clang_createIndex(/*excludeDeclarationsFromPCH=*/0,
                                      /*displayDiagnostics=*/0);

    // Build argument list for clang_parseTranslationUnit
    std::vector<std::string> args_str = {
        "-std=c++17",
        "-w",          // suppress all warnings
        "-ferror-limit=0",
    };
    // Project include directories
    for(auto& d : include_dirs_) {
        args_str.push_back("-I"); args_str.push_back(d);
    }
    // Auto-add parent directories as potential include roots
    auto parent = path.parent_path().string();
    auto root   = path.parent_path().parent_path().string();
    if(!parent.empty()) { args_str.push_back("-I"); args_str.push_back(parent); }
    if(!root.empty() && root != parent) { args_str.push_back("-I"); args_str.push_back(root); }

    std::vector<const char*> cargs;
    cargs.reserve(args_str.size());
    for(auto& s : args_str) cargs.push_back(s.c_str());

    unsigned tu_flags =
        CXTranslationUnit_DetailedPreprocessingRecord |
        CXTranslationUnit_KeepGoing;   // continue despite errors

    CXTranslationUnit tu = clang_parseTranslationUnit(
        index,
        path.string().c_str(),
        cargs.data(), (int)cargs.size(),
        nullptr, 0,
        tu_flags);

    if(!tu) {
        clang_disposeIndex(index);
        return false;
    }

    VisitData vd{db_, out, path.string(), lines, tu, "", "", ""};
    clang_visitChildren(clang_getTranslationUnitCursor(tu), ast_visitor, &vd);

    clang_disposeTranslationUnit(tu);
    clang_disposeIndex(index);
    return true;
}

#endif // PQC_HAS_LIBCLANG

} // namespace pqc
