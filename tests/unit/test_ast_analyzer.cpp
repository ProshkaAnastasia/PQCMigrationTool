#include "test_runner.hpp"
#include "pqc/vuln_database.hpp"
#include "pqc/ast_analyzer.hpp"
#ifndef PQC_TEST_DATA_DIR
#  define PQC_TEST_DATA_DIR "data"
#endif
#ifndef PQC_TEST_FIXTURES_DIR
#  define PQC_TEST_FIXTURES_DIR "tests/fixtures"
#endif
static pqc::VulnDatabase make_db2(){
    pqc::VulnDatabase db;
    db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
    return db;
}
int run_ast_analyzer_tests() {
    TestSuite ts("ASTAnalyzer");
    ts.add("mode_name", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        ASSERT_EQ(aa.mode_name(), std::string("ast"));
    });
    ts.add("has_libclang_flag", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
#ifdef PQC_HAS_LIBCLANG
        ASSERT_TRUE(aa.has_libclang());
#else
        ASSERT_FALSE(aa.has_libclang());
#endif
    });
    ts.add("finds_vulnerabilities_in_fixture", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        ASSERT_NOT_EMPTY(findings);
        ASSERT_GE((int)findings.size(), 5);
    });
    ts.add("context_function_extracted", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        bool has_context = false;
        for(auto& f : findings)
            if(!f.context_function.empty() && f.context_function!="<global>") { has_context=true; break; }
        ASSERT_TRUE(has_context);
    });
    ts.add("context_class_extracted", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        bool has_class = false;
        for(auto& f : findings)
            if(!f.context_class.empty()) { has_class=true; break; }
        ASSERT_TRUE(has_class);
    });
    ts.add("analyzer_mode_is_ast_or_token", [](){
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings)
            ASSERT_TRUE(f.analyzer_mode=="ast" || f.analyzer_mode=="token");
    });
    ts.add("no_system_header_findings", [](){
        // All findings should be in our file, not in openssl headers
        auto db = make_db2();
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings)
            ASSERT_CONTAINS(f.file_path, "sample_vulnerable");
    });
    return ts.run();
}
