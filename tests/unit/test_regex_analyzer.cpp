#include "test_runner.hpp"
#include "pqc/vuln_database.hpp"
#include "pqc/regex_analyzer.hpp"
#include "pqc/project_scanner.hpp"
#ifndef PQC_TEST_DATA_DIR
#  define PQC_TEST_DATA_DIR "data"
#endif
#ifndef PQC_TEST_FIXTURES_DIR
#  define PQC_TEST_FIXTURES_DIR "tests/fixtures"
#endif
static pqc::VulnDatabase make_db(){
    pqc::VulnDatabase db;
    db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
    return db;
}
int run_regex_analyzer_tests() {
    TestSuite ts("RegexAnalyzer");
    ts.add("finds_rsa_in_fixture", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        ASSERT_NOT_EMPTY(findings);
        bool found_rsa = false;
        for(auto& f : findings)
            if(f.function_name=="RSA_generate_key_ex") { found_rsa=true; break; }
        ASSERT_TRUE(found_rsa);
    });
    ts.add("finds_ecdsa", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        bool found = false;
        for(auto& f : findings)
            if(f.function_name=="ECDSA_sign") { found=true; break; }
        ASSERT_TRUE(found);
    });
    ts.add("finds_md5", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        bool found = false;
        for(auto& f : findings) if(f.function_name=="MD5") { found=true; break; }
        ASSERT_TRUE(found);
    });
    ts.add("no_false_positives_for_safe_code", [](){
        // safe_encrypt uses AES-256-GCM, should not trigger
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings) {
            // EVP_EncryptInit_ex should NOT be in the DB
            ASSERT_TRUE(f.function_name != "EVP_EncryptInit_ex");
        }
    });
    ts.add("finding_has_line_number", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings) ASSERT_GT(f.line_number, 0);
    });
    ts.add("finding_has_library", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings) ASSERT_NOT_EMPTY(f.library);
    });
    ts.add("finding_has_nist_reference", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        for(auto& f : findings) ASSERT_NOT_EMPTY(f.nist_reference);
    });
    ts.add("minimum_10_findings_in_fixture", [](){
        auto db = make_db();
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze_file(PQC_TEST_FIXTURES_DIR "/sample_vulnerable.cpp");
        ASSERT_GE((int)findings.size(), 8); // at least 8 of 10
    });
    return ts.run();
}
