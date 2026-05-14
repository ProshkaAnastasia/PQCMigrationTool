#include "test_runner.hpp"
#include "pqc/vuln_database.hpp"
#ifndef PQC_TEST_DATA_DIR
#  define PQC_TEST_DATA_DIR "data"
#endif
int run_vuln_database_tests() {
    TestSuite ts("VulnDatabase");
    pqc::VulnDatabase db;
    ts.add("load_json", [&](){
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        ASSERT_GT((int)db.size(), 15);
    });
    ts.add("find_rsa_keygen", [&](){
        auto opt = db.find_by_name("RSA_generate_key_ex");
        ASSERT_TRUE(opt.has_value());
        ASSERT_EQ(opt->algorithm, "RSA");
        ASSERT_EQ(opt->quantum_vulnerability, "high");
        ASSERT_GT(opt->risk_score, 9.0);
    });
    ts.add("find_alias", [&](){
        auto opt = db.find_by_name("RSA_generate_key"); // alias
        ASSERT_TRUE(opt.has_value());
        ASSERT_EQ(opt->name, "RSA_generate_key_ex");
    });
    ts.add("find_case_insensitive", [&](){
        auto opt = db.find_by_name("rsa_generate_key_ex");
        ASSERT_TRUE(opt.has_value());
    });
    ts.add("not_found", [&](){
        auto opt = db.find_by_name("this_function_does_not_exist");
        ASSERT_FALSE(opt.has_value());
    });
    ts.add("replacements_present", [&](){
        auto opt = db.find_by_name("RSA_generate_key_ex");
        ASSERT_TRUE(opt.has_value());
        ASSERT_NOT_EMPTY(opt->replacements);
        ASSERT_CONTAINS(opt->replacements[0].standard, "FIPS");
    });
    ts.add("tc26_reference_present", [&](){
        auto opt = db.find_by_name("RSA_generate_key_ex");
        ASSERT_TRUE(opt.has_value());
        ASSERT_NOT_EMPTY(opt->tc26_reference);
    });
    ts.add("gost_library_entries", [&](){
        auto gost_fns = db.by_library("gost_openssl");
        ASSERT_GT((int)gost_fns.size(), 0);
    });
    ts.add("merge_extra_db", [&](){
        // Create in-memory JSON and merge
        nlohmann::json extra = {
            {"version","1.0"},
            {"libraries",{{"test_lib",{{"functions",nlohmann::json::array({
                {{"id","test-1"},{"name","test_vuln_fn"},{"aliases",nlohmann::json::array()},
                 {"category","test"},{"algorithm","TEST"},
                 {"quantum_vulnerability","high"},{"risk_score",9.0},
                 {"description","test"},{"nist_reference",""},{"tc26_reference",""},
                 {"deprecation_url",""},{"patterns",nlohmann::json::array({"test_vuln_fn\\s*\\("})},
                 {"context_keywords",nlohmann::json::array()},
                 {"replacements",nlohmann::json::array()}}
            })}}}}}
        };
        size_t before = db.size();
        db.merge_json(extra);
        ASSERT_GT((int)db.size(), (int)before);
        auto opt = db.find_by_name("test_vuln_fn");
        ASSERT_TRUE(opt.has_value());
    });
    return ts.run();
}
