#include "test_runner.hpp"
#include "pqc/vuln_database.hpp"
#include "pqc/risk_assessor.hpp"
#include "pqc/project_scanner.hpp"
#ifndef PQC_TEST_DATA_DIR
#  define PQC_TEST_DATA_DIR "data"
#endif
#ifndef PQC_TEST_FIXTURES_DIR
#  define PQC_TEST_FIXTURES_DIR "tests/fixtures"
#endif
static pqc::Finding make_finding(const std::string& fn, const std::string& lib,
    const std::string& alg, const std::string& cat, double score,
    const std::string& file="src/net.cpp", int line=10) {
    pqc::Finding f;
    f.function_name=fn; f.library=lib; f.algorithm=alg; f.category=cat;
    f.base_risk_score=score; f.file_path=file; f.line_number=line;
    f.quantum_vulnerability="high"; return f;
}
int run_risk_assessor_tests() {
    TestSuite ts("RiskAssessor");
    pqc::VulnDatabase db; db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
    ts.add("network_file_increases_risk", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5,"src/network/tls.cpp");
        auto rr = ra.assess({f}, inv);
        ASSERT_NOT_EMPTY(rr.migration_plan);
        ASSERT_GE(rr.migration_plan[0].risk.final_score, 9.5);
    });
    ts.add("test_file_reduces_risk", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5,"tests/test_tls.cpp");
        auto rr = ra.assess({f}, inv);
        ASSERT_NOT_EMPTY(rr.migration_plan);
        ASSERT_TRUE(rr.migration_plan[0].risk.final_score < 9.5);
    });
    ts.add("migration_order_sorted_by_risk", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        pqc::Finding f1 = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5,"src/net.cpp");
        pqc::Finding f2 = make_finding("SHA1","openssl","SHA-1","hash_function",6.5,"src/util.cpp");
        auto rr = ra.assess({f2,f1}, inv); // intentionally wrong order
        ASSERT_EQ((int)rr.migration_plan.size(), 2);
        // First action must have higher or equal risk than second
        ASSERT_GE(rr.migration_plan[0].risk.final_score, rr.migration_plan[1].risk.final_score);
    });
    ts.add("file_summaries_populated", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5);
        auto rr = ra.assess({f}, inv);
        ASSERT_FALSE(rr.file_summaries.empty());
    });
    ts.add("nist_readiness_not_started_for_critical", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5,"src/network/tls.cpp");
        auto rr = ra.assess({f}, inv);
        ASSERT_TRUE(rr.nist_readiness=="not-started" || rr.nist_readiness=="in-progress");
    });
    ts.add("replacement_info_present", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5);
        auto rr = ra.assess({f}, inv);
        ASSERT_NOT_EMPTY(rr.migration_plan);
        ASSERT_NOT_EMPTY(rr.migration_plan[0].replacement_function);
        ASSERT_CONTAINS(rr.migration_plan[0].replacement_standard, "FIPS");
    });
    ts.add("tc26_note_present", [&](){
        pqc::RiskAssessor ra(db);
        pqc::ProjectInventory inv;
        auto f = make_finding("RSA_generate_key_ex","openssl","RSA","asymmetric_key_generation",9.5);
        auto rr = ra.assess({f}, inv);
        ASSERT_NOT_EMPTY(rr.migration_plan);
        ASSERT_NOT_EMPTY(rr.migration_plan[0].nist_reference);
    });
    return ts.run();
}
