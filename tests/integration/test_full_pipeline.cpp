/**
 * Integration test: runs the complete pipeline on the fixture directory
 * and validates correctness of findings, CBOM, and migration plan.
 */
#include "pqc/vuln_database.hpp"
#include "pqc/project_scanner.hpp"
#include "pqc/regex_analyzer.hpp"
#include "pqc/ast_analyzer.hpp"
#include "pqc/risk_assessor.hpp"
#include "pqc/report_generator.hpp"
#include "pqc/metrics.hpp"
#include "../unit/test_runner.hpp"
#include <filesystem>
#include <iostream>
#ifndef PQC_TEST_FIXTURES_DIR
#define PQC_TEST_FIXTURES_DIR "tests/fixtures"
#endif
#ifndef PQC_TEST_DATA_DIR
#define PQC_TEST_DATA_DIR "data"
#endif

int main()
{
    std::cout << "PQC Migration Tool — Integration Tests\n";
    std::cout << std::string(55, '=') << "\n";
    TestSuite ts("FullPipeline");

    ts.add("regex_pipeline_end_to_end", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze(inv);
        ASSERT_NOT_EMPTY(findings);
        pqc::RiskAssessor assessor(db);
        auto rr = assessor.assess(findings, inv);
        ASSERT_NOT_EMPTY(rr.migration_plan);
        ASSERT_GT(rr.overall_risk_score, 0.0);
        ASSERT_NOT_EMPTY(rr.nist_readiness);
        ASSERT_FALSE(rr.file_summaries.empty());
    });

    ts.add("ast_pipeline_end_to_end", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::ASTAnalyzer aa(db);
        auto findings = aa.analyze(inv);
        ASSERT_NOT_EMPTY(findings);
        std::cout << "      [AST] " << findings.size() << " findings ("
                  << (aa.has_libclang() ? "libclang" : "token fallback") << ")\n";
    });

    ts.add("regex_precision_recall_gt50pct", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze(inv);
        auto gt =
            pqc::MetricsCalculator::load_from_json(PQC_TEST_FIXTURES_DIR "/ground_truth.json");
        pqc::MetricsCalculator calc;
        auto m = calc.compute(findings, gt);
        m.print();
        ASSERT_GE(m.precision(), 0.5);
        ASSERT_GE(m.recall(), 0.5);
        ASSERT_GE(m.f1_score(), 0.5);
    });

    ts.add("risk_report_has_tc26_data", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze(inv);
        pqc::RiskAssessor assessor(db);
        auto rr = assessor.assess(findings, inv);
        bool has_tc26 = false;
        for (auto& a : rr.migration_plan)
            if (!a.tc26_note.empty()) {
                has_tc26 = true;
                break;
            }
        ASSERT_TRUE(has_tc26);
    });

    ts.add("migration_plan_has_fips_references", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze(inv);
        pqc::RiskAssessor assessor(db);
        auto rr = assessor.assess(findings, inv);
        bool has_fips = false;
        for (auto& a : rr.migration_plan)
            if (a.replacement_standard.find("FIPS") != std::string::npos) {
                has_fips = true;
                break;
            }
        ASSERT_TRUE(has_fips);
    });

    ts.add("report_json_serialization", []() {
        pqc::VulnDatabase db;
        db.load(PQC_TEST_DATA_DIR "/vulnerable_functions.json");
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        pqc::RegexAnalyzer ra(db);
        auto findings = ra.analyze(inv);
        pqc::RiskAssessor assessor(db);
        auto rr = assessor.assess(findings, inv);
        auto j = rr.to_json();
        ASSERT_TRUE(j.contains("migration_plan"));
        ASSERT_TRUE(j.contains("file_risk_summaries"));
        ASSERT_TRUE(j.contains("nist_readiness"));
    });

    int fail = ts.run();
    std::cout << "\n"
              << (fail == 0 ? "ALL INTEGRATION TESTS PASSED" : "SOME INTEGRATION TESTS FAILED")
              << "\n";
    return fail;
}
