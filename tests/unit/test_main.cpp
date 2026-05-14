#include "test_runner.hpp"
#include <iostream>
// Forward declarations of suite builders
int run_vuln_database_tests();
int run_project_scanner_tests();
int run_regex_analyzer_tests();
int run_ast_analyzer_tests();
int run_risk_assessor_tests();
int run_metrics_tests();

int main() {
    std::cout << "PQC Migration Tool — Unit Tests\n";
    std::cout << std::string(50,'=') << "\n";
    int total_fail = 0;
    total_fail += run_vuln_database_tests();
    total_fail += run_project_scanner_tests();
    total_fail += run_regex_analyzer_tests();
    total_fail += run_ast_analyzer_tests();
    total_fail += run_risk_assessor_tests();
    total_fail += run_metrics_tests();
    std::cout << "\n" << std::string(50,'=') << "\n";
    std::cout << (total_fail==0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    return total_fail;
}
