#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <filesystem>
namespace pqc {
enum class AnalysisMode { REGEX, STATIC_AST };
struct AppConfig {
    std::string source_path, cert_path;
    std::string db_path = "data/vulnerable_functions.json";
    std::string output_path = "pqc_report.json";
    std::string cbom_output_path = "pqc_cbom.json";
    AnalysisMode analysis_mode = AnalysisMode::REGEX;
    bool verbose = false, cbom_only = false, skip_cert = false, run_metrics = false;
    std::string ground_truth_path;
    std::vector<std::string> extra_db_paths, include_dirs;
    static AppConfig parse(int argc, char* argv[]);
    static void print_usage(const char* prog);
};
}  // namespace pqc
