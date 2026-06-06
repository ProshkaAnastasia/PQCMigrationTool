#include "pqc/config.hpp"
#include "pqc/vuln_database.hpp"
#include "pqc/project_scanner.hpp"
#include "pqc/regex_analyzer.hpp"
#include "pqc/ast_analyzer.hpp"
#include "pqc/cert_analyzer.hpp"
#include "pqc/risk_assessor.hpp"
#include "pqc/report_generator.hpp"
#include "pqc/metrics.hpp"
#include <iostream>
#include <stdexcept>
#include <chrono>
int main(int argc, char* argv[])
{
    auto t0 = std::chrono::steady_clock::now();
    try {
        pqc::AppConfig cfg = pqc::AppConfig::parse(argc, argv);
        if (cfg.verbose)
            std::cout << "[1/6] Source: " << cfg.source_path << "\n";

        pqc::VulnDatabase db;
        db.load(cfg.db_path);
        for (auto& extra : cfg.extra_db_paths) db.load(extra);
        if (cfg.verbose)
            std::cout << "[2/6] DB loaded: " << db.size() << " functions (v" << db.db_version()
                      << ", updated " << db.last_updated() << ")\n";

        pqc::ProjectScanner scanner;
        pqc::ProjectInventory inv = scanner.scan(cfg.source_path);
        if (cfg.verbose)
            inv.print_summary();
        auto source_files = inv.get_source_files();
        if (cfg.verbose)
            std::cout << "[3/6] Inventory: " << inv.files.size() << " total files, "
                      << source_files.size() << " source/header\n";

        std::vector<pqc::Finding> findings;
        if (cfg.analysis_mode == pqc::AnalysisMode::STATIC_AST) {
            pqc::ASTAnalyzer ast_analyzer(db);
            ast_analyzer.set_include_dirs(cfg.include_dirs);
#ifdef PQC_HAS_LIBCLANG
            if (cfg.verbose)
                std::cout << "[4/6] AST analysis (libclang)\n";
#else
            if (cfg.verbose)
                std::cout << "[4/6] AST analysis (token fallback — libclang not found)\n";
#endif
            findings = ast_analyzer.analyze(inv);
        } else {
            if (cfg.verbose)
                std::cout << "[4/6] Regex analysis\n";
            pqc::RegexAnalyzer regex_analyzer(db);
            findings = regex_analyzer.analyze(inv);
        }
        if (cfg.verbose)
            std::cout << "      Found " << findings.size() << " quantum-vulnerable calls\n";

        std::vector<pqc::CertInfo> cert_infos;
        if (!cfg.skip_cert && !cfg.cert_path.empty()) {
            if (cfg.verbose)
                std::cout << "[5/6] Certificate analysis: " << cfg.cert_path << "\n";
            pqc::CertAnalyzer cert_analyzer;
            cert_infos = cert_analyzer.analyze(cfg.cert_path);
            if (cfg.verbose)
                std::cout << "      Analyzed " << cert_infos.size() << " certificates\n";
        } else {
            if (cfg.verbose)
                std::cout << "[5/6] Certificate analysis: skipped\n";
        }

        if (cfg.verbose)
            std::cout << "[6/6] Risk assessment & migration plan\n";
        pqc::RiskAssessor risk_assessor(db);
        pqc::RiskReport risk_report = risk_assessor.assess(findings, inv, cert_infos);

        std::unique_ptr<pqc::AnalysisMetrics> metrics;
        if (cfg.run_metrics) {
            auto gt = pqc::MetricsCalculator::load_from_json(cfg.ground_truth_path);
            pqc::MetricsCalculator calc;
            metrics = std::make_unique<pqc::AnalysisMetrics>(calc.compute(findings, gt));
            metrics->print();
        }

        pqc::ReportGenerator gen;
        gen.generate(cfg, inv, findings, cert_infos, risk_report, metrics.get());

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t0)
                           .count();
        std::cout << "\nDone in " << elapsed << " ms\n";
        return 0;
    } catch (const std::invalid_argument& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
}
