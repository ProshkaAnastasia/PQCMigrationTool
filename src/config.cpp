#include "pqc/config.hpp"
#include <iostream>
#include <stdexcept>
#include <cstring>
namespace pqc {
void AppConfig::print_usage(const char* prog){
    std::cerr << "Usage: " << prog << " -s <source_path> [options]\n\n"
        "Required:\n"
        "  -s, --source <path>          Source code directory or file\n\n"
        "Analysis:\n"
        "  -m, --mode <regex|ast>       Analysis mode (default: regex)\n"
        "  -I, --include <path>         Add include path for libclang (repeatable)\n\n"
        "Certificates:\n"
        "  -c, --cert <path>            X.509 certificate file or directory\n"
        "  --skip-cert                  Skip certificate analysis\n\n"
        "Database:\n"
        "  -d, --db <path>              Vulnerability DB (default: data/vulnerable_functions.json)\n"
        "  --extra-db <path>            Additional DB to merge (repeatable)\n\n"
        "Output:\n"
        "  -o, --output <path>          Full JSON report output (default: pqc_report.json)\n"
        "  --cbom-output <path>         CBOM JSON output (default: pqc_cbom.json)\n"
        "  --cbom-only                  Only generate CBOM, skip risk analysis\n\n"
        "Metrics:\n"
        "  --metrics                    Compute precision/recall/F1\n"
        "  --ground-truth <path>        Ground truth JSON for metrics\n\n"
        "  -v, --verbose                Verbose output\n"
        "  -h, --help                   Show this help\n";
}
AppConfig AppConfig::parse(int argc, char* argv[]){
    AppConfig cfg;
    if(argc<2){ print_usage(argv[0]); throw std::invalid_argument("No arguments provided"); }
    for(int i=1;i<argc;++i){
        std::string a=argv[i];
        auto nxt=[&]()->std::string{
            if(i+1>=argc) throw std::invalid_argument("Missing value for "+a);
            return argv[++i];
        };
        if(a=="-s"||a=="--source")          cfg.source_path=nxt();
        else if(a=="-c"||a=="--cert")       cfg.cert_path=nxt();
        else if(a=="-d"||a=="--db")         cfg.db_path=nxt();
        else if(a=="-o"||a=="--output")     cfg.output_path=nxt();
        else if(a=="--cbom-output")         cfg.cbom_output_path=nxt();
        else if(a=="-m"||a=="--mode"){      std::string m=nxt();
            if(m=="ast")   cfg.analysis_mode=AnalysisMode::STATIC_AST;
            else if(m=="regex") cfg.analysis_mode=AnalysisMode::REGEX;
            else throw std::invalid_argument("Unknown mode: "+m+". Use regex or ast");
        }
        else if(a=="-I"||a=="--include")    cfg.include_dirs.push_back(nxt());
        else if(a=="--extra-db")            cfg.extra_db_paths.push_back(nxt());
        else if(a=="--cbom-only")           cfg.cbom_only=true;
        else if(a=="--skip-cert")           cfg.skip_cert=true;
        else if(a=="--metrics")             cfg.run_metrics=true;
        else if(a=="--ground-truth")        cfg.ground_truth_path=nxt();
        else if(a=="-v"||a=="--verbose")    cfg.verbose=true;
        else if(a=="-h"||a=="--help"){ print_usage(argv[0]); throw std::invalid_argument("Help requested"); }
        else throw std::invalid_argument("Unknown argument: "+a);
    }
    if(cfg.source_path.empty()) throw std::invalid_argument("Source path (-s) is required");
    if(cfg.run_metrics&&cfg.ground_truth_path.empty())
        throw std::invalid_argument("--metrics requires --ground-truth <path>");
    return cfg;
}
} // namespace pqc
