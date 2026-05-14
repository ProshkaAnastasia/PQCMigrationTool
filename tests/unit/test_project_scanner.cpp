#include "test_runner.hpp"
#include "pqc/project_scanner.hpp"
#ifndef PQC_TEST_FIXTURES_DIR
#  define PQC_TEST_FIXTURES_DIR "tests/fixtures"
#endif
int run_project_scanner_tests() {
    TestSuite ts("ProjectScanner");
    ts.add("scan_fixtures_dir", [](){
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        ASSERT_NOT_EMPTY(inv.files);
        ASSERT_NOT_EMPTY(inv.project_name);
    });
    ts.add("cpp_files_detected", [](){
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        auto src = inv.get_source_files();
        ASSERT_GT((int)src.size(), 0);
        bool found_cpp = false;
        for(auto* f : src)
            if(f->path.extension()==".cpp") { found_cpp=true; break; }
        ASSERT_TRUE(found_cpp);
    });
    ts.add("language_stats_cpp", [](){
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        ASSERT_TRUE(inv.language_stats.count("cpp")>0);
    });
    ts.add("cbom_metadata_json", [](){
        pqc::ProjectScanner scanner;
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        auto j = inv.to_cbom_metadata();
        ASSERT_TRUE(j.contains("project_name"));
        ASSERT_TRUE(j.contains("total_files"));
        ASSERT_TRUE(j.contains("by_category"));
    });
    ts.add("custom_plugin", [](){
        pqc::ProjectScanner scanner;
        class TestPlugin : public pqc::ILanguagePlugin {
        public:
            std::string language_name() const override { return "test_lang"; }
            bool matches(const std::filesystem::path& p) const override { return p.extension()==".testlang"; }
            pqc::FileCategory categorize(const std::filesystem::path&) const override { return pqc::FileCategory::SOURCE; }
        };
        scanner.register_plugin(std::make_unique<TestPlugin>());
        auto inv = scanner.scan(PQC_TEST_FIXTURES_DIR);
        // Plugin registered — scanner should work normally
        ASSERT_NOT_EMPTY(inv.files);
    });
    return ts.run();
}
