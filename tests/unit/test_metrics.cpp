#include "test_runner.hpp"
#include "pqc/metrics.hpp"
int run_metrics_tests() {
    TestSuite ts("MetricsCalculator");
    ts.add("perfect_match", [](){
        pqc::MetricsCalculator calc;
        pqc::Finding f; f.function_name="RSA_generate_key_ex"; f.file_path="src/a.cpp"; f.line_number=42;
        pqc::GroundTruth gt; gt.function_name="RSA_generate_key_ex"; gt.line_number=42; gt.line_tolerance=3;
        auto m = calc.compute({f},{gt});
        ASSERT_EQ(m.true_positives,1);
        ASSERT_EQ(m.false_positives,0);
        ASSERT_EQ(m.false_negatives,0);
        ASSERT_EQ((int)(m.precision()*100+0.5),100);
        ASSERT_EQ((int)(m.recall()*100+0.5),100);
        ASSERT_EQ((int)(m.f1_score()*100+0.5),100);
    });
    ts.add("false_positive", [](){
        pqc::MetricsCalculator calc;
        pqc::Finding f; f.function_name="ECDSA_sign"; f.line_number=10;
        pqc::GroundTruth gt; gt.function_name="RSA_sign"; gt.line_number=10; gt.line_tolerance=3;
        auto m = calc.compute({f},{gt});
        ASSERT_EQ(m.false_positives,1);
        ASSERT_EQ(m.false_negatives,1);
        ASSERT_EQ(m.true_positives,0);
    });
    ts.add("line_tolerance", [](){
        pqc::MetricsCalculator calc;
        pqc::Finding f; f.function_name="RSA_sign"; f.line_number=45;
        pqc::GroundTruth gt; gt.function_name="RSA_sign"; gt.line_number=42; gt.line_tolerance=5;
        auto m = calc.compute({f},{gt});
        ASSERT_EQ(m.true_positives,1); // within tolerance
    });
    ts.add("empty_findings", [](){
        pqc::MetricsCalculator calc;
        pqc::GroundTruth gt; gt.function_name="RSA_sign"; gt.line_number=42;
        auto m = calc.compute({},{gt});
        ASSERT_EQ(m.false_negatives,1);
        ASSERT_EQ((int)(m.precision()*100+0.5),0); // 0 TP, 0 FP
        ASSERT_EQ((int)(m.recall()*100+0.5),0);
    });
    ts.add("json_serialization", [](){
        pqc::AnalysisMetrics m; m.true_positives=8; m.false_positives=2;
        m.false_negatives=2; m.ground_truth_total=10;
        auto j = m.to_json();
        ASSERT_TRUE(j.contains("precision"));
        ASSERT_TRUE(j.contains("recall"));
        ASSERT_TRUE(j.contains("f1_score"));
    });
    return ts.run();
}
