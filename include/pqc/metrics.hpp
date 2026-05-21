#pragma once
#include "pqc/code_analyzer.hpp"
#include <nlohmann/json.hpp>
namespace pqc {
struct GroundTruth {
    std::string function_name, file_path;
    int line_number = -1, line_tolerance = 3;
};
struct AnalysisMetrics {
    int true_positives = 0, false_positives = 0, false_negatives = 0, ground_truth_total = 0;
    double precision() const;
    double recall() const;
    double f1_score() const;
    nlohmann::json to_json() const;
    void print() const;
};
class MetricsCalculator {
public:
    AnalysisMetrics compute(const std::vector<Finding>& findings,
                            const std::vector<GroundTruth>& gt) const;
    static std::vector<GroundTruth> load_from_json(const std::string& path);
};
}  // namespace pqc
