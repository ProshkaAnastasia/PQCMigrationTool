#include "pqc/metrics.hpp"
#include <fstream>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <stdexcept>
namespace pqc {
double AnalysisMetrics::precision() const {
    int denom=true_positives+false_positives;
    return denom==0 ? 0.0 : (double)true_positives/denom;
}
double AnalysisMetrics::recall() const {
    return ground_truth_total==0 ? 0.0 : (double)true_positives/ground_truth_total;
}
double AnalysisMetrics::f1_score() const {
    double p=precision(), r=recall();
    return (p+r==0.0) ? 0.0 : 2.0*p*r/(p+r);
}
nlohmann::json AnalysisMetrics::to_json() const {
    return {{"true_positives",true_positives},{"false_positives",false_positives},
            {"false_negatives",false_negatives},{"ground_truth_total",ground_truth_total},
            {"precision",precision()},{"recall",recall()},{"f1_score",f1_score()}};
}
void AnalysisMetrics::print() const {
    std::cout<<"\n=== Analysis Metrics ===\n";
    std::cout<<std::fixed<<std::setprecision(3);
    std::cout<<"  Ground truth  : "<<ground_truth_total<<"\n";
    std::cout<<"  True positives : "<<true_positives<<"\n";
    std::cout<<"  False positives: "<<false_positives<<"\n";
    std::cout<<"  False negatives: "<<false_negatives<<"\n";
    std::cout<<"  Precision      : "<<precision()*100<<"%\n";
    std::cout<<"  Recall         : "<<recall()*100<<"%\n";
    std::cout<<"  F1 score       : "<<f1_score()*100<<"%\n";
}
AnalysisMetrics MetricsCalculator::compute(const std::vector<Finding>& findings,
                                            const std::vector<GroundTruth>& gt) const {
    AnalysisMetrics m;
    m.ground_truth_total=(int)gt.size();
    std::vector<bool> gt_matched(gt.size(),false);
    std::vector<bool> f_matched(findings.size(),false);
    // Match each finding to a GT entry (function name match + optional location)
    for(size_t fi=0;fi<findings.size();++fi){
        auto& f=findings[fi];
        for(size_t gi=0;gi<gt.size();++gi){
            if(gt_matched[gi]) continue;
            auto& g=gt[gi];
            // Function name must match
            if(f.function_name!=g.function_name) continue;
            // File path: if GT specifies one, check substring match
            if(!g.file_path.empty() && f.file_path.find(g.file_path)==std::string::npos) continue;
            // Line number: if GT specifies, check tolerance
            if(g.line_number>=0 && std::abs(f.line_number-g.line_number)>g.line_tolerance) continue;
            gt_matched[gi]=true; f_matched[fi]=true; ++m.true_positives; break;
        }
    }
    for(size_t fi=0;fi<findings.size();++fi) if(!f_matched[fi]) ++m.false_positives;
    for(size_t gi=0;gi<gt.size();++gi)       if(!gt_matched[gi]) ++m.false_negatives;
    return m;
}
std::vector<GroundTruth> MetricsCalculator::load_from_json(const std::string& path) {
    std::ifstream ifs(path);
    if(!ifs.is_open()) throw std::runtime_error("Cannot open ground truth file: "+path);
    nlohmann::json j; ifs>>j;
    std::vector<GroundTruth> gts;
    for(auto& e:j){
        GroundTruth g;
        g.function_name=e.value("function_name","");
        g.file_path    =e.value("file_path","");
        g.line_number  =e.value("line_number",-1);
        g.line_tolerance=e.value("line_tolerance",3);
        gts.push_back(g);
    }
    return gts;
}
} // namespace pqc
