#pragma once

#include <binsight/process_runner.hpp>
#include <binsight/types.hpp>

namespace binsight {

struct LlmConnectionTest {
  bool ok = false;
  std::string message;
  std::string raw_response;
};

class LlmClient {
 public:
  explicit LlmClient(ProcessRunner runner);
  RiskAssessment local_analysis(const ScanOptions& options, const AnalysisReport& report) const;
  AiAnalysis analyze(const ScanOptions& options,
                     const AnalysisReport& report,
                     std::vector<std::string>& warnings) const;
  AiAnalysis parse_ai_assessment(const ScanOptions& options,
                                 const RiskAssessment& local,
                                 const std::string& model_text,
                                 const std::string& raw_response,
                                 std::vector<std::string>& warnings) const;
  FinalAssessment fuse_assessments(const AnalysisReport& report,
                                   const RiskAssessment& local,
                                   const AiAnalysis& ai,
                                   std::vector<std::string>& warnings) const;
  LlmConnectionTest test_connection(const ScanOptions& options,
                                    std::vector<std::string>& warnings) const;

 private:
  AiAnalysis offline_analysis(const ScanOptions& options, const RiskAssessment& local) const;
  std::string build_prompt(const ScanOptions& options, const AnalysisReport& report) const;
  std::string system_prompt(const ScanOptions& options) const;

  ProcessRunner runner_;
};

}  // namespace binsight
