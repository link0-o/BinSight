#pragma once

#include <binsight/process_runner.hpp>
#include <binsight/types.hpp>

namespace binsight {

class LlmClient {
 public:
  explicit LlmClient(ProcessRunner runner);
  AiAnalysis analyze(const ScanOptions& options,
                     const AnalysisReport& report,
                     std::vector<std::string>& warnings) const;

 private:
  AiAnalysis offline_analysis(const ScanOptions& options, const AnalysisReport& report) const;
  std::string build_prompt(const AnalysisReport& report) const;

  ProcessRunner runner_;
};

}  // namespace binsight

