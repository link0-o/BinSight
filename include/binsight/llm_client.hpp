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
  AiAnalysis analyze(const ScanOptions& options,
                     const AnalysisReport& report,
                     std::vector<std::string>& warnings) const;
  LlmConnectionTest test_connection(const ScanOptions& options,
                                    std::vector<std::string>& warnings) const;

 private:
  AiAnalysis offline_analysis(const ScanOptions& options, const AnalysisReport& report) const;
  std::string build_prompt(const ScanOptions& options, const AnalysisReport& report) const;
  std::string system_prompt(const ScanOptions& options) const;

  ProcessRunner runner_;
};

}  // namespace binsight
