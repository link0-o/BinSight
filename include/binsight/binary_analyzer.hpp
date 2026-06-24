#pragma once

#include <binsight/process_runner.hpp>
#include <binsight/string_scanner.hpp>
#include <binsight/types.hpp>

namespace binsight {

class BinaryAnalyzer {
 public:
  BinaryAnalyzer(ProcessRunner runner, StringScanner string_scanner);

  AnalysisReport analyze(const ScanOptions& options) const;

 private:
  bool analyze_with_lief(const ScanOptions& options, AnalysisReport& report) const;
  TargetInfo detect_target(const ScanOptions& options, AnalysisReport& report) const;
  void analyze_elf(const ScanOptions& options, AnalysisReport& report) const;
  void analyze_pe(const ScanOptions& options, AnalysisReport& report) const;
  void extract_strings(const ScanOptions& options, AnalysisReport& report) const;
  void extract_disassembly(const ScanOptions& options, AnalysisReport& report) const;

  ProcessRunner runner_;
  StringScanner string_scanner_;
};

}  // namespace binsight
