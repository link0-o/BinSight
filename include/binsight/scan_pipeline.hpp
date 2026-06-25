#pragma once

#include <binsight/types.hpp>

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace binsight {

struct ScanExecutionResult {
  AnalysisReport report;
  std::vector<std::pair<std::filesystem::path, ReportLanguage>> markdown_outputs;
  std::filesystem::path json_output;
};

std::filesystem::path with_output_dir(const std::filesystem::path& output_dir,
                                      const std::filesystem::path& path);
std::filesystem::path language_path(const std::filesystem::path& path,
                                    const std::string& suffix);
std::vector<std::pair<std::filesystem::path, ReportLanguage>> markdown_output_paths(
    const ScanOptions& options);
void resolve_resource_dirs(ScanOptions& options, const std::filesystem::path& executable_dir);
AnalysisReport analyze_binary(const ScanOptions& options,
                              const std::vector<std::string>& initial_warnings = {});
ScanExecutionResult analyze_and_write_reports(
    ScanOptions options,
    const std::filesystem::path& executable_dir,
    const std::vector<std::string>& initial_warnings = {});

}  // namespace binsight
