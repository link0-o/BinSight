#pragma once

#include <binsight/types.hpp>
#include <filesystem>

namespace binsight {

class ReportWriter {
 public:
  void write_markdown(const std::filesystem::path& path,
                      const AnalysisReport& report,
                      ReportLanguage language) const;
  void write_json(const std::filesystem::path& path, const AnalysisReport& report) const;
};

}  // namespace binsight
