#pragma once

#include <binsight/types.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace binsight {

class LocalRagIndex {
 public:
  std::vector<RagEntry> retrieve(const std::filesystem::path& knowledge_dir,
                                 const AnalysisReport& report,
                                 std::vector<std::string>& warnings,
                                 std::size_t limit = 5) const;
};

}  // namespace binsight

