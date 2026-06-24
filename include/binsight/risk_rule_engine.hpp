#pragma once

#include <binsight/types.hpp>
#include <filesystem>
#include <regex>
#include <string>
#include <vector>

namespace binsight {

class RiskRuleEngine {
 public:
  std::vector<RuleFinding> evaluate(const std::filesystem::path& rules_dir,
                                    const AnalysisReport& report,
                                    std::vector<std::string>& warnings) const;
};

}  // namespace binsight

