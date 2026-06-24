#pragma once

#include <binsight/types.hpp>
#include <string>
#include <vector>

namespace binsight {

class ProcessRunner {
 public:
  ToolResult run(const std::vector<std::string>& args, int timeout_seconds = 20) const;
};

}  // namespace binsight

