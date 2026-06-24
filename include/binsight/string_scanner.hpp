#pragma once

#include <binsight/types.hpp>
#include <string>
#include <vector>

namespace binsight {

class StringScanner {
 public:
  std::vector<SuspiciousString> scan(const std::string& strings_output, std::size_t limit = 200) const;
};

}  // namespace binsight

