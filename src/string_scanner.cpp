#include <binsight/string_scanner.hpp>
#include <binsight/utils.hpp>

#include <regex>
#include <set>

namespace binsight {

std::vector<SuspiciousString> StringScanner::scan(const std::string& strings_output,
                                                  std::size_t limit) const {
  struct Pattern {
    std::string category;
    std::regex regex;
  };
  const std::vector<Pattern> patterns = {
      {"url", std::regex(R"(https?://[^\s"']+)", std::regex::icase)},
      {"ip-address", std::regex(R"(\b([0-9]{1,3}\.){3}[0-9]{1,3}\b)")},
      {"shell", std::regex(R"((/bin/sh|/bin/bash|cmd\.exe|powershell|bash -c|shutdown\s+/[a-z]|title\s+))", std::regex::icase)},
      {"registry", std::regex(R"((HKEY_|Software\\Microsoft\\Windows))", std::regex::icase)},
      {"credential", std::regex(R"((password|passwd|token|secret|apikey|api_key))", std::regex::icase)},
      {"filesystem", std::regex(R"((/etc/passwd|/tmp/|AppData|System32))", std::regex::icase)},
      {"anti-debug", std::regex(R"((debugger|IsDebuggerPresent|ptrace|anti-debug))", std::regex::icase)},
  };

  std::vector<SuspiciousString> results;
  std::set<std::string> seen;
  for (const auto& raw_line : split_lines(strings_output)) {
    const std::string line = trim(raw_line);
    if (line.empty() || line.size() > 300) {
      continue;
    }
    for (const auto& pattern : patterns) {
      if (std::regex_search(line, pattern.regex)) {
        const std::string key = pattern.category + "\n" + line;
        if (seen.insert(key).second) {
          results.push_back({line, pattern.category});
        }
        break;
      }
    }
    if (results.size() >= limit) {
      break;
    }
  }
  return results;
}

}  // namespace binsight
