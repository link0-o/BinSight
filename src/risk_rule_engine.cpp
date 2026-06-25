#include <binsight/risk_rule_engine.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>

namespace binsight {

namespace {

struct RuleSpec {
  std::string id;
  std::string title;
  Severity severity = Severity::Info;
  std::vector<std::string> tags;
  std::vector<std::string> functions;
  std::vector<std::string> libraries;
  std::vector<std::string> string_regexes;
  std::vector<std::string> section_flags;
  std::vector<std::string> section_names;
  double section_entropy_min = 0.0;
  int import_count_max = -1;
  std::string description;
  std::string recommendation;
};

std::vector<std::filesystem::path> rule_files(const std::filesystem::path& rules_dir) {
  std::vector<std::filesystem::path> files;
  if (!std::filesystem::exists(rules_dir)) {
    return files;
  }
  for (const auto& entry : std::filesystem::directory_iterator(rules_dir)) {
    if (!entry.is_regular_file()) continue;
    const auto ext = entry.path().extension().string();
    if (ext == ".yaml" || ext == ".yml") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::string unquote(std::string value) {
  value = trim(value);
  if (value.size() >= 2 &&
      ((value.front() == '"' && value.back() == '"') || (value.front() == '\'' && value.back() == '\''))) {
    value = value.substr(1, value.size() - 2);
  }
  return value;
}

std::vector<std::string> parse_inline_list(const std::string& value) {
  const auto begin = value.find('[');
  const auto end = value.rfind(']');
  if (begin == std::string::npos || end == std::string::npos || end <= begin) {
    return {};
  }
  std::vector<std::string> result;
  std::string inner = value.substr(begin + 1, end - begin - 1);
  std::string item;
  bool in_single = false;
  bool in_double = false;
  for (char c : inner) {
    if (c == '\'' && !in_double) {
      in_single = !in_single;
      item.push_back(c);
    } else if (c == '"' && !in_single) {
      in_double = !in_double;
      item.push_back(c);
    } else if (c == ',' && !in_single && !in_double) {
      item = unquote(item);
      if (!item.empty()) result.push_back(item);
      item.clear();
    } else {
      item.push_back(c);
    }
  }
  item = unquote(item);
  if (!item.empty()) result.push_back(item);
  return result;
}

std::string value_after_colon(const std::string& line) {
  const auto pos = line.find(':');
  if (pos == std::string::npos) return {};
  return unquote(line.substr(pos + 1));
}

std::vector<RuleSpec> parse_rule_file(const std::filesystem::path& path,
                                      std::vector<std::string>& warnings) {
  std::ifstream in(path);
  if (!in) {
    warnings.push_back("failed to read rule file: " + path.string());
    return {};
  }
  std::vector<RuleSpec> rules;
  RuleSpec current;
  bool in_rule = false;
  std::string line;
  while (std::getline(in, line)) {
    const std::string stripped = trim(line);
    if (stripped.empty() || stripped.front() == '#') continue;
    if (stripped.rfind("- id:", 0) == 0) {
      if (in_rule) rules.push_back(current);
      current = RuleSpec{};
      current.id = value_after_colon(stripped);
      in_rule = true;
    } else if (!in_rule) {
      continue;
    } else if (stripped.rfind("title:", 0) == 0) {
      current.title = value_after_colon(stripped);
    } else if (stripped.rfind("severity:", 0) == 0) {
      current.severity = severity_from_string(value_after_colon(stripped));
    } else if (stripped.rfind("tags:", 0) == 0) {
      current.tags = parse_inline_list(stripped);
    } else if (stripped.rfind("functions:", 0) == 0) {
      current.functions = parse_inline_list(stripped);
    } else if (stripped.rfind("libraries:", 0) == 0) {
      current.libraries = parse_inline_list(stripped);
    } else if (stripped.rfind("strings_regex:", 0) == 0) {
      current.string_regexes = parse_inline_list(stripped);
    } else if (stripped.rfind("section_flags:", 0) == 0) {
      current.section_flags = parse_inline_list(stripped);
    } else if (stripped.rfind("section_names:", 0) == 0) {
      current.section_names = parse_inline_list(stripped);
    } else if (stripped.rfind("section_entropy_min:", 0) == 0) {
      try {
        current.section_entropy_min = std::stod(value_after_colon(stripped));
      } catch (...) {
        warnings.push_back("invalid section_entropy_min in rule " + current.id);
      }
    } else if (stripped.rfind("import_count_max:", 0) == 0) {
      try {
        current.import_count_max = std::stoi(value_after_colon(stripped));
      } catch (...) {
        warnings.push_back("invalid import_count_max in rule " + current.id);
      }
    } else if (stripped.rfind("description:", 0) == 0) {
      current.description = value_after_colon(stripped);
    } else if (stripped.rfind("recommendation:", 0) == 0) {
      current.recommendation = value_after_colon(stripped);
    }
  }
  if (in_rule) rules.push_back(current);
  return rules;
}

bool matches_symbol(const std::string& wanted, const std::string& observed) {
  return lowercase(wanted) == lowercase(observed);
}

bool flags_match(const std::string& wanted, const std::string& observed) {
  for (char c : wanted) {
    if (observed.find(c) == std::string::npos) return false;
  }
  return true;
}

bool section_name_match(const std::string& wanted, const std::string& observed) {
  return lowercase(observed).find(lowercase(wanted)) != std::string::npos;
}

}  // namespace

std::vector<RuleFinding> RiskRuleEngine::evaluate(const std::filesystem::path& rules_dir,
                                                  const AnalysisReport& report,
                                                  std::vector<std::string>& warnings) const {
  std::vector<RuleFinding> findings;
  const auto files = rule_files(rules_dir);
  if (files.empty()) {
    warnings.push_back("no YAML rule files found in " + rules_dir.string());
    return findings;
  }

  std::vector<RuleSpec> rules;
  for (const auto& path : files) {
    auto parsed = parse_rule_file(path, warnings);
    rules.insert(rules.end(), parsed.begin(), parsed.end());
  }

  for (const auto& rule : rules) {
    std::set<std::string> evidence;
    for (const auto& import : report.imports) {
      for (const auto& wanted : rule.functions) {
        if (!import.symbol.empty() && matches_symbol(wanted, import.symbol)) {
          evidence.insert("function:" + import.symbol);
        }
      }
      for (const auto& wanted : rule.libraries) {
        if (!import.library.empty() &&
            lowercase(import.library).find(lowercase(wanted)) != std::string::npos) {
          evidence.insert("library:" + import.library);
        }
      }
    }

    for (const auto& suspicious : report.strings) {
      for (const auto& pattern : rule.string_regexes) {
        try {
          std::string normalized = pattern;
          auto flags = std::regex::ECMAScript;
          if (normalized.rfind("(?i)", 0) == 0) {
            normalized = normalized.substr(4);
            flags |= std::regex::icase;
          }
          if (std::regex_search(suspicious.value, std::regex(normalized, flags))) {
            evidence.insert("string:" + suspicious.category + ":" + suspicious.value);
          }
        } catch (const std::exception& ex) {
          warnings.push_back("invalid regex in rule " + rule.id + ": " + ex.what());
        }
      }
    }

    for (const auto& section : report.sections) {
      for (const auto& wanted : rule.section_flags) {
        if (flags_match(wanted, section.flags)) {
          evidence.insert("section:" + section.name + ":" + section.flags);
        }
      }
      for (const auto& wanted : rule.section_names) {
        if (section_name_match(wanted, section.name)) {
          evidence.insert("section-name:" + section.name);
        }
      }
      if (rule.section_entropy_min > 0.0 && section.entropy >= rule.section_entropy_min) {
        std::ostringstream entropy;
        entropy.setf(std::ios::fixed);
        entropy.precision(2);
        entropy << section.entropy;
        evidence.insert("section-entropy:" + section.name + ":" + entropy.str());
      }
    }

    if (rule.import_count_max >= 0 &&
        report.imports.size() <= static_cast<std::size_t>(rule.import_count_max) &&
        report.target.format != BinaryFormat::Unknown) {
      evidence.insert("import-count:" + std::to_string(report.imports.size()));
    }

    if (!evidence.empty()) {
      RuleFinding finding;
      finding.id = rule.id;
      finding.title = rule.title.empty() ? rule.id : rule.title;
      finding.severity = rule.severity;
      finding.tags = rule.tags;
      finding.description = rule.description;
      finding.recommendation = rule.recommendation;
      finding.evidence.assign(evidence.begin(), evidence.end());
      findings.push_back(std::move(finding));
    }
  }
  return findings;
}

}  // namespace binsight
