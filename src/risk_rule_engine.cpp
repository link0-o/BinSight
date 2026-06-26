#include <binsight/risk_rule_engine.hpp>
#include <binsight/utils.hpp>

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <filesystem>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace binsight {

namespace {

struct RuleSpec {
  std::string id;
  std::string title;
  Severity severity = Severity::Info;
  std::string risk_type = "suspicious";
  std::string confidence = "medium";
  std::string evidence_strength = "medium";
  std::vector<std::string> tags;
  std::vector<std::string> functions;
  std::vector<std::string> libraries;
  std::vector<std::string> string_regexes;
  std::vector<std::string> section_flags;
  std::vector<std::string> section_names;
  std::vector<std::string> requires_all;
  std::vector<std::string> requires_any;
  double section_entropy_min = 0.0;
  int import_count_max = -1;
  int min_evidence_count = 1;
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

std::string scalar(const YAML::Node& node, const std::string& fallback = {}) {
  if (!node || node.IsNull()) {
    return fallback;
  }
  try {
    return node.as<std::string>();
  } catch (...) {
    return fallback;
  }
}

int integer(const YAML::Node& node, int fallback) {
  if (!node || node.IsNull()) {
    return fallback;
  }
  try {
    return node.as<int>();
  } catch (...) {
    return fallback;
  }
}

double real(const YAML::Node& node, double fallback) {
  if (!node || node.IsNull()) {
    return fallback;
  }
  try {
    return node.as<double>();
  } catch (...) {
    return fallback;
  }
}

std::vector<std::string> string_list(const YAML::Node& node) {
  std::vector<std::string> values;
  if (!node || node.IsNull()) {
    return values;
  }
  try {
    if (node.IsSequence()) {
      for (const auto& item : node) {
        const auto value = scalar(item);
        if (!value.empty()) {
          values.push_back(value);
        }
      }
    } else {
      const auto value = scalar(node);
      if (!value.empty()) {
        values.push_back(value);
      }
    }
  } catch (...) {
    return {};
  }
  return values;
}

std::vector<RuleSpec> parse_rule_file(const std::filesystem::path& path,
                                      std::vector<std::string>& warnings) {
  std::vector<RuleSpec> rules;
  YAML::Node root;
  try {
    root = YAML::LoadFile(path.string());
  } catch (const std::exception& ex) {
    warnings.push_back("failed to parse rule file with yaml-cpp: " + path.string() + ": " + ex.what());
    return rules;
  }

  const auto rule_nodes = root["rules"];
  if (!rule_nodes || !rule_nodes.IsSequence()) {
    warnings.push_back("rule file has no rules sequence: " + path.string());
    return rules;
  }

  for (const auto& node : rule_nodes) {
    RuleSpec rule;
    rule.id = scalar(node["id"]);
    if (rule.id.empty()) {
      warnings.push_back("skipping rule without id in " + path.string());
      continue;
    }
    rule.title = scalar(node["title"], rule.id);
    rule.severity = severity_from_string(scalar(node["severity"], "info"));
    rule.risk_type = scalar(node["risk_type"], "suspicious");
    rule.confidence = scalar(node["confidence"], "medium");
    rule.evidence_strength = scalar(node["evidence_strength"], "medium");
    rule.tags = string_list(node["tags"]);
    rule.description = scalar(node["description"]);
    rule.recommendation = scalar(node["recommendation"]);

    const auto match = node["match"];
    rule.functions = string_list(match["functions"]);
    rule.libraries = string_list(match["libraries"]);
    rule.string_regexes = string_list(match["strings_regex"]);
    rule.section_flags = string_list(match["section_flags"]);
    rule.section_names = string_list(match["section_names"]);
    rule.section_entropy_min = real(match["section_entropy_min"], 0.0);
    rule.import_count_max = integer(match["import_count_max"], -1);
    rule.requires_all = string_list(match["requires_all"]);
    rule.requires_any = string_list(match["requires_any"]);
    rule.min_evidence_count = integer(match["min_evidence_count"], 1);
    rules.push_back(std::move(rule));
  }
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

bool is_configuration_string(const SuspiciousString& item) {
  return lowercase(item.category) == "configuration";
}

std::string normalize_evidence_kind(std::string value) {
  value = lowercase(trim(value));
  if (value == "functions") return "function";
  if (value == "libraries") return "library";
  if (value == "strings") return "string";
  if (value == "section_flags") return "section_flag";
  if (value == "section_names") return "section_name";
  return value;
}

bool has_kind(const std::map<std::string, std::set<std::string>>& evidence_by_kind,
              const std::string& kind) {
  const auto it = evidence_by_kind.find(normalize_evidence_kind(kind));
  return it != evidence_by_kind.end() && !it->second.empty();
}

bool satisfies_requirements(const RuleSpec& rule,
                            const std::map<std::string, std::set<std::string>>& evidence_by_kind,
                            std::size_t evidence_count) {
  if (evidence_count < static_cast<std::size_t>(std::max(1, rule.min_evidence_count))) {
    return false;
  }
  for (const auto& required : rule.requires_all) {
    if (!has_kind(evidence_by_kind, required)) {
      return false;
    }
  }
  if (!rule.requires_any.empty()) {
    bool any = false;
    for (const auto& required : rule.requires_any) {
      any = any || has_kind(evidence_by_kind, required);
    }
    if (!any) {
      return false;
    }
  }
  return true;
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
    std::map<std::string, std::set<std::string>> evidence_by_kind;
    for (const auto& import : report.imports) {
      for (const auto& wanted : rule.functions) {
        if (!import.symbol.empty() && matches_symbol(wanted, import.symbol)) {
          evidence_by_kind["function"].insert("function:" + import.symbol);
        }
      }
      for (const auto& wanted : rule.libraries) {
        if (!import.library.empty() &&
            lowercase(import.library).find(lowercase(wanted)) != std::string::npos) {
          evidence_by_kind["library"].insert("library:" + import.library);
        }
      }
    }

    for (const auto& suspicious : report.strings) {
      if (is_configuration_string(suspicious)) {
        continue;
      }
      for (const auto& pattern : rule.string_regexes) {
        try {
          std::string normalized = pattern;
          auto flags = std::regex::ECMAScript;
          if (normalized.rfind("(?i)", 0) == 0) {
            normalized = normalized.substr(4);
            flags |= std::regex::icase;
          }
          if (std::regex_search(suspicious.value, std::regex(normalized, flags))) {
            evidence_by_kind["string"].insert("string:" + suspicious.category + ":" + suspicious.value);
          }
        } catch (const std::exception& ex) {
          warnings.push_back("invalid regex in rule " + rule.id + ": " + ex.what());
        }
      }
    }

    for (const auto& section : report.sections) {
      for (const auto& wanted : rule.section_flags) {
        if (flags_match(wanted, section.flags)) {
          evidence_by_kind["section_flag"].insert("section:" + section.name + ":" + section.flags);
        }
      }
      for (const auto& wanted : rule.section_names) {
        if (section_name_match(wanted, section.name)) {
          evidence_by_kind["section_name"].insert("section-name:" + section.name);
        }
      }
      if (rule.section_entropy_min > 0.0 && section.entropy >= rule.section_entropy_min) {
        std::ostringstream entropy;
        entropy.setf(std::ios::fixed);
        entropy.precision(2);
        entropy << section.entropy;
        evidence_by_kind["section_entropy"].insert("section-entropy:" + section.name + ":" + entropy.str());
      }
    }

    if (rule.import_count_max >= 0 &&
        report.imports.size() <= static_cast<std::size_t>(rule.import_count_max) &&
        report.target.format != BinaryFormat::Unknown) {
      evidence_by_kind["import_count"].insert("import-count:" + std::to_string(report.imports.size()));
    }

    std::set<std::string> evidence;
    for (const auto& [_, values] : evidence_by_kind) {
      evidence.insert(values.begin(), values.end());
    }
    if (evidence.empty() || !satisfies_requirements(rule, evidence_by_kind, evidence.size())) {
      continue;
    }

    RuleFinding finding;
    finding.id = rule.id;
    finding.title = rule.title.empty() ? rule.id : rule.title;
    finding.severity = rule.severity;
    finding.risk_type = rule.risk_type;
    finding.confidence = rule.confidence;
    finding.evidence_strength = rule.evidence_strength;
    finding.tags = rule.tags;
    finding.description = rule.description;
    finding.recommendation = rule.recommendation;
    finding.evidence.assign(evidence.begin(), evidence.end());
    findings.push_back(std::move(finding));
  }
  return findings;
}

}  // namespace binsight
