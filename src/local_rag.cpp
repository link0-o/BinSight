#include <binsight/local_rag.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <filesystem>
#include <map>
#include <regex>
#include <set>
#include <sstream>

namespace binsight {

namespace {

struct KnowledgeDoc {
  std::string id;
  std::string title;
  std::string source;
  std::string content;
  std::map<std::string, std::vector<std::string>> metadata;
};

std::vector<std::string> tokens_from_text(const std::string& text) {
  std::vector<std::string> tokens;
  std::regex word_re(R"([A-Za-z][A-Za-z0-9_-]{2,})");
  for (std::sregex_iterator it(text.begin(), text.end(), word_re), end; it != end; ++it) {
    tokens.push_back(lowercase(it->str()));
  }
  return tokens;
}

std::string first_heading_or_stem(const std::filesystem::path& path, const std::string& content) {
  for (const auto& line : split_lines(content)) {
    if (line.rfind("# ", 0) == 0) {
      return trim(line.substr(2));
    }
  }
  return path.stem().string();
}

std::string excerpt(const std::string& content) {
  std::string text = content;
  text.erase(std::remove(text.begin(), text.end(), '\r'), text.end());
  if (text.size() > 1200) {
    text = text.substr(0, 1200) + "...";
  }
  return text;
}

std::vector<std::string> parse_inline_list(const std::string& value) {
  const auto begin = value.find('[');
  const auto end = value.rfind(']');
  if (begin == std::string::npos || end == std::string::npos || end <= begin) {
    return {};
  }

  std::vector<std::string> values;
  std::string current;
  bool in_single = false;
  bool in_double = false;
  const std::string inner = value.substr(begin + 1, end - begin - 1);
  for (char c : inner) {
    if (c == '\'' && !in_double) {
      in_single = !in_single;
      current.push_back(c);
    } else if (c == '"' && !in_single) {
      in_double = !in_double;
      current.push_back(c);
    } else if (c == ',' && !in_single && !in_double) {
      std::string item = trim(current);
      if (item.size() >= 2 &&
          ((item.front() == '"' && item.back() == '"') ||
           (item.front() == '\'' && item.back() == '\''))) {
        item = item.substr(1, item.size() - 2);
      }
      if (!item.empty()) values.push_back(item);
      current.clear();
    } else {
      current.push_back(c);
    }
  }

  std::string item = trim(current);
  if (item.size() >= 2 &&
      ((item.front() == '"' && item.back() == '"') ||
       (item.front() == '\'' && item.back() == '\''))) {
    item = item.substr(1, item.size() - 2);
  }
  if (!item.empty()) values.push_back(item);
  return values;
}

KnowledgeDoc parse_doc(const std::filesystem::path& path, const std::string& raw_content) {
  KnowledgeDoc doc;
  doc.source = path.string();
  doc.id = path.stem().string();

  const auto lines = split_lines(raw_content);
  std::size_t content_start = 0;
  if (!lines.empty() && trim(lines.front()) == "---") {
    for (std::size_t i = 1; i < lines.size(); ++i) {
      const std::string line = trim(lines[i]);
      if (line == "---") {
        content_start = i + 1;
        break;
      }
      const auto colon = line.find(':');
      if (colon == std::string::npos) continue;
      const std::string key = lowercase(trim(line.substr(0, colon)));
      const std::string value = trim(line.substr(colon + 1));
      if (key == "id") {
        doc.id = value;
      } else {
        doc.metadata[key] = parse_inline_list(value);
      }
    }
  }

  std::ostringstream body;
  for (std::size_t i = content_start; i < lines.size(); ++i) {
    body << lines[i] << '\n';
  }
  doc.content = body.str();
  doc.title = first_heading_or_stem(path, doc.content);
  return doc;
}

bool equals_ci(const std::string& a, const std::string& b) {
  return lowercase(a) == lowercase(b);
}

bool contains_ci(const std::string& text, const std::string& needle) {
  if (needle.empty()) return false;
  return lowercase(text).find(lowercase(needle)) != std::string::npos;
}

std::string evidence_value(const std::string& evidence) {
  const auto pos = evidence.find(':');
  if (pos == std::string::npos) return evidence;
  const auto second = evidence.find(':', pos + 1);
  if (second == std::string::npos) return evidence.substr(pos + 1);
  return evidence.substr(second + 1);
}

void add_unique(std::vector<std::string>& values, const std::string& value) {
  if (std::find(values.begin(), values.end(), value) == values.end()) {
    values.push_back(value);
  }
}

}  // namespace

std::vector<RagEntry> LocalRagIndex::retrieve(const std::filesystem::path& knowledge_dir,
                                              const AnalysisReport& report,
                                              std::vector<std::string>& warnings,
                                              std::size_t limit) const {
  if (!std::filesystem::exists(knowledge_dir)) {
    warnings.push_back("knowledge directory not found: " + knowledge_dir.string());
    return {};
  }

  std::map<std::string, int> weak_tokens;
  auto add_weak = [&](const std::string& token, int weight) {
    const std::string normalized = lowercase(token);
    if (normalized.size() >= 4) {
      weak_tokens[normalized] += weight;
    }
  };

  std::vector<std::string> rule_ids;
  std::vector<std::string> finding_tags;
  std::vector<std::string> observed_apis;
  std::vector<std::string> observed_strings;

  for (const auto& finding : report.rule_findings) {
    add_unique(rule_ids, finding.id);
    add_weak(finding.id, 4);
    add_weak(finding.title, 2);
    for (const auto& token : tokens_from_text(finding.title + " " + finding.description)) {
      add_weak(token, 1);
    }
    for (const auto& tag : finding.tags) {
      add_unique(finding_tags, tag);
      add_weak(tag, 3);
    }
    for (const auto& evidence : finding.evidence) {
      const std::string value = evidence_value(evidence);
      if (evidence.rfind("function:", 0) == 0) {
        add_unique(observed_apis, value);
        add_weak(value, 3);
      } else if (evidence.rfind("string:", 0) == 0) {
        add_unique(observed_strings, value);
        for (const auto& token : tokens_from_text(value)) add_weak(token, 2);
      }
    }
  }

  for (const auto& item : report.imports) {
    if (!item.symbol.empty()) {
      add_unique(observed_apis, item.symbol);
      add_weak(item.symbol, 2);
    }
    add_weak(item.library, 1);
  }
  for (const auto& item : report.strings) {
    add_unique(observed_strings, item.value);
    add_weak(item.category, 2);
    for (const auto& token : tokens_from_text(item.value)) add_weak(token, 2);
  }

  std::vector<RagEntry> entries;
  for (const auto& entry : std::filesystem::directory_iterator(knowledge_dir)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".md") {
      continue;
    }

    std::string raw_content;
    try {
      raw_content = read_file(entry.path());
    } catch (const std::exception& ex) {
      warnings.push_back("failed to read knowledge file " + entry.path().string() + ": " + ex.what());
      continue;
    }

    const KnowledgeDoc doc = parse_doc(entry.path(), raw_content);
    RagEntry result;
    result.id = doc.id.empty() ? entry.path().stem().string() : doc.id;
    result.title = doc.title;
    result.source = entry.path().string();
    result.excerpt = excerpt(doc.content);

    auto score_metadata = [&](const std::string& field,
                              const std::vector<std::string>& observed,
                              int weight,
                              const std::string& reason_prefix,
                              bool allow_substring) {
      const auto found = doc.metadata.find(field);
      if (found == doc.metadata.end()) return;
      for (const auto& observed_value : observed) {
        for (const auto& expected : found->second) {
          const bool matched = allow_substring ? contains_ci(observed_value, expected)
                                               : equals_ci(observed_value, expected);
          if (matched) {
            result.score += weight;
            add_unique(result.matched_terms, expected);
            add_unique(result.match_reasons, reason_prefix + ": " + expected);
          }
        }
      }
    };

    score_metadata("rules", rule_ids, 1000, "matched rule", false);
    score_metadata("apis", observed_apis, 220, "matched api", false);
    score_metadata("strings", observed_strings, 180, "matched string", true);
    score_metadata("tags", finding_tags, 120, "matched tag", false);

    const std::string searchable = lowercase(doc.id + " " + doc.title + " " + doc.content + " " +
                                             entry.path().stem().string());
    for (const auto& [token, weight] : weak_tokens) {
      if (searchable.find(token) != std::string::npos) {
        result.score += weight;
        if (weight >= 2) {
          add_unique(result.matched_terms, token);
        }
      }
    }

    if (result.score > 0) {
      entries.push_back(std::move(result));
    }
  }

  std::sort(entries.begin(), entries.end(), [](const RagEntry& a, const RagEntry& b) {
    if (a.score != b.score) return a.score > b.score;
    return a.id < b.id;
  });
  if (entries.size() > limit) {
    entries.resize(limit);
  }
  return entries;
}

}  // namespace binsight
