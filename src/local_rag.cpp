#include <binsight/local_rag.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <filesystem>
#include <regex>
#include <set>

namespace binsight {

namespace {

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
  if (text.size() > 420) {
    text = text.substr(0, 420) + "...";
  }
  return text;
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

  std::set<std::string> query_tokens;
  for (const auto& finding : report.rule_findings) {
    for (const auto& token : tokens_from_text(finding.id + " " + finding.title + " " +
                                              finding.description)) {
      query_tokens.insert(token);
    }
    for (const auto& tag : finding.tags) {
      query_tokens.insert(lowercase(tag));
    }
  }
  for (const auto& item : report.imports) {
    for (const auto& token : tokens_from_text(item.library + " " + item.symbol)) {
      query_tokens.insert(token);
    }
  }
  for (const auto& item : report.strings) {
    query_tokens.insert(lowercase(item.category));
  }

  std::vector<RagEntry> entries;
  for (const auto& entry : std::filesystem::directory_iterator(knowledge_dir)) {
    if (!entry.is_regular_file() || entry.path().extension() != ".md") {
      continue;
    }
    std::string content;
    try {
      content = read_file(entry.path());
    } catch (const std::exception& ex) {
      warnings.push_back("failed to read knowledge file " + entry.path().string() + ": " + ex.what());
      continue;
    }
    const std::string lower_content = lowercase(content + " " + entry.path().stem().string());
    int score = 0;
    for (const auto& token : query_tokens) {
      if (token.size() < 3) {
        continue;
      }
      if (lower_content.find(token) != std::string::npos) {
        score += 1;
      }
    }
    if (score > 0) {
      entries.push_back({entry.path().stem().string(), first_heading_or_stem(entry.path(), content),
                         score, excerpt(content)});
    }
  }

  std::sort(entries.begin(), entries.end(), [](const RagEntry& a, const RagEntry& b) {
    if (a.score != b.score) {
      return a.score > b.score;
    }
    return a.id < b.id;
  });
  if (entries.size() > limit) {
    entries.resize(limit);
  }
  return entries;
}

}  // namespace binsight

