#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace binsight {

enum class BinaryFormat { Unknown, ELF, PE };

enum class Severity { Info, Low, Medium, High, Critical };

struct ToolResult {
  int exit_code = -1;
  std::string output;
  std::string error;
};

struct ScanOptions {
  std::filesystem::path binary_path;
  std::filesystem::path knowledge_dir = "knowledge";
  std::filesystem::path rules_dir = "rules";
  bool knowledge_dir_explicit = false;
  bool rules_dir_explicit = false;
  std::filesystem::path markdown_out = "report.md";
  std::filesystem::path json_out = "report.json";
  std::string provider = "none";
  std::string model;
  std::string base_url;
  std::string api_key_env = "OPENAI_API_KEY";
  int max_disasm_snippets = 6;
};

struct TargetInfo {
  std::string path;
  BinaryFormat format = BinaryFormat::Unknown;
  std::string format_name = "unknown";
  std::string architecture = "unknown";
  int bits = 0;
  bool stripped = false;
  std::uintmax_t size = 0;
  std::string content_hash;
};

struct ImportEntry {
  std::string library;
  std::string symbol;
};

struct SectionInfo {
  std::string name;
  std::string flags;
  std::uint64_t size = 0;
  std::string risk_note;
};

struct SuspiciousString {
  std::string value;
  std::string category;
};

struct DisassemblySnippet {
  std::string trigger;
  std::string text;
};

struct RuleFinding {
  std::string id;
  std::string title;
  Severity severity = Severity::Info;
  std::vector<std::string> tags;
  std::string description;
  std::string recommendation;
  std::vector<std::string> evidence;
};

struct RagEntry {
  std::string id;
  std::string title;
  std::string source;
  int score = 0;
  std::string excerpt;
  std::vector<std::string> matched_terms;
  std::vector<std::string> match_reasons;
};

struct AiAnalysis {
  std::string provider = "none";
  std::string model;
  Severity severity = Severity::Info;
  std::string summary;
  std::vector<std::string> risk_sources;
  std::vector<std::string> recommendations;
  std::string raw_response;
};

struct AnalysisReport {
  TargetInfo target;
  std::vector<ImportEntry> imports;
  std::vector<SectionInfo> sections;
  std::vector<SuspiciousString> strings;
  std::vector<DisassemblySnippet> disassembly_snippets;
  std::vector<RuleFinding> rule_findings;
  std::vector<RagEntry> rag_context;
  AiAnalysis ai_analysis;
  std::vector<std::string> warnings;
};

std::string to_string(BinaryFormat format);
std::string to_string(Severity severity);
Severity severity_from_string(const std::string& value);
std::string to_json(const AnalysisReport& report);

}  // namespace binsight
