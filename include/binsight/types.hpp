#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace binsight {

enum class BinaryFormat { Unknown, ELF, PE };

enum class Severity { Info, Low, Medium, High, Critical };

enum class ReportLanguage { English, Chinese, Both };

enum class AnalysisMode { Static, StaticWithDynamicReport };

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
  std::filesystem::path output_dir;
  ReportLanguage report_language = ReportLanguage::Both;
  std::string provider = "none";
  std::string model;
  std::string base_url;
  std::string api_key_env = "OPENAI_API_KEY";
  std::string api_key_name;
  std::string api_key_override;
  std::filesystem::path dynamic_report_path;
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
  double entropy = 0.0;
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
  std::string risk_type = "suspicious";
  std::string confidence = "medium";
  std::string evidence_strength = "medium";
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

struct RiskAssessment {
  Severity severity = Severity::Info;
  std::string summary;
  std::vector<std::string> risk_sources;
  std::vector<std::string> recommendations;
};

struct AiAnalysis {
  std::string provider = "none";
  std::string model;
  Severity severity = Severity::Info;
  std::string confidence = "low";
  std::string summary;
  std::string decision_basis;
  std::vector<std::string> risk_sources;
  std::vector<std::string> recommendations;
  std::string raw_response;
};

struct FinalAssessment {
  Severity severity = Severity::Info;
  std::string summary;
  std::string decision_basis;
  std::vector<std::string> risk_sources;
  std::vector<std::string> recommendations;
};

struct DynamicProcessEvent {
  std::string event_type;
  int pid = 0;
  int parent_pid = 0;
  std::string image;
  std::string command_line;
};

struct DynamicFileEvent {
  std::string path;
  std::string operation;
  std::uint64_t size = 0;
  std::string hash;
};

struct DynamicNetworkEvent {
  std::string operation;
  std::string destination;
  std::string detail;
};

struct DynamicObservations {
  bool present = false;
  std::string platform;
  std::string mode;
  int timeout_seconds = 0;
  bool timed_out = false;
  int exit_code = -1;
  std::string network_mode;
  std::string stdout_text;
  std::string stderr_text;
  std::vector<DynamicProcessEvent> process_events;
  std::vector<DynamicFileEvent> file_events;
  std::vector<DynamicNetworkEvent> network_events;
  std::vector<std::string> syscall_summary;
  std::vector<std::string> warnings;
};

struct AnalysisReport {
  AnalysisMode analysis_mode = AnalysisMode::Static;
  TargetInfo target;
  std::vector<ImportEntry> imports;
  std::vector<SectionInfo> sections;
  std::vector<SuspiciousString> strings;
  std::vector<DisassemblySnippet> disassembly_snippets;
  std::vector<RuleFinding> rule_findings;
  std::vector<RagEntry> rag_context;
  RiskAssessment local_analysis;
  AiAnalysis ai_analysis;
  FinalAssessment final_assessment;
  DynamicObservations dynamic_observations;
  std::vector<std::string> warnings;
};

std::string to_string(BinaryFormat format);
std::string to_string(Severity severity);
std::string to_string(ReportLanguage language);
std::string to_string(AnalysisMode mode);
Severity severity_from_string(const std::string& value);
ReportLanguage report_language_from_string(const std::string& value);
std::string to_json(const AnalysisReport& report);

}  // namespace binsight
