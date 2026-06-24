#include <binsight/types.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <sstream>

namespace binsight {

std::string to_string(BinaryFormat format) {
  switch (format) {
    case BinaryFormat::ELF:
      return "ELF";
    case BinaryFormat::PE:
      return "PE";
    case BinaryFormat::Unknown:
      return "unknown";
  }
  return "unknown";
}

std::string to_string(Severity severity) {
  switch (severity) {
    case Severity::Info:
      return "info";
    case Severity::Low:
      return "low";
    case Severity::Medium:
      return "medium";
    case Severity::High:
      return "high";
    case Severity::Critical:
      return "critical";
  }
  return "info";
}

Severity severity_from_string(const std::string& value) {
  std::string lower = value;
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (lower == "critical") return Severity::Critical;
  if (lower == "high") return Severity::High;
  if (lower == "medium") return Severity::Medium;
  if (lower == "low") return Severity::Low;
  return Severity::Info;
}

namespace {

void json_string(std::ostringstream& out, const std::string& value) {
  out << '"' << json_escape(value) << '"';
}

void json_string_array(std::ostringstream& out, const std::vector<std::string>& values) {
  out << '[';
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i != 0) out << ',';
    json_string(out, values[i]);
  }
  out << ']';
}

}  // namespace

std::string to_json(const AnalysisReport& report) {
  std::ostringstream out;
  out << "{\n";
  out << "  \"target\": {";
  out << "\"path\":"; json_string(out, report.target.path); out << ',';
  out << "\"format\":"; json_string(out, report.target.format_name); out << ',';
  out << "\"architecture\":"; json_string(out, report.target.architecture); out << ',';
  out << "\"bits\":" << report.target.bits << ',';
  out << "\"stripped\":" << (report.target.stripped ? "true" : "false") << ',';
  out << "\"size\":" << report.target.size << ',';
  out << "\"content_hash\":"; json_string(out, report.target.content_hash);
  out << "},\n";

  out << "  \"imports\": [";
  for (const auto& item : report.imports) {
    if (&item != &report.imports.front()) out << ',';
    out << "{\"library\":"; json_string(out, item.library);
    out << ",\"symbol\":"; json_string(out, item.symbol); out << '}';
  }
  out << "],\n";

  out << "  \"sections\": [";
  for (const auto& item : report.sections) {
    if (&item != &report.sections.front()) out << ',';
    out << "{\"name\":"; json_string(out, item.name);
    out << ",\"flags\":"; json_string(out, item.flags);
    out << ",\"size\":" << item.size;
    out << ",\"risk_note\":"; json_string(out, item.risk_note); out << '}';
  }
  out << "],\n";

  out << "  \"strings\": [";
  for (const auto& item : report.strings) {
    if (&item != &report.strings.front()) out << ',';
    out << "{\"value\":"; json_string(out, item.value);
    out << ",\"category\":"; json_string(out, item.category); out << '}';
  }
  out << "],\n";

  out << "  \"disassembly_snippets\": [";
  for (const auto& item : report.disassembly_snippets) {
    if (&item != &report.disassembly_snippets.front()) out << ',';
    out << "{\"trigger\":"; json_string(out, item.trigger);
    out << ",\"text\":"; json_string(out, item.text); out << '}';
  }
  out << "],\n";

  out << "  \"rule_findings\": [";
  for (const auto& item : report.rule_findings) {
    if (&item != &report.rule_findings.front()) out << ',';
    out << "{\"id\":"; json_string(out, item.id);
    out << ",\"title\":"; json_string(out, item.title);
    out << ",\"severity\":"; json_string(out, to_string(item.severity));
    out << ",\"tags\":"; json_string_array(out, item.tags);
    out << ",\"description\":"; json_string(out, item.description);
    out << ",\"recommendation\":"; json_string(out, item.recommendation);
    out << ",\"evidence\":"; json_string_array(out, item.evidence); out << '}';
  }
  out << "],\n";

  out << "  \"rag_context\": [";
  for (const auto& item : report.rag_context) {
    if (&item != &report.rag_context.front()) out << ',';
    out << "{\"id\":"; json_string(out, item.id);
    out << ",\"title\":"; json_string(out, item.title);
    out << ",\"score\":" << item.score;
    out << ",\"excerpt\":"; json_string(out, item.excerpt); out << '}';
  }
  out << "],\n";

  out << "  \"ai_analysis\": {";
  out << "\"provider\":"; json_string(out, report.ai_analysis.provider); out << ',';
  out << "\"model\":"; json_string(out, report.ai_analysis.model); out << ',';
  out << "\"severity\":"; json_string(out, to_string(report.ai_analysis.severity)); out << ',';
  out << "\"summary\":"; json_string(out, report.ai_analysis.summary); out << ',';
  out << "\"risk_sources\":"; json_string_array(out, report.ai_analysis.risk_sources); out << ',';
  out << "\"recommendations\":"; json_string_array(out, report.ai_analysis.recommendations); out << ',';
  out << "\"raw_response\":"; json_string(out, report.ai_analysis.raw_response);
  out << "},\n";

  out << "  \"warnings\": ";
  json_string_array(out, report.warnings);
  out << "\n}\n";
  return out.str();
}

}  // namespace binsight
