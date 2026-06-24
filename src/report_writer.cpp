#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <fstream>
#include <sstream>

namespace binsight {

namespace {

void markdown_list(std::ostringstream& out, const std::vector<std::string>& values) {
  if (values.empty()) {
    out << "- None\n";
    return;
  }
  for (const auto& value : values) {
    out << "- " << value << '\n';
  }
}

}  // namespace

void ReportWriter::write_markdown(const std::filesystem::path& path,
                                  const AnalysisReport& report) const {
  std::ostringstream out;
  out << "# BinSight Risk Report\n\n";
  out << "## Target\n\n";
  out << "- Path: `" << report.target.path << "`\n";
  out << "- Format: " << report.target.format_name << "\n";
  out << "- Architecture: " << report.target.architecture << "\n";
  out << "- Bits: " << report.target.bits << "\n";
  out << "- Stripped: " << (report.target.stripped ? "yes" : "no") << "\n";
  out << "- Size: " << report.target.size << " bytes\n";
  out << "- Hash: `" << report.target.content_hash << "`\n\n";

  out << "## AI Analysis\n\n";
  out << "- Provider: " << report.ai_analysis.provider << "\n";
  out << "- Model: " << (report.ai_analysis.model.empty() ? "(none)" : report.ai_analysis.model) << "\n";
  out << "- Severity: " << to_string(report.ai_analysis.severity) << "\n\n";
  out << report.ai_analysis.summary << "\n\n";

  out << "### Risk Sources\n\n";
  markdown_list(out, report.ai_analysis.risk_sources);
  out << "\n### Recommendations\n\n";
  markdown_list(out, report.ai_analysis.recommendations);

  out << "\n## Rule Findings\n\n";
  if (report.rule_findings.empty()) {
    out << "No rule findings.\n\n";
  } else {
    for (const auto& finding : report.rule_findings) {
      out << "### " << finding.id << ": " << finding.title << "\n\n";
      out << "- Severity: " << to_string(finding.severity) << "\n";
      out << "- Description: " << finding.description << "\n";
      out << "- Recommendation: " << finding.recommendation << "\n";
      out << "- Evidence:\n";
      markdown_list(out, finding.evidence);
      out << '\n';
    }
  }

  out << "## Imports\n\n";
  if (report.imports.empty()) {
    out << "No imports extracted.\n\n";
  } else {
    for (const auto& item : report.imports) {
      out << "- " << (item.library.empty() ? "(unknown library)" : item.library);
      if (!item.symbol.empty()) {
        out << " :: `" << item.symbol << "`";
      }
      out << '\n';
    }
    out << '\n';
  }

  out << "## Suspicious Strings\n\n";
  if (report.strings.empty()) {
    out << "No suspicious strings matched built-in classifiers.\n\n";
  } else {
    for (const auto& item : report.strings) {
      out << "- `" << item.category << "`: `" << item.value << "`\n";
    }
    out << '\n';
  }

  out << "## RAG Context\n\n";
  if (report.rag_context.empty()) {
    out << "No local knowledge entries retrieved.\n\n";
  } else {
    for (const auto& item : report.rag_context) {
      out << "- " << item.id << " (" << item.score << "): " << item.title << '\n';
    }
    out << '\n';
  }

  out << "## Warnings\n\n";
  markdown_list(out, report.warnings);

  write_file(path, out.str());
}

void ReportWriter::write_json(const std::filesystem::path& path,
                              const AnalysisReport& report) const {
  write_file(path, to_json(report));
}

}  // namespace binsight
