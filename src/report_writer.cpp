#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <fstream>
#include <sstream>

namespace binsight {

namespace {

void markdown_list(std::ostringstream& out, const std::vector<std::string>& values) {
  if (values.empty()) {
    out << "- None / 无\n";
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
  out << "# BinSight Risk Report / BinSight 风险报告\n\n";
  out << "## Target / 目标文件\n\n";
  out << "- Path / 路径: `" << report.target.path << "`\n";
  out << "- Format / 格式: " << report.target.format_name << "\n";
  out << "- Architecture / 架构: " << report.target.architecture << "\n";
  out << "- Bits / 位数: " << report.target.bits << "\n";
  out << "- Stripped / 是否剥离符号: " << (report.target.stripped ? "yes / 是" : "no / 否") << "\n";
  out << "- Size / 大小: " << report.target.size << " bytes\n";
  out << "- Hash / 哈希: `" << report.target.content_hash << "`\n\n";

  out << "## AI Analysis / AI 分析\n\n";
  out << "- Provider / 提供方: " << report.ai_analysis.provider << "\n";
  out << "- Model / 模型: " << (report.ai_analysis.model.empty() ? "(none / 无)" : report.ai_analysis.model) << "\n";
  out << "- Severity / 风险等级: " << to_string(report.ai_analysis.severity) << "\n\n";
  out << report.ai_analysis.summary << "\n\n";

  out << "### Risk Sources / 风险来源\n\n";
  markdown_list(out, report.ai_analysis.risk_sources);
  out << "\n### Recommendations / 建议\n\n";
  markdown_list(out, report.ai_analysis.recommendations);

  out << "\n## Rule Findings / 规则命中\n\n";
  if (report.rule_findings.empty()) {
    out << "No rule findings. / 未命中规则。\n\n";
  } else {
    for (const auto& finding : report.rule_findings) {
      out << "### " << finding.id << ": " << finding.title << "\n\n";
      out << "- Severity / 风险等级: " << to_string(finding.severity) << "\n";
      out << "- Description / 描述: " << finding.description << "\n";
      out << "- Recommendation / 建议: " << finding.recommendation << "\n";
      out << "- Evidence / 证据:\n";
      markdown_list(out, finding.evidence);
      out << '\n';
    }
  }

  out << "## Imports / 导入项\n\n";
  if (report.imports.empty()) {
    out << "No imports extracted. / 未提取到导入项。\n\n";
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

  out << "## Suspicious Strings / 可疑字符串\n\n";
  if (report.strings.empty()) {
    out << "No suspicious strings matched built-in classifiers. / 内置分类器未匹配到可疑字符串。\n\n";
  } else {
    for (const auto& item : report.strings) {
      out << "- `" << item.category << "`: `" << item.value << "`\n";
    }
    out << '\n';
  }

  out << "## RAG Context / RAG 上下文\n\n";
  if (report.rag_context.empty()) {
    out << "No local knowledge entries retrieved. / 未检索到本地知识条目。\n\n";
  } else {
    for (const auto& item : report.rag_context) {
      out << "- " << item.id << " (" << item.score << "): " << item.title << '\n';
      if (!item.source.empty()) {
        out << "  - Source / 来源: `" << item.source << "`\n";
      }
      if (!item.match_reasons.empty()) {
        out << "  - Match reasons / 命中原因:\n";
        for (const auto& reason : item.match_reasons) {
          out << "    - " << reason << '\n';
        }
      }
    }
    out << '\n';
  }

  out << "## Warnings / 警告\n\n";
  markdown_list(out, report.warnings);

  write_file(path, out.str());
}

void ReportWriter::write_json(const std::filesystem::path& path,
                              const AnalysisReport& report) const {
  write_file(path, to_json(report));
}

}  // namespace binsight
