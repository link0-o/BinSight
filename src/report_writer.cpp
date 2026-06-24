#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <sstream>

namespace binsight {

namespace {

void markdown_list(std::ostringstream& out, const std::vector<std::string>& values,
                   const std::string& none_text) {
  if (values.empty()) {
    out << "- " << none_text << '\n';
    return;
  }
  for (const auto& value : values) {
    out << "- " << value << '\n';
  }
}

void write_target_en(std::ostringstream& out, const AnalysisReport& report) {
  out << "## Target\n\n";
  out << "- Path: `" << report.target.path << "`\n";
  out << "- Format: " << report.target.format_name << "\n";
  out << "- Architecture: " << report.target.architecture << "\n";
  out << "- Bits: " << report.target.bits << "\n";
  out << "- Stripped: " << (report.target.stripped ? "yes" : "no") << "\n";
  out << "- Size: " << report.target.size << " bytes\n";
  out << "- Hash: `" << report.target.content_hash << "`\n\n";
}

void write_target_zh(std::ostringstream& out, const AnalysisReport& report) {
  out << "## 目标文件\n\n";
  out << "- 路径：`" << report.target.path << "`\n";
  out << "- 格式：" << report.target.format_name << "\n";
  out << "- 架构：" << report.target.architecture << "\n";
  out << "- 位数：" << report.target.bits << "\n";
  out << "- 是否剥离符号：" << (report.target.stripped ? "是" : "否") << "\n";
  out << "- 大小：" << report.target.size << " bytes\n";
  out << "- 哈希：`" << report.target.content_hash << "`\n\n";
}

std::string zh_known_text(const std::string& value) {
  if (value == "Command execution capability") return "命令执行能力";
  if (value == "Network communication capability") return "网络通信能力";
  if (value == "Process injection capability") return "进程注入能力";
  if (value == "The binary contains imports or strings associated with launching commands or child processes.") {
    return "该文件包含与启动命令或子进程相关的导入函数或字符串。";
  }
  if (value == "Review call sites and confirm whether command construction includes untrusted input.") {
    return "检查相关调用点，确认命令构造过程是否包含不可信输入。";
  }
  if (value == "No deterministic risk rules matched. This does not prove the binary is safe.") {
    return "未命中确定性风险规则。这并不能证明该文件安全。";
  }
  if (value == "Review full imports, strings, and sections if the sample is high value.") {
    return "如果样本价值较高，建议继续人工审查完整导入项、字符串和节区信息。";
  }
  return value;
}

std::string zh_summary(const AnalysisReport& report) {
  if (report.ai_analysis.provider != "none") {
    return report.ai_analysis.summary;
  }
  if (report.rule_findings.empty()) {
    return "未命中确定性风险规则。这并不能证明该文件安全。";
  }
  return "确定性规则命中 " + std::to_string(report.rule_findings.size()) +
         " 个风险项。本地最高风险等级：" + to_string(report.ai_analysis.severity) + "。";
}

std::string zh_risk_source(const std::string& value) {
  const auto pos = value.find(": ");
  if (pos == std::string::npos) {
    return zh_known_text(value);
  }
  return value.substr(0, pos + 2) + zh_known_text(value.substr(pos + 2));
}

std::string zh_match_reason(const std::string& value) {
  if (value.rfind("matched rule: ", 0) == 0) return "命中规则：" + value.substr(14);
  if (value.rfind("matched api: ", 0) == 0) return "命中 API：" + value.substr(13);
  if (value.rfind("matched string: ", 0) == 0) return "命中字符串：" + value.substr(16);
  if (value.rfind("matched tag: ", 0) == 0) return "命中标签：" + value.substr(13);
  return value;
}

void write_imports(std::ostringstream& out, const AnalysisReport& report,
                   const std::string& title, const std::string& empty_text) {
  out << "## " << title << "\n\n";
  if (report.imports.empty()) {
    out << empty_text << "\n\n";
    return;
  }
  for (const auto& item : report.imports) {
    out << "- " << (item.library.empty() ? "(unknown library)" : item.library);
    if (!item.symbol.empty()) {
      out << " :: `" << item.symbol << "`";
    }
    out << '\n';
  }
  out << '\n';
}

void write_strings(std::ostringstream& out, const AnalysisReport& report,
                   const std::string& title, const std::string& empty_text) {
  out << "## " << title << "\n\n";
  if (report.strings.empty()) {
    out << empty_text << "\n\n";
    return;
  }
  for (const auto& item : report.strings) {
    out << "- `" << item.category << "`: `" << item.value << "`\n";
  }
  out << '\n';
}

void write_rag_en(std::ostringstream& out, const AnalysisReport& report) {
  out << "## RAG Context\n\n";
  if (report.rag_context.empty()) {
    out << "No local knowledge entries retrieved.\n\n";
    return;
  }
  for (const auto& item : report.rag_context) {
    out << "- " << item.id << " (" << item.score << "): " << item.title << '\n';
    if (!item.source.empty()) {
      out << "  - Source: `" << item.source << "`\n";
    }
    if (!item.match_reasons.empty()) {
      out << "  - Match reasons:\n";
      for (const auto& reason : item.match_reasons) {
        out << "    - " << reason << '\n';
      }
    }
  }
  out << '\n';
}

void write_rag_zh(std::ostringstream& out, const AnalysisReport& report) {
  out << "## RAG 上下文\n\n";
  if (report.rag_context.empty()) {
    out << "未检索到本地知识条目。\n\n";
    return;
  }
  for (const auto& item : report.rag_context) {
    out << "- " << item.id << " (" << item.score << "): " << item.title << '\n';
    if (!item.source.empty()) {
      out << "  - 来源：`" << item.source << "`\n";
    }
    if (!item.match_reasons.empty()) {
      out << "  - 命中原因：\n";
      for (const auto& reason : item.match_reasons) {
        out << "    - " << zh_match_reason(reason) << '\n';
      }
    }
  }
  out << '\n';
}

}  // namespace

void ReportWriter::write_markdown(const std::filesystem::path& path,
                                  const AnalysisReport& report,
                                  ReportLanguage language) const {
  const bool zh = language == ReportLanguage::Chinese;
  std::ostringstream out;
  out << (zh ? "# BinSight 风险报告\n\n" : "# BinSight Risk Report\n\n");

  if (zh) {
    write_target_zh(out, report);
    out << "## AI 分析\n\n";
    out << "- 提供方：" << report.ai_analysis.provider << "\n";
    out << "- 模型：" << (report.ai_analysis.model.empty() ? "无" : report.ai_analysis.model) << "\n";
    out << "- 风险等级：" << to_string(report.ai_analysis.severity) << "\n\n";
    out << zh_summary(report) << "\n\n";
    out << "### 风险来源\n\n";
    if (report.ai_analysis.risk_sources.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& source : report.ai_analysis.risk_sources) {
        out << "- " << zh_risk_source(source) << '\n';
      }
    }
    out << "\n### 建议\n\n";
    if (report.ai_analysis.recommendations.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& recommendation : report.ai_analysis.recommendations) {
        out << "- " << zh_known_text(recommendation) << '\n';
      }
    }

    out << "\n## 规则命中\n\n";
    if (report.rule_findings.empty()) {
      out << "未命中规则。\n\n";
    } else {
      for (const auto& finding : report.rule_findings) {
        out << "### " << finding.id << ": " << zh_known_text(finding.title) << "\n\n";
        out << "- 风险等级：" << to_string(finding.severity) << "\n";
        out << "- 描述：" << zh_known_text(finding.description) << "\n";
        out << "- 建议：" << zh_known_text(finding.recommendation) << "\n";
        out << "- 证据：\n";
        markdown_list(out, finding.evidence, "无");
        out << '\n';
      }
    }

    write_imports(out, report, "导入项", "未提取到导入项。");
    write_strings(out, report, "可疑字符串", "内置分类器未匹配到可疑字符串。");
    write_rag_zh(out, report);
    out << "## 警告\n\n";
    markdown_list(out, report.warnings, "无");
  } else {
    write_target_en(out, report);
    out << "## AI Analysis\n\n";
    out << "- Provider: " << report.ai_analysis.provider << "\n";
    out << "- Model: " << (report.ai_analysis.model.empty() ? "(none)" : report.ai_analysis.model) << "\n";
    out << "- Severity: " << to_string(report.ai_analysis.severity) << "\n\n";
    out << report.ai_analysis.summary << "\n\n";
    out << "### Risk Sources\n\n";
    markdown_list(out, report.ai_analysis.risk_sources, "None");
    out << "\n### Recommendations\n\n";
    markdown_list(out, report.ai_analysis.recommendations, "None");

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
        markdown_list(out, finding.evidence, "None");
        out << '\n';
      }
    }

    write_imports(out, report, "Imports", "No imports extracted.");
    write_strings(out, report, "Suspicious Strings", "No suspicious strings matched built-in classifiers.");
    write_rag_en(out, report);
    out << "## Warnings\n\n";
    markdown_list(out, report.warnings, "None");
  }

  write_file(path, out.str());
}

void ReportWriter::write_json(const std::filesystem::path& path,
                              const AnalysisReport& report) const {
  write_file(path, to_json(report));
}

}  // namespace binsight
