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
  out << "- Analysis mode: " << to_string(report.analysis_mode) << "\n";
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
  out << "- 分析模式：" << to_string(report.analysis_mode) << "\n";
  out << "- 路径：`" << report.target.path << "`\n";
  out << "- 格式：" << report.target.format_name << "\n";
  out << "- 架构：" << report.target.architecture << "\n";
  out << "- 位数：" << report.target.bits << "\n";
  out << "- 是否剥离符号：" << (report.target.stripped ? "是" : "否") << "\n";
  out << "- 大小：" << report.target.size << " bytes\n";
  out << "- 哈希：`" << report.target.content_hash << "`\n\n";
}

std::string zh_known_text(const std::string& value) {
  if (value == "capability") return "能力提示";
  if (value == "suspicious") return "可疑行为";
  if (value == "malicious-likely") return "高风险倾向";
  if (value == "low") return "低";
  if (value == "weak") return "弱";
  if (value == "medium") return "中";
  if (value == "high") return "高";
  if (value == "strong") return "强";
  if (value == "Command execution capability") return "命令执行能力";
  if (value == "Dangerous command execution pattern") return "危险命令执行模式";
  if (value == "Network communication capability") return "网络通信能力";
  if (value == "Network API with embedded destination") return "网络 API 与内嵌目标地址";
  if (value == "Process injection capability") return "进程注入能力";
  if (value == "Anti-debugging API usage") return "反调试 API 使用";
  if (value == "Anti-debugging keyword") return "反调试关键词";
  if (value == "High entropy section") return "高熵节区";
  if (value == "Packer-like section name") return "疑似加壳节区名";
  if (value == "Sparse imports in executable") return "可执行文件导入项很少";
  if (value == "Dynamic import resolution capability") return "动态导入解析能力";
  if (value == "Writable executable section") return "可写可执行节区";
  if (value == "The binary imports APIs that can launch commands or child processes. This is a capability signal, not proof of malicious behavior.") {
    return "该文件导入了可启动命令或子进程的 API。这是能力信号，不等于恶意行为证据。";
  }
  if (value == "Command execution APIs appear together with dangerous command strings.") {
    return "命令执行 API 与危险命令字符串同时出现。";
  }
  if (value == "The binary imports APIs that can perform network communication. This alone does not imply malicious behavior.") {
    return "该文件导入了可进行网络通信的 API。单独出现时不代表恶意行为。";
  }
  if (value == "Networking APIs appear together with embedded URL or IP-like strings.") {
    return "网络 API 与内嵌 URL 或疑似 IP 字符串同时出现。";
  }
  if (value == "The binary imports multiple APIs commonly used for remote process manipulation.") {
    return "该文件导入了多个常用于远程进程操作的 API。";
  }
  if (value == "The binary imports APIs commonly used to detect or interfere with debugging.") {
    return "该文件导入了常用于检测或干扰调试的 API。";
  }
  if (value == "The binary contains anti-debugging related text. Keywords alone are weak evidence.") {
    return "该文件包含反调试相关文本。仅有关键词属于弱证据。";
  }
  if (value == "A section has high byte entropy, which may indicate packing, compression, encryption, or embedded data.") {
    return "某个节区具有较高字节熵，可能表示加壳、压缩、加密或嵌入数据。";
  }
  if (value == "The binary contains section names or strings commonly associated with packers or protectors.") {
    return "该文件包含常见于加壳器或保护器的节区名或字符串。";
  }
  if (value == "The binary has very few static imports, which can occur in packed binaries or loaders that resolve APIs dynamically.") {
    return "该文件静态导入项很少，这可能出现在加壳文件或运行时动态解析 API 的加载器中。";
  }
  if (value == "The binary can resolve APIs or libraries dynamically at runtime.") {
    return "该文件可以在运行时动态解析 API 或库。";
  }
  if (value == "Treat static conclusions as incomplete and consider controlled dynamic observation for Linux samples or a dedicated sandbox for high-risk samples.") {
    return "应将静态结论视为不完整；Linux 样本可考虑受控动态观测，高风险样本应使用专用沙箱。";
  }
  if (value == "Verify whether the packing is expected. Strong packers can hide imports and strings from static analysis.") {
    return "确认加壳是否符合预期。强壳可能隐藏导入项和字符串，使静态分析证据不完整。";
  }
  if (value == "Combine this weak signal with entropy, section flags, dynamic API resolution, or runtime observations before drawing conclusions.") {
    return "这是弱信号，应结合熵、节区权限、动态 API 解析或运行时观测后再判断。";
  }
  if (value == "Review this together with packing indicators, writable executable memory, and suspicious runtime behavior.") {
    return "应结合加壳指标、可写可执行内存和可疑运行时行为一起审查。";
  }
  if (value == "Review call sites and confirm whether command construction includes untrusted input.") {
    return "检查相关调用点，确认命令构造过程是否包含不可信输入。";
  }
  if (value == "Review call sites and command construction before treating this as malicious.") {
    return "先审查调用点和命令构造过程，再判断是否恶意。";
  }
  if (value == "Inspect the command path, inputs, and whether execution is expected for this program.") {
    return "检查命令路径、输入来源，以及该程序执行该命令是否符合预期。";
  }
  if (value == "Combine this with destinations, protocols, persistence, credential access, or dynamic observations before escalating.") {
    return "应结合目标地址、协议、持久化、凭据访问或动态观测后再升级风险。";
  }
  if (value == "Verify destinations, protocol use, and whether network behavior is expected.") {
    return "确认目标地址、协议使用方式，以及联网行为是否符合预期。";
  }
  if (value == "Confirm whether matching strings are user-facing text, documentation, or actual anti-analysis logic.") {
    return "确认匹配字符串是用户可见文本、文档内容，还是实际反分析逻辑。";
  }
  if (value == "No deterministic risk rules matched. This does not prove the binary is safe.") {
    return "未命中确定性风险规则。这并不能证明该文件安全。";
  }
  if (value == "Review full imports, strings, and sections if the sample is high value.") {
    return "如果样本价值较高，建议继续人工审查完整导入项、字符串和节区信息。";
  }
  if (value == "No online AI assessment was available; final assessment uses the local deterministic baseline.") {
    return "未获得在线 AI 评估；最终结论使用本地确定性基线。";
  }
  if (value == "AI assessment unavailable; this mirrors the local deterministic baseline.") {
    return "AI 评估不可用；此处镜像本地确定性基线。";
  }
  return value;
}

std::string zh_risk_source(const std::string& value) {
  const auto pos = value.find(": ");
  if (pos == std::string::npos) {
    return zh_known_text(value);
  }
  return value.substr(0, pos + 2) + zh_known_text(value.substr(pos + 2));
}

std::string zh_analysis_summary(const std::string& value) {
  if (value == "No deterministic risk rules matched. This does not prove the binary is safe.") {
    return "未命中确定性风险规则。这并不能证明该文件安全。";
  }
  const std::string prefix = "Deterministic rules matched ";
  const std::string middle = " finding(s). Highest local severity: ";
  if (value.rfind(prefix, 0) == 0) {
    const auto middle_pos = value.find(middle, prefix.size());
    if (middle_pos != std::string::npos) {
      const auto count = value.substr(prefix.size(), middle_pos - prefix.size());
      const auto severity_start = middle_pos + middle.size();
      auto severity = value.substr(severity_start);
      if (!severity.empty() && severity.back() == '.') {
        severity.pop_back();
      }
      return "确定性规则命中 " + count + " 个风险项。本地最高风险等级：" + severity + "。";
    }
  }
  const std::string final_prefix = "Final severity ";
  const std::string combines = " combines local baseline (";
  if (value.rfind(final_prefix, 0) == 0) {
    return value;
  }
  return value;
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

void write_dynamic_en(std::ostringstream& out, const AnalysisReport& report) {
  out << "## Dynamic Observations\n\n";
  if (!report.dynamic_observations.present) {
    out << "No dynamic observation report was attached. Static analysis did not execute the target.\n\n";
    return;
  }
  const auto& dynamic = report.dynamic_observations;
  out << "- Platform: " << dynamic.platform << "\n";
  out << "- Mode: " << dynamic.mode << "\n";
  out << "- Network mode: " << dynamic.network_mode << "\n";
  out << "- Timeout: " << dynamic.timeout_seconds << " seconds\n";
  out << "- Timed out: " << (dynamic.timed_out ? "yes" : "no") << "\n";
  out << "- Exit code: " << dynamic.exit_code << "\n\n";

  out << "### Process Events\n\n";
  if (dynamic.process_events.empty()) {
    out << "- None recorded\n";
  } else {
    for (const auto& event : dynamic.process_events) {
      out << "- " << event.event_type << ": `" << event.image << "` " << event.command_line << "\n";
    }
  }

  out << "\n### Network Events\n\n";
  if (dynamic.network_events.empty()) {
    out << "- None recorded\n";
  } else {
    for (const auto& event : dynamic.network_events) {
      out << "- " << event.operation << ": " << event.detail << "\n";
    }
  }

  out << "\n### File Artifacts\n\n";
  if (dynamic.file_events.empty()) {
    out << "- None recorded\n";
  } else {
    for (const auto& event : dynamic.file_events) {
      out << "- `" << event.path << "` (" << event.size << " bytes, " << event.hash << ")\n";
    }
  }

  out << "\n### Syscall Summary\n\n";
  markdown_list(out, dynamic.syscall_summary, "None recorded");
  out << "\n### Dynamic Warnings\n\n";
  markdown_list(out, dynamic.warnings, "None");
  out << '\n';
}

void write_dynamic_zh(std::ostringstream& out, const AnalysisReport& report) {
  out << "## 动态观测\n\n";
  if (!report.dynamic_observations.present) {
    out << "未附加动态观测报告。静态分析没有执行目标文件。\n\n";
    return;
  }
  const auto& dynamic = report.dynamic_observations;
  out << "- 平台：" << dynamic.platform << "\n";
  out << "- 模式：" << dynamic.mode << "\n";
  out << "- 网络模式：" << dynamic.network_mode << "\n";
  out << "- 超时：" << dynamic.timeout_seconds << " 秒\n";
  out << "- 是否超时：" << (dynamic.timed_out ? "是" : "否") << "\n";
  out << "- 退出码：" << dynamic.exit_code << "\n\n";

  out << "### 进程事件\n\n";
  if (dynamic.process_events.empty()) {
    out << "- 未记录\n";
  } else {
    for (const auto& event : dynamic.process_events) {
      out << "- " << event.event_type << "：`" << event.image << "` " << event.command_line << "\n";
    }
  }

  out << "\n### 网络事件\n\n";
  if (dynamic.network_events.empty()) {
    out << "- 未记录\n";
  } else {
    for (const auto& event : dynamic.network_events) {
      out << "- " << event.operation << "：" << event.detail << "\n";
    }
  }

  out << "\n### 文件产物\n\n";
  if (dynamic.file_events.empty()) {
    out << "- 未记录\n";
  } else {
    for (const auto& event : dynamic.file_events) {
      out << "- `" << event.path << "`（" << event.size << " bytes，" << event.hash << "）\n";
    }
  }

  out << "\n### 系统调用摘要\n\n";
  markdown_list(out, dynamic.syscall_summary, "未记录");
  out << "\n### 动态观测警告\n\n";
  markdown_list(out, dynamic.warnings, "无");
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
    out << "## 最终评估\n\n";
    out << "- 风险等级：" << to_string(report.final_assessment.severity) << "\n";
    out << "- 融合依据：" << zh_known_text(report.final_assessment.decision_basis) << "\n\n";
    out << zh_analysis_summary(report.final_assessment.summary) << "\n\n";
    out << "### 风险来源\n\n";
    if (report.final_assessment.risk_sources.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& source : report.final_assessment.risk_sources) {
        out << "- " << zh_risk_source(source) << '\n';
      }
    }
    out << "\n### 建议\n\n";
    if (report.final_assessment.recommendations.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& recommendation : report.final_assessment.recommendations) {
        out << "- " << zh_known_text(recommendation) << '\n';
      }
    }

    out << "\n## 本地规则评估\n\n";
    out << "- 风险等级：" << to_string(report.local_analysis.severity) << "\n\n";
    out << zh_analysis_summary(report.local_analysis.summary) << "\n\n";
    out << "### 本地风险来源\n\n";
    if (report.local_analysis.risk_sources.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& source : report.local_analysis.risk_sources) {
        out << "- " << zh_risk_source(source) << '\n';
      }
    }
    out << "\n### 本地建议\n\n";
    if (report.local_analysis.recommendations.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& recommendation : report.local_analysis.recommendations) {
        out << "- " << zh_known_text(recommendation) << '\n';
      }
    }

    out << "\n## AI 评估\n\n";
    out << "- 提供方：" << report.ai_analysis.provider << "\n";
    out << "- 模型：" << (report.ai_analysis.model.empty() ? "无" : report.ai_analysis.model) << "\n";
    out << "- 风险等级：" << to_string(report.ai_analysis.severity) << "\n";
    out << "- 置信度：" << zh_known_text(report.ai_analysis.confidence) << "\n";
    out << "- 判断依据：" << zh_known_text(report.ai_analysis.decision_basis) << "\n\n";
    out << zh_analysis_summary(report.ai_analysis.summary) << "\n\n";
    out << "### AI 风险来源\n\n";
    if (report.ai_analysis.risk_sources.empty()) {
      out << "- 无\n";
    } else {
      for (const auto& source : report.ai_analysis.risk_sources) {
        out << "- " << zh_risk_source(source) << '\n';
      }
    }
    out << "\n### AI 建议\n\n";
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
        out << "- 风险类型：" << zh_known_text(finding.risk_type) << "\n";
        out << "- 置信度：" << zh_known_text(finding.confidence) << "\n";
        out << "- 证据强度：" << zh_known_text(finding.evidence_strength) << "\n";
        out << "- 描述：" << zh_known_text(finding.description) << "\n";
        out << "- 建议：" << zh_known_text(finding.recommendation) << "\n";
        out << "- 证据：\n";
        markdown_list(out, finding.evidence, "无");
        out << '\n';
      }
    }

    write_imports(out, report, "导入项", "未提取到导入项。");
    write_strings(out, report, "可疑字符串", "内置分类器未匹配到可疑字符串。");
    write_dynamic_zh(out, report);
    write_rag_zh(out, report);
    out << "## 警告\n\n";
    markdown_list(out, report.warnings, "无");
  } else {
    write_target_en(out, report);
    out << "## Final Assessment\n\n";
    out << "- Severity: " << to_string(report.final_assessment.severity) << "\n";
    out << "- Decision basis: " << report.final_assessment.decision_basis << "\n\n";
    out << report.final_assessment.summary << "\n\n";
    out << "### Risk Sources\n\n";
    markdown_list(out, report.final_assessment.risk_sources, "None");
    out << "\n### Recommendations\n\n";
    markdown_list(out, report.final_assessment.recommendations, "None");

    out << "\n## Local Rule Assessment\n\n";
    out << "- Severity: " << to_string(report.local_analysis.severity) << "\n\n";
    out << report.local_analysis.summary << "\n\n";
    out << "### Local Risk Sources\n\n";
    markdown_list(out, report.local_analysis.risk_sources, "None");
    out << "\n### Local Recommendations\n\n";
    markdown_list(out, report.local_analysis.recommendations, "None");

    out << "\n## AI Assessment\n\n";
    out << "- Provider: " << report.ai_analysis.provider << "\n";
    out << "- Model: " << (report.ai_analysis.model.empty() ? "(none)" : report.ai_analysis.model) << "\n";
    out << "- Severity: " << to_string(report.ai_analysis.severity) << "\n";
    out << "- Confidence: " << report.ai_analysis.confidence << "\n";
    out << "- Decision basis: " << report.ai_analysis.decision_basis << "\n\n";
    out << report.ai_analysis.summary << "\n\n";
    out << "### AI Risk Sources\n\n";
    markdown_list(out, report.ai_analysis.risk_sources, "None");
    out << "\n### AI Recommendations\n\n";
    markdown_list(out, report.ai_analysis.recommendations, "None");

    out << "\n## Rule Findings\n\n";
    if (report.rule_findings.empty()) {
      out << "No rule findings.\n\n";
    } else {
      for (const auto& finding : report.rule_findings) {
        out << "### " << finding.id << ": " << finding.title << "\n\n";
        out << "- Severity: " << to_string(finding.severity) << "\n";
        out << "- Risk type: " << finding.risk_type << "\n";
        out << "- Confidence: " << finding.confidence << "\n";
        out << "- Evidence strength: " << finding.evidence_strength << "\n";
        out << "- Description: " << finding.description << "\n";
        out << "- Recommendation: " << finding.recommendation << "\n";
        out << "- Evidence:\n";
        markdown_list(out, finding.evidence, "None");
        out << '\n';
      }
    }

    write_imports(out, report, "Imports", "No imports extracted.");
    write_strings(out, report, "Suspicious Strings", "No suspicious strings matched built-in classifiers.");
    write_dynamic_en(out, report);
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
