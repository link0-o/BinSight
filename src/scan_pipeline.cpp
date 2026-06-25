#include <binsight/scan_pipeline.hpp>

#include <binsight/binary_analyzer.hpp>
#include <binsight/dynamic_observer.hpp>
#include <binsight/llm_client.hpp>
#include <binsight/local_rag.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/risk_rule_engine.hpp>
#include <binsight/string_scanner.hpp>
#include <binsight/utils.hpp>

namespace binsight {

namespace {

std::filesystem::path resolve_resource_dir(const std::filesystem::path& requested,
                                           bool explicit_path,
                                           const std::filesystem::path& exe_dir,
                                           const std::string& name) {
  if (explicit_path || std::filesystem::exists(requested)) {
    return requested;
  }
  if (!exe_dir.empty()) {
    const auto beside_exe = exe_dir / name;
    if (std::filesystem::exists(beside_exe)) {
      return beside_exe;
    }
    const auto one_up = exe_dir.parent_path() / name;
    if (std::filesystem::exists(one_up)) {
      return one_up;
    }
  }
  return requested;
}

bool has_static_inconclusive_finding(const AnalysisReport& report) {
  for (const auto& finding : report.rule_findings) {
    for (const auto& tag : finding.tags) {
      const auto lower = lowercase(tag);
      if (lower == "static-inconclusive" || lower == "packing" || lower == "obfuscation") {
        return true;
      }
    }
  }
  return false;
}

}  // namespace

std::filesystem::path with_output_dir(const std::filesystem::path& output_dir,
                                      const std::filesystem::path& path) {
  if (output_dir.empty() || path.is_absolute() || path.has_parent_path()) {
    return path;
  }
  return output_dir / path;
}

std::filesystem::path language_path(const std::filesystem::path& path,
                                    const std::string& suffix) {
  const auto parent = path.parent_path();
  const std::string stem = path.stem().string();
  const std::string ext = path.extension().empty() ? ".md" : path.extension().string();
  return parent / (stem + "." + suffix + ext);
}

std::vector<std::pair<std::filesystem::path, ReportLanguage>> markdown_output_paths(
    const ScanOptions& options) {
  const auto base = with_output_dir(options.output_dir, options.markdown_out);
  if (options.report_language == ReportLanguage::English) {
    return {{base, ReportLanguage::English}};
  }
  if (options.report_language == ReportLanguage::Chinese) {
    return {{base, ReportLanguage::Chinese}};
  }
  return {{language_path(base, "zh-CN"), ReportLanguage::Chinese},
          {language_path(base, "en"), ReportLanguage::English}};
}

void resolve_resource_dirs(ScanOptions& options, const std::filesystem::path& executable_dir) {
  options.knowledge_dir = resolve_resource_dir(options.knowledge_dir, options.knowledge_dir_explicit,
                                               executable_dir, "knowledge");
  options.rules_dir = resolve_resource_dir(options.rules_dir, options.rules_dir_explicit,
                                           executable_dir, "rules");
}

AnalysisReport analyze_binary(const ScanOptions& options,
                              const std::vector<std::string>& initial_warnings) {
  ProcessRunner runner;
  BinaryAnalyzer analyzer{runner, StringScanner{}};
  AnalysisReport report = analyzer.analyze(options);
  report.warnings.insert(report.warnings.end(), initial_warnings.begin(), initial_warnings.end());

  if (!options.dynamic_report_path.empty()) {
    std::string error;
    const auto dynamic = read_dynamic_observations(options.dynamic_report_path, error);
    if (dynamic) {
      report.analysis_mode = AnalysisMode::StaticWithDynamicReport;
      report.dynamic_observations = *dynamic;
      report.dynamic_observations.present = true;
    } else {
      report.warnings.push_back("failed to read dynamic report: " + error);
    }
  }

  RiskRuleEngine rules;
  report.rule_findings = rules.evaluate(options.rules_dir, report, report.warnings);
  if (has_static_inconclusive_finding(report)) {
    report.warnings.push_back(
        "static_inconclusive: packing or obfuscation indicators were observed; static evidence may be incomplete");
    if (report.target.format == BinaryFormat::PE) {
      report.warnings.push_back(
          "windows_dynamic_not_automatic: BinSight does not automatically execute Windows samples; use a dedicated VM, professional sandbox, or imported Sysmon events for high-risk packed samples");
    }
  }

  LocalRagIndex rag;
  report.rag_context = rag.retrieve(options.knowledge_dir, report, report.warnings);

  LlmClient llm{runner};
  report.ai_analysis = llm.analyze(options, report, report.warnings);
  return report;
}

ScanExecutionResult analyze_and_write_reports(
    ScanOptions options,
    const std::filesystem::path& executable_dir,
    const std::vector<std::string>& initial_warnings) {
  resolve_resource_dirs(options, executable_dir);
  ScanExecutionResult result;
  result.report = analyze_binary(options, initial_warnings);
  result.markdown_outputs = markdown_output_paths(options);
  result.json_output = with_output_dir(options.output_dir, options.json_out);

  ReportWriter writer;
  for (const auto& [path, language] : result.markdown_outputs) {
    writer.write_markdown(path, result.report, language);
  }
  writer.write_json(result.json_output, result.report);
  return result;
}

}  // namespace binsight
