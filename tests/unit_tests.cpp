#include <binsight/binary_analyzer.hpp>
#include <binsight/dynamic_observer.hpp>
#include <binsight/local_rag.hpp>
#include <binsight/llm_client.hpp>
#include <binsight/process_runner.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/risk_rule_engine.hpp>
#include <binsight/scan_pipeline.hpp>
#include <binsight/string_scanner.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

}  // namespace

int main(int argc, char** argv) {
  {
    std::cerr << "[unit] string scanner\n";
    binsight::StringScanner scanner;
    const auto results = scanner.scan("https://example.test/a\n/bin/sh\nshutdown /s /t 0\nnormal text\npassword=secret\n");
    check(results.size() == 4, "StringScanner should find four suspicious strings");
    check(!results.empty() && results[0].category == "url", "first string should be URL");
  }

  {
    std::cerr << "[unit] internal PE fixture\n";
    std::vector<unsigned char> pe(0x500, 0);
    pe[0] = 'M';
    pe[1] = 'Z';
    pe[0x3c] = 0x80;
    const std::size_t pe_offset = 0x80;
    pe[pe_offset] = 'P';
    pe[pe_offset + 1] = 'E';
    pe[pe_offset + 4] = 0x64;
    pe[pe_offset + 5] = 0x86;
    pe[pe_offset + 6] = 1;
    pe[pe_offset + 20] = 0xf0;
    pe[pe_offset + 22] = 0x22;
    pe[pe_offset + 24] = 0x0b;
    pe[pe_offset + 25] = 0x02;
    const std::size_t data_directory = pe_offset + 24 + 112;
    pe[data_directory + 8] = 0x00;
    pe[data_directory + 9] = 0x11;

    const std::size_t section = pe_offset + 24 + 0xf0;
    const std::string section_name = ".rdata";
    std::copy(section_name.begin(), section_name.end(), pe.begin() + section);
    pe[section + 8] = 0x00;
    pe[section + 9] = 0x03;
    pe[section + 12] = 0x00;
    pe[section + 13] = 0x10;
    pe[section + 16] = 0x00;
    pe[section + 17] = 0x03;
    pe[section + 20] = 0x00;
    pe[section + 21] = 0x02;
    pe[section + 39] = 0x40;

    const std::size_t import_descriptor = 0x300;
    pe[import_descriptor] = 0x60;
    pe[import_descriptor + 1] = 0x11;
    pe[import_descriptor + 12] = 0x40;
    pe[import_descriptor + 13] = 0x11;
    pe[import_descriptor + 16] = 0x60;
    pe[import_descriptor + 17] = 0x11;

    const std::string dll = "KERNEL32.dll";
    std::copy(dll.begin(), dll.end(), pe.begin() + 0x340);
    pe[0x360] = 0x80;
    pe[0x361] = 0x11;
    const std::string symbol = "CreateFileA";
    std::copy(symbol.begin(), symbol.end(), pe.begin() + 0x382);
    const std::string command = "shutdown /s /t 0";
    std::copy(command.begin(), command.end(), pe.begin() + 0x420);

    const auto path = std::filesystem::current_path() / "binsight-pe-fixture.bin";
    {
      std::ofstream out(path, std::ios::binary);
      check(static_cast<bool>(out), "PE fixture should be writable");
      out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    binsight::BinaryAnalyzer analyzer{binsight::ProcessRunner{}, binsight::StringScanner{}};
    binsight::ScanOptions options;
    options.binary_path = path;
    options.max_disasm_snippets = 0;
    const auto report = analyzer.analyze(options);
    check(report.target.format == binsight::BinaryFormat::PE, "internal detector should identify PE");
    check(report.target.architecture == "x86_64", "internal detector should identify PE architecture");
#ifndef BINSIGHT_USE_LIEF
    check(std::any_of(report.imports.begin(), report.imports.end(), [](const binsight::ImportEntry& entry) {
            return entry.library == "KERNEL32.dll" && entry.symbol == "CreateFileA";
          }),
          "internal PE parser should extract imports");
#endif
    check(std::any_of(report.strings.begin(), report.strings.end(), [](const binsight::SuspiciousString& item) {
            return item.value == "shutdown /s /t 0";
          }),
          "internal string extractor should find suspicious ASCII strings");
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
  }

#ifdef BINSIGHT_USE_LIEF
  {
    std::cerr << "[unit] LIEF parser self scan\n";
    binsight::BinaryAnalyzer analyzer{binsight::ProcessRunner{}, binsight::StringScanner{}};
    binsight::ScanOptions options;
    options.binary_path = std::filesystem::absolute(argv[0]);
    options.max_disasm_snippets = 0;
    const auto report = analyzer.analyze(options);
    check(report.target.format != binsight::BinaryFormat::Unknown,
          "LIEF parser should identify the current test executable");
    check(!report.sections.empty(), "LIEF parser should extract sections from the current test executable");
    check(std::none_of(report.warnings.begin(), report.warnings.end(), [](const std::string& warning) {
            return warning.find("LIEF parser failed") != std::string::npos;
          }),
          "LIEF parser self scan should not fall back");
  }
#else
  (void)argc;
  (void)argv;
#endif

  {
    std::cerr << "[unit] RAG network retrieval\n";
    binsight::AnalysisReport report;
    binsight::RuleFinding finding;
    finding.id = "network-capability";
    finding.title = "Network communication capability";
    finding.tags = {"network"};
    report.rule_findings.push_back(finding);

    std::vector<std::string> warnings;
    binsight::LocalRagIndex rag;
    const auto entries = rag.retrieve("knowledge", report, warnings, 3);
    check(!entries.empty(), "RAG should return at least one entry");
    check(std::any_of(entries.begin(), entries.end(), [](const binsight::RagEntry& entry) {
            return entry.id == "network-behavior";
          }),
          "RAG should include network knowledge for network findings");
  }

  {
    std::cerr << "[unit] RAG command execution ranking\n";
    binsight::AnalysisReport report;
    binsight::RuleFinding finding;
    finding.id = "dangerous-command-exec";
    finding.title = "Command execution capability";
    finding.tags = {"command-execution", "process"};
    finding.evidence = {"function:system", "string:shell:shutdown /s /t 0"};
    report.rule_findings.push_back(finding);
    report.imports.push_back({"msvcrt.dll", "system"});
    report.strings.push_back({"shutdown /s /t 0", "shell"});

    std::vector<std::string> warnings;
    binsight::LocalRagIndex rag;
    const auto entries = rag.retrieve("knowledge", report, warnings, 5);
    check(!entries.empty(), "command execution RAG should return entries");
    check(!entries.empty() && entries.front().id == "command-execution",
          "command execution knowledge should rank first");
    check(!entries.empty() && !entries.front().match_reasons.empty(),
          "RAG entries should explain match reasons");
  }

  {
    std::cerr << "[unit] RAG process injection ranking\n";
    binsight::AnalysisReport report;
    binsight::RuleFinding finding;
    finding.id = "process-injection";
    finding.title = "Process injection capability";
    finding.tags = {"injection", "windows"};
    finding.evidence = {"function:CreateRemoteThread"};
    report.rule_findings.push_back(finding);
    report.imports.push_back({"KERNEL32.dll", "CreateRemoteThread"});

    std::vector<std::string> warnings;
    binsight::LocalRagIndex rag;
    const auto entries = rag.retrieve("knowledge", report, warnings, 5);
    check(!entries.empty() && entries.front().id == "process-injection",
          "process injection knowledge should rank first");
  }

  {
    std::cerr << "[unit] dynamic observation JSON\n";
    binsight::DynamicObservations dynamic;
    dynamic.present = true;
    dynamic.platform = "linux";
    dynamic.mode = "linux-docker";
    dynamic.timeout_seconds = 30;
    dynamic.exit_code = 0;
    dynamic.network_mode = "none";
    dynamic.process_events.push_back({"execve", 0, 0, "/sample/app", "\"/sample/app\""});
    dynamic.file_events.push_back({"drop.bin", "artifact", 7, "fnv1a64:abc"});
    dynamic.network_events.push_back({"connect", "", "connect(AF_INET)"});
    dynamic.syscall_summary.push_back("execve:1");
    dynamic.warnings.push_back("test warning");
    const auto json = binsight::to_json(dynamic);
    std::string error;
    const auto parsed = binsight::dynamic_observations_from_json(json, error);
    check(parsed.has_value(), "dynamic observations JSON should parse");
    check(parsed && parsed->present, "dynamic observations should remain present");
    check(parsed && parsed->mode == "linux-docker", "dynamic observations should keep mode");
    check(parsed && !parsed->process_events.empty() && parsed->process_events.front().image == "/sample/app",
          "dynamic observations should keep process events");
    check(parsed && !parsed->file_events.empty() && parsed->file_events.front().path == "drop.bin",
          "dynamic observations should keep file events");
  }

  {
    std::cerr << "[unit] packed rules\n";
    binsight::AnalysisReport report;
    report.target.format = binsight::BinaryFormat::ELF;
    report.target.format_name = "ELF";
    report.imports = {{"libc.so.6", "printf"}, {"libc.so.6", "puts"}, {"libc.so.6", "exit"},
                      {"libc.so.6", "malloc"}};
    binsight::SectionInfo packed;
    packed.name = ".packed";
    packed.flags = "AX";
    packed.size = 4096;
    packed.entropy = 7.8;
    report.sections.push_back(packed);
    std::vector<std::string> warnings;
    binsight::RiskRuleEngine rules;
    const auto findings = rules.evaluate("rules", report, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "high-entropy-section";
          }),
          "high entropy section should trigger packed rule");
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "packer-section-name";
          }),
          "packer section name should trigger packed rule");
  }

  {
    std::cerr << "[unit] false-positive controlled rules\n";
    binsight::RiskRuleEngine rules;

    binsight::AnalysisReport only_url;
    only_url.strings.push_back({"https://example.test/api", "url"});
    std::vector<std::string> warnings;
    auto findings = rules.evaluate("rules", only_url, warnings);
    check(std::none_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.severity >= binsight::Severity::High;
          }),
          "a single URL should not be high risk");

    binsight::AnalysisReport only_connect;
    only_connect.imports.push_back({"libc.so.6", "connect"});
    findings = rules.evaluate("rules", only_connect, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "network-capability" && finding.severity == binsight::Severity::Low &&
                   finding.risk_type == "capability" && finding.evidence_strength == "weak";
          }),
          "a single network API should be a weak capability finding");
    check(std::none_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.severity >= binsight::Severity::High;
          }),
          "a single network API should not be high risk");

    binsight::AnalysisReport network_with_url;
    network_with_url.imports.push_back({"libc.so.6", "connect"});
    network_with_url.strings.push_back({"https://example.test/api", "url"});
    findings = rules.evaluate("rules", network_with_url, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "suspicious-network-behavior" &&
                   finding.severity == binsight::Severity::Medium;
          }),
          "network API plus URL should become medium suspicious behavior");

    binsight::AnalysisReport only_popen;
    only_popen.imports.push_back({"libc.so.6", "popen"});
    findings = rules.evaluate("rules", only_popen, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "command-execution-capability" &&
                   finding.severity == binsight::Severity::Medium;
          }),
          "popen alone should be a command execution capability finding");
    check(std::none_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.severity >= binsight::Severity::High;
          }),
          "popen alone should not be high risk");

    binsight::AnalysisReport shutdown_command;
    shutdown_command.imports.push_back({"msvcrt.dll", "system"});
    shutdown_command.strings.push_back({"shutdown /s /t 0", "shell"});
    findings = rules.evaluate("rules", shutdown_command, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "dangerous-command-exec" &&
                   finding.severity == binsight::Severity::High &&
                   finding.risk_type == "malicious-likely" &&
                   finding.evidence_strength == "strong";
          }),
          "system plus shutdown should be high risk");

    binsight::AnalysisReport anti_debug_keyword;
    anti_debug_keyword.strings.push_back({"anti-debug", "anti-debug"});
    findings = rules.evaluate("rules", anti_debug_keyword, warnings);
    check(std::any_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.id == "anti-debug-keyword" && finding.severity == binsight::Severity::Low;
          }),
          "anti-debug text alone should be low risk");
    check(std::none_of(findings.begin(), findings.end(), [](const binsight::RuleFinding& finding) {
            return finding.severity >= binsight::Severity::High;
          }),
          "anti-debug text alone should not be high risk");

    binsight::AnalysisReport configuration_strings;
    configuration_strings.strings.push_back({"https://api.openai.com/v1", "configuration"});
    configuration_strings.strings.push_back({"OPENAI_API_KEY", "configuration"});
    findings = rules.evaluate("rules", configuration_strings, warnings);
    check(findings.empty(), "configuration strings should not trigger risk rules");
  }

  {
    std::cerr << "[unit] dual-track assessment fusion\n";
    binsight::LlmClient llm{binsight::ProcessRunner{}};
    binsight::ScanOptions options;
    options.provider = "openai";
    options.model = "test-model";

    binsight::AnalysisReport capability_report;
    binsight::RuleFinding capability;
    capability.id = "network-capability";
    capability.title = "Network communication capability";
    capability.severity = binsight::Severity::Low;
    capability.risk_type = "capability";
    capability.confidence = "low";
    capability.evidence_strength = "weak";
    capability.evidence = {"function:connect"};
    capability_report.rule_findings.push_back(capability);
    capability_report.local_analysis = llm.local_analysis(options, capability_report);
    std::vector<std::string> warnings;
    auto ai = llm.parse_ai_assessment(
        options, capability_report.local_analysis,
        R"({"severity":"info","confidence":"medium","summary":"Only benign capability evidence is present.","decision_basis":"The local finding is capability-only.","risk_sources":["network API capability"],"recommendations":["Verify expected network usage."]})",
        "raw", warnings);
    auto final = llm.fuse_assessments(capability_report, capability_report.local_analysis, ai, warnings);
    check(final.severity == binsight::Severity::Info,
          "AI may downgrade capability-only local findings");
    check(final.decision_basis.find("AI downgrade") != std::string::npos,
          "AI downgrade should be recorded in final decision basis");

    binsight::AnalysisReport strong_report;
    binsight::RuleFinding strong;
    strong.id = "dangerous-command-exec";
    strong.title = "Dangerous command execution pattern";
    strong.severity = binsight::Severity::High;
    strong.risk_type = "malicious-likely";
    strong.confidence = "high";
    strong.evidence_strength = "strong";
    strong.evidence = {"function:system", "string:shell:shutdown /s /t 0"};
    strong_report.rule_findings.push_back(strong);
    strong_report.local_analysis = llm.local_analysis(options, strong_report);
    ai = llm.parse_ai_assessment(
        options, strong_report.local_analysis,
        R"({"severity":"low","confidence":"low","summary":"The behavior may be user initiated.","decision_basis":"AI sees possible benign context.","risk_sources":["system plus shutdown"],"recommendations":["Confirm intent."]})",
        "raw", warnings);
    final = llm.fuse_assessments(strong_report, strong_report.local_analysis, ai, warnings);
    check(final.severity == binsight::Severity::High,
          "strong high malicious-likely local evidence should set a high-risk floor");

    binsight::AnalysisReport medium_report;
    binsight::RuleFinding medium;
    medium.id = "dynamic-import-resolution";
    medium.title = "Dynamic import resolution capability";
    medium.severity = binsight::Severity::Medium;
    medium.risk_type = "capability";
    medium.confidence = "medium";
    medium.evidence_strength = "medium";
    medium.evidence = {"function:GetProcAddress"};
    medium_report.rule_findings.push_back(medium);
    medium_report.local_analysis = llm.local_analysis(options, medium_report);
    ai = llm.parse_ai_assessment(
        options, medium_report.local_analysis,
        R"({"severity":"high","confidence":"medium","summary":"Combined context suggests loader behavior.","decision_basis":"AI sees stronger combined risk than rules captured.","risk_sources":["dynamic import resolution plus suspicious context"],"recommendations":["Review dynamic API targets."]})",
        "raw", warnings);
    final = llm.fuse_assessments(medium_report, medium_report.local_analysis, ai, warnings);
    check(final.severity == binsight::Severity::High,
          "AI may escalate final severity above the local baseline");
    check(final.decision_basis.find("AI escalation") != std::string::npos,
          "AI escalation should be recorded in final decision basis");

    const auto before_warnings = warnings.size();
    ai = llm.parse_ai_assessment(options, medium_report.local_analysis, "not json", "raw", warnings);
    check(warnings.size() > before_warnings, "invalid AI JSON should produce a warning");
    check(ai.severity == medium_report.local_analysis.severity,
          "invalid AI JSON should fall back to local baseline");
  }

  {
    std::cerr << "[unit] scan pipeline output paths\n";
    binsight::ScanOptions options;
    options.output_dir = "out";
    options.markdown_out = "report.md";
    options.report_language = binsight::ReportLanguage::Both;
    const auto paths = binsight::markdown_output_paths(options);
    check(paths.size() == 2, "both language mode should emit two Markdown paths");
    check(paths.size() == 2 && paths[0].first == std::filesystem::path("out/report.zh-CN.md"),
          "Chinese report path should use zh-CN suffix");
    check(paths.size() == 2 && paths[1].first == std::filesystem::path("out/report.en.md"),
          "English report path should use en suffix");
  }

  {
    std::cerr << "[unit] report writer\n";
    binsight::AnalysisReport report;
    report.target.path = "sample";
    report.target.format_name = "ELF";
    report.analysis_mode = binsight::AnalysisMode::StaticWithDynamicReport;
    report.dynamic_observations.present = true;
    report.dynamic_observations.platform = "linux";
    report.dynamic_observations.mode = "linux-docker";
    report.dynamic_observations.network_mode = "none";
    report.ai_analysis.provider = "none";
    report.ai_analysis.severity = binsight::Severity::Low;
    report.ai_analysis.summary = "No deterministic risk rules matched.";
    report.ai_analysis.decision_basis = "AI assessment unavailable; this mirrors the local deterministic baseline.";
    binsight::RuleFinding finding;
    finding.id = "network-capability";
    finding.title = "Network communication capability";
    finding.severity = binsight::Severity::Low;
    finding.risk_type = "capability";
    finding.confidence = "low";
    finding.evidence_strength = "weak";
    finding.description = "Network capability test";
    finding.recommendation = "Review destinations.";
    finding.evidence = {"function:connect"};
    report.rule_findings.push_back(finding);
    report.local_analysis.severity = binsight::Severity::Low;
    report.local_analysis.summary = "Local rule baseline summary.";
    report.local_analysis.risk_sources = {"network-capability"};
    report.local_analysis.recommendations = {"Review destinations."};
    report.final_assessment.severity = binsight::Severity::Low;
    report.final_assessment.summary = "Final assessment summary.";
    report.final_assessment.decision_basis =
        "No online AI assessment was available; final assessment uses the local deterministic baseline.";
    report.final_assessment.risk_sources = report.local_analysis.risk_sources;
    report.final_assessment.recommendations = report.local_analysis.recommendations;

    const auto path = std::filesystem::current_path() / "binsight-report-writer-test.json";
    const auto zh_path = std::filesystem::current_path() / "binsight-report-writer-test.zh-CN.md";
    const auto en_path = std::filesystem::current_path() / "binsight-report-writer-test.en.md";
    binsight::ReportWriter writer;
    writer.write_json(path, report);
    writer.write_markdown(zh_path, report, binsight::ReportLanguage::Chinese);
    writer.write_markdown(en_path, report, binsight::ReportLanguage::English);

    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    check(content.find("\"target\"") != std::string::npos, "JSON report should contain target");
    check(content.find("\"analysis_mode\"") != std::string::npos, "JSON report should contain analysis mode");
    check(content.find("\"local_analysis\"") != std::string::npos,
          "JSON report should contain local analysis");
    check(content.find("\"final_assessment\"") != std::string::npos,
          "JSON report should contain final assessment");
    check(content.find("\"risk_type\":\"capability\"") != std::string::npos,
          "JSON report should contain rule risk type");
    check(content.find("\"confidence\":\"low\"") != std::string::npos,
          "JSON report should contain rule confidence");
    check(content.find("\"evidence_strength\":\"weak\"") != std::string::npos,
          "JSON report should contain rule evidence strength");
    check(content.find("\"dynamic_observations\"") != std::string::npos,
          "JSON report should contain dynamic observations");
    std::ifstream zh_in(zh_path);
    std::string zh_content((std::istreambuf_iterator<char>(zh_in)), std::istreambuf_iterator<char>());
    check(zh_content.find("## 目标文件") != std::string::npos, "Chinese report should use Chinese headings");
    check(zh_content.find("## 最终评估") != std::string::npos,
          "Chinese report should include final assessment");
    check(zh_content.find("## 本地规则评估") != std::string::npos,
          "Chinese report should include local assessment");
    check(zh_content.find("## AI 评估") != std::string::npos,
          "Chinese report should include AI assessment");
    check(zh_content.find("## 动态观测") != std::string::npos, "Chinese report should include dynamic section");
    check(zh_content.find("风险类型：能力提示") != std::string::npos,
          "Chinese report should include risk type");
    check(zh_content.find("证据强度：弱") != std::string::npos,
          "Chinese report should include evidence strength");
    check(zh_content.find("Target /") == std::string::npos, "Chinese report should not use mixed headings");
    std::ifstream en_in(en_path);
    std::string en_content((std::istreambuf_iterator<char>(en_in)), std::istreambuf_iterator<char>());
    check(en_content.find("## Target") != std::string::npos, "English report should use English headings");
    check(en_content.find("## Final Assessment") != std::string::npos,
          "English report should include final assessment");
    check(en_content.find("## Local Rule Assessment") != std::string::npos,
          "English report should include local assessment");
    check(en_content.find("## AI Assessment") != std::string::npos,
          "English report should include AI assessment");
    check(en_content.find("## Dynamic Observations") != std::string::npos,
          "English report should include dynamic section");
    check(en_content.find("Risk type: capability") != std::string::npos,
          "English report should include risk type");
    check(en_content.find("Evidence strength: weak") != std::string::npos,
          "English report should include evidence strength");
    check(en_content.find("目标文件") == std::string::npos, "English report should not use Chinese headings");
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
    std::filesystem::remove(zh_path, remove_error);
    std::filesystem::remove(en_path, remove_error);
  }

  if (failures != 0) {
    return 1;
  }
  std::cout << "All unit tests passed\n";
  return 0;
}
