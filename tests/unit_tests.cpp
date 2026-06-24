#include <binsight/local_rag.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/string_scanner.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <string>

namespace {

int failures = 0;

void check(bool condition, const std::string& message) {
  if (!condition) {
    std::cerr << "FAIL: " << message << '\n';
    ++failures;
  }
}

}  // namespace

int main() {
  {
    binsight::StringScanner scanner;
    const auto results = scanner.scan("https://example.test/a\n/bin/sh\nshutdown /s /t 0\nnormal text\npassword=secret\n");
    check(results.size() == 4, "StringScanner should find four suspicious strings");
    check(!results.empty() && results[0].category == "url", "first string should be URL");
  }

  {
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
    binsight::AnalysisReport report;
    report.target.path = "sample";
    report.target.format_name = "ELF";
    report.ai_analysis.provider = "none";
    report.ai_analysis.summary = "No deterministic risk rules matched.";

    const auto path = std::filesystem::temp_directory_path() / "binsight-report-writer-test.json";
    binsight::ReportWriter writer;
    writer.write_json(path, report);

    std::ifstream in(path);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    check(content.find("\"target\"") != std::string::npos, "JSON report should contain target");
    std::filesystem::remove(path);
  }

  if (failures != 0) {
    return 1;
  }
  std::cout << "All unit tests passed\n";
  return 0;
}
