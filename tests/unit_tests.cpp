#include <binsight/local_rag.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/string_scanner.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
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
    const auto results = scanner.scan("https://example.test/a\n/bin/sh\nnormal text\npassword=secret\n");
    check(results.size() == 3, "StringScanner should find three suspicious strings");
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
    check(!entries.empty() && entries.front().id == "network-behavior",
          "network knowledge should rank first");
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

