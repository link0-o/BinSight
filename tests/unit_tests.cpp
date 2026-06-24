#include <binsight/binary_analyzer.hpp>
#include <binsight/local_rag.hpp>
#include <binsight/process_runner.hpp>
#include <binsight/report_writer.hpp>
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

int main() {
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
    check(std::any_of(report.imports.begin(), report.imports.end(), [](const binsight::ImportEntry& entry) {
            return entry.library == "KERNEL32.dll" && entry.symbol == "CreateFileA";
          }),
          "internal PE parser should extract imports");
    check(std::any_of(report.strings.begin(), report.strings.end(), [](const binsight::SuspiciousString& item) {
            return item.value == "shutdown /s /t 0";
          }),
          "internal string extractor should find suspicious ASCII strings");
    std::error_code remove_error;
    std::filesystem::remove(path, remove_error);
  }

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
    std::cerr << "[unit] report writer\n";
    binsight::AnalysisReport report;
    report.target.path = "sample";
    report.target.format_name = "ELF";
    report.ai_analysis.provider = "none";
    report.ai_analysis.summary = "No deterministic risk rules matched.";

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
    std::ifstream zh_in(zh_path);
    std::string zh_content((std::istreambuf_iterator<char>(zh_in)), std::istreambuf_iterator<char>());
    check(zh_content.find("## 目标文件") != std::string::npos, "Chinese report should use Chinese headings");
    check(zh_content.find("Target /") == std::string::npos, "Chinese report should not use mixed headings");
    std::ifstream en_in(en_path);
    std::string en_content((std::istreambuf_iterator<char>(en_in)), std::istreambuf_iterator<char>());
    check(en_content.find("## Target") != std::string::npos, "English report should use English headings");
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
