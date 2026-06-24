#include <binsight/binary_analyzer.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <filesystem>
#include <regex>
#include <set>
#include <sstream>

namespace binsight {

namespace {

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

std::uint64_t parse_hex_or_zero(const std::string& value) {
  try {
    return std::stoull(value, nullptr, 16);
  } catch (...) {
    return 0;
  }
}

std::string normalize_symbol(std::string symbol) {
  symbol = trim(symbol);
  const auto version_pos = symbol.find("@@");
  if (version_pos != std::string::npos) {
    symbol = symbol.substr(0, version_pos);
  }
  const auto at_pos = symbol.find('@');
  if (at_pos != std::string::npos) {
    symbol = symbol.substr(0, at_pos);
  }
  return symbol;
}

}  // namespace

BinaryAnalyzer::BinaryAnalyzer(ProcessRunner runner, StringScanner string_scanner)
    : runner_(std::move(runner)), string_scanner_(std::move(string_scanner)) {}

AnalysisReport BinaryAnalyzer::analyze(const ScanOptions& options) const {
  AnalysisReport report;
  report.target = detect_target(options, report);
  if (report.target.format == BinaryFormat::ELF) {
    analyze_elf(options, report);
  } else if (report.target.format == BinaryFormat::PE) {
    analyze_pe(options, report);
  } else {
    report.warnings.push_back("unsupported or unknown binary format");
  }
  extract_strings(options, report);
  extract_disassembly(options, report);
  return report;
}

TargetInfo BinaryAnalyzer::detect_target(const ScanOptions& options, AnalysisReport& report) const {
  TargetInfo target;
  target.path = options.binary_path.string();
  if (std::filesystem::exists(options.binary_path)) {
    target.size = std::filesystem::file_size(options.binary_path);
    target.content_hash = fnv1a64_file(options.binary_path);
  }

  const ToolResult file = runner_.run({"file", "-b", options.binary_path.string()});
  if (file.exit_code != 0) {
    report.warnings.push_back("file command failed: " + file.output);
    return target;
  }

  const std::string lower = lowercase(file.output);
  target.stripped = contains(lower, "stripped") && !contains(lower, "not stripped");
  if (contains(file.output, "ELF")) {
    target.format = BinaryFormat::ELF;
    target.format_name = "ELF";
  } else if (contains(file.output, "PE32") || contains(file.output, "MS Windows")) {
    target.format = BinaryFormat::PE;
    target.format_name = "PE";
  }

  if (contains(lower, "64-bit") || contains(lower, "pe32+")) {
    target.bits = 64;
  } else if (contains(lower, "32-bit") || contains(lower, "pe32")) {
    target.bits = 32;
  }

  if (contains(lower, "x86-64") || contains(lower, "x86_64")) {
    target.architecture = "x86_64";
  } else if (contains(lower, "intel 80386") || contains(lower, "i386")) {
    target.architecture = "x86";
  } else if (contains(lower, "aarch64")) {
    target.architecture = "aarch64";
  } else if (contains(lower, "arm")) {
    target.architecture = "arm";
  }
  return target;
}

void BinaryAnalyzer::analyze_elf(const ScanOptions& options, AnalysisReport& report) const {
  const ToolResult dynamic = runner_.run({"readelf", "-d", options.binary_path.string()});
  if (dynamic.exit_code == 0) {
    std::regex needed_re(R"(\(NEEDED\).*\[(.+)\])");
    for (const auto& line : split_lines(dynamic.output)) {
      std::smatch match;
      if (std::regex_search(line, match, needed_re)) {
        report.imports.push_back({match[1].str(), ""});
      }
    }
  } else {
    report.warnings.push_back("readelf -d failed: " + dynamic.output);
  }

  const ToolResult symbols = runner_.run({"objdump", "-T", options.binary_path.string()});
  if (symbols.exit_code == 0) {
    std::set<std::string> seen;
    std::regex symbol_re(R"(\*UND\*.*\s([A-Za-z_][A-Za-z0-9_@.$]*)(?:\s*)$)");
    for (const auto& line : split_lines(symbols.output)) {
      std::smatch match;
      if (std::regex_search(line, match, symbol_re)) {
        std::string symbol = normalize_symbol(match[1].str());
        if (!symbol.empty() && seen.insert(symbol).second) {
          report.imports.push_back({"", symbol});
        }
      }
    }
  } else {
    report.warnings.push_back("objdump -T failed: " + symbols.output);
  }

  const ToolResult sections = runner_.run({"readelf", "-S", "-W", options.binary_path.string()});
  if (sections.exit_code == 0) {
    std::regex sec_re(R"(\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+\S+\s+([0-9a-fA-F]+)\s+\S+\s+([A-Z]+))");
    for (const auto& line : split_lines(sections.output)) {
      std::smatch match;
      if (std::regex_search(line, match, sec_re)) {
        SectionInfo section;
        section.name = match[1].str();
        section.size = parse_hex_or_zero(match[2].str());
        section.flags = match[3].str();
        if (contains(section.flags, "W") && contains(section.flags, "X")) {
          section.risk_note = "writable and executable";
        }
        report.sections.push_back(section);
      }
    }
  } else {
    report.warnings.push_back("readelf -S failed: " + sections.output);
  }
}

void BinaryAnalyzer::analyze_pe(const ScanOptions& options, AnalysisReport& report) const {
  const ToolResult headers = runner_.run({"objdump", "-x", options.binary_path.string()});
  if (headers.exit_code == 0) {
    std::string current_dll;
    std::regex dll_re(R"(DLL Name:\s*(.+))");
    std::regex import_re(R"(^\s*(?:[0-9a-fA-F]+\s+)?([A-Za-z_][A-Za-z0-9_@$?]+)\s*$)");
    for (const auto& line : split_lines(headers.output)) {
      std::smatch match;
      if (std::regex_search(line, match, dll_re)) {
        current_dll = trim(match[1].str());
        report.imports.push_back({current_dll, ""});
      } else if (!current_dll.empty() && std::regex_match(line, match, import_re)) {
        const std::string symbol = trim(match[1].str());
        if (symbol != "Name" && symbol.size() > 2) {
          report.imports.push_back({current_dll, symbol});
        }
      }
    }
  } else {
    report.warnings.push_back("objdump -x failed: " + headers.output);
  }

  const ToolResult sections = runner_.run({"objdump", "-h", options.binary_path.string()});
  if (sections.exit_code == 0) {
    std::regex sec_re(R"(^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+)");
    for (const auto& line : split_lines(sections.output)) {
      std::smatch match;
      if (std::regex_search(line, match, sec_re)) {
        SectionInfo section;
        section.name = match[1].str();
        section.size = parse_hex_or_zero(match[2].str());
        section.flags = "";
        report.sections.push_back(section);
      }
    }
  } else {
    report.warnings.push_back("objdump -h failed: " + sections.output);
  }
}

void BinaryAnalyzer::extract_strings(const ScanOptions& options, AnalysisReport& report) const {
  const ToolResult strings = runner_.run({"strings", "-a", "-n", "5", options.binary_path.string()});
  if (strings.exit_code != 0) {
    report.warnings.push_back("strings failed: " + strings.output);
    return;
  }
  report.strings = string_scanner_.scan(strings.output);
}

void BinaryAnalyzer::extract_disassembly(const ScanOptions& options, AnalysisReport& report) const {
  const ToolResult disasm = runner_.run({"objdump", "-d", options.binary_path.string()}, 30);
  if (disasm.exit_code != 0) {
    report.warnings.push_back("objdump -d failed: " + disasm.output);
    return;
  }

  const auto lines = split_lines(disasm.output);
  std::vector<std::string> triggers;
  for (const auto& import : report.imports) {
    if (!import.symbol.empty()) {
      const std::string lower = lowercase(import.symbol);
      if (lower == "system" || lower == "popen" || lower == "execve" ||
          lower == "createremotethread" || lower == "writeprocessmemory" ||
          lower == "socket" || lower == "connect") {
        triggers.push_back(import.symbol);
      }
    }
  }
  for (const auto& suspicious : report.strings) {
    if (triggers.size() >= static_cast<std::size_t>(options.max_disasm_snippets)) {
      break;
    }
    triggers.push_back(suspicious.category);
  }
  if (triggers.empty()) {
    triggers.push_back("entry-context");
  }

  std::set<std::string> emitted;
  for (const auto& trigger : triggers) {
    if (report.disassembly_snippets.size() >= static_cast<std::size_t>(options.max_disasm_snippets)) {
      break;
    }
    if (!emitted.insert(trigger).second) {
      continue;
    }
    std::ostringstream snippet;
    std::size_t start = 0;
    bool found = false;
    for (std::size_t i = 0; i < lines.size(); ++i) {
      if (lowercase(lines[i]).find(lowercase(trigger)) != std::string::npos) {
        start = (i > 4) ? i - 4 : 0;
        found = true;
        break;
      }
    }
    if (!found && trigger != "entry-context") {
      continue;
    }
    const std::size_t end = std::min(lines.size(), start + 18);
    for (std::size_t i = start; i < end; ++i) {
      snippet << lines[i] << '\n';
    }
    report.disassembly_snippets.push_back({trigger, snippet.str()});
  }
}

}  // namespace binsight

