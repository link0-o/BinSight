#include <binsight/binary_analyzer.hpp>
#include <binsight/utils.hpp>

#ifdef BINSIGHT_USE_LIEF
#include <LIEF/LIEF.hpp>
#endif

#include <algorithm>
#include <cctype>
#include <fstream>
#include <filesystem>
#include <limits>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <vector>

namespace binsight {

namespace {

bool contains(const std::string& text, const std::string& needle) {
  return text.find(needle) != std::string::npos;
}

std::vector<unsigned char> read_bytes(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::uint16_t le16(const std::vector<unsigned char>& data, std::size_t offset) {
  if (offset + 2 > data.size()) {
    return 0;
  }
  return static_cast<std::uint16_t>(data[offset] | (data[offset + 1] << 8));
}

std::uint32_t le32(const std::vector<unsigned char>& data, std::size_t offset) {
  if (offset + 4 > data.size()) {
    return 0;
  }
  return static_cast<std::uint32_t>(data[offset]) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 3]) << 24);
}

std::uint64_t le64(const std::vector<unsigned char>& data, std::size_t offset) {
  return static_cast<std::uint64_t>(le32(data, offset)) |
         (static_cast<std::uint64_t>(le32(data, offset + 4)) << 32);
}

std::string read_c_string(const std::vector<unsigned char>& data, std::size_t offset,
                          std::size_t limit = 4096) {
  std::string out;
  for (std::size_t i = offset; i < data.size() && out.size() < limit; ++i) {
    if (data[i] == 0) {
      break;
    }
    out.push_back(static_cast<char>(data[i]));
  }
  return out;
}

std::string pe_architecture(std::uint16_t machine) {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x86_64";
    case 0xaa64:
      return "arm64";
    case 0x01c0:
    case 0x01c4:
      return "arm";
    default:
      return "unknown";
  }
}

std::string elf_architecture(std::uint16_t machine) {
  switch (machine) {
    case 0x03:
      return "x86";
    case 0x3e:
      return "x86_64";
    case 0xb7:
      return "aarch64";
    case 0x28:
      return "arm";
    default:
      return "unknown";
  }
}

bool is_printable_ascii(unsigned char c) {
  return c == '\t' || (c >= 0x20 && c <= 0x7e);
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

struct PeSection {
  std::string name;
  std::uint32_t virtual_address = 0;
  std::uint32_t virtual_size = 0;
  std::uint32_t raw_pointer = 0;
  std::uint32_t raw_size = 0;
  std::uint32_t characteristics = 0;
};

std::optional<std::size_t> pe_rva_to_offset(const std::vector<PeSection>& sections,
                                            std::uint32_t rva) {
  for (const auto& section : sections) {
    const std::uint32_t span = std::max(section.virtual_size, section.raw_size);
    if (rva >= section.virtual_address && rva < section.virtual_address + span) {
      return static_cast<std::size_t>(section.raw_pointer + (rva - section.virtual_address));
    }
  }
  if (rva < 0x1000) {
    return static_cast<std::size_t>(rva);
  }
  return std::nullopt;
}

std::vector<PeSection> parse_pe_sections(const std::vector<unsigned char>& data,
                                         std::size_t pe_offset,
                                         std::uint16_t section_count,
                                         std::uint16_t optional_header_size) {
  std::vector<PeSection> sections;
  std::size_t section_offset = pe_offset + 24 + optional_header_size;
  for (std::uint16_t i = 0; i < section_count && section_offset + 40 <= data.size(); ++i) {
    PeSection section;
    for (std::size_t n = 0; n < 8 && data[section_offset + n] != 0; ++n) {
      section.name.push_back(static_cast<char>(data[section_offset + n]));
    }
    section.virtual_size = le32(data, section_offset + 8);
    section.virtual_address = le32(data, section_offset + 12);
    section.raw_size = le32(data, section_offset + 16);
    section.raw_pointer = le32(data, section_offset + 20);
    section.characteristics = le32(data, section_offset + 36);
    sections.push_back(section);
    section_offset += 40;
  }
  return sections;
}

std::string pe_section_flags(std::uint32_t characteristics) {
  std::string flags;
  if ((characteristics & 0x40000000u) != 0) {
    flags += "R";
  }
  if ((characteristics & 0x80000000u) != 0) {
    flags += "W";
  }
  if ((characteristics & 0x20000000u) != 0) {
    flags += "X";
  }
  return flags;
}

#ifdef BINSIGHT_USE_LIEF
void fill_target_common(const ScanOptions& options, TargetInfo& target) {
  target.path = options.binary_path.string();
  if (std::filesystem::exists(options.binary_path)) {
    target.size = std::filesystem::file_size(options.binary_path);
    target.content_hash = fnv1a64_file(options.binary_path);
  }
}

std::string pe_lief_architecture(LIEF::PE::Header::MACHINE_TYPES machine) {
  return pe_architecture(static_cast<std::uint16_t>(machine));
}

std::string elf_lief_architecture(LIEF::ELF::ARCH machine) {
  return elf_architecture(static_cast<std::uint16_t>(machine));
}

std::string elf_section_flags(const LIEF::ELF::Section& section) {
  std::string flags;
  if (section.has(LIEF::ELF::Section::FLAGS::ALLOC)) {
    flags += "A";
  }
  if (section.has(LIEF::ELF::Section::FLAGS::WRITE)) {
    flags += "W";
  }
  if (section.has(LIEF::ELF::Section::FLAGS::EXECINSTR)) {
    flags += "X";
  }
  return flags;
}

void add_unique_import(std::vector<ImportEntry>& imports, std::set<std::string>& seen,
                       std::string library, std::string symbol) {
  const std::string key = library + "\n" + symbol;
  if (seen.insert(key).second) {
    imports.push_back({std::move(library), std::move(symbol)});
  }
}
#endif

void append_ascii_strings(const std::vector<unsigned char>& data, std::ostringstream& out) {
  std::string current;
  for (unsigned char c : data) {
    if (is_printable_ascii(c)) {
      current.push_back(static_cast<char>(c));
      continue;
    }
    if (current.size() >= 5) {
      out << current << '\n';
    }
    current.clear();
  }
  if (current.size() >= 5) {
    out << current << '\n';
  }
}

void append_utf16le_strings(const std::vector<unsigned char>& data, std::ostringstream& out) {
  std::string current;
  for (std::size_t i = 0; i + 1 < data.size(); i += 2) {
    if (data[i + 1] == 0 && is_printable_ascii(data[i])) {
      current.push_back(static_cast<char>(data[i]));
      continue;
    }
    if (current.size() >= 5) {
      out << current << '\n';
    }
    current.clear();
  }
  if (current.size() >= 5) {
    out << current << '\n';
  }
}

}  // namespace

BinaryAnalyzer::BinaryAnalyzer(ProcessRunner runner, StringScanner string_scanner)
    : runner_(std::move(runner)), string_scanner_(std::move(string_scanner)) {}

AnalysisReport BinaryAnalyzer::analyze(const ScanOptions& options) const {
  AnalysisReport report;
#ifdef BINSIGHT_USE_LIEF
  if (analyze_with_lief(options, report)) {
    extract_strings(options, report);
    extract_disassembly(options, report);
    return report;
  }
#endif
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

bool BinaryAnalyzer::analyze_with_lief(const ScanOptions& options, AnalysisReport& report) const {
#ifndef BINSIGHT_USE_LIEF
  (void)options;
  (void)report;
  return false;
#else
  const auto data = read_bytes(options.binary_path);
  if (data.empty()) {
    report.warnings.push_back("LIEF parser skipped: file could not be read");
    return false;
  }

  try {
    if (data.size() >= 20 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' &&
        data[3] == 'F') {
      auto binary = LIEF::ELF::Parser::parse(options.binary_path.string());
      if (binary == nullptr) {
        report.warnings.push_back("LIEF ELF parser failed; using fallback parser");
        return false;
      }

      fill_target_common(options, report.target);
      report.target.format = BinaryFormat::ELF;
      report.target.format_name = "ELF";
      report.target.bits = data[4] == 2 ? 64 : (data[4] == 1 ? 32 : 0);
      report.target.architecture = elf_lief_architecture(binary->header().machine_type());

      std::set<std::string> seen_imports;
      for (const auto& entry : binary->dynamic_entries()) {
        if (const auto* library = entry.cast<LIEF::ELF::DynamicEntryLibrary>()) {
          add_unique_import(report.imports, seen_imports, library->name(), "");
        }
      }
      for (const auto& symbol : binary->imported_symbols()) {
        const std::string name = normalize_symbol(symbol.name());
        if (!name.empty()) {
          add_unique_import(report.imports, seen_imports, "", name);
        }
      }

      bool has_symtab = false;
      for (const auto& lief_section : binary->sections()) {
        SectionInfo section;
        section.name = lief_section.name();
        section.size = lief_section.size();
        section.flags = elf_section_flags(lief_section);
        if (section.name == ".symtab") {
          has_symtab = true;
        }
        if (contains(section.flags, "W") && contains(section.flags, "X")) {
          section.risk_note = "writable and executable";
        }
        report.sections.push_back(section);
      }
      report.target.stripped = !has_symtab;
      return true;
    }

    if (data.size() >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
      auto binary = LIEF::PE::Parser::parse(options.binary_path.string());
      if (binary == nullptr) {
        report.warnings.push_back("LIEF PE parser failed; using fallback parser");
        return false;
      }

      fill_target_common(options, report.target);
      report.target.format = BinaryFormat::PE;
      report.target.format_name = "PE";
      report.target.architecture = pe_lief_architecture(binary->header().machine());
      report.target.bits = binary->type() == LIEF::PE::PE_TYPE::PE32_PLUS ? 64 : 32;
      report.target.stripped =
          binary->header().has_characteristic(LIEF::PE::Header::CHARACTERISTICS::DEBUG_STRIPPED) ||
          binary->header().has_characteristic(
              LIEF::PE::Header::CHARACTERISTICS::LOCAL_SYMS_STRIPPED);

      std::set<std::string> seen_imports;
      for (const auto& import : binary->imports()) {
        add_unique_import(report.imports, seen_imports, import.name(), "");
        for (const auto& entry : import.entries()) {
          std::string symbol;
          if (entry.is_ordinal()) {
            symbol = "#" + std::to_string(entry.ordinal());
          } else {
            symbol = entry.name();
          }
          if (!symbol.empty()) {
            add_unique_import(report.imports, seen_imports, import.name(), symbol);
          }
        }
      }

      for (const auto& lief_section : binary->sections()) {
        SectionInfo section;
        section.name = lief_section.name();
        section.size = lief_section.sizeof_raw_data() != 0 ? lief_section.sizeof_raw_data()
                                                           : lief_section.virtual_size();
        section.flags = pe_section_flags(lief_section.characteristics());
        if (contains(section.flags, "W") && contains(section.flags, "X")) {
          section.risk_note = "writable and executable";
        }
        report.sections.push_back(section);
      }
      return true;
    }
  } catch (const std::exception& ex) {
    report.warnings.push_back(std::string("LIEF parser failed; using fallback parser: ") + ex.what());
    return false;
  }

  return false;
#endif
}

TargetInfo BinaryAnalyzer::detect_target(const ScanOptions& options, AnalysisReport& report) const {
  TargetInfo target;
  target.path = options.binary_path.string();
  if (std::filesystem::exists(options.binary_path)) {
    target.size = std::filesystem::file_size(options.binary_path);
    target.content_hash = fnv1a64_file(options.binary_path);
  }

  const auto data = read_bytes(options.binary_path);
  if (data.size() >= 20 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
    target.format = BinaryFormat::ELF;
    target.format_name = "ELF";
    target.bits = data[4] == 2 ? 64 : 32;
    target.architecture = elf_architecture(le16(data, 18));
    return target;
  }
  if (data.size() >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
    const std::uint32_t pe_offset = le32(data, 0x3c);
    if (pe_offset + 26 < data.size() && data[pe_offset] == 'P' && data[pe_offset + 1] == 'E' &&
        data[pe_offset + 2] == 0 && data[pe_offset + 3] == 0) {
      target.format = BinaryFormat::PE;
      target.format_name = "PE";
      const std::uint16_t machine = le16(data, pe_offset + 4);
      const std::uint16_t characteristics = le16(data, pe_offset + 22);
      const std::uint16_t optional_magic = le16(data, pe_offset + 24);
      target.architecture = pe_architecture(machine);
      target.bits = optional_magic == 0x20b ? 64 : (optional_magic == 0x10b ? 32 : 0);
      target.stripped = (characteristics & 0x0200u) != 0;
      return target;
    }
  }

#ifndef _WIN32
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
#else
  (void)report;
#endif
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
  // Temporary / Prototype / Educational Implementation.
  // Production PE parsing should prefer the configured embeddable parser component.
  const auto data = read_bytes(options.binary_path);
  if (data.size() < 0x40 || data[0] != 'M' || data[1] != 'Z') {
    report.warnings.push_back("PE parser failed: missing MZ header");
    return;
  }
  const std::uint32_t pe_offset = le32(data, 0x3c);
  if (pe_offset + 24 >= data.size() || data[pe_offset] != 'P' || data[pe_offset + 1] != 'E') {
    report.warnings.push_back("PE parser failed: missing PE signature");
    return;
  }

  const std::uint16_t section_count = le16(data, pe_offset + 6);
  const std::uint16_t optional_header_size = le16(data, pe_offset + 20);
  const std::uint16_t optional_magic = le16(data, pe_offset + 24);
  const bool is_pe64 = optional_magic == 0x20b;
  const std::size_t data_directory_offset = pe_offset + 24 + (is_pe64 ? 112 : 96);
  const auto pe_sections = parse_pe_sections(data, pe_offset, section_count, optional_header_size);

  for (const auto& pe_section : pe_sections) {
    SectionInfo section;
    section.name = pe_section.name;
    section.size = pe_section.raw_size != 0 ? pe_section.raw_size : pe_section.virtual_size;
    section.flags = pe_section_flags(pe_section.characteristics);
    if (contains(section.flags, "W") && contains(section.flags, "X")) {
      section.risk_note = "writable and executable";
    }
    report.sections.push_back(section);
  }

  if (data_directory_offset + 16 > data.size()) {
    report.warnings.push_back("PE parser warning: import directory unavailable");
    return;
  }
  const std::uint32_t import_rva = le32(data, data_directory_offset + 8);
  if (import_rva == 0) {
    return;
  }
  const auto import_offset = pe_rva_to_offset(pe_sections, import_rva);
  if (!import_offset || *import_offset >= data.size()) {
    report.warnings.push_back("PE parser warning: import directory RVA could not be mapped");
    return;
  }

  std::set<std::string> seen_imports;
  for (std::size_t descriptor = *import_offset; descriptor + 20 <= data.size(); descriptor += 20) {
    const std::uint32_t original_first_thunk = le32(data, descriptor);
    const std::uint32_t name_rva = le32(data, descriptor + 12);
    const std::uint32_t first_thunk = le32(data, descriptor + 16);
    if (original_first_thunk == 0 && name_rva == 0 && first_thunk == 0) {
      break;
    }

    const auto name_offset = pe_rva_to_offset(pe_sections, name_rva);
    if (!name_offset || *name_offset >= data.size()) {
      continue;
    }
    const std::string dll_name = read_c_string(data, *name_offset);
    if (dll_name.empty()) {
      continue;
    }
    if (seen_imports.insert(dll_name + "\n").second) {
      report.imports.push_back({dll_name, ""});
    }

    const std::uint32_t thunk_rva = original_first_thunk != 0 ? original_first_thunk : first_thunk;
    const auto thunk_offset = pe_rva_to_offset(pe_sections, thunk_rva);
    if (!thunk_offset || *thunk_offset >= data.size()) {
      continue;
    }

    const std::size_t thunk_size = is_pe64 ? 8 : 4;
    const std::uint64_t ordinal_mask = is_pe64 ? 0x8000000000000000ull : 0x80000000ull;
    for (std::size_t thunk = *thunk_offset; thunk + thunk_size <= data.size(); thunk += thunk_size) {
      const std::uint64_t value = is_pe64 ? le64(data, thunk) : le32(data, thunk);
      if (value == 0) {
        break;
      }
      if ((value & ordinal_mask) != 0) {
        continue;
      }
      const auto hint_name_offset = pe_rva_to_offset(pe_sections, static_cast<std::uint32_t>(value));
      if (!hint_name_offset || *hint_name_offset + 2 >= data.size()) {
        continue;
      }
      const std::string symbol = read_c_string(data, *hint_name_offset + 2);
      const std::string key = dll_name + "\n" + symbol;
      if (!symbol.empty() && seen_imports.insert(key).second) {
        report.imports.push_back({dll_name, symbol});
      }
    }
  }
}

void BinaryAnalyzer::extract_strings(const ScanOptions& options, AnalysisReport& report) const {
  const auto data = read_bytes(options.binary_path);
  if (data.empty()) {
    report.warnings.push_back("internal strings extractor failed: file could not be read");
    return;
  }
  std::ostringstream extracted;
  append_ascii_strings(data, extracted);
  append_utf16le_strings(data, extracted);
  report.strings = string_scanner_.scan(extracted.str());
}

void BinaryAnalyzer::extract_disassembly(const ScanOptions& options, AnalysisReport& report) const {
  if (options.max_disasm_snippets <= 0) {
    return;
  }

  const ToolResult disasm = runner_.run({"objdump", "-d", options.binary_path.string()}, 30);
  if (disasm.exit_code != 0) {
    const ToolResult llvm_disasm = runner_.run({"llvm-objdump", "-d", options.binary_path.string()}, 30);
    if (llvm_disasm.exit_code != 0) {
      report.warnings.push_back("optional disassembly unavailable: objdump/llvm-objdump failed");
      return;
    }
    const auto lines = split_lines(llvm_disasm.output);
    if (lines.empty()) {
      report.warnings.push_back("optional disassembly unavailable: llvm-objdump returned no output");
      return;
    }
    std::ostringstream snippet;
    for (std::size_t i = 0; i < std::min<std::size_t>(18, lines.size()); ++i) {
      snippet << lines[i] << '\n';
    }
    report.disassembly_snippets.push_back({"entry-context", snippet.str()});
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
