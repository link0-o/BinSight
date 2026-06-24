#include <binsight/binary_analyzer.hpp>
#include <binsight/config.hpp>
#include <binsight/llm_client.hpp>
#include <binsight/local_rag.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/risk_rule_engine.hpp>
#include <binsight/utils.hpp>

#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

void print_usage() {
  std::cout
      << "Usage:\n"
      << "  binsight scan <binary> [--out report.md] [--json report.json]\n"
      << "                 [--report-lang zh-CN|en|both]\n"
      << "                 [--provider none|openai|ollama] [--model name]\n"
      << "                 [--base-url url] [--api-key-env ENV] [--api-key-name NAME]\n"
      << "                 [--knowledge-dir knowledge] [--rules-dir rules]\n"
      << "                 [--max-disasm-snippets N]\n"
      << "  binsight config wizard\n"
      << "  binsight config show\n"
      << "  binsight config set-key --provider deepseek|openai [--name NAME]\n"
      << "  binsight config delete-key --provider deepseek|openai [--name NAME]\n";
}

bool next_value(int& index, int argc, char** argv, std::string& value) {
  if (index + 1 >= argc) {
    return false;
  }
  value = argv[++index];
  return true;
}

std::filesystem::path executable_dir(char** argv) {
  std::error_code ec;
  std::filesystem::path path = std::filesystem::absolute(argv[0], ec);
  if (ec) {
    return {};
  }
  return path.parent_path();
}

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

std::string prompt_line(const std::string& label, const std::string& default_value = {}) {
  std::cout << label;
  if (!default_value.empty()) {
    std::cout << " [" << default_value << "]";
  }
  std::cout << ": ";
  std::string value;
  std::getline(std::cin, value);
  return value.empty() ? default_value : value;
}

std::string read_secret(const std::string& label) {
  std::cout << label << ": ";
#ifdef _WIN32
  HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  GetConsoleMode(input, &mode);
  SetConsoleMode(input, mode & ~ENABLE_ECHO_INPUT);
  std::string value;
  std::getline(std::cin, value);
  SetConsoleMode(input, mode);
#else
  termios old_term{};
  tcgetattr(STDIN_FILENO, &old_term);
  termios new_term = old_term;
  new_term.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
  std::string value;
  std::getline(std::cin, value);
  tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
#endif
  std::cout << '\n';
  return value;
}

void apply_provider_preset(const std::string& provider_name, binsight::AppConfig& config) {
  const std::string lower = binsight::lowercase(provider_name);
  if (lower == "deepseek") {
    config.provider = "openai";
    config.base_url = "https://api.deepseek.com";
    config.model = "deepseek-chat";
    config.api_key_env = "DEEPSEEK_API_KEY";
    config.api_key_name = "binsight:deepseek";
  } else if (lower == "openai") {
    config.provider = "openai";
    config.base_url = "https://api.openai.com/v1";
    config.model = "gpt-4.1-mini";
    config.api_key_env = "OPENAI_API_KEY";
    config.api_key_name = "binsight:openai";
  } else if (lower == "ollama") {
    config.provider = "ollama";
    config.base_url = "http://localhost:11434";
    config.model = "llama3.1";
    config.api_key_env.clear();
    config.api_key_name.clear();
  } else {
    config.provider = "none";
    config.base_url.clear();
    config.model.clear();
    config.api_key_name.clear();
  }
}

void apply_config_to_options(const binsight::AppConfig& config, binsight::ScanOptions& options) {
  options.provider = config.provider;
  options.model = config.model;
  options.base_url = config.base_url;
  options.api_key_env = config.api_key_env.empty() ? options.api_key_env : config.api_key_env;
  options.api_key_name = config.api_key_name;
  options.report_language = config.report_language;
  options.output_dir = config.output_dir;
}

std::filesystem::path with_output_dir(const std::filesystem::path& output_dir,
                                      const std::filesystem::path& path) {
  if (output_dir.empty() || path.is_absolute() || path.has_parent_path()) {
    return path;
  }
  return output_dir / path;
}

std::filesystem::path language_path(const std::filesystem::path& path, const std::string& suffix) {
  const auto parent = path.parent_path();
  const std::string stem = path.stem().string();
  const std::string ext = path.extension().empty() ? ".md" : path.extension().string();
  return parent / (stem + "." + suffix + ext);
}

std::vector<std::pair<std::filesystem::path, binsight::ReportLanguage>> markdown_outputs(
    const binsight::ScanOptions& options) {
  const auto base = with_output_dir(options.output_dir, options.markdown_out);
  if (options.report_language == binsight::ReportLanguage::English) {
    return {{base, binsight::ReportLanguage::English}};
  }
  if (options.report_language == binsight::ReportLanguage::Chinese) {
    return {{base, binsight::ReportLanguage::Chinese}};
  }
  return {{language_path(base, "zh-CN"), binsight::ReportLanguage::Chinese},
          {language_path(base, "en"), binsight::ReportLanguage::English}};
}

int handle_config(int argc, char** argv) {
  if (argc < 3) {
    print_usage();
    return 1;
  }

  binsight::ConfigManager manager;
  binsight::CredentialStore credentials;
  std::vector<std::string> warnings;
  binsight::AppConfig config = manager.load(warnings).value_or(binsight::AppConfig{});
  const std::string subcommand = argv[2];

  if (subcommand == "show") {
    std::cout << "Config path: " << manager.config_path() << '\n';
    std::cout << "Provider: " << config.provider << '\n';
    std::cout << "Base URL: " << config.base_url << '\n';
    std::cout << "Model: " << config.model << '\n';
    std::cout << "Report language: " << binsight::to_string(config.report_language) << '\n';
    std::cout << "Output dir: " << config.output_dir << '\n';
    std::cout << "API key env: " << config.api_key_env << '\n';
    std::cout << "API key secure name: " << (config.api_key_name.empty() ? "(none)" : config.api_key_name)
              << '\n';
    if (!config.api_key_name.empty()) {
      std::string error;
      const auto secret = credentials.load(config.api_key_name, error);
      std::cout << "API key stored: " << (secret && !secret->empty() ? "yes" : "no") << '\n';
    }
    return 0;
  }

  if (subcommand == "wizard") {
    const std::string provider = prompt_line("Provider (none/openai/deepseek/ollama)", config.provider);
    apply_provider_preset(provider, config);
    config.base_url = prompt_line("Base URL", config.base_url);
    config.model = prompt_line("Model", config.model);
    config.report_language = binsight::report_language_from_string(
        prompt_line("Default report language (zh-CN/en/both)", binsight::to_string(config.report_language)));
    const std::string output_dir = prompt_line("Default output directory (empty = current directory)",
                                               config.output_dir.string());
    config.output_dir = output_dir;
    manager.save(config);
    std::cout << "Saved non-sensitive config: " << manager.config_path() << '\n';

    if (config.provider == "openai" && credentials.is_secure_store_available()) {
      const std::string save_key = prompt_line("Save API key to secure credential store? (yes/no)", "no");
      if (binsight::lowercase(save_key) == "yes" || binsight::lowercase(save_key) == "y") {
        const std::string secret = read_secret("API key");
        std::string error;
        if (!credentials.store(config.api_key_name, secret, error)) {
          std::cerr << "Failed to save API key: " << error << '\n';
          return 1;
        }
        std::cout << "API key saved to secure credential store as " << config.api_key_name << '\n';
      }
    } else if (config.provider == "openai") {
      std::cout << "Secure credential storage is unavailable in this build. Use env var: "
                << config.api_key_env << '\n';
    }
    return 0;
  }

  if (subcommand == "set-key" || subcommand == "delete-key") {
    std::string provider = "deepseek";
    std::string name;
    for (int i = 3; i < argc; ++i) {
      const std::string arg = argv[i];
      std::string value;
      if (arg == "--provider" && next_value(i, argc, argv, value)) {
        provider = value;
      } else if (arg == "--name" && next_value(i, argc, argv, value)) {
        name = value;
      } else {
        std::cerr << "binsight: invalid config option: " << arg << '\n';
        return 1;
      }
    }
    if (name.empty()) {
      name = binsight::default_key_name_for_provider(provider);
    }
    if (!credentials.is_secure_store_available()) {
      std::cerr << "Secure credential storage is unavailable in this build. Use an environment variable.\n";
      return 1;
    }
    std::string error;
    if (subcommand == "delete-key") {
      if (!credentials.erase(name, error)) {
        std::cerr << error << '\n';
        return 1;
      }
      std::cout << "Deleted API key: " << name << '\n';
      return 0;
    }
    const std::string secret = read_secret("API key");
    if (!credentials.store(name, secret, error)) {
      std::cerr << error << '\n';
      return 1;
    }
    apply_provider_preset(provider, config);
    config.api_key_name = name;
    manager.save(config);
    std::cout << "Saved API key to secure credential store as " << name << '\n';
    return 0;
  }

  print_usage();
  return 1;
}

int handle_scan(int argc, char** argv) {
  binsight::ScanOptions options;
  std::vector<std::string> config_warnings;
  binsight::ConfigManager config_manager;
  if (const auto config = config_manager.load(config_warnings)) {
    apply_config_to_options(*config, options);
  }

  if (argc < 3) {
    std::cerr << "binsight: scan requires a binary path\n";
    print_usage();
    return 1;
  }

  options.binary_path = argv[2];
  bool out_explicit = false;
  bool json_explicit = false;
  for (int i = 3; i < argc; ++i) {
    const std::string arg = argv[i];
    std::string value;
    if (arg == "--out" && next_value(i, argc, argv, value)) {
      options.markdown_out = value;
      out_explicit = true;
    } else if (arg == "--json" && next_value(i, argc, argv, value)) {
      options.json_out = value;
      json_explicit = true;
    } else if (arg == "--report-lang" && next_value(i, argc, argv, value)) {
      options.report_language = binsight::report_language_from_string(value);
    } else if (arg == "--provider" && next_value(i, argc, argv, value)) {
      options.provider = value;
    } else if (arg == "--model" && next_value(i, argc, argv, value)) {
      options.model = value;
    } else if (arg == "--base-url" && next_value(i, argc, argv, value)) {
      options.base_url = value;
    } else if (arg == "--api-key-env" && next_value(i, argc, argv, value)) {
      options.api_key_env = value;
    } else if (arg == "--api-key-name" && next_value(i, argc, argv, value)) {
      options.api_key_name = value;
    } else if (arg == "--knowledge-dir" && next_value(i, argc, argv, value)) {
      options.knowledge_dir = value;
      options.knowledge_dir_explicit = true;
    } else if (arg == "--rules-dir" && next_value(i, argc, argv, value)) {
      options.rules_dir = value;
      options.rules_dir_explicit = true;
    } else if (arg == "--max-disasm-snippets" && next_value(i, argc, argv, value)) {
      options.max_disasm_snippets = std::stoi(value);
    } else {
      std::cerr << "binsight: invalid or incomplete option: " << arg << '\n';
      print_usage();
      return 1;
    }
  }

  if (!out_explicit && !options.output_dir.empty()) {
    options.markdown_out = with_output_dir(options.output_dir, options.markdown_out);
  }
  if (!json_explicit) {
    options.json_out = with_output_dir(options.output_dir, options.json_out);
  }

  const auto exe_dir = executable_dir(argv);
  options.knowledge_dir = resolve_resource_dir(options.knowledge_dir, options.knowledge_dir_explicit,
                                               exe_dir, "knowledge");
  options.rules_dir = resolve_resource_dir(options.rules_dir, options.rules_dir_explicit, exe_dir, "rules");

  if (options.provider != "none" && options.provider != "openai" && options.provider != "ollama") {
    std::cerr << "binsight: provider must be one of none, openai, or ollama\n";
    return 1;
  }

  try {
    binsight::ProcessRunner runner;
    binsight::BinaryAnalyzer analyzer{runner, binsight::StringScanner{}};
    binsight::AnalysisReport report = analyzer.analyze(options);
    report.warnings.insert(report.warnings.end(), config_warnings.begin(), config_warnings.end());

    binsight::RiskRuleEngine rules;
    report.rule_findings = rules.evaluate(options.rules_dir, report, report.warnings);

    binsight::LocalRagIndex rag;
    report.rag_context = rag.retrieve(options.knowledge_dir, report, report.warnings);

    binsight::LlmClient llm{runner};
    report.ai_analysis = llm.analyze(options, report, report.warnings);

    binsight::ReportWriter writer;
    for (const auto& [path, language] : markdown_outputs(options)) {
      writer.write_markdown(path, report, language);
      std::cout << "Markdown report: " << path << '\n';
    }
    writer.write_json(options.json_out, report);

    std::cout << "JSON report: " << options.json_out << '\n';
    if (!report.warnings.empty()) {
      std::cout << "Warnings: " << report.warnings.size() << '\n';
    }
    return 0;
  } catch (const std::exception& ex) {
    std::cerr << "binsight: " << ex.what() << '\n';
    return 1;
  }
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
    print_usage();
    return argc < 2 ? 1 : 0;
  }
  const std::string command = argv[1];
  if (command == "scan") {
    return handle_scan(argc, argv);
  }
  if (command == "config") {
    return handle_config(argc, argv);
  }
  std::cerr << "binsight: unknown command: " << command << '\n';
  print_usage();
  return 1;
}
