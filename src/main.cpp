#include <binsight/binary_analyzer.hpp>
#include <binsight/llm_client.hpp>
#include <binsight/local_rag.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/risk_rule_engine.hpp>

#include <exception>
#include <iostream>
#include <string>

namespace {

void print_usage() {
  std::cout
      << "Usage:\n"
      << "  binsight scan <binary> [--out report.md] [--json report.json]\n"
      << "                 [--provider none|openai|ollama] [--model name]\n"
      << "                 [--base-url url] [--api-key-env ENV]\n"
      << "                 [--knowledge-dir knowledge] [--rules-dir rules]\n"
      << "                 [--max-disasm-snippets N]\n";
}

bool next_value(int& index, int argc, char** argv, std::string& value) {
  if (index + 1 >= argc) {
    return false;
  }
  value = argv[++index];
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  binsight::ScanOptions options;

  if (argc < 2 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
    print_usage();
    return argc < 2 ? 1 : 0;
  }
  if (std::string(argv[1]) != "scan") {
    std::cerr << "binsight: unknown command: " << argv[1] << '\n';
    print_usage();
    return 1;
  }
  if (argc < 3) {
    std::cerr << "binsight: scan requires a binary path\n";
    print_usage();
    return 1;
  }

  options.binary_path = argv[2];
  for (int i = 3; i < argc; ++i) {
    const std::string arg = argv[i];
    std::string value;
    if (arg == "--out" && next_value(i, argc, argv, value)) {
      options.markdown_out = value;
    } else if (arg == "--json" && next_value(i, argc, argv, value)) {
      options.json_out = value;
    } else if (arg == "--provider" && next_value(i, argc, argv, value)) {
      options.provider = value;
    } else if (arg == "--model" && next_value(i, argc, argv, value)) {
      options.model = value;
    } else if (arg == "--base-url" && next_value(i, argc, argv, value)) {
      options.base_url = value;
    } else if (arg == "--api-key-env" && next_value(i, argc, argv, value)) {
      options.api_key_env = value;
    } else if (arg == "--knowledge-dir" && next_value(i, argc, argv, value)) {
      options.knowledge_dir = value;
    } else if (arg == "--rules-dir" && next_value(i, argc, argv, value)) {
      options.rules_dir = value;
    } else if (arg == "--max-disasm-snippets" && next_value(i, argc, argv, value)) {
      options.max_disasm_snippets = std::stoi(value);
    } else {
      std::cerr << "binsight: invalid or incomplete option: " << arg << '\n';
      print_usage();
      return 1;
    }
  }

  if (options.provider != "none" && options.provider != "openai" && options.provider != "ollama") {
    std::cerr << "binsight: provider must be one of none, openai, or ollama\n";
    return 1;
  }

  try {
    binsight::ProcessRunner runner;
    binsight::BinaryAnalyzer analyzer{runner, binsight::StringScanner{}};
    binsight::AnalysisReport report = analyzer.analyze(options);

    binsight::RiskRuleEngine rules;
    report.rule_findings = rules.evaluate(options.rules_dir, report, report.warnings);

    binsight::LocalRagIndex rag;
    report.rag_context = rag.retrieve(options.knowledge_dir, report, report.warnings);

    binsight::LlmClient llm{runner};
    report.ai_analysis = llm.analyze(options, report, report.warnings);

    binsight::ReportWriter writer;
    writer.write_markdown(options.markdown_out, report);
    writer.write_json(options.json_out, report);

    std::cout << "Markdown report: " << options.markdown_out << '\n';
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

