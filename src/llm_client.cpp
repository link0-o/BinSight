#include <binsight/llm_client.hpp>
#include <binsight/config.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>

namespace binsight {

namespace {

Severity max_severity(const std::vector<RuleFinding>& findings) {
  Severity result = Severity::Info;
  for (const auto& finding : findings) {
    if (static_cast<int>(finding.severity) > static_cast<int>(result)) {
      result = finding.severity;
    }
  }
  return result;
}

std::string first_chars(const std::string& value, std::size_t count) {
  if (value.size() <= count) {
    return value;
  }
  return value.substr(0, count) + "...";
}

std::string json_unescape_string(const std::string& value) {
  std::string out;
  out.reserve(value.size());
  bool escape = false;
  for (char c : value) {
    if (escape) {
      switch (c) {
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case '"':
          out.push_back('"');
          break;
        case '\\':
          out.push_back('\\');
          break;
        default:
          out.push_back(c);
          break;
      }
      escape = false;
    } else if (c == '\\') {
      escape = true;
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::optional<std::string> api_key_from_options(const ScanOptions& options,
                                                std::vector<std::string>& warnings) {
  if (!options.api_key_name.empty()) {
    CredentialStore store;
    std::string error;
    auto secret = store.load(options.api_key_name, error);
    if (secret && !secret->empty()) {
      return secret;
    }
    warnings.push_back("configured API key was not available from secure storage: " + error);
  }

  const char* key = std::getenv(options.api_key_env.c_str());
  if (key != nullptr && std::string(key).size() > 0) {
    return std::string(key);
  }
  return std::nullopt;
}

}  // namespace

LlmClient::LlmClient(ProcessRunner runner) : runner_(std::move(runner)) {}

AiAnalysis LlmClient::analyze(const ScanOptions& options,
                              const AnalysisReport& report,
                              std::vector<std::string>& warnings) const {
  if (options.provider == "none") {
    return offline_analysis(options, report);
  }

  const std::string prompt = build_prompt(options, report);
  std::string body;
  std::string url;
  std::vector<std::string> curl_headers = {"Content-Type: application/json"};

  if (options.provider == "openai") {
    const auto key = api_key_from_options(options, warnings);
    if (!key) {
      warnings.push_back("OpenAI-compatible provider requested but no API key is available. Configure secure storage or env var: " +
                         options.api_key_env);
      return offline_analysis(options, report);
    }
    const std::string base = options.base_url.empty() ? "https://api.openai.com/v1" : options.base_url;
    url = base + "/chat/completions";
    curl_headers.push_back("Authorization: Bearer " + *key);
    const std::string model = options.model.empty() ? "gpt-4.1-mini" : options.model;
    body = std::string("{\"model\":\"") + json_escape(model) +
           "\",\"temperature\":0.1,\"messages\":[{\"role\":\"system\",\"content\":\"" +
           json_escape(system_prompt(options)) + "\"},{\"role\":\"user\",\"content\":\"" +
           json_escape(prompt) + "\"}]}";
  } else if (options.provider == "ollama") {
    const std::string base = options.base_url.empty() ? "http://localhost:11434" : options.base_url;
    url = base + "/api/generate";
    const std::string model = options.model.empty() ? "llama3.1" : options.model;
    body = std::string("{\"model\":\"") + json_escape(model) + "\",\"prompt\":\"" +
           json_escape(prompt) + "\",\"stream\":false}";
  } else {
    warnings.push_back("unknown provider: " + options.provider);
    return offline_analysis(options, report);
  }

  const auto temp_path = std::filesystem::temp_directory_path() /
                         ("binsight-llm-request-" + std::to_string(std::rand()) + ".json");
  const auto curl_config_path = std::filesystem::temp_directory_path() /
                                ("binsight-curl-config-" + std::to_string(std::rand()) + ".txt");
  write_file(temp_path, body);
  std::ostringstream curl_config;
  curl_config << "request = \"POST\"\n";
  curl_config << "url = \"" << url << "\"\n";
  for (const auto& header : curl_headers) {
    curl_config << "header = \"" << header << "\"\n";
  }
  curl_config << "data-binary = \"@" << temp_path.generic_string() << "\"\n";
  write_file(curl_config_path, curl_config.str());

  std::vector<std::string> args = {"curl", "-sS", "--config", curl_config_path.string()};
  ToolResult response = runner_.run(args, 60);
  std::filesystem::remove(temp_path);
  std::filesystem::remove(curl_config_path);
  if (response.exit_code != 0) {
    warnings.push_back("LLM request failed: " + response.output);
    return offline_analysis(options, report);
  }

  AiAnalysis analysis = offline_analysis(options, report);
  analysis.provider = options.provider;
  analysis.model = options.model;
  analysis.raw_response = response.output;
  std::smatch match;
  if (options.provider == "openai" &&
      std::regex_search(response.output, match,
                        std::regex(R"JSON("content"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = json_unescape_string(match[1].str());
  } else if (options.provider == "ollama" &&
             std::regex_search(response.output, match,
                               std::regex(R"JSON("response"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = json_unescape_string(match[1].str());
  } else {
    warnings.push_back("failed to parse LLM response JSON with lightweight parser");
    analysis.summary = first_chars(response.output, 1200);
  }
  return analysis;
}

AiAnalysis LlmClient::offline_analysis(const ScanOptions& options, const AnalysisReport& report) const {
  AiAnalysis analysis;
  analysis.provider = options.provider;
  analysis.model = options.model;
  analysis.severity = max_severity(report.rule_findings);
  if (report.rule_findings.empty()) {
    analysis.summary = "No deterministic risk rules matched. This does not prove the binary is safe.";
    analysis.recommendations.push_back("Review full imports, strings, and sections if the sample is high value.");
  } else {
    std::ostringstream summary;
    summary << "Deterministic rules matched " << report.rule_findings.size()
            << " finding(s). Highest local severity: " << to_string(analysis.severity) << ".";
    analysis.summary = summary.str();
    for (const auto& finding : report.rule_findings) {
      analysis.risk_sources.push_back(finding.id + ": " + finding.title);
      if (!finding.recommendation.empty()) {
        analysis.recommendations.push_back(finding.recommendation);
      }
    }
  }
  return analysis;
}

std::string LlmClient::build_prompt(const ScanOptions& options, const AnalysisReport& report) const {
  std::ostringstream prompt;
  if (options.report_language == ReportLanguage::English) {
    prompt << "Analyze the binary risk from this structured evidence. Return concise English Markdown with:\n"
           << "- Overall severity\n"
           << "- Confirmed evidence\n"
           << "- Static evidence versus dynamic observations\n"
           << "- Speculative risks\n"
           << "- Risk sources\n"
           << "- Recommendations\n\n";
  } else {
    prompt << "请基于以下结构化证据分析二进制文件风险。请使用简洁、专业的中文 Markdown，并包含：\n"
           << "- 总体风险等级\n"
           << "- 已确认的证据\n"
           << "- 静态证据与动态观测的区别\n"
           << "- 推测性风险\n"
           << "- 风险来源\n"
           << "- 处置建议\n\n";
  }
  prompt << to_json(report);
  return first_chars(prompt.str(), 24000);
}

std::string LlmClient::system_prompt(const ScanOptions& options) const {
  std::ostringstream prompt;
  if (options.report_language == ReportLanguage::English) {
    prompt << "You are a binary risk analyst. Use only the provided evidence and retrieved knowledge. "
           << "Separate confirmed evidence from speculation, and distinguish static evidence from dynamic observations. "
           << "Answer in English.";
  } else {
    prompt << "你是二进制安全风险分析员。只能基于提供的证据和检索到的知识进行判断，"
           << "必须区分已确认事实和推测风险，并区分静态证据与动态观测。请使用中文回答。";
  }
  return prompt.str();
}

}  // namespace binsight
