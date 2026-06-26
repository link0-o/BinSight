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

struct LlmHttpRequest {
  std::string body;
  std::string url;
  std::vector<std::string> headers = {"Content-Type: application/json"};
};

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
  if (!options.api_key_override.empty()) {
    return options.api_key_override;
  }

  if (!options.api_key_name.empty()) {
    CredentialStore store;
    if (store.is_secure_store_available()) {
      std::string error;
      auto secret = store.load(options.api_key_name, error);
      if (secret && !secret->empty()) {
        return secret;
      }
      warnings.push_back("configured API key was not available from secure storage: " + error);
    }
  }

  const char* key = std::getenv(options.api_key_env.c_str());
  if (key != nullptr && std::string(key).size() > 0) {
    return std::string(key);
  }
  return std::nullopt;
}

std::string join_url(const std::string& base, const std::string& suffix) {
  if (base.empty()) {
    return suffix;
  }
  if (base.back() == '/' && !suffix.empty() && suffix.front() == '/') {
    return base.substr(0, base.size() - 1) + suffix;
  }
  if (base.back() != '/' && !suffix.empty() && suffix.front() != '/') {
    return base + "/" + suffix;
  }
  return base + suffix;
}

std::optional<LlmHttpRequest> build_request(const ScanOptions& options,
                                            const std::string& system_prompt,
                                            const std::string& user_prompt,
                                            std::vector<std::string>& warnings) {
  LlmHttpRequest request;
  if (options.provider == "responses") {
    const auto key = api_key_from_options(options, warnings);
    if (!key) {
      warnings.push_back("OpenAI Responses provider requested but no API key is available. Configure secure storage or env var: " +
                         options.api_key_env);
      return std::nullopt;
    }
    const std::string base = options.base_url.empty() ? "https://api.openai.com/v1" : options.base_url;
    request.url = join_url(base, "/responses");
    request.headers.push_back("Authorization: Bearer " + *key);
    const std::string model = options.model.empty() ? "gpt-5.5" : options.model;
    request.body = std::string("{\"model\":\"") + json_escape(model) +
                   "\",\"input\":[{\"role\":\"system\",\"content\":\"" +
                   json_escape(system_prompt) + "\"},{\"role\":\"user\",\"content\":\"" +
                   json_escape(user_prompt) + "\"}],\"temperature\":0.1}";
  } else if (options.provider == "openai") {
    const auto key = api_key_from_options(options, warnings);
    if (!key) {
      warnings.push_back("OpenAI-compatible provider requested but no API key is available. Configure secure storage or env var: " +
                         options.api_key_env);
      return std::nullopt;
    }
    const std::string base = options.base_url.empty() ? "https://api.openai.com/v1" : options.base_url;
    request.url = join_url(base, "/chat/completions");
    request.headers.push_back("Authorization: Bearer " + *key);
    const std::string model = options.model.empty() ? "gpt-5.5" : options.model;
    request.body = std::string("{\"model\":\"") + json_escape(model) +
                   "\",\"temperature\":0.1,\"messages\":[{\"role\":\"system\",\"content\":\"" +
                   json_escape(system_prompt) + "\"},{\"role\":\"user\",\"content\":\"" +
                   json_escape(user_prompt) + "\"}]}";
  } else if (options.provider == "anthropic") {
    const auto key = api_key_from_options(options, warnings);
    if (!key) {
      warnings.push_back("Anthropic-compatible provider requested but no API key is available. Configure secure storage or env var: " +
                         options.api_key_env);
      return std::nullopt;
    }
    const std::string base = options.base_url.empty() ? "https://api.anthropic.com" : options.base_url;
    request.url = join_url(base, "/v1/messages");
    request.headers.push_back("x-api-key: " + *key);
    request.headers.push_back("anthropic-version: 2023-06-01");
    const std::string model = options.model.empty() ? "claude-3-5-sonnet-latest" : options.model;
    request.body = std::string("{\"model\":\"") + json_escape(model) +
                   "\",\"max_tokens\":1200,\"temperature\":0.1,\"system\":\"" +
                   json_escape(system_prompt) + "\",\"messages\":[{\"role\":\"user\",\"content\":\"" +
                   json_escape(user_prompt) + "\"}]}";
  } else if (options.provider == "ollama") {
    const std::string base = options.base_url.empty() ? "http://localhost:11434" : options.base_url;
    request.url = join_url(base, "/api/generate");
    const std::string model = options.model.empty() ? "llama3.1" : options.model;
    request.body = std::string("{\"model\":\"") + json_escape(model) + "\",\"prompt\":\"" +
                   json_escape(system_prompt + "\n\n" + user_prompt) + "\",\"stream\":false}";
  } else {
    warnings.push_back("unknown provider: " + options.provider);
    return std::nullopt;
  }
  return request;
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
  const auto request = build_request(options, system_prompt(options), prompt, warnings);
  if (!request) {
    return offline_analysis(options, report);
  }

  const auto temp_path = std::filesystem::temp_directory_path() /
                         ("binsight-llm-request-" + std::to_string(std::rand()) + ".json");
  const auto curl_config_path = std::filesystem::temp_directory_path() /
                                ("binsight-curl-config-" + std::to_string(std::rand()) + ".txt");
  write_file(temp_path, request->body);
  std::ostringstream curl_config;
  curl_config << "request = \"POST\"\n";
  curl_config << "url = \"" << request->url << "\"\n";
  for (const auto& header : request->headers) {
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
  if (options.provider == "responses" &&
      std::regex_search(response.output, match,
                        std::regex(R"JSON("output_text"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = json_unescape_string(match[1].str());
  } else if (options.provider == "responses" &&
             std::regex_search(response.output, match,
                               std::regex(R"JSON("text"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = json_unescape_string(match[1].str());
  } else if (options.provider == "openai" &&
      std::regex_search(response.output, match,
                        std::regex(R"JSON("content"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = json_unescape_string(match[1].str());
  } else if (options.provider == "anthropic" &&
             std::regex_search(response.output, match,
                               std::regex(R"JSON("text"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
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

LlmConnectionTest LlmClient::test_connection(const ScanOptions& options,
                                             std::vector<std::string>& warnings) const {
  LlmConnectionTest result;
  if (options.provider == "none") {
    result.ok = true;
    result.message = "Provider is none; no network test is required.";
    return result;
  }

  const auto request = build_request(options,
                                     "You are a connectivity test endpoint.",
                                     "Reply with OK.",
                                     warnings);
  if (!request) {
    result.message = warnings.empty() ? "failed to build LLM request" : warnings.back();
    return result;
  }

  const auto temp_path = std::filesystem::temp_directory_path() /
                         ("binsight-llm-test-" + std::to_string(std::rand()) + ".json");
  const auto curl_config_path = std::filesystem::temp_directory_path() /
                                ("binsight-curl-test-" + std::to_string(std::rand()) + ".txt");
  write_file(temp_path, request->body);
  std::ostringstream curl_config;
  curl_config << "request = \"POST\"\n";
  curl_config << "url = \"" << request->url << "\"\n";
  for (const auto& header : request->headers) {
    curl_config << "header = \"" << header << "\"\n";
  }
  curl_config << "data-binary = \"@" << temp_path.generic_string() << "\"\n";
  write_file(curl_config_path, curl_config.str());

  std::vector<std::string> args = {"curl", "-sS", "--fail-with-body", "--config",
                                   curl_config_path.string()};
  ToolResult response = runner_.run(args, 30);
  std::filesystem::remove(temp_path);
  std::filesystem::remove(curl_config_path);
  result.raw_response = response.output;
  if (response.exit_code == 0) {
    result.ok = true;
    result.message = "LLM provider connection succeeded.";
  } else {
    result.ok = false;
    result.message = "LLM provider connection failed: " + first_chars(response.output, 1200);
  }
  return result;
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
