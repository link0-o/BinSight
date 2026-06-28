#include <binsight/llm_client.hpp>
#include <binsight/config.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>

namespace binsight {

namespace {

using json = nlohmann::json;

struct LlmHttpRequest {
  std::string body;
  std::string url;
  std::vector<std::string> headers = {"Content-Type: application/json"};
};

constexpr int kDefaultLlmRequestTimeoutSeconds = 90;

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

int normalized_llm_timeout_seconds(const ScanOptions& options) {
  if (options.llm_timeout_seconds == 0) {
    return kDefaultLlmRequestTimeoutSeconds;
  }
  if (options.llm_timeout_seconds < 5) {
    return 5;
  }
  if (options.llm_timeout_seconds > 600) {
    return 600;
  }
  return options.llm_timeout_seconds;
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

int severity_rank(Severity severity) {
  return static_cast<int>(severity);
}

Severity max_severity(Severity left, Severity right) {
  return severity_rank(left) >= severity_rank(right) ? left : right;
}

std::vector<std::string> string_array_from_json(const json& value) {
  std::vector<std::string> result;
  if (!value.is_array()) {
    return result;
  }
  for (const auto& item : value) {
    if (item.is_string()) {
      result.push_back(item.get<std::string>());
    }
  }
  return result;
}

std::string string_from_json(const json& value, const std::string& fallback = {}) {
  return value.is_string() ? value.get<std::string>() : fallback;
}

std::string strip_code_fence(std::string text) {
  text = trim(text);
  if (text.rfind("```", 0) != 0) {
    return text;
  }
  const auto first_newline = text.find('\n');
  const auto last_fence = text.rfind("```");
  if (first_newline == std::string::npos || last_fence == std::string::npos || last_fence <= first_newline) {
    return text;
  }
  return trim(text.substr(first_newline + 1, last_fence - first_newline - 1));
}

std::optional<std::string> extract_json_object_text(const std::string& text) {
  const std::string stripped = strip_code_fence(text);
  const auto begin = stripped.find('{');
  const auto end = stripped.rfind('}');
  if (begin == std::string::npos || end == std::string::npos || end <= begin) {
    return std::nullopt;
  }
  return stripped.substr(begin, end - begin + 1);
}

std::optional<std::string> response_text_from_json(const std::string& provider,
                                                   const std::string& response) {
  try {
    const auto parsed = json::parse(response);
    if (provider == "responses") {
      if (parsed.contains("output_text") && parsed["output_text"].is_string()) {
        return parsed["output_text"].get<std::string>();
      }
      if (parsed.contains("output") && parsed["output"].is_array()) {
        for (const auto& output : parsed["output"]) {
          if (!output.contains("content") || !output["content"].is_array()) {
            continue;
          }
          for (const auto& content : output["content"]) {
            if (content.contains("text") && content["text"].is_string()) {
              return content["text"].get<std::string>();
            }
          }
        }
      }
    } else if (provider == "openai") {
      return parsed.at("choices").at(0).at("message").at("content").get<std::string>();
    } else if (provider == "anthropic") {
      return parsed.at("content").at(0).at("text").get<std::string>();
    } else if (provider == "ollama") {
      return parsed.at("response").get<std::string>();
    }
  } catch (...) {
    return std::nullopt;
  }
  return std::nullopt;
}

std::optional<std::string> response_text_from_regex(const std::string& provider,
                                                    const std::string& response) {
  std::smatch match;
  if (provider == "responses" &&
      std::regex_search(response, match,
                        std::regex(R"JSON("output_text"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    return json_unescape_string(match[1].str());
  }
  if ((provider == "responses" || provider == "anthropic") &&
      std::regex_search(response, match,
                        std::regex(R"JSON("text"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    return json_unescape_string(match[1].str());
  }
  if (provider == "openai" &&
      std::regex_search(response, match,
                        std::regex(R"JSON("content"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    return json_unescape_string(match[1].str());
  }
  if (provider == "ollama" &&
      std::regex_search(response, match,
                        std::regex(R"JSON("response"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    return json_unescape_string(match[1].str());
  }
  return std::nullopt;
}

std::string extract_model_text(const std::string& provider, const std::string& response) {
  if (const auto parsed = response_text_from_json(provider, response)) {
    return *parsed;
  }
  if (const auto parsed = response_text_from_regex(provider, response)) {
    return *parsed;
  }
  return {};
}

std::size_t count_cjk_text(const std::string& text) {
  std::size_t count = 0;
  for (std::size_t i = 0; i + 2 < text.size(); ++i) {
    const auto b0 = static_cast<unsigned char>(text[i]);
    const auto b1 = static_cast<unsigned char>(text[i + 1]);
    const auto b2 = static_cast<unsigned char>(text[i + 2]);
    if (b0 >= 0xE4 && b0 <= 0xE9 && b1 >= 0x80 && b1 <= 0xBF && b2 >= 0x80 && b2 <= 0xBF) {
      ++count;
      i += 2;
    }
  }
  return count;
}

std::size_t count_ascii_letters(const std::string& text) {
  std::size_t count = 0;
  for (const unsigned char c : text) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
      ++count;
    }
  }
  return count;
}

std::string narrative_text(const AiAnalysis& analysis) {
  std::string text = analysis.summary + "\n" + analysis.decision_basis + "\n";
  for (const auto& item : analysis.risk_sources) {
    text += item + "\n";
  }
  for (const auto& item : analysis.recommendations) {
    text += item + "\n";
  }
  return text;
}

bool language_mismatch(ReportLanguage language, const AiAnalysis& analysis) {
  const auto text = narrative_text(analysis);
  if (text.empty()) {
    return true;
  }
  if (language == ReportLanguage::Chinese) {
    const auto cjk = count_cjk_text(text);
    const auto latin = count_ascii_letters(text);
    return cjk < 4 && latin > 40;
  }
  if (language == ReportLanguage::English) {
    const auto cjk = count_cjk_text(text);
    const auto latin = count_ascii_letters(text);
    return cjk >= 8 && cjk * 2 > latin;
  }
  return false;
}

bool parse_ai_json_object(const ScanOptions& options,
                          const RiskAssessment& local,
                          const std::string& model_text,
                          const std::string& raw_response,
                          AiAnalysis& analysis,
                          std::string& error) {
  analysis = {};
  analysis.provider = options.provider;
  analysis.model = options.model;
  analysis.raw_response = raw_response;
  const auto object_text = extract_json_object_text(model_text);
  if (!object_text) {
    error = "AI assessment did not contain a JSON object";
    return false;
  }

  try {
    const auto parsed = json::parse(*object_text);
    if (!parsed.is_object()) {
      error = "AI assessment JSON root is not an object";
      return false;
    }
    analysis.severity = severity_from_string(string_from_json(parsed.value("severity", json::object()), "info"));
    analysis.confidence = string_from_json(parsed.value("confidence", json::object()), "low");
    analysis.summary = string_from_json(parsed.value("summary", json::object()));
    analysis.decision_basis = string_from_json(parsed.value("decision_basis", json::object()));
    analysis.risk_sources = string_array_from_json(parsed.value("risk_sources", json::array()));
    analysis.recommendations = string_array_from_json(parsed.value("recommendations", json::array()));
    if (analysis.summary.empty()) {
      error = "AI assessment JSON missed summary";
      return false;
    }
    (void)local;
    return true;
  } catch (const std::exception& ex) {
    error = std::string("failed to parse AI assessment JSON: ") + ex.what();
    return false;
  }
}

bool has_strong_high_local_evidence(const AnalysisReport& report) {
  for (const auto& finding : report.rule_findings) {
    if ((finding.severity == Severity::High || finding.severity == Severity::Critical) &&
        lowercase(finding.risk_type) == "malicious-likely" &&
        lowercase(finding.evidence_strength) == "strong") {
      return true;
    }
  }
  return false;
}

bool local_findings_are_capability_only(const AnalysisReport& report) {
  if (report.rule_findings.empty()) {
    return true;
  }
  for (const auto& finding : report.rule_findings) {
    if (lowercase(finding.risk_type) != "capability") {
      return false;
    }
  }
  return true;
}

bool ai_is_offline_fallback(const AiAnalysis& ai) {
  return ai.decision_basis == "AI assessment unavailable; this mirrors the local deterministic baseline.";
}

void append_unique(std::vector<std::string>& target, const std::vector<std::string>& values) {
  for (const auto& value : values) {
    if (!value.empty() && std::find(target.begin(), target.end(), value) == target.end()) {
      target.push_back(value);
    }
  }
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

std::string llm_failure_diagnostic(const ToolResult& response, int timeout_seconds) {
  const std::string output = response.output.empty() ? response.error : response.output;
  const std::string lower = lowercase(output);
  if (lower.find("timed out") != std::string::npos ||
      lower.find("operation timed out") != std::string::npos ||
      lower.find("curl: (28)") != std::string::npos) {
    return "llm_timeout: request timed out after " + std::to_string(timeout_seconds) +
           " seconds. Increase --llm-timeout, check network/proxy settings, or try a faster model.";
  }
  if (lower.find("curl: (6)") != std::string::npos ||
      lower.find("could not resolve host") != std::string::npos) {
    return "llm_network_dns_error: could not resolve the API host. Check DNS, proxy, VPN, or base URL.";
  }
  if (lower.find("curl: (7)") != std::string::npos ||
      lower.find("failed to connect") != std::string::npos ||
      lower.find("could not connect") != std::string::npos) {
    return "llm_network_connect_error: failed to connect to the API endpoint. Check firewall, proxy, VPN, or provider availability.";
  }
  if (lower.find("401") != std::string::npos || lower.find("unauthorized") != std::string::npos ||
      lower.find("invalid api key") != std::string::npos) {
    return "llm_auth_failed: authentication failed. Check the API key and selected provider.";
  }
  if (lower.find("403") != std::string::npos || lower.find("forbidden") != std::string::npos) {
    return "llm_permission_denied: provider rejected the request. Check account permissions, model access, or regional restrictions.";
  }
  if (lower.find("404") != std::string::npos || lower.find("model_not_found") != std::string::npos ||
      lower.find("model not found") != std::string::npos) {
    return "llm_model_or_url_invalid: model or base URL was not accepted by the provider.";
  }
  if (lower.find("429") != std::string::npos || lower.find("rate limit") != std::string::npos) {
    return "llm_rate_limited: provider rate limit or quota was reached.";
  }
  if (lower.find("500") != std::string::npos || lower.find("502") != std::string::npos ||
      lower.find("503") != std::string::npos || lower.find("504") != std::string::npos) {
    return "llm_provider_server_error: provider returned a server error; retry later.";
  }
  return "llm_request_failed: " + first_chars(output, 1000);
}

bool retryable_llm_failure(const ToolResult& response) {
  const std::string lower = lowercase(response.output.empty() ? response.error : response.output);
  return lower.find("curl: (6)") != std::string::npos ||
         lower.find("curl: (7)") != std::string::npos ||
         lower.find("curl: (28)") != std::string::npos ||
         lower.find("failed to connect") != std::string::npos ||
         lower.find("could not connect") != std::string::npos ||
         lower.find("timed out") != std::string::npos ||
         lower.find("502") != std::string::npos ||
         lower.find("503") != std::string::npos ||
         lower.find("504") != std::string::npos;
}

ToolResult execute_llm_request(const LlmHttpRequest& request,
                               const ProcessRunner& runner,
                               const std::string& temp_prefix,
                               int timeout_seconds) {
  const auto temp_path = std::filesystem::temp_directory_path() /
                         (temp_prefix + "-request-" + std::to_string(std::rand()) + ".json");
  const auto curl_config_path = std::filesystem::temp_directory_path() /
                                (temp_prefix + "-curl-" + std::to_string(std::rand()) + ".txt");
  write_file(temp_path, request.body);
  std::ostringstream curl_config;
  curl_config << "request = \"POST\"\n";
  curl_config << "url = \"" << request.url << "\"\n";
  for (const auto& header : request.headers) {
    curl_config << "header = \"" << header << "\"\n";
  }
  curl_config << "data-binary = \"@" << temp_path.generic_string() << "\"\n";
  write_file(curl_config_path, curl_config.str());

  std::vector<std::string> args = {"curl", "-sS", "--fail-with-body", "--max-time",
                                   std::to_string(timeout_seconds),
                                   "--config", curl_config_path.string()};
  ToolResult response = runner.run(args, timeout_seconds);
  std::filesystem::remove(temp_path);
  std::filesystem::remove(curl_config_path);
  return response;
}

ToolResult execute_llm_request_with_retry(const LlmHttpRequest& request,
                                          const ProcessRunner& runner,
                                          const std::string& temp_prefix,
                                          int timeout_seconds,
                                          std::vector<std::string>& warnings) {
  ToolResult response = execute_llm_request(request, runner, temp_prefix, timeout_seconds);
  if (response.exit_code == 0 || !retryable_llm_failure(response)) {
    return response;
  }
  warnings.push_back("LLM request failed with a retryable network/provider error; retrying once.");
  ToolResult retry = execute_llm_request(request, runner, temp_prefix + "-retry", timeout_seconds);
  if (retry.exit_code == 0) {
    warnings.push_back("LLM request succeeded after one retry.");
  }
  return retry;
}

std::string language_name(ReportLanguage language) {
  return language == ReportLanguage::Chinese ? "Simplified Chinese" : "English";
}

std::string repair_system_prompt(ReportLanguage language) {
  if (language == ReportLanguage::Chinese) {
    return "你是 JSON 修复器。只能返回严格 JSON，不要 Markdown。字段名保持英文，所有叙述字段必须使用简体中文。技术标识如 API、DLL、section、规则 ID 可以保留原文。";
  }
  return "You are a JSON repair tool. Return strict JSON only, with no Markdown. Keep field names in English and write all narrative fields in English. Technical identifiers such as APIs, DLLs, sections, and rule IDs may remain unchanged.";
}

std::string build_repair_prompt(ReportLanguage language,
                                const std::string& model_text,
                                const std::string& error) {
  std::ostringstream prompt;
  if (language == ReportLanguage::Chinese) {
    prompt << "请修正下面的模型输出，使其成为一个 JSON 对象。字段必须是："
           << "{\"severity\":\"info|low|medium|high|critical\",\"confidence\":\"low|medium|high\","
           << "\"summary\":\"...\",\"decision_basis\":\"...\",\"risk_sources\":[\"...\"],"
           << "\"recommendations\":[\"...\"]}。"
           << "summary、decision_basis、risk_sources、recommendations 的叙述内容必须使用简体中文。"
           << "错误原因：" << error << "\n\n原始输出：\n" << model_text;
  } else {
    prompt << "Repair the following model output into one JSON object with exactly these fields: "
           << "{\"severity\":\"info|low|medium|high|critical\",\"confidence\":\"low|medium|high\","
           << "\"summary\":\"...\",\"decision_basis\":\"...\",\"risk_sources\":[\"...\"],"
           << "\"recommendations\":[\"...\"]}. "
           << "The narrative content in summary, decision_basis, risk_sources, and recommendations must be English. "
           << "Error: " << error << "\n\nOriginal output:\n" << model_text;
  }
  return first_chars(prompt.str(), 16000);
}

}  // namespace

LlmClient::LlmClient(ProcessRunner runner) : runner_(std::move(runner)) {}

RiskAssessment LlmClient::local_analysis(const ScanOptions&, const AnalysisReport& report) const {
  RiskAssessment analysis;
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
      analysis.risk_sources.push_back(finding.id + ": " + finding.title + " [" +
                                      finding.risk_type + ", " + finding.confidence + ", " +
                                      finding.evidence_strength + "]");
      if (!finding.recommendation.empty()) {
        analysis.recommendations.push_back(finding.recommendation);
      }
    }
  }
  return analysis;
}

AiAnalysis LlmClient::analyze(const ScanOptions& options,
                              const AnalysisReport& report,
                              std::vector<std::string>& warnings) const {
  return analyze_for_language(options, report, options.report_language == ReportLanguage::Both
                                                   ? ReportLanguage::Chinese
                                                   : options.report_language,
                              warnings);
}

AiAnalysis LlmClient::analyze_for_language(const ScanOptions& options,
                                           const AnalysisReport& report,
                                           ReportLanguage language,
                                           std::vector<std::string>& warnings) const {
  ScanOptions language_options = options;
  language_options.report_language = language;
  const auto local = report.local_analysis.summary.empty() ? local_analysis(options, report) : report.local_analysis;
  if (language_options.provider == "none") {
    return offline_analysis(language_options, local);
  }

  const std::string prompt = build_prompt(language_options, report);
  const auto request = build_request(language_options, system_prompt(language_options), prompt, warnings);
  if (!request) {
    return offline_analysis(language_options, local);
  }

  const int timeout_seconds = normalized_llm_timeout_seconds(language_options);
  ToolResult response = execute_llm_request_with_retry(*request, runner_, "binsight-llm",
                                                       timeout_seconds, warnings);
  if (response.exit_code != 0) {
    warnings.push_back("LLM request failed: " + llm_failure_diagnostic(response, timeout_seconds));
    warnings.push_back("llm_unavailable: no online AI assessment was completed; final assessment falls back to the local deterministic baseline");
    return offline_analysis(language_options, local);
  }

  const std::string model_text = extract_model_text(language_options.provider, response.output);
  if (model_text.empty()) {
    warnings.push_back("failed to extract LLM response text; attempting AI repair for " +
                       to_string(language));
    const auto repair_request = build_request(
        language_options, repair_system_prompt(language),
        build_repair_prompt(language, response.output, "failed to extract model response text"),
        warnings);
    if (repair_request) {
      ToolResult repair_response = execute_llm_request_with_retry(*repair_request, runner_,
                                                                  "binsight-llm-repair",
                                                                  timeout_seconds, warnings);
      const std::string repair_text = extract_model_text(language_options.provider, repair_response.output);
      AiAnalysis repaired;
      std::string repair_error;
      if (repair_response.exit_code == 0 &&
          parse_ai_json_object(language_options, local, repair_text, response.output + "\n\n--- repair raw response ---\n" + repair_response.output,
                               repaired, repair_error) &&
          !language_mismatch(language, repaired)) {
        warnings.push_back("AI assessment required one repair request for " + to_string(language));
        return repaired;
      }
      warnings.push_back("AI repair failed for " + to_string(language) + ": " +
                         (repair_error.empty() ? repair_response.output : repair_error));
    }
    auto fallback = offline_analysis(language_options, local);
    fallback.raw_response = response.output;
    return fallback;
  }

  AiAnalysis analysis;
  std::string parse_error;
  if (parse_ai_json_object(language_options, local, model_text, response.output, analysis, parse_error) &&
      !language_mismatch(language, analysis)) {
    return analysis;
  }

  if (parse_error.empty()) {
    parse_error = "AI response language did not match " + language_name(language);
  }
  warnings.push_back(parse_error + "; attempting AI repair for " + to_string(language));
  const auto repair_request = build_request(language_options, repair_system_prompt(language),
                                            build_repair_prompt(language, model_text, parse_error),
                                            warnings);
  if (repair_request) {
    ToolResult repair_response = execute_llm_request_with_retry(*repair_request, runner_,
                                                                "binsight-llm-repair",
                                                                timeout_seconds, warnings);
    const std::string repair_text = extract_model_text(language_options.provider, repair_response.output);
    AiAnalysis repaired;
    std::string repair_error;
    if (repair_response.exit_code == 0 &&
        parse_ai_json_object(language_options, local, repair_text,
                             response.output + "\n\n--- repair raw response ---\n" + repair_response.output,
                             repaired, repair_error) &&
        !language_mismatch(language, repaired)) {
      warnings.push_back("AI assessment required one repair request for " + to_string(language));
      return repaired;
    }
    warnings.push_back("AI repair failed for " + to_string(language) + ": " +
                       (repair_error.empty() ? repair_response.output : repair_error));
  }

  auto fallback = offline_analysis(language_options, local);
  fallback.raw_response = response.output;
  return fallback;
}

AiAnalysis LlmClient::parse_ai_assessment(const ScanOptions& options,
                                          const RiskAssessment& local,
                                          const std::string& model_text,
                                          const std::string& raw_response,
                                          std::vector<std::string>& warnings) const {
  AiAnalysis analysis;
  std::string error;
  if (!parse_ai_json_object(options, local, model_text, raw_response, analysis, error)) {
    warnings.push_back(error + "; using local baseline for AI assessment");
    auto fallback = offline_analysis(options, local);
    fallback.raw_response = raw_response;
    return fallback;
  }
  return analysis;
}

FinalAssessment LlmClient::fuse_assessments(const AnalysisReport& report,
                                            const RiskAssessment& local,
                                            const AiAnalysis& ai,
                                            std::vector<std::string>&) const {
  FinalAssessment final;
  final.severity = local.severity;
  final.summary = local.summary;
  final.decision_basis = "No online AI assessment was available; final assessment uses the local deterministic baseline.";
  final.risk_sources = local.risk_sources;
  final.recommendations = local.recommendations;

  if (ai.provider == "none" || ai.summary.empty() || ai_is_offline_fallback(ai)) {
    return final;
  }

  const bool strong_floor = has_strong_high_local_evidence(report);
  const bool capability_only = local_findings_are_capability_only(report);
  Severity chosen = local.severity;
  std::string basis;

  if (strong_floor && severity_rank(ai.severity) < severity_rank(Severity::High)) {
    chosen = Severity::High;
    basis = "Local strong malicious-likely evidence sets a high-risk floor; AI assessment was lower and kept as context.";
  } else if (severity_rank(ai.severity) > severity_rank(local.severity)) {
    chosen = ai.severity;
    basis = "AI escalation: AI assessment identified higher combined risk than the local rule baseline.";
  } else if (severity_rank(ai.severity) < severity_rank(local.severity) && capability_only) {
    chosen = ai.severity;
    basis = "AI downgrade: local findings are capability-only and AI judged the combined evidence lower risk.";
  } else if (severity_rank(ai.severity) < severity_rank(local.severity)) {
    chosen = local.severity;
    basis = "Local baseline remains higher because findings include suspicious or stronger deterministic evidence.";
  } else {
    chosen = local.severity;
    basis = "Local and AI assessments agree on severity.";
  }

  final.severity = chosen;
  final.summary = "Final severity " + to_string(chosen) + " combines local baseline (" +
                  to_string(local.severity) + ") and AI assessment (" + to_string(ai.severity) + ").";
  if (!ai.summary.empty()) {
    final.summary += " AI summary: " + ai.summary;
  }
  final.decision_basis = ai.decision_basis.empty() ? basis : basis + " " + ai.decision_basis;
  final.risk_sources = local.risk_sources;
  append_unique(final.risk_sources, ai.risk_sources);
  final.recommendations = local.recommendations;
  append_unique(final.recommendations, ai.recommendations);
  return final;
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

  const int timeout_seconds = normalized_llm_timeout_seconds(options);
  ToolResult response = execute_llm_request_with_retry(*request, runner_, "binsight-llm-test",
                                                       timeout_seconds, warnings);
  result.raw_response = response.output;
  if (response.exit_code == 0) {
    result.ok = true;
    result.message = "LLM provider connection succeeded.";
  } else {
    result.ok = false;
    result.message = "LLM provider connection failed: " +
                     llm_failure_diagnostic(response, timeout_seconds);
  }
  return result;
}

AiAnalysis LlmClient::offline_analysis(const ScanOptions& options, const RiskAssessment& local) const {
  AiAnalysis analysis;
  analysis.provider = options.provider;
  analysis.model = options.model;
  analysis.severity = local.severity;
  analysis.confidence = "low";
  analysis.summary = local.summary;
  analysis.decision_basis = "AI assessment unavailable; this mirrors the local deterministic baseline.";
  analysis.risk_sources = local.risk_sources;
  analysis.recommendations = local.recommendations;
  return analysis;
}

std::string LlmClient::build_prompt(const ScanOptions& options, const AnalysisReport& report) const {
  std::ostringstream prompt;
  if (options.report_language == ReportLanguage::English) {
    prompt << "Analyze the binary risk from this structured evidence as an independent AI reviewer. "
           << "Return ONLY one JSON object with these fields:\n"
           << "{\"severity\":\"info|low|medium|high|critical\",\"confidence\":\"low|medium|high\","
           << "\"summary\":\"...\",\"decision_basis\":\"...\",\"risk_sources\":[\"...\"],"
           << "\"recommendations\":[\"...\"]}\n"
           << "All narrative values in summary, decision_basis, risk_sources, and recommendations MUST be English. "
           << "Keep technical identifiers such as APIs, DLLs, sections, rule IDs, paths, and hashes unchanged. "
           << "Use the local_analysis as a baseline, but provide your own assessment from all evidence. "
           << "Do not classify a sample as high risk from a single API import, a single URL, or provider/API-key configuration strings. "
           << "Escalate only when evidence strength, confidence, and combined evidence support it.\n\n";
  } else {
    prompt << "请作为独立 AI 复核者，基于以下结构化证据评估二进制风险。"
           << "只能返回一个 JSON 对象，不要返回 Markdown。字段为：\n"
           << "{\"severity\":\"info|low|medium|high|critical\",\"confidence\":\"low|medium|high\","
           << "\"summary\":\"...\",\"decision_basis\":\"...\",\"risk_sources\":[\"...\"],"
           << "\"recommendations\":[\"...\"]}\n"
           << "字段名必须保持英文；summary、decision_basis、risk_sources、recommendations 的叙述内容必须使用简体中文。"
           << "API、DLL、section、规则 ID、路径、hash 等技术标识可以保留原文。"
           << "请把 local_analysis 作为本地基线参考，但你需要基于所有证据给出自己的评估。"
           << "不要因为单个 API 导入、单个 URL、Provider/API key 配置字符串就判定为高风险。"
           << "只有当证据强度、置信度和组合证据足够时才升级风险。\n\n";
  }
  prompt << to_json(report);
  return first_chars(prompt.str(), 24000);
}

std::string LlmClient::system_prompt(const ScanOptions& options) const {
  std::ostringstream prompt;
  if (options.report_language == ReportLanguage::English) {
    prompt << "You are a binary risk analyst. Use only the provided evidence and retrieved knowledge. "
           << "Separate confirmed evidence from speculation, and distinguish static evidence from dynamic observations. "
           << "Treat capability findings, suspicious findings, and malicious-likely findings differently. "
           << "A single API import, URL, or configuration string is not enough for a high-risk conclusion. "
           << "Return strict JSON only, with no Markdown or code fences. All narrative field values must be English.";
  } else {
    prompt << "你是二进制安全风险分析员。只能基于提供的证据和检索到的知识进行判断，"
           << "必须区分已确认事实和推测风险，并区分静态证据与动态观测。"
           << "必须区分能力提示、可疑行为和高风险倾向；单个 API、URL 或配置字符串不足以得出高风险结论。"
           << "只能返回严格 JSON，不要返回 Markdown 或代码块。字段名保持英文，所有叙述字段值必须使用简体中文。";
  }
  return prompt.str();
}

}  // namespace binsight
