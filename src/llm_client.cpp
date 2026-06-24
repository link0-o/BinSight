#include <binsight/llm_client.hpp>
#include <binsight/report_writer.hpp>
#include <binsight/utils.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
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

}  // namespace

LlmClient::LlmClient(ProcessRunner runner) : runner_(std::move(runner)) {}

AiAnalysis LlmClient::analyze(const ScanOptions& options,
                              const AnalysisReport& report,
                              std::vector<std::string>& warnings) const {
  if (options.provider == "none") {
    return offline_analysis(options, report);
  }

  const std::string prompt = build_prompt(report);
  std::string body;
  std::string url;
  std::vector<std::string> args = {"curl", "-sS", "-X", "POST", "-H", "Content-Type: application/json"};

  if (options.provider == "openai") {
    const char* key = std::getenv(options.api_key_env.c_str());
    if (key == nullptr || std::string(key).empty()) {
      warnings.push_back("OpenAI-compatible provider requested but API key env var is missing: " +
                         options.api_key_env);
      return offline_analysis(options, report);
    }
    const std::string base = options.base_url.empty() ? "https://api.openai.com/v1" : options.base_url;
    url = base + "/chat/completions";
    args.push_back("-H");
    args.push_back("Authorization: Bearer " + std::string(key));
    const std::string model = options.model.empty() ? "gpt-4.1-mini" : options.model;
    body = std::string("{\"model\":\"") + json_escape(model) +
           "\",\"temperature\":0.1,\"messages\":[{\"role\":\"system\",\"content\":\""
           "You are a binary risk analyst. Use only the provided evidence and retrieved knowledge. "
           "Separate confirmed evidence from speculation.\"},{\"role\":\"user\",\"content\":\"" +
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
  write_file(temp_path, body);
  args.push_back("--data-binary");
  args.push_back("@" + temp_path.string());
  args.push_back(url);

  ToolResult response = runner_.run(args, 60);
  std::filesystem::remove(temp_path);
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
    analysis.summary = match[1].str();
  } else if (options.provider == "ollama" &&
             std::regex_search(response.output, match,
                               std::regex(R"JSON("response"\s*:\s*"((?:\\.|[^"\\])*)")JSON"))) {
    analysis.summary = match[1].str();
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

std::string LlmClient::build_prompt(const AnalysisReport& report) const {
  std::ostringstream prompt;
  prompt << "Analyze the binary risk from this structured evidence. Return concise Markdown with:\n"
         << "- Overall severity\n"
         << "- Confirmed evidence\n"
         << "- Speculative risks\n"
         << "- Risk sources\n"
         << "- Recommendations\n\n"
         << to_json(report);
  return first_chars(prompt.str(), 24000);
}

}  // namespace binsight
