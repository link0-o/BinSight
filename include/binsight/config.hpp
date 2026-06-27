#pragma once

#include <binsight/types.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace binsight {

struct AppConfig {
  std::string provider = "none";
  std::string model;
  std::string base_url;
  std::string api_key_env = "OPENAI_API_KEY";
  std::string api_key_name;
  ReportLanguage report_language = ReportLanguage::Both;
  std::filesystem::path output_dir;
  int llm_timeout_seconds = 90;
};

class ConfigManager {
 public:
  std::filesystem::path config_path() const;
  std::optional<AppConfig> load(std::vector<std::string>& warnings) const;
  void save(const AppConfig& config) const;
};

class CredentialStore {
 public:
  bool store(const std::string& name, const std::string& secret, std::string& error) const;
  std::optional<std::string> load(const std::string& name, std::string& error) const;
  bool erase(const std::string& name, std::string& error) const;
  bool is_secure_store_available() const;
};

std::string default_key_name_for_provider(const std::string& provider);

}  // namespace binsight
