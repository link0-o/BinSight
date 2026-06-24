#include <binsight/config.hpp>
#include <binsight/utils.hpp>

#include <cstdlib>
#include <regex>
#include <sstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincred.h>
#endif

namespace binsight {

namespace {

std::string json_field(const std::string& content, const std::string& name) {
  const std::regex field("\\\"" + name + "\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"");
  std::smatch match;
  if (!std::regex_search(content, match, field)) {
    return {};
  }
  std::string value = match[1].str();
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

std::filesystem::path user_config_home() {
#ifdef _WIN32
  const char* appdata = std::getenv("APPDATA");
  if (appdata != nullptr && std::string(appdata).size() > 0) {
    return std::filesystem::path(appdata) / "BinSight";
  }
#else
  const char* xdg = std::getenv("XDG_CONFIG_HOME");
  if (xdg != nullptr && std::string(xdg).size() > 0) {
    return std::filesystem::path(xdg) / "binsight";
  }
  const char* home = std::getenv("HOME");
  if (home != nullptr && std::string(home).size() > 0) {
    return std::filesystem::path(home) / ".config" / "binsight";
  }
#endif
  return std::filesystem::current_path() / ".binsight";
}

}  // namespace

std::filesystem::path ConfigManager::config_path() const {
  return user_config_home() / "config.json";
}

std::optional<AppConfig> ConfigManager::load(std::vector<std::string>& warnings) const {
  const auto path = config_path();
  if (!std::filesystem::exists(path)) {
    return std::nullopt;
  }
  try {
    const std::string content = read_file(path);
    AppConfig config;
    const std::string provider = json_field(content, "provider");
    if (!provider.empty()) config.provider = provider;
    config.model = json_field(content, "model");
    config.base_url = json_field(content, "base_url");
    const std::string api_key_env = json_field(content, "api_key_env");
    if (!api_key_env.empty()) config.api_key_env = api_key_env;
    config.api_key_name = json_field(content, "api_key_name");
    const std::string language = json_field(content, "report_language");
    if (!language.empty()) config.report_language = report_language_from_string(language);
    const std::string output_dir = json_field(content, "output_dir");
    if (!output_dir.empty()) config.output_dir = output_dir;
    return config;
  } catch (const std::exception& ex) {
    warnings.push_back(std::string("failed to read config: ") + ex.what());
    return std::nullopt;
  }
}

void ConfigManager::save(const AppConfig& config) const {
  std::ostringstream out;
  out << "{\n";
  out << "  \"provider\": \"" << json_escape(config.provider) << "\",\n";
  out << "  \"model\": \"" << json_escape(config.model) << "\",\n";
  out << "  \"base_url\": \"" << json_escape(config.base_url) << "\",\n";
  out << "  \"api_key_env\": \"" << json_escape(config.api_key_env) << "\",\n";
  out << "  \"api_key_name\": \"" << json_escape(config.api_key_name) << "\",\n";
  out << "  \"report_language\": \"" << json_escape(to_string(config.report_language)) << "\",\n";
  out << "  \"output_dir\": \"" << json_escape(config.output_dir.string()) << "\"\n";
  out << "}\n";
  write_file(config_path(), out.str());
}

bool CredentialStore::store(const std::string& name, const std::string& secret, std::string& error) const {
#ifdef _WIN32
  CREDENTIALA credential{};
  credential.Type = CRED_TYPE_GENERIC;
  credential.TargetName = const_cast<LPSTR>(name.c_str());
  credential.CredentialBlobSize = static_cast<DWORD>(secret.size());
  credential.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<char*>(secret.data()));
  credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
  if (!CredWriteA(&credential, 0)) {
    error = "Windows Credential Manager write failed: " + std::to_string(GetLastError());
    return false;
  }
  return true;
#else
  error = "secure credential storage is not available in this build; use an API key environment variable";
  return false;
#endif
}

std::optional<std::string> CredentialStore::load(const std::string& name, std::string& error) const {
#ifdef _WIN32
  PCREDENTIALA credential = nullptr;
  if (!CredReadA(name.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
    error = "Windows Credential Manager read failed: " + std::to_string(GetLastError());
    return std::nullopt;
  }
  std::string secret(reinterpret_cast<const char*>(credential->CredentialBlob),
                     credential->CredentialBlobSize);
  CredFree(credential);
  return secret;
#else
  error = "secure credential storage is not available in this build; use an API key environment variable";
  return std::nullopt;
#endif
}

bool CredentialStore::erase(const std::string& name, std::string& error) const {
#ifdef _WIN32
  if (!CredDeleteA(name.c_str(), CRED_TYPE_GENERIC, 0)) {
    error = "Windows Credential Manager delete failed: " + std::to_string(GetLastError());
    return false;
  }
  return true;
#else
  error = "secure credential storage is not available in this build; use an API key environment variable";
  return false;
#endif
}

bool CredentialStore::is_secure_store_available() const {
#ifdef _WIN32
  return true;
#else
  return false;
#endif
}

std::string default_key_name_for_provider(const std::string& provider) {
  const std::string lower = lowercase(provider);
  if (lower == "deepseek") return "binsight:deepseek";
  if (lower == "openai") return "binsight:openai";
  if (lower == "ollama") return "binsight:ollama";
  return "binsight:" + lower;
}

}  // namespace binsight
