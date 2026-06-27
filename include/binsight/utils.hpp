#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace binsight {

std::string read_file(const std::filesystem::path& path);
void write_file(const std::filesystem::path& path, const std::string& content);
void write_file_utf8_bom(const std::filesystem::path& path, const std::string& content);
std::string lowercase(std::string value);
std::string trim(const std::string& value);
std::vector<std::string> split_lines(const std::string& value);
std::string fnv1a64_file(const std::filesystem::path& path);
std::string shell_quote(const std::string& value);
std::string json_escape_for_shell_file(const std::string& value);
std::string json_escape(const std::string& value);

}  // namespace binsight
