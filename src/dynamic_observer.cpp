#include <binsight/dynamic_observer.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <regex>
#include <sstream>

namespace binsight {

namespace {

void json_string(std::ostringstream& out, const std::string& value) {
  out << '"' << json_escape(value) << '"';
}

std::string first_chars(const std::string& value, std::size_t count) {
  if (value.size() <= count) {
    return value;
  }
  return value.substr(0, count) + "...";
}

std::uint64_t file_size_or_zero(const std::filesystem::path& path) {
  std::error_code ec;
  const auto size = std::filesystem::file_size(path, ec);
  return ec ? 0 : static_cast<std::uint64_t>(size);
}

std::uint64_t directory_size(const std::filesystem::path& path) {
  std::uint64_t total = 0;
  std::error_code ec;
  if (!std::filesystem::exists(path, ec)) {
    return total;
  }
  for (const auto& entry : std::filesystem::recursive_directory_iterator(path, ec)) {
    if (ec) {
      break;
    }
    if (entry.is_regular_file(ec)) {
      total += file_size_or_zero(entry.path());
    }
  }
  return total;
}

std::string json_unescape(std::string value) {
  std::string out;
  out.reserve(value.size());
  bool escaped = false;
  for (char c : value) {
    if (escaped) {
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
        case '\\':
          out.push_back('\\');
          break;
        case '"':
          out.push_back('"');
          break;
        default:
          out.push_back(c);
          break;
      }
      escaped = false;
    } else if (c == '\\') {
      escaped = true;
    } else {
      out.push_back(c);
    }
  }
  return out;
}

std::string json_string_field(const std::string& json, const std::string& key) {
  std::smatch match;
  const std::regex re("\"" + key + R"JSON("\s*:\s*"((?:\\.|[^"\\])*)")JSON");
  if (std::regex_search(json, match, re)) {
    return json_unescape(match[1].str());
  }
  return {};
}

int json_int_field(const std::string& json, const std::string& key, int fallback = 0) {
  std::smatch match;
  const std::regex re("\"" + key + R"("\s*:\s*(-?\d+))");
  if (std::regex_search(json, match, re)) {
    try {
      return std::stoi(match[1].str());
    } catch (...) {
      return fallback;
    }
  }
  return fallback;
}

bool json_bool_field(const std::string& json, const std::string& key) {
  std::smatch match;
  const std::regex re("\"" + key + R"("\s*:\s*(true|false))");
  return std::regex_search(json, match, re) && match[1].str() == "true";
}

std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
  std::vector<std::string> values;
  std::smatch match;
  const std::regex array_re("\"" + key + R"("\s*:\s*\[(.*?)\])", std::regex::ECMAScript);
  if (!std::regex_search(json, match, array_re)) {
    return values;
  }
  const std::string body = match[1].str();
  const std::regex string_re(R"JSON("((?:\\.|[^"\\])*)")JSON");
  for (auto it = std::sregex_iterator(body.begin(), body.end(), string_re);
       it != std::sregex_iterator(); ++it) {
    values.push_back(json_unescape((*it)[1].str()));
  }
  return values;
}

std::string json_array_body(const std::string& json, const std::string& key) {
  const std::string marker = "\"" + key + "\"";
  const auto key_pos = json.find(marker);
  if (key_pos == std::string::npos) {
    return {};
  }
  const auto array_begin = json.find('[', key_pos + marker.size());
  if (array_begin == std::string::npos) {
    return {};
  }
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (std::size_t i = array_begin; i < json.size(); ++i) {
    const char c = json[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c == '\\' && in_string) {
      escaped = true;
      continue;
    }
    if (c == '"') {
      in_string = !in_string;
      continue;
    }
    if (in_string) {
      continue;
    }
    if (c == '[') {
      ++depth;
    } else if (c == ']') {
      --depth;
      if (depth == 0) {
        return json.substr(array_begin + 1, i - array_begin - 1);
      }
    }
  }
  return {};
}

std::vector<std::string> json_objects_in_array(const std::string& json, const std::string& key) {
  std::vector<std::string> objects;
  const auto body = json_array_body(json, key);
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  std::size_t begin = std::string::npos;
  for (std::size_t i = 0; i < body.size(); ++i) {
    const char c = body[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c == '\\' && in_string) {
      escaped = true;
      continue;
    }
    if (c == '"') {
      in_string = !in_string;
      continue;
    }
    if (in_string) {
      continue;
    }
    if (c == '{') {
      if (depth == 0) {
        begin = i;
      }
      ++depth;
    } else if (c == '}') {
      --depth;
      if (depth == 0 && begin != std::string::npos) {
        objects.push_back(body.substr(begin, i - begin + 1));
        begin = std::string::npos;
      }
    }
  }
  return objects;
}

std::vector<std::string> trace_lines_with(const std::vector<std::string>& lines,
                                          const std::string& needle,
                                          std::size_t limit) {
  std::vector<std::string> out;
  for (const auto& line : lines) {
    if (line.find(needle) != std::string::npos) {
      out.push_back(first_chars(trim(line), 300));
      if (out.size() >= limit) {
        break;
      }
    }
  }
  return out;
}

std::map<std::string, int> syscall_counts(const std::vector<std::string>& lines) {
  std::map<std::string, int> counts;
  const std::regex re(R"((?:^\d+\s+)?\d\d:\d\d:\d\d(?:\.\d+)?\s+([A-Za-z_][A-Za-z0-9_]+)\()");
  for (const auto& line : lines) {
    std::smatch match;
    if (std::regex_search(line, match, re)) {
      ++counts[match[1].str()];
    }
  }
  return counts;
}

std::vector<DynamicProcessEvent> process_events_from_trace(const std::vector<std::string>& lines) {
  std::vector<DynamicProcessEvent> events;
  const std::regex exec_re(R"JSON(execve\("([^"]+)",\s*\[([^\]]*)\])JSON");
  for (const auto& line : lines) {
    std::smatch match;
    if (std::regex_search(line, match, exec_re)) {
      DynamicProcessEvent event;
      event.event_type = "execve";
      event.image = match[1].str();
      event.command_line = first_chars(match[2].str(), 500);
      events.push_back(std::move(event));
      if (events.size() >= 32) {
        break;
      }
    }
  }
  return events;
}

std::vector<DynamicNetworkEvent> network_events_from_trace(const std::vector<std::string>& lines) {
  std::vector<DynamicNetworkEvent> events;
  for (const auto& line : trace_lines_with(lines, "connect(", 32)) {
    DynamicNetworkEvent event;
    event.operation = "connect";
    event.detail = line;
    events.push_back(std::move(event));
  }
  return events;
}

std::vector<DynamicFileEvent> artifact_events(const std::filesystem::path& work_dir) {
  std::vector<DynamicFileEvent> events;
  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(work_dir, ec)) {
    if (ec || !entry.is_regular_file(ec)) {
      continue;
    }
    const auto name = entry.path().filename().string();
    if (name == "trace.log" || name == "stdout.txt" || name == "stderr.txt" ||
        name == "exit_code.txt") {
      continue;
    }
    DynamicFileEvent event;
    event.path = name;
    event.operation = "artifact";
    event.size = file_size_or_zero(entry.path());
    event.hash = fnv1a64_file(entry.path());
    events.push_back(std::move(event));
  }
  std::sort(events.begin(), events.end(), [](const auto& left, const auto& right) {
    return left.path < right.path;
  });
  return events;
}

}  // namespace

LinuxDockerObserver::LinuxDockerObserver(ProcessRunner runner) : runner_(std::move(runner)) {}

DynamicObservations LinuxDockerObserver::observe(const DockerObserveOptions& options,
                                                 std::vector<std::string>& warnings) const {
  DynamicObservations observations;
  observations.present = true;
  observations.platform = "linux";
  observations.mode = "linux-docker";
  observations.timeout_seconds = options.timeout_seconds;
  observations.network_mode = options.network_mode;

#ifdef _WIN32
  warnings.push_back("linux-docker observation is not supported by the Windows build");
  observations.warnings = warnings;
  write_dynamic_observations(options.output_path, observations);
  return observations;
#else
  if (!options.risk_accepted) {
    warnings.push_back("dynamic observation refused: missing --i-understand-risk");
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }
  if (!std::filesystem::exists(options.binary_path)) {
    warnings.push_back("dynamic observation failed: binary does not exist");
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }

  const ToolResult docker_version = runner_.run({"docker", "--version"}, 10);
  if (docker_version.exit_code != 0) {
    warnings.push_back("dynamic observation unavailable: docker command failed: " +
                       first_chars(docker_version.output, 300));
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }

  const auto absolute_binary = std::filesystem::absolute(options.binary_path);
  const auto work_dir = std::filesystem::temp_directory_path() /
                        ("binsight-observe-" + std::to_string(std::rand()));
  std::filesystem::create_directories(work_dir);

  const std::string sample_name = absolute_binary.filename().string();
  const std::string script =
      "timeout " + std::to_string(options.timeout_seconds) + "s strace -f -qq -tt "
      "-o /work/trace.log /sample/" + shell_quote(sample_name) +
      " > /work/stdout.txt 2> /work/stderr.txt; code=$?; echo $code > /work/exit_code.txt; exit 0";

  std::vector<std::string> args = {
      "docker", "run", "--rm",
      "--network", options.network_mode,
      "--cpus", "1",
      "--memory", "512m",
      "--pids-limit", "128",
      "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges",
      "--read-only",
      "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
      "--workdir", "/work",
      "-v", absolute_binary.string() + ":/sample/" + sample_name + ":ro",
      "-v", work_dir.string() + ":/work:rw",
      options.image,
      "sh", "-c", script};

  const ToolResult docker_run = runner_.run(args, options.timeout_seconds + 30);
  if (docker_run.exit_code != 0) {
    warnings.push_back("docker observation command failed: " + first_chars(docker_run.output, 800));
  }

  const auto stdout_path = work_dir / "stdout.txt";
  const auto stderr_path = work_dir / "stderr.txt";
  const auto trace_path = work_dir / "trace.log";
  const auto exit_code_path = work_dir / "exit_code.txt";
  if (std::filesystem::exists(stdout_path)) {
    observations.stdout_text = first_chars(read_file(stdout_path), 4000);
  }
  if (std::filesystem::exists(stderr_path)) {
    observations.stderr_text = first_chars(read_file(stderr_path), 4000);
  }
  if (std::filesystem::exists(exit_code_path)) {
    try {
      observations.exit_code = std::stoi(trim(read_file(exit_code_path)));
    } catch (...) {
      observations.exit_code = -1;
    }
  }
  observations.timed_out = observations.exit_code == 124;
  if (observations.timed_out) {
    warnings.push_back("dynamic observation timed out");
  }

  std::vector<std::string> trace_lines;
  if (std::filesystem::exists(trace_path)) {
    trace_lines = split_lines(read_file(trace_path));
    observations.process_events = process_events_from_trace(trace_lines);
    observations.network_events = network_events_from_trace(trace_lines);
    for (const auto& [name, count] : syscall_counts(trace_lines)) {
      observations.syscall_summary.push_back(name + ":" + std::to_string(count));
      if (observations.syscall_summary.size() >= 64) {
        break;
      }
    }
  } else {
    warnings.push_back("dynamic observation did not produce trace.log; ensure the observer image includes strace");
  }

  observations.file_events = artifact_events(work_dir);
  const auto bytes = directory_size(work_dir);
  if (bytes > 500ull * 1024ull * 1024ull) {
    warnings.push_back("dynamic observation artifacts exceed 500MB soft limit");
  }
  std::error_code remove_error;
  std::filesystem::remove_all(work_dir, remove_error);
  if (remove_error) {
    warnings.push_back("failed to remove temporary dynamic observation directory: " +
                       remove_error.message());
  }
  observations.warnings = warnings;
  write_dynamic_observations(options.output_path, observations);
  return observations;
#endif
}

std::string to_json(const DynamicObservations& observations) {
  std::ostringstream out;
  out << "{";
  out << "\"present\":" << (observations.present ? "true" : "false") << ',';
  out << "\"platform\":"; json_string(out, observations.platform); out << ',';
  out << "\"mode\":"; json_string(out, observations.mode); out << ',';
  out << "\"timeout_seconds\":" << observations.timeout_seconds << ',';
  out << "\"timed_out\":" << (observations.timed_out ? "true" : "false") << ',';
  out << "\"exit_code\":" << observations.exit_code << ',';
  out << "\"network_mode\":"; json_string(out, observations.network_mode); out << ',';
  out << "\"stdout\":"; json_string(out, observations.stdout_text); out << ',';
  out << "\"stderr\":"; json_string(out, observations.stderr_text); out << ',';

  out << "\"process_events\":[";
  for (std::size_t i = 0; i < observations.process_events.size(); ++i) {
    if (i != 0) out << ',';
    const auto& event = observations.process_events[i];
    out << "{\"event_type\":"; json_string(out, event.event_type);
    out << ",\"pid\":" << event.pid;
    out << ",\"parent_pid\":" << event.parent_pid;
    out << ",\"image\":"; json_string(out, event.image);
    out << ",\"command_line\":"; json_string(out, event.command_line);
    out << '}';
  }
  out << "],";

  out << "\"file_events\":[";
  for (std::size_t i = 0; i < observations.file_events.size(); ++i) {
    if (i != 0) out << ',';
    const auto& event = observations.file_events[i];
    out << "{\"path\":"; json_string(out, event.path);
    out << ",\"operation\":"; json_string(out, event.operation);
    out << ",\"size\":" << event.size;
    out << ",\"hash\":"; json_string(out, event.hash);
    out << '}';
  }
  out << "],";

  out << "\"network_events\":[";
  for (std::size_t i = 0; i < observations.network_events.size(); ++i) {
    if (i != 0) out << ',';
    const auto& event = observations.network_events[i];
    out << "{\"operation\":"; json_string(out, event.operation);
    out << ",\"destination\":"; json_string(out, event.destination);
    out << ",\"detail\":"; json_string(out, event.detail);
    out << '}';
  }
  out << "],";

  out << "\"syscall_summary\":[";
  for (std::size_t i = 0; i < observations.syscall_summary.size(); ++i) {
    if (i != 0) out << ',';
    json_string(out, observations.syscall_summary[i]);
  }
  out << "],";

  out << "\"warnings\":[";
  for (std::size_t i = 0; i < observations.warnings.size(); ++i) {
    if (i != 0) out << ',';
    json_string(out, observations.warnings[i]);
  }
  out << "]}";
  return out.str();
}

std::optional<DynamicObservations> dynamic_observations_from_json(const std::string& json,
                                                                 std::string& error) {
  if (json.find("\"mode\"") == std::string::npos) {
    error = "dynamic report does not contain a mode field";
    return std::nullopt;
  }
  DynamicObservations observations;
  observations.present = json_bool_field(json, "present");
  observations.platform = json_string_field(json, "platform");
  observations.mode = json_string_field(json, "mode");
  observations.timeout_seconds = json_int_field(json, "timeout_seconds");
  observations.timed_out = json_bool_field(json, "timed_out");
  observations.exit_code = json_int_field(json, "exit_code", -1);
  observations.network_mode = json_string_field(json, "network_mode");
  observations.stdout_text = json_string_field(json, "stdout");
  observations.stderr_text = json_string_field(json, "stderr");
  for (const auto& object : json_objects_in_array(json, "process_events")) {
    DynamicProcessEvent event;
    event.event_type = json_string_field(object, "event_type");
    event.pid = json_int_field(object, "pid");
    event.parent_pid = json_int_field(object, "parent_pid");
    event.image = json_string_field(object, "image");
    event.command_line = json_string_field(object, "command_line");
    observations.process_events.push_back(std::move(event));
  }
  for (const auto& object : json_objects_in_array(json, "file_events")) {
    DynamicFileEvent event;
    event.path = json_string_field(object, "path");
    event.operation = json_string_field(object, "operation");
    event.size = static_cast<std::uint64_t>(json_int_field(object, "size"));
    event.hash = json_string_field(object, "hash");
    observations.file_events.push_back(std::move(event));
  }
  for (const auto& object : json_objects_in_array(json, "network_events")) {
    DynamicNetworkEvent event;
    event.operation = json_string_field(object, "operation");
    event.destination = json_string_field(object, "destination");
    event.detail = json_string_field(object, "detail");
    observations.network_events.push_back(std::move(event));
  }
  observations.syscall_summary = json_string_array_field(json, "syscall_summary");
  observations.warnings = json_string_array_field(json, "warnings");
  return observations;
}

void write_dynamic_observations(const std::filesystem::path& path,
                                const DynamicObservations& observations) {
  write_file(path, to_json(observations) + "\n");
}

std::optional<DynamicObservations> read_dynamic_observations(const std::filesystem::path& path,
                                                            std::string& error) {
  try {
    return dynamic_observations_from_json(read_file(path), error);
  } catch (const std::exception& ex) {
    error = ex.what();
    return std::nullopt;
  }
}

}  // namespace binsight
