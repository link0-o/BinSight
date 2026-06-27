#include <binsight/dynamic_observer.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <thread>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <ws2tcpip.h>
#endif

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

void append_warning_once(std::vector<std::string>& warnings, const std::string& warning) {
  if (std::find(warnings.begin(), warnings.end(), warning) == warnings.end()) {
    warnings.push_back(warning);
  }
}

bool event_budget_exceeded(const DynamicObservations& observations,
                           const WindowsEtwObserveOptions& options) {
  const auto count = observations.process_events.size() + observations.file_events.size() +
                     observations.network_events.size();
  return count >= options.max_events || to_json(observations).size() >= options.max_json_bytes;
}

void append_process_event(DynamicObservations& observations,
                          const WindowsEtwObserveOptions& options,
                          std::vector<std::string>& warnings,
                          DynamicProcessEvent event) {
  if (event_budget_exceeded(observations, options)) {
    append_warning_once(warnings, "windows_etw_event_limit_reached: event details were truncated");
    return;
  }
  event.image = first_chars(event.image, 500);
  event.command_line = first_chars(event.command_line, 1000);
  observations.process_events.push_back(std::move(event));
}

void append_file_event(DynamicObservations& observations,
                       const WindowsEtwObserveOptions& options,
                       std::vector<std::string>& warnings,
                       DynamicFileEvent event) {
  if (event_budget_exceeded(observations, options)) {
    append_warning_once(warnings, "windows_etw_event_limit_reached: event details were truncated");
    return;
  }
  event.path = first_chars(event.path, 700);
  observations.file_events.push_back(std::move(event));
}

void append_network_event(DynamicObservations& observations,
                          const WindowsEtwObserveOptions& options,
                          std::vector<std::string>& warnings,
                          DynamicNetworkEvent event) {
  if (event_budget_exceeded(observations, options)) {
    append_warning_once(warnings, "windows_etw_event_limit_reached: event details were truncated");
    return;
  }
  event.destination = first_chars(event.destination, 300);
  event.detail = first_chars(event.detail, 700);
  observations.network_events.push_back(std::move(event));
}

#if defined(_WIN32)
std::string narrow_from_wide(const std::wstring& value) {
  if (value.empty()) {
    return {};
  }
  const int bytes = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                                        nullptr, 0, nullptr, nullptr);
  if (bytes <= 0) {
    return {};
  }
  std::string out(static_cast<std::size_t>(bytes), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), out.data(), bytes,
                      nullptr, nullptr);
  return out;
}

std::wstring quote_windows_path(const std::filesystem::path& path) {
  std::wstring value = path.wstring();
  std::wstring out = L"\"";
  for (wchar_t c : value) {
    if (c == L'"') {
      out += L"\\\"";
    } else {
      out.push_back(c);
    }
  }
  out.push_back(L'"');
  return out;
}

std::map<std::filesystem::path, std::uint64_t> shallow_file_snapshot(
    const std::filesystem::path& directory) {
  std::map<std::filesystem::path, std::uint64_t> snapshot;
  std::error_code ec;
  if (!std::filesystem::exists(directory, ec)) {
    return snapshot;
  }
  for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
    if (ec || !entry.is_regular_file(ec)) {
      continue;
    }
    snapshot[entry.path()] = file_size_or_zero(entry.path());
  }
  return snapshot;
}

std::vector<DWORD> child_processes_of(const std::set<DWORD>& parent_pids) {
  std::vector<DWORD> children;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) {
    return children;
  }
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry)) {
    do {
      if (parent_pids.find(entry.th32ParentProcessID) != parent_pids.end()) {
        children.push_back(entry.th32ProcessID);
      }
    } while (Process32NextW(snapshot, &entry));
  }
  CloseHandle(snapshot);
  return children;
}

std::string process_image_path(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) {
    return {};
  }
  std::wstring buffer(32768, L'\0');
  DWORD size = static_cast<DWORD>(buffer.size());
  std::string out;
  if (QueryFullProcessImageNameW(process, 0, buffer.data(), &size) != 0) {
    buffer.resize(size);
    out = narrow_from_wide(buffer);
  }
  CloseHandle(process);
  return out;
}

std::string ipv4_address(DWORD value) {
  in_addr addr{};
  addr.S_un.S_addr = value;
  char buffer[INET_ADDRSTRLEN]{};
  if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
    return {};
  }
  return buffer;
}

void collect_tcp_connections(const std::set<DWORD>& pids,
                             DynamicObservations& observations,
                             const WindowsEtwObserveOptions& options,
                             std::vector<std::string>& warnings,
                             std::set<std::string>& seen) {
  ULONG bytes = 0;
  if (GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) !=
      ERROR_INSUFFICIENT_BUFFER) {
    return;
  }
  std::vector<unsigned char> buffer(bytes);
  auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
  if (GetExtendedTcpTable(table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
    return;
  }
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
    const auto& row = table->table[i];
    if (pids.find(row.dwOwningPid) == pids.end()) {
      continue;
    }
    const std::string destination =
        ipv4_address(row.dwRemoteAddr) + ":" + std::to_string(ntohs(static_cast<unsigned short>(row.dwRemotePort)));
    const std::string key = std::to_string(row.dwOwningPid) + ":tcp:" + destination + ":" +
                            std::to_string(row.dwState);
    if (!seen.insert(key).second) {
      continue;
    }
    DynamicNetworkEvent event;
    event.operation = "tcp";
    event.destination = destination;
    event.detail = "pid=" + std::to_string(row.dwOwningPid) + " state=" + std::to_string(row.dwState);
    append_network_event(observations, options, warnings, std::move(event));
  }
}
#endif

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

DynamicObservations WindowsEtwObserver::observe(const WindowsEtwObserveOptions& options,
                                                std::vector<std::string>& warnings) const {
  DynamicObservations observations;
  observations.present = true;
  observations.platform = "windows";
  observations.mode = "windows_etw";
  observations.timeout_seconds = options.timeout_seconds;
  observations.network_mode = options.network_mode;

  if (!options.risk_accepted) {
    warnings.push_back("windows_etw observation refused: missing --i-understand-risk");
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }
  if (!std::filesystem::exists(options.binary_path)) {
    warnings.push_back("windows_etw observation failed: binary does not exist");
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }
  if (options.network_mode != "observe" && options.network_mode != "off") {
    warnings.push_back("windows_etw observation failed: network mode must be observe or off");
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }

#if !defined(_WIN32)
  warnings.push_back("windows_etw observation is only supported by the Windows build");
  observations.warnings = warnings;
  write_dynamic_observations(options.output_path, observations);
  return observations;
#elif !defined(BINSIGHT_USE_ETW)
  warnings.push_back("windows_etw observation is not enabled in this build");
  observations.warnings = warnings;
  write_dynamic_observations(options.output_path, observations);
  return observations;
#else
  warnings.push_back(
      "windows_etw_risk_notice: target was executed on the local Windows host; BinSight is not a sandbox");
  warnings.push_back(
      "windows_etw_storage_policy: raw ETL logs are not saved; only bounded JSON summaries are written");

  const auto absolute_binary = std::filesystem::absolute(options.binary_path);
  const auto watched_dir = absolute_binary.parent_path();
  const auto before_files = shallow_file_snapshot(watched_dir);

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};
  std::wstring command_line = quote_windows_path(absolute_binary);
  const BOOL created = CreateProcessW(
      nullptr,
      command_line.data(),
      nullptr,
      nullptr,
      FALSE,
      CREATE_UNICODE_ENVIRONMENT,
      nullptr,
      watched_dir.empty() ? nullptr : watched_dir.wstring().c_str(),
      &startup,
      &process);
  if (!created) {
    warnings.push_back("windows_etw observation failed: CreateProcessW error " +
                       std::to_string(GetLastError()));
    observations.warnings = warnings;
    write_dynamic_observations(options.output_path, observations);
    return observations;
  }

  std::set<DWORD> observed_pids;
  std::set<std::string> seen_network;
  observed_pids.insert(process.dwProcessId);
  append_process_event(observations, options, warnings,
                       {"process_start",
                        static_cast<int>(process.dwProcessId),
                        0,
                        narrow_from_wide(absolute_binary.wstring()),
                        narrow_from_wide(command_line)});

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(std::max(1, options.timeout_seconds));
  while (true) {
    const DWORD wait_result = WaitForSingleObject(process.hProcess, 500);
    for (DWORD child_pid : child_processes_of(observed_pids)) {
      if (observed_pids.insert(child_pid).second) {
        append_process_event(observations, options, warnings,
                             {"process_start", static_cast<int>(child_pid),
                              static_cast<int>(process.dwProcessId), process_image_path(child_pid), {}});
      }
    }
    if (options.network_mode == "observe") {
      collect_tcp_connections(observed_pids, observations, options, warnings, seen_network);
    }
    if (wait_result == WAIT_OBJECT_0) {
      break;
    }
    if (std::chrono::steady_clock::now() >= deadline) {
      observations.timed_out = true;
      warnings.push_back("windows_etw observation timed out; target process was terminated");
      TerminateProcess(process.hProcess, 124);
      WaitForSingleObject(process.hProcess, 5000);
      break;
    }
  }

  DWORD exit_code = 0;
  if (GetExitCodeProcess(process.hProcess, &exit_code)) {
    observations.exit_code = static_cast<int>(exit_code);
  }
  append_process_event(observations, options, warnings,
                       {"process_exit", static_cast<int>(process.dwProcessId), 0,
                        narrow_from_wide(absolute_binary.wstring()),
                        "exit_code=" + std::to_string(observations.exit_code)});

  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);

  const auto after_files = shallow_file_snapshot(watched_dir);
  for (const auto& [path, size] : after_files) {
    const auto before = before_files.find(path);
    if (before == before_files.end()) {
      append_file_event(observations, options, warnings,
                        {narrow_from_wide(path.wstring()), "created_or_nearby_artifact", size,
                         fnv1a64_file(path)});
    } else if (before->second != size) {
      append_file_event(observations, options, warnings,
                        {narrow_from_wide(path.wstring()), "modified_nearby_file", size,
                         fnv1a64_file(path)});
    }
  }
  for (const auto& [path, size] : before_files) {
    if (after_files.find(path) == after_files.end()) {
      append_file_event(observations, options, warnings,
                        {narrow_from_wide(path.wstring()), "deleted_nearby_file", size, {}});
    }
  }

  observations.syscall_summary.push_back(
      "process_events:" + std::to_string(observations.process_events.size()));
  observations.syscall_summary.push_back(
      "file_events:" + std::to_string(observations.file_events.size()));
  observations.syscall_summary.push_back(
      "network_events:" + std::to_string(observations.network_events.size()));
  if (to_json(observations).size() >= options.max_json_bytes) {
    append_warning_once(warnings, "windows_etw_json_limit_reached: JSON summary was truncated");
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
