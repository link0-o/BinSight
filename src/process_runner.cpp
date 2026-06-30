#include <binsight/process_runner.hpp>
#include <binsight/utils.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/wait.h>
#endif

namespace binsight {

namespace {

std::string make_command_line(const std::vector<std::string>& args) {
  std::ostringstream command;
  for (std::size_t i = 0; i < args.size(); ++i) {
    if (i != 0) {
      command << ' ';
    }
#ifdef _WIN32
    if (i == 0 && args[i].find_first_of(" \t\"&|<>()^") == std::string::npos) {
      command << args[i];
      continue;
    }
#endif
    command << shell_quote(args[i]);
  }
  return command.str();
}

std::string read_file_best_effort(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return {};
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

#ifdef _WIN32
ToolResult run_windows_process(const std::vector<std::string>& args, int timeout_seconds) {
  ToolResult result;
  const auto output_path = std::filesystem::temp_directory_path() /
                           ("binsight-process-" + std::to_string(GetCurrentProcessId()) + "-" +
                            std::to_string(GetTickCount64()) + ".txt");
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  HANDLE output = CreateFileA(output_path.string().c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
  if (output == INVALID_HANDLE_VALUE) {
    result.error = "failed to create process output file";
    return result;
  }

  STARTUPINFOA startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = output;
  startup.hStdError = output;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION process{};
  std::string command = make_command_line(args);
  std::vector<char> mutable_command(command.begin(), command.end());
  mutable_command.push_back('\0');

  const BOOL created = CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
  CloseHandle(output);
  if (!created) {
    result.exit_code = static_cast<int>(GetLastError());
    result.error = "failed to start command: " + args.front();
    result.output = read_file_best_effort(output_path);
    std::error_code ec;
    std::filesystem::remove(output_path, ec);
    return result;
  }

  const DWORD wait_ms = timeout_seconds > 0
                            ? static_cast<DWORD>(std::max(1, timeout_seconds) * 1000)
                            : INFINITE;
  const DWORD wait_result = WaitForSingleObject(process.hProcess, wait_ms);
  if (wait_result == WAIT_TIMEOUT) {
    TerminateProcess(process.hProcess, 124);
    WaitForSingleObject(process.hProcess, 5000);
    result.exit_code = 124;
    result.error = "command timed out after " + std::to_string(timeout_seconds) + " seconds";
  } else {
    DWORD exit_code = 1;
    if (GetExitCodeProcess(process.hProcess, &exit_code)) {
      result.exit_code = static_cast<int>(exit_code);
    } else {
      result.exit_code = 1;
    }
  }

  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  result.output = read_file_best_effort(output_path);
  if (!result.error.empty()) {
    if (!result.output.empty()) {
      result.output += "\n";
    }
    result.output += result.error;
  }
  std::error_code ec;
  std::filesystem::remove(output_path, ec);
  return result;
}
#endif

}  // namespace

ToolResult ProcessRunner::run(const std::vector<std::string>& args, int timeout_seconds) const {
  ToolResult result;
  if (args.empty()) {
    result.error = "no command provided";
    return result;
  }

#ifdef _WIN32
  return run_windows_process(args, timeout_seconds);
#else
  std::ostringstream command;
  if (timeout_seconds > 0) {
    command << "timeout " << timeout_seconds << "s ";
  }
  command << make_command_line(args);
  command << " 2>&1";

  std::array<char, 4096> buffer{};
  FILE* pipe = popen(command.str().c_str(), "r");
  if (!pipe) {
    result.error = "failed to start command: " + args.front();
    return result;
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    result.output += buffer.data();
  }

  const int status = pclose(pipe);
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else {
    result.exit_code = status;
  }
  return result;
#endif
}

}  // namespace binsight
