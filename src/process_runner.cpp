#include <binsight/process_runner.hpp>
#include <binsight/utils.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <sstream>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#else
#include <sys/wait.h>
#endif

namespace binsight {

ToolResult ProcessRunner::run(const std::vector<std::string>& args, int timeout_seconds) const {
  ToolResult result;
  if (args.empty()) {
    result.error = "no command provided";
    return result;
  }

  std::ostringstream command;
#ifndef _WIN32
  if (timeout_seconds > 0) {
    command << "timeout " << timeout_seconds << "s ";
  }
#else
  (void)timeout_seconds;
#endif
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
#ifdef _WIN32
  result.exit_code = status;
#else
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else {
    result.exit_code = status;
  }
#endif
  return result;
}

}  // namespace binsight
