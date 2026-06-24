#include <binsight/process_runner.hpp>
#include <binsight/utils.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <sys/wait.h>

namespace binsight {

ToolResult ProcessRunner::run(const std::vector<std::string>& args, int timeout_seconds) const {
  ToolResult result;
  if (args.empty()) {
    result.error = "no command provided";
    return result;
  }

  std::ostringstream command;
  if (timeout_seconds > 0) {
    command << "timeout " << timeout_seconds << "s ";
  }
  for (std::size_t i = 0; i < args.size(); ++i) {
    if (i != 0) {
      command << ' ';
    }
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
  if (WIFEXITED(status)) {
    result.exit_code = WEXITSTATUS(status);
  } else {
    result.exit_code = status;
  }
  return result;
}

}  // namespace binsight

