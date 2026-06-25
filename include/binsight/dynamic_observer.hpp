#pragma once

#include <binsight/process_runner.hpp>
#include <binsight/types.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace binsight {

struct DockerObserveOptions {
  std::filesystem::path binary_path;
  std::filesystem::path output_path = "dynamic.json";
  std::string image = "binsight-observer:latest";
  int timeout_seconds = 30;
  std::string network_mode = "none";
  bool risk_accepted = false;
};

class LinuxDockerObserver {
 public:
  explicit LinuxDockerObserver(ProcessRunner runner);

  DynamicObservations observe(const DockerObserveOptions& options,
                              std::vector<std::string>& warnings) const;

 private:
  ProcessRunner runner_;
};

std::string to_json(const DynamicObservations& observations);
std::optional<DynamicObservations> dynamic_observations_from_json(const std::string& json,
                                                                 std::string& error);
void write_dynamic_observations(const std::filesystem::path& path,
                                const DynamicObservations& observations);
std::optional<DynamicObservations> read_dynamic_observations(const std::filesystem::path& path,
                                                            std::string& error);

}  // namespace binsight
