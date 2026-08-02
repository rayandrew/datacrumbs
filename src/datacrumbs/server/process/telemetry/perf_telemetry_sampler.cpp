#include <datacrumbs/server/process/telemetry/perf_telemetry_sampler.h>

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)

#include <datacrumbs/common/logging.h>
#include <linux/perf_event.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace datacrumbs {

namespace {

std::vector<int> parse_cpu_list(const std::string& spec) {
  std::vector<int> cpus;
  size_t i = 0;
  while (i < spec.size()) {
    const size_t comma = spec.find(',', i);
    const std::string part =
        spec.substr(i, comma == std::string::npos ? std::string::npos : comma - i);
    const size_t dash = part.find('-');
    try {
      if (dash == std::string::npos) {
        if (!part.empty()) cpus.push_back(std::stoi(part));
      } else {
        const int lo = std::stoi(part.substr(0, dash));
        const int hi = std::stoi(part.substr(dash + 1));
        for (int c = lo; c <= hi; ++c) cpus.push_back(c);
      }
    } catch (...) {
    }
    if (comma == std::string::npos) break;
    i = comma + 1;
  }
  return cpus;
}

// The cpus to open a perf event of type `pmu_type` on: the cpumask of the
// matching PMU under /sys/bus/event_source/devices (uncore PMUs publish one cpu
// per socket). Falls back to cpu 0 if no PMU advertises the type.
std::vector<int> cpus_for_pmu_type(uint32_t pmu_type) {
  std::error_code ec;
  for (const auto& entry :
       std::filesystem::directory_iterator("/sys/bus/event_source/devices", ec)) {
    std::ifstream tf(entry.path() / "type");
    uint32_t t = 0;
    if (tf && (tf >> t) && t == pmu_type) {
      std::ifstream cf(entry.path() / "cpumask");
      std::string spec;
      if (cf && std::getline(cf, spec)) {
        auto cpus = parse_cpu_list(spec);
        if (!cpus.empty()) return cpus;
      }
      break;
    }
  }
  return {0};
}

}  // namespace

void PerfTelemetrySampler::on_start() {
  fds_.assign(sources_.size(), {});
  if (pfm_initialize() != PFM_SUCCESS) {
    DC_LOG_ERROR("PerfTelemetry: pfm_initialize() failed");
    return;
  }
  for (size_t s = 0; s < sources_.size(); ++s) {
    fds_[s].assign(sources_[s].counters.size(), {});
    for (size_t c = 0; c < sources_[s].counters.size(); ++c) {
      const std::string& name = sources_[s].counters[c].perf_event;
      if (name.empty()) continue;
      struct perf_event_attr attr;
      memset(&attr, 0, sizeof(attr));
      attr.size = sizeof(attr);
      pfm_perf_encode_arg_t arg;
      memset(&arg, 0, sizeof(arg));
      arg.attr = &attr;
      arg.size = sizeof(arg);
      if (pfm_get_os_event_encoding(name.c_str(), PFM_PLM0 | PFM_PLM3, PFM_OS_PERF_EVENT, &arg) !=
          PFM_SUCCESS) {
        DC_LOG_WARN("PerfTelemetry: event '%s' not recognized by libpfm4; skipping", name.c_str());
        continue;
      }
      attr.disabled = 0;
      attr.inherit = 0;
      for (int cpu : cpus_for_pmu_type(attr.type)) {
        int fd =
            syscall(__NR_perf_event_open, &attr, /*pid=*/-1, cpu, /*group_fd=*/-1, /*flags=*/0);
        if (fd >= 0) fds_[s][c].push_back(fd);
      }
      if (fds_[s][c].empty()) {
        DC_LOG_WARN("PerfTelemetry: '%s' could not be opened (check PMU/permissions)",
                    name.c_str());
      } else {
        DC_LOG_INFO("PerfTelemetry: '%s' opened on %zu cpu(s)", name.c_str(), fds_[s][c].size());
      }
    }
  }
}

void PerfTelemetrySampler::on_stop() {
  for (auto& per_source : fds_)
    for (auto& per_counter : per_source)
      for (int fd : per_counter) close(fd);
  fds_.clear();
}

bool PerfTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  if (src >= fds_.size() || ctr >= fds_[src].size() || fds_[src][ctr].empty()) return false;
  unsigned long long sum = 0;
  bool ok = false;
  for (int fd : fds_[src][ctr]) {
    unsigned long long val = 0;
    if (::read(fd, &val, sizeof(val)) == static_cast<ssize_t>(sizeof(val))) {
      sum += val;
      ok = true;
    }
  }
  if (!ok) return false;
  *out = sum;
  return true;
}

}  // namespace datacrumbs

#endif  // DATACRUMBS_ENABLE_HW_COUNTERS
