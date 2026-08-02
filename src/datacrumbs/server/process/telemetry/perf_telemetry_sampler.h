#ifndef DATACRUMBS_SERVER_PROCESS_PERF_TELEMETRY_SAMPLER_H__
#define DATACRUMBS_SERVER_PROCESS_PERF_TELEMETRY_SAMPLER_H__

#include <datacrumbs/datacrumbs_config.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)

#include <cstddef>
#include <vector>

namespace datacrumbs {

// Reads each counter's `perf_event` (uncore PMU) via libpfm4 + perf_event_open,
// opened system-wide on the cpus in the PMU's cpumask and summed.
class PerfTelemetrySampler : public TelemetrySampler {
 public:
  using TelemetrySampler::TelemetrySampler;
  ~PerfTelemetrySampler() override { stop(); }

 protected:
  void on_start() override;
  void on_stop() override;
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;

 private:
  std::vector<std::vector<std::vector<int>>> fds_;  // [src][ctr][cpu]
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_ENABLE_HW_COUNTERS
#endif  // DATACRUMBS_SERVER_PROCESS_PERF_TELEMETRY_SAMPLER_H__
