#ifndef DATACRUMBS_COMMON_TELEMETRY_TYPES_H__
#define DATACRUMBS_COMMON_TELEMETRY_TYPES_H__

#include <cstdint>
#include <string>
#include <vector>

namespace datacrumbs {

// One sampled counter -> one series of a Chrome counter track. The sampler emits
// the per-interval delta * scale as `label`. A counter reads either a sysfs file
// (`path`) or, when `perf_event` is set, a system-wide perf event by libpfm4 name
// (uncore PMUs). scale != 1 handles unit conversion (IB *_data are 4-octet units).
struct TelemetryCounter {
  std::string label;
  std::string path;
  double scale = 1.0;
  std::string perf_event;
};

// One telemetry source -> one Chrome counter track (cat/name). event_id is a
// synthetic id registered in category_map by load_runtime_probe_file().
struct TelemetrySource {
  std::string cat;
  std::string name;
  uint64_t event_id = 0;
  std::vector<TelemetryCounter> counters;
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_COMMON_TELEMETRY_TYPES_H__
