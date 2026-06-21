#ifndef DATACRUMBS_COMMON_TELEMETRY_TYPES_H__
#define DATACRUMBS_COMMON_TELEMETRY_TYPES_H__

#include <cstdint>
#include <string>
#include <vector>

namespace datacrumbs {

// One sampled sysfs counter -> one series of a Chrome counter track. The sampler
// reads `path` each interval and emits the per-interval delta * scale as `label`.
// scale != 1 handles unit conversion (IB *_data counters are in 4-octet units).
struct TelemetryCounter {
  std::string label;
  std::string path;
  double scale = 1.0;
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
