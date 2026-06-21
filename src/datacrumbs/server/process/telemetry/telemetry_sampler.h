#ifndef DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
#define DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__

#include <datacrumbs/common/telemetry_types.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace datacrumbs {

// Samples each TelemetrySource's sysfs counters on a thread and emits one Chrome
// counter ("C") event per source per interval (per-interval deltas), overlaying
// the function timeline for correlation. No-op when no sources are configured.
class TelemetrySampler {
 public:
  TelemetrySampler(std::shared_ptr<ChromeWriter> writer, std::vector<TelemetrySource> sources,
                   unsigned int interval_ms, std::atomic<uint64_t>* event_index);
  ~TelemetrySampler();

  void start();
  void stop();

 private:
  void loop();

  std::shared_ptr<ChromeWriter> writer_;
  std::vector<TelemetrySource> sources_;
  unsigned int interval_ms_;
  std::atomic<uint64_t>* event_index_;
  std::vector<std::vector<unsigned long long>> prev_;  // [source][counter] last raw read

  std::atomic<bool> running_{false};
  std::thread thread_;
  std::mutex mutex_;
  std::condition_variable cv_;
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
