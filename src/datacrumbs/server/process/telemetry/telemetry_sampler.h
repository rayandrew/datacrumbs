#ifndef DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
#define DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__

#include <datacrumbs/common/telemetry_types.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace datacrumbs {

// Base interval counter sampler: owns the thread, the interval wait, per-counter
// previous-value tracking, and emitting one Chrome counter ("C") event per
// source per interval (per-interval delta * scale). Subclasses supply only the
// per-counter read (and any resource open/close), so the read mechanism (sysfs,
// perf) lives in one place each. No-op when no sources or writer are configured.
class TelemetrySampler {
 public:
  TelemetrySampler(std::shared_ptr<ChromeWriter> writer, std::vector<TelemetrySource> sources,
                   unsigned int interval_ms, std::atomic<uint64_t>* event_index);
  virtual ~TelemetrySampler();

  void start();
  void stop();

 protected:
  // Acquire/release any per-mechanism resources (e.g. perf fds). Defaults no-op.
  virtual void on_start() {}
  virtual void on_stop() {}
  // Read the current raw value of counters_[src][ctr]; false skips it this tick.
  virtual bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) = 0;

  std::vector<TelemetrySource> sources_;

 private:
  void loop();

  std::shared_ptr<ChromeWriter> writer_;
  unsigned int interval_ms_;
  std::atomic<uint64_t>* event_index_;
  std::vector<std::vector<unsigned long long>> prev_;  // [source][counter] last raw read

  std::atomic<bool> running_{false};
  std::thread thread_;
  std::mutex mutex_;
  std::condition_variable cv_;
};

// Reads each counter's sysfs `path` (NIC and other sysfs counters).
class SysfsTelemetrySampler : public TelemetrySampler {
 public:
  using TelemetrySampler::TelemetrySampler;
  ~SysfsTelemetrySampler() override { stop(); }

 protected:
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
