#ifndef DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
#define DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__

#include <datacrumbs/common/telemetry_types.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace datacrumbs {

// Owns the sampling thread and interval wait. Emits one Chrome counter event per
// source per interval, as delta times scale since the last read. Subclasses supply
// only the per-counter read and any resource open or close. No-op when no sources
// or writer are configured.
class TelemetrySampler {
 public:
  TelemetrySampler(std::shared_ptr<ChromeWriter> writer, std::vector<TelemetrySource> sources,
                   unsigned int interval_ms, std::atomic<uint64_t>* event_index);
  virtual ~TelemetrySampler();

  void start();
  void stop();

 protected:
  // Acquires or releases per-mechanism resources, such as perf fds. Default is no-op.
  virtual void on_start() {}
  virtual void on_stop() {}
  // Reads the current raw value of counters_[src][ctr]. Returns false to skip it this tick.
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

// Reads each counter's sysfs path: NIC and other sysfs counters.
class SysfsTelemetrySampler : public TelemetrySampler {
 public:
  using TelemetrySampler::TelemetrySampler;
  ~SysfsTelemetrySampler() override { stop(); }

 protected:
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;
};

// Driver stats via the SIOCETHTOOL ioctl, read in-process instead of forked. This is the only
// source for the mlx5 vport_* counters: the sysfs IB port counters do not see traffic on the
// DevX/DOCA RDMA path. source.name is the netdev; each counter's path holds the ethtool stat
// name.
class EthtoolTelemetrySampler : public TelemetrySampler {
 public:
  using TelemetrySampler::TelemetrySampler;
  ~EthtoolTelemetrySampler() override { stop(); }

 protected:
  void on_start() override;
  void on_stop() override;
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;

 private:
  bool refresh(std::size_t src);

  int fd_ = -1;
  std::vector<std::vector<int>> index_;                  // [source][counter] -> ethtool stat index
  std::vector<std::vector<unsigned long long>> values_;  // [source] full stat array this tick
};

// Per-QP RDMA counters over RDMA_NLDEV_CMD_STAT_GET, scoped to bound QPs so other device traffic
// does not pollute them. Requires per-port auto mode via
// "rdma statistic qp set link <dev>/<port> auto type on", which binds by QP type since hardware
// has a limited number of counter sets. source.name is ibdev/port, path is the hw counter name.
class RdmaQpTelemetrySampler : public TelemetrySampler {
 public:
  using TelemetrySampler::TelemetrySampler;
  ~RdmaQpTelemetrySampler() override { stop(); }

 protected:
  void on_start() override;
  void on_stop() override;
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;

 private:
  bool refresh(std::size_t src);

  int fd_ = -1;
  unsigned int seq_ = 0;
  std::vector<int> dev_index_;
  std::vector<unsigned int> port_;
  // [source] hw counter name -> value summed over this port's bound counter sets
  std::vector<std::map<std::string, unsigned long long>> values_;
};

// Utilisation from procfs: node and per-process busy time, resident memory, and preemption
// counts, none of which a PMU reports. BlueField-3 has only the armv8_pmuv3_0 core PMU and no
// uncore, so this is the only source there; the x86 host's uncore adds DMA and package energy
// visibility. source.name is "node" or a pid; each counter's path names the procfs field.
class ProcTelemetrySampler : public TelemetrySampler {
 public:
  ProcTelemetrySampler(std::shared_ptr<ChromeWriter> writer, std::vector<TelemetrySource> sources,
                       unsigned int interval_ms, std::atomic<uint64_t>* event_index, int pid_map_fd)
      : TelemetrySampler(std::move(writer), std::move(sources), interval_ms, event_index),
        pid_map_fd_(pid_map_fd) {}
  ~ProcTelemetrySampler() override { stop(); }

 protected:
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;

 private:
  int pid_map_fd_;
};

// Hardware counters for the traced processes, on the sampler's own fixed interval. This is the
// only sound scope for a workload whose threads block: cpu-scope counters sweep up other tasks,
// and probe-based deltas span arbitrary wall time during off-CPU stretches.
class TaskPmuTelemetrySampler : public TelemetrySampler {
 public:
  TaskPmuTelemetrySampler(std::shared_ptr<ChromeWriter> writer,
                          std::vector<TelemetrySource> sources, unsigned int interval_ms,
                          std::atomic<uint64_t>* event_index, int pid_map_fd)
      : TelemetrySampler(std::move(writer), std::move(sources), interval_ms, event_index),
        pid_map_fd_(pid_map_fd) {}
  ~TaskPmuTelemetrySampler() override { stop(); }

 protected:
  void on_start() override;
  void on_stop() override;
  bool read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) override;

 private:
  void refresh_pids(std::size_t src);

  int pid_map_fd_ = -1;
  std::map<unsigned int, std::vector<int>> fds_;  // tgid -> one fd per counter
};

}  // namespace datacrumbs

#endif  // DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
