#ifndef DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__
#define DATACRUMBS_SERVER_PROCESS_TELEMETRY_SAMPLER_H__

#include <datacrumbs/common/telemetry_types.h>
#include <datacrumbs/server/process/writer/chrome_writer.h>

#include <atomic>
#include <condition_variable>
#include <map>
#include <string>
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

// Driver stats via the SIOCETHTOOL ioctl (ETHTOOL_GSTRINGS + ETHTOOL_GSTATS), i.e. what
// `ethtool -S` prints, read in-process rather than by forking. This is the only place the mlx5
// vport_* counters live: the sysfs IB port counters are blind to the DevX/DOCA RDMA path
// (rx_write_requests stays ~0 while the link moves GB).
//
// `source.name` is the netdev; each counter's `path` holds the ethtool stat NAME, resolved to an
// index once at start. ETHTOOL_GSTATS returns every stat in one call, so the array is fetched on
// counter 0 of each source and reused for the rest of that tick.
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
  std::vector<std::vector<int>> index_;              // [source][counter] -> ethtool stat index
  std::vector<std::vector<unsigned long long>> values_;  // [source] full stat array this tick
};

// Per-QP-scope RDMA counters over RDMA netlink (RDMA_NLDEV_CMD_STAT_GET), i.e. what
// `rdma statistic qp show` prints, read in-process. Unlike the port-wide sysfs counters these are
// scoped to the QPs bound to a counter, so other traffic on the device does not pollute them.
//
// Requires per-port auto mode ("rdma statistic qp set link <dev>/<port> auto type on"), which binds
// QPs to a counter by type - so the scope is per QP TYPE, not per individual QP; the hardware has a
// limited number of counter sets.
//
// `source.name` is "<ibdev>/<port>"; each counter's `path` is the hw counter name.
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

// Hardware counters for the TRACED PROCESSES, read on the sampler's own fixed interval.
//
// This is the only counter scope that is sound for a workload whose threads block. The cpu-scope
// counters (perf_event_open with pid=-1) sweep up every other task on the core, and counters read
// from probe/sample events inherit that event's timing - during an off-CPU stretch the samples go
// sparse and a "delta since last sample" silently spans an arbitrary wall interval. Both together
// produced a 25,000x page-fault "signal" that was other processes running while ours was blocked.
//
// Opened per-task (pid=tgid, cpu=-1, inherit=1) so a counter follows the thread across cpus and
// covers threads spawned later. Traced tgids come from the BPF pid_map, refreshed each tick.
class TaskPmuTelemetrySampler : public TelemetrySampler {
 public:
  TaskPmuTelemetrySampler(std::shared_ptr<ChromeWriter> writer, std::vector<TelemetrySource> sources,
                          unsigned int interval_ms, std::atomic<uint64_t>* event_index,
                          int pid_map_fd)
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
