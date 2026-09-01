#pragma once
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// Other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/enumerations.h>
// std headers
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

namespace datacrumbs {

// Writes events as a multi-member gzip .pfw: each drained batch is coalesced into ~1MB chunks and
// each chunk is a self-contained gzip member. Concatenated members are a valid gzip stream, so a
// killed server still leaves every completed member readable (truncation-tolerant). Events cross a
// bounded queue to a worker pool (DATACRUMBS_WRITER_THREADS, default 1); a producer outrunning the
// writer is behind is held back for DATACRUMBS_STALL_BUDGET_MS and then dropped, because blocking
// without limit stops collection and costs the tail of a run rather than precision across it.
// Members compress in parallel; only the file append is serial.
class ChromeWriter {
 public:
  ChromeWriter();
  ~ChromeWriter();

  // Enqueue an event; takes ownership of the event and its args and frees them after writing.
  // Blocks while the queue is at its backpressure bound.
  void push_event(EventWithId* event);

  // Drain the queue, emit the closing member, close the file, and join the worker. Idempotent.
  void finalize();

  /// Nanoseconds producers spent blocked at the backpressure bound, and how many times.
  ///
  /// Non-zero means the run stopped collecting for that long: the instrument, not the workload,
  /// decided what the trace contains.
  unsigned long long stall_ns() const { return stall_ns_.load(std::memory_order_relaxed); }
  unsigned long long stall_count() const { return stall_count_.load(std::memory_order_relaxed); }

  /// Events refused because the writer stayed behind for longer than the stall budget.
  ///
  /// Losing these keeps collection running, so the loss is spread across the run rather than
  /// removing its tail. Non-zero means the trace is sampled, not complete.
  unsigned long long dropped() const { return dropped_.load(std::memory_order_relaxed); }

 private:
  void worker_loop();
  std::string serialize_event(EventWithId* event);  // one event -> JSON line; frees the event
  void write_member(const std::string& data);       // gzip `data` as one member, append to file
  // dftracer process_name/thread_name records for a lane not yet named, or "" if already named.
  // Most lanes in a full-visibility trace are not the traced app (a system_wide tracepoint files
  // its event under the waking task), so without a name they all read as a bare "proc <pid>".
  std::string name_process(unsigned int pid, unsigned int tid);

  FILE* file_ = nullptr;
  std::mutex file_mutex_;  // serializes fwrite of members; compression stays outside it

  std::string hostname_;  // this node's hostname, resolved once at construction
  std::string hhash_;     // md5(hostname) as dftracer's 16-hex host key; first key of every args

  std::mutex named_mutex_;
  std::unordered_set<unsigned long long> named_;  // (pid << 32) | tid already labelled

  std::deque<EventWithId*> event_queue_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;     // worker wakes on nonempty / stop
  std::condition_variable not_full_cv_;  // producer wakes when the queue drains below the bound
  size_t max_queue_events_;              // backpressure bound (0 = unbounded)

  std::vector<std::thread> workers_;
  bool stop_flag_ = false;
  bool finalized_ = false;
  std::atomic<unsigned long> index_{0};  // unique complete-event id, shared across pool workers
  // How long producers spent blocked at the bound. Blocking rather than dropping keeps the trace
  // complete for what it holds, but it stops collection while it lasts, and a trace that stops
  // early looks exactly like a workload that went quiet. Reported so a run states its own coverage.
  std::atomic<unsigned long long> stall_ns_{0};
  std::atomic<unsigned long long> stall_count_{0};
  std::atomic<unsigned long long> dropped_{0};  // events refused after the stall budget expired
  std::chrono::milliseconds stall_budget_{200};
  size_t flush_bytes_;                   // coalesce serialized JSON to ~this many bytes per member
  int zlib_level_;
};

}  // namespace datacrumbs
