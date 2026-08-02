#pragma once
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// Other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/enumerations.h>
// std headers
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace datacrumbs {

// Writes events as a multi-member gzip .pfw: each drained batch is coalesced into ~1MB chunks and
// each chunk is a self-contained gzip member. Concatenated members are a valid gzip stream, so a
// killed server still leaves every completed member readable (truncation-tolerant). Events cross a
// bounded queue to a worker pool (DATACRUMBS_WRITER_THREADS, default 1); a producer outrunning the
// writer is blocked, never dropped. Members compress in parallel; only the file append is serial.
class ChromeWriter {
 public:
  ChromeWriter();
  ~ChromeWriter();

  // Enqueue an event; takes ownership of the event and its args and frees them after writing.
  // Blocks while the queue is at its backpressure bound.
  void push_event(EventWithId* event);

  // Drain the queue, emit the closing member, close the file, and join the worker. Idempotent.
  void finalize();

 private:
  void worker_loop();
  std::string serialize_event(EventWithId* event);  // one event -> JSON line; frees the event
  void write_member(const std::string& data);       // gzip `data` as one member, append to file

  FILE* file_ = nullptr;
  std::mutex file_mutex_;  // serializes fwrite of members; compression stays outside it

  std::string hostname_;  // this node's hostname, resolved once at construction
  std::string hhash_;     // md5(hostname) as dftracer's 16-hex host key; first key of every args

  std::deque<EventWithId*> event_queue_;
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;     // worker wakes on nonempty / stop
  std::condition_variable not_full_cv_;  // producer wakes when the queue drains below the bound
  size_t max_queue_events_;              // backpressure bound (0 = unbounded)

  std::vector<std::thread> workers_;
  bool stop_flag_ = false;
  bool finalized_ = false;
  std::atomic<unsigned long> index_{0};  // unique complete-event id, shared across pool workers
  size_t flush_bytes_;                   // coalesce serialized JSON to ~this many bytes per member
  int zlib_level_;
};

}  // namespace datacrumbs
