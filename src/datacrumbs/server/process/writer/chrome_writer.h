#pragma once
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// Other headers
#include <datacrumbs/common/data_structures.h>
#include <datacrumbs/common/dc_timesync_snapshot.h>
#include <datacrumbs/server/process/compress/zlib_compressor.h>
// std headers
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <any>
#include <atomic>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace datacrumbs {

class ChromeWriter {
 public:
  // Create a ChromeWriter that writes to the given filename.
  ChromeWriter();

  // Destructor flushes and closes the file, and joins the worker thread.
  ~ChromeWriter();

  void push_event(EventWithId* event);

  void finalize();

 private:
  void worker_loop();                         // pool thread: grab -> serialize -> gzip -> write
  std::string serialize_event(EventWithId*);  // one event -> JSON line; frees the event

  // dc_timesync: remap a CLOCK_MONOTONIC event ts (ns) onto the shared cross-node
  // reference timeline using the daemon's seqlock snapshot. Passes through
  // unchanged when no valid snapshot is mapped (trace stays MONOTONIC).
  unsigned long long remap_ts(unsigned long long mono_ns) const;
  void map_timesync_snapshot();  // mmap the read-only snapshot (best-effort)
  const volatile dc_timesync_snapshot* tsync_ = nullptr;  // mmap'd; null if unavailable
  std::atomic<bool> domain_emitted_{false};  // emit the clock-domain metadata line once

  std::mutex file_mutex_;  // serialize gzip-member appends to file_
  FILE* file_ = nullptr;

  std::deque<EventWithId*> event_queue_;  // poll thread -> pool
  std::mutex queue_mutex_;
  std::condition_variable queue_cv_;     // pool wakes on empty->nonempty / stop
  std::condition_variable not_full_cv_;  // poll thread wakes when queue drains below cap
  size_t max_queue_events_;              // backpressure bound (0 = unbounded)

  std::vector<std::thread> workers_;  // parallel serialize+gzip+write pool
  bool stop_flag_;
  bool finalized_;
  std::atomic<unsigned long> index_;  // unique event id (parallel -> atomic)
  size_t batch_events_;               // events grabbed per lock acquisition
  size_t flush_bytes_;                // coalesce serialized JSON to ~this per gzip member
  int zlib_level_;                    // DATACRUMBS_ZLIB_LEVEL (default 6)
};

}  // namespace datacrumbs
