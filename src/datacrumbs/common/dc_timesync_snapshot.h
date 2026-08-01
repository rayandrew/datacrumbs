#ifndef DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
#define DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H

// Shared contract: the dc_timesync daemon (utils) publishes clock-fit parameters here via a seqlock
// in an mmap'd file, and a reader remaps a CLOCK_MONOTONIC ts onto the global reference timeline:
//   t_ref = (t_mono + bridge_mono_to_phc_ns) + offset_ns + skew_ppb*(t_phc - anchor_phc_ns)/1e9
// A hw timestamp taken on PHC k first crosses to the synced PHC via clocks[k].delta_to_synced_ns.
// Plain C struct: included from both C (daemon) and C++ (server).

#include <stdint.h>

#define DC_TIMESYNC_MAGIC 0x44435453u  // "DCTS"; guards against a stale/foreign mmap
#define DC_TIMESYNC_MAX_CLOCKS 8
#define DC_TIMESYNC_DEFAULT_PATH "/dev/shm/dc_timesync.snapshot"  // override via DC_TIMESYNC_SNAPSHOT

#ifdef __cplusplus
extern "C" {
#endif

struct dc_timesync_snapshot {
  uint32_t magic;
  uint32_t seq;    // seqlock: odd = write in progress, reader retries
  uint32_t valid;  // 0 = no trustworthy fix yet -> reader falls back to MONOTONIC
  uint32_t ref_id;
  uint32_t self_id;  // self_id == ref_id => reference node (offset/skew are identity)
  int64_t bridge_mono_to_phc_ns;
  int64_t anchor_phc_ns;
  int64_t offset_ns;
  int64_t skew_ppb;  // signed relative rate, ns per s
  uint64_t updated_mono_ns;
  double residual_rms_ns;  // fit quality (diagnostic)
  uint32_t n_clocks;
  int32_t synced_phc_index;  // the PHC the fit refers to, -1 if unknown
  struct dc_timesync_clock {
    int32_t phc_index;           // N of /dev/ptpN
    uint32_t valid;              // 0 = not measured this cycle
    int64_t delta_to_synced_ns;  // ADD to this PHC's ns -> synced PHC ns
    uint64_t updated_mono_ns;
  } clocks[DC_TIMESYNC_MAX_CLOCKS];
};

#ifdef __cplusplus
}
#endif

#endif  // DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
