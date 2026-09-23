#ifndef DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
#define DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H

// dc_timesync daemon (utils) publishes clock-fit params here via a seqlock in an mmap'd file.
// t_ref = (t_mono + bridge_mono_to_phc_ns) + offset_ns + skew_ppb * (t_phc - anchor_phc_ns) / 1e9.
// A hw ts on PHC k crosses via clocks[k].delta_to_synced_ns. A raw HCA (CQE) ts is a cycle count:
// convert with mlx5dv_ts_to_ns against raw_clock_info_* first, then apply raw_to_synced_ns.

#include <stdint.h>

#define DC_TIMESYNC_MAGIC 0x44435453u  // "DCTS"; guards against a stale/foreign mmap
#define DC_TIMESYNC_MAX_CLOCKS 8
#define DC_TIMESYNC_DEFAULT_PATH \
  "/dev/shm/dc_timesync.snapshot"  // override via DC_TIMESYNC_SNAPSHOT

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
  // HCA free-running raw clock -> synced PHC fit, so an unprivileged consumer maps a CQE ts to the
  // global epoch with no local anchor: t_synced = raw_ns + raw_to_synced_ns +
  // raw_skew_ppb*(raw_ns - raw_anchor_ns)/1e9. raw_ns is the raw clock already in ns (see
  // raw_clock_info_* below), not the CQE's raw cycle count. valid=0 unless given the fabric ib
  // device.
  uint32_t raw_valid;
  int64_t raw_anchor_ns;
  int64_t raw_to_synced_ns;
  int64_t raw_skew_ppb;
  // mlx5dv_get_clock_info() snapshot, refreshed by the daemon every
  // DC_TIMESYNC_CLOCK_INFO_REFRESH_MS (default 60000ms): the vendor tuple a raw CQE timestamp
  // converts through (mlx5dv_ts_to_ns). raw_clock_info_mask is 41 bits on known hardware, so the
  // conversion is correct only while the gap between a raw timestamp and last_cycles stays under
  // mask/2 (about 18.3 minutes). valid=0 until set.
  uint32_t raw_clock_info_valid;
  uint64_t raw_clock_info_updated_mono_ns;
  uint64_t raw_clock_info_nsec;
  uint64_t raw_clock_info_last_cycles;
  uint64_t raw_clock_info_frac;
  uint32_t raw_clock_info_mult;
  uint32_t raw_clock_info_shift;
  uint64_t raw_clock_info_mask;
};

#ifdef __cplusplus
}
#endif

#endif  // DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
