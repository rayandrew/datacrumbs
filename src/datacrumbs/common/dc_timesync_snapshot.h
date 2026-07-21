#ifndef DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
#define DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H

// Shared contract between the dc_timesync daemon (datacrumbs-utils, writer) and
// the datacrumbs server (reader). The daemon periodically measures this node's
// NIC PHC vs a reference node's PHC (HW-timestamped exchange) and the local
// PHC<->CLOCK_MONOTONIC bridge, fits a line, and publishes the parameters here
// via a lock-free seqlock in a small mmap'd file. The server reads a consistent
// snapshot per batch and remaps each event's MONOTONIC timestamp onto the shared
// reference timeline -- no post-processing, no clock steering.
//
// Plain C struct: included from both C (daemon) and C++ (server).

#include <stdint.h>

#define DC_TIMESYNC_MAGIC 0x44435453u  // "DCTS"
// v2 APPENDS the local clock registry (clocks[]) after the v1 body. Appending keeps v1 readers valid:
// they mmap sizeof(v1) and see an unchanged prefix. Bump only for prefix-breaking changes.
#define DC_TIMESYNC_VERSION 2u
#define DC_TIMESYNC_MAX_CLOCKS 8
// Default publish path (mmap'd file). Override via env DC_TIMESYNC_SNAPSHOT.
#define DC_TIMESYNC_DEFAULT_PATH "/dev/shm/dc_timesync.snapshot"

#ifdef __cplusplus
extern "C" {
#endif

// Global timeline remap for a MONOTONIC timestamp t_mono (ns, CLOCK_MONOTONIC as
// stamped by bpf_ktime_get_ns):
//   t_phc_local = t_mono + bridge_mono_to_phc_ns              (local NIC PHC ns)
//   t_ref       = t_phc_local + offset_ns
//                             + skew_ppb * (t_phc_local - anchor_phc_ns) / 1e9
// where offset_ns/skew_ppb map this node's PHC onto ref_id's PHC. On the
// reference node itself offset_ns=0, skew_ppb=0 (identity beyond the bridge).
struct dc_timesync_snapshot {
  uint32_t magic;    // DC_TIMESYNC_MAGIC once initialized
  uint32_t version;  // DC_TIMESYNC_VERSION
  uint32_t seq;      // seqlock: odd = write in progress; reader retries
  uint32_t valid;    // 0 = no trustworthy fix yet -> server falls back to MONOTONIC

  uint32_t ref_id;   // reference node id this fit maps onto
  uint32_t self_id;  // this node's id (self_id == ref_id => reference node)

  int64_t bridge_mono_to_phc_ns;  // add to CLOCK_MONOTONIC ns -> local PHC ns
  int64_t anchor_phc_ns;          // local PHC ns at which offset_ns holds (fit origin)
  int64_t offset_ns;              // local PHC -> ref PHC offset at anchor
  int64_t skew_ppb;               // ref/local relative rate (ns per s), signed

  uint64_t updated_mono_ns;  // CLOCK_MONOTONIC ns of last successful update
  double residual_rms_ns;    // fit quality (diagnostic)

  // ---- v2: local clock registry ------------------------------------------------------------
  // The fit above maps ONE clock (synced_phc_index) onto the reference. But a NIC hardware
  // timestamp comes from whichever device carried the traffic, and a node has several independent
  // PHCs (BlueField exposes 4). Without this table a hw timestamp from another PHC is silently ~20 s
  // away from the reference. Each entry bridges one local PHC onto the synced one; the PHCs share an
  // oscillator so the delta is stable (~2 ns/s drift), and it is measured by differencing two
  // PTP_SYS_OFFSET_PRECISE reads (hardware cross-timestamping), i.e. sub-ns.
  //
  // Remap a hw timestamp t_phc taken on PHC k:
  //   t_synced = t_phc + clocks[k].delta_to_synced_ns
  //   t_ref    = t_synced + offset_ns + skew_ppb * (t_synced - anchor_phc_ns) / 1e9
  uint32_t n_clocks;          // entries populated in clocks[]
  int32_t synced_phc_index;   // the PHC the fit above refers to; -1 if unknown
  struct dc_timesync_clock {
    int32_t phc_index;            // N of /dev/ptpN
    uint32_t valid;               // 0 = not measured this cycle; do NOT remap with it
    int64_t delta_to_synced_ns;   // ADD to this PHC's ns -> synced PHC ns (0 for the synced PHC)
    uint64_t updated_mono_ns;     // CLOCK_MONOTONIC ns of this entry's last measurement
  } clocks[DC_TIMESYNC_MAX_CLOCKS];
};

#ifdef __cplusplus
}
#endif

#endif  // DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
