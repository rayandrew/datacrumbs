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
#define DC_TIMESYNC_VERSION 1u
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
};

#ifdef __cplusplus
}
#endif

#endif  // DATACRUMBS_COMMON_DC_TIMESYNC_SNAPSHOT_H
