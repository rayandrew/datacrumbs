#ifndef DATACRUMBS_SERVER_BPF_SHARED_H
#define DATACRUMBS_SERVER_BPF_SHARED_H

#include <custom_probes_process.h>
#include <datacrumbs/datacrumbs_config.h>

static int DATACRUMBS_TS_KEY = 1;
static int DATACRUMBS_FAILED_EVENTS_KEY = 2;

#define DATACRUMBS_MAX_CAPTURE_ARGS 5
#define DATACRUMBS_MAX_CAPTURE_BYTES 64

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
// Max concurrently traced threads holding per-task counter events (TASK/BOTH).
#define DATACRUMBS_HW_TASK_SLOTS 64
// BPF -> userspace notice to open/close per-task counter events for a tid.
struct hwc_pid_notify_t {
  unsigned int op;  // 1 = add (open events), 0 = remove (close events)
  unsigned int tid;
};
#endif

enum datacrumbs_runtime_probe_kind_t {
  DATACRUMBS_RUNTIME_PROBE_KIND_KPROBE = 1,
  DATACRUMBS_RUNTIME_PROBE_KIND_UPROBE = 2,
  DATACRUMBS_RUNTIME_PROBE_KIND_SYSCALL = 3,
  DATACRUMBS_RUNTIME_PROBE_KIND_USDT = 4,
  DATACRUMBS_RUNTIME_PROBE_KIND_TRACEPOINT = 5,
};

struct generic_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
  unsigned int arg_count;
  unsigned long long args[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned char arg_data[DATACRUMBS_MAX_CAPTURE_ARGS][DATACRUMBS_MAX_CAPTURE_BYTES];
  unsigned int ret;  // function return value (PT_REGS_RC); for fork/clone this is the child pid
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  // Primary per-call counter deltas (exit - entry): task-scoped for TASK/BOTH,
  // per-cpu for CPU. enabled/running deltas allow scaling if multiplexed.
  unsigned long long hwc_delta[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned long long hwc_enabled_delta[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned long long hwc_running_delta[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned int hwc_valid_mask;  // bit i set => hwc_delta[i] is trustworthy
  unsigned int hwc_migrated;    // 1 => thread changed cpu entry->exit (cpu read suspect)
  // Per-cpu deltas, populated only in BOTH so interference = cpu - primary.
  unsigned long long hwc_cpu_delta[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned int hwc_cpu_valid_mask;
#endif
};
typedef struct generic_event_t general_event_t;
struct usdt_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
};

#define MAX_STR_READ_LEN 256

struct fn_key_t {
  unsigned long long id;
  unsigned long long event_id;
};

// hot-probe guard: per-probe fire counter over a sliding window (caps a runaway probe's emit rate).
struct probe_guard_t {
  unsigned long long win_ts;
  unsigned long long count;
  unsigned long long dropped;  // cumulative events suppressed (userspace can read to warn)
};

struct fn_value_t {
  unsigned long long ts;
  unsigned int arg_count;
  unsigned long long args[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned char arg_data[DATACRUMBS_MAX_CAPTURE_ARGS][DATACRUMBS_MAX_CAPTURE_BYTES];
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  // Hardware PMU counter snapshots taken at function entry, keyed alongside ts in
  // fn_pid_map so the exit handler can compute the per-call delta.
  unsigned long long hwc_ctr[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned long long hwc_enabled[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned long long hwc_running[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned int hwc_entry_cpu;         // cpu id at entry (migration detection)
  unsigned int hwc_entry_valid_mask;  // bit i set => entry read of slot i succeeded
  // cached at entry, reused at exit -> no second hwc_ctl/hwc_task_slot lookup
  unsigned int hwc_active;        // active counter count
  unsigned int hwc_scope_cached;  // 0=cpu 1=task 2=both
  int hwc_task_slot_cached;       // task slot, or -1 if not opened
  // Per-cpu entry snapshot, used only in BOTH (primary holds the task snapshot).
  unsigned long long hwc_cpu_ctr[DATACRUMBS_HW_COUNTER_SLOTS];
  unsigned int hwc_cpu_entry_valid_mask;
#endif
};

struct runtime_event_config_t {
  unsigned long long event_id;
  unsigned int probe_kind;
  unsigned int arg_count;
  unsigned int arg_index[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_num_bytes[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_is_pointer[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int
      arg_offset[DATACRUMBS_MAX_CAPTURE_ARGS];  // byte offset into the pointee (struct field)
};

struct fn_t {
  struct fn_key_t key;
  struct fn_value_t value;
};

struct string_t {
  unsigned int len;
  char str[MAX_STR_READ_LEN];
};

struct profile_key_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long time_interval;
};

struct profile_value_t {
  unsigned long long duration;
  unsigned long long frequency;
};

struct usdt_profile_key_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long time_interval;
  unsigned int class_hash;
  unsigned int method_hash;
};

struct counter_event_t {
  struct profile_key_t* key;
  struct profile_value_t* value;
};

struct usdt_counter_event_t {
  struct usdt_profile_key_t* key;
  struct profile_value_t* value;
};

#endif  // DATACRUMBS_SERVER_BPF_SHARED_H
