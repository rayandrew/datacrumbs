#ifndef DATACRUMBS_SERVER_BPF_SHARED_H
#define DATACRUMBS_SERVER_BPF_SHARED_H

#include <custom_probes_process.h>
#include <datacrumbs/common/constants.h>
#include <datacrumbs/datacrumbs_config.h>

static int DATACRUMBS_TS_KEY __attribute__((unused)) = 1;
static int DATACRUMBS_FAILED_EVENTS_KEY __attribute__((unused)) = 2;

// A raw user stack snapshot (regs + N bytes from sp) for capture_stack probes whose FP walk is too
// shallow (crosses a frame-pointer-less vendor lib). Emitted sampled on its own ringbuf record; the
// offline analysis replays each module's .eh_frame CFI over regs+stackdump. uregs = pc, sp, fp, lr.
// pmu[] holds the counters' running totals, not a delta: a sample is a point, so the work between
// two consecutive samples on the same cpu is what the deltas measure. Hence cpu is captured too.
struct stack_sample_t {
  unsigned int type;  // = DATACRUMBS_STACK_SAMPLE_TYPE
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long uregs[4];
  unsigned int cpu;
  unsigned int pmu_count;
  unsigned long long pmu[DATACRUMBS_MAX_PMU];
  unsigned int stackdump_len;
  unsigned char stackdump[DATACRUMBS_STACKDUMP_BYTES];
};

enum datacrumbs_runtime_probe_kind_t {
  DATACRUMBS_RUNTIME_PROBE_KIND_KPROBE = 1,
  DATACRUMBS_RUNTIME_PROBE_KIND_UPROBE = 2,
  DATACRUMBS_RUNTIME_PROBE_KIND_SYSCALL = 3,
  DATACRUMBS_RUNTIME_PROBE_KIND_USDT = 4,
  DATACRUMBS_RUNTIME_PROBE_KIND_TRACEPOINT = 5,
  DATACRUMBS_RUNTIME_PROBE_KIND_PERF_EVENT = 6,
};

// Per-cpu carry for the sampler's PMU deltas. `valid` suppresses the first sample on each cpu,
// whose "delta" would be the counter's whole history.
struct pmu_sample_prev_t {
  unsigned long long v[DATACRUMBS_MAX_PMU];
  unsigned int valid;
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
  unsigned int pmu_count;                      // hardware counters read (0 = PMU off)
  unsigned long long pmu[DATACRUMBS_MAX_PMU];  // per-counter entry->exit delta
  int stack_id;  // BPF_MAP_TYPE_STACK_TRACE id of the user stack at capture; -1 = none
};
typedef struct generic_event_t general_event_t;
struct usdt_event_t {
  unsigned int type;
  unsigned long long id;
  unsigned long long event_id;
  unsigned long long ts;
  unsigned long long dur;
};

struct fn_key_t {
  unsigned long long id;
  unsigned long long event_id;
};

struct probe_guard_t {
  unsigned long long win_ts;
  unsigned long long count;
  unsigned long long dropped;  // cumulative events suppressed; userspace can read to warn
};

struct fn_value_t {
  unsigned long long ts;
  unsigned int arg_count;
  unsigned long long args[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_len[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_data_status[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned char arg_data[DATACRUMBS_MAX_CAPTURE_ARGS][DATACRUMBS_MAX_CAPTURE_BYTES];
  unsigned int pmu_count;                            // counters snapshotted at entry (0 = PMU off)
  unsigned long long pmu_start[DATACRUMBS_MAX_PMU];  // entry counter values
};

struct agg_key_t {
  unsigned long long event_id;
  unsigned long long time_interval;
};

struct agg_value_t {
  unsigned long long count;
  unsigned long long duration_ns;  // summed entry->exit duration
  unsigned long long pid_tgid;     // a representative pid_tgid for the counter record
  // A sum and a count give a mean, and a mean hides the tail that usually explains a stall. These
  // are what dftracer's numeric aggregation carries, so a reader gets the same four fields.
  unsigned long long min_ns;
  unsigned long long max_ns;
  // Sum of squared durations, so a standard deviation can be derived. The accumulator rather than
  // the deviation itself: min, max, sum and count all merge across windows and a deviation does
  // not, so a reader that re-buckets a trace would have to throw a computed one away. Saturates
  // rather than wrapping, since a wrapped value reads as a plausible small variance.
  unsigned long long sum_sq_ns2;
};

struct runtime_event_config_t {
  unsigned long long event_id;
  unsigned int probe_kind;
  unsigned int system_wide;    // tracepoints: 1 => skip the pid gate (capture on all pids)
  unsigned int aggregate;      // 1 => accumulate count/duration instead of emitting per-event
  unsigned int capture_stack;  // 1 => grab the user call stack (bpf_get_stackid, BPF_F_USER_STACK)
  unsigned int stack_dump_mask;  // raw regs+stack snapshot taken when (prandom & mask) == 0
  unsigned int arg_count;
  unsigned int arg_index[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_num_bytes[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_is_pointer[DATACRUMBS_MAX_CAPTURE_ARGS];
  unsigned int arg_offset[DATACRUMBS_MAX_CAPTURE_ARGS];  // byte offset of the field/struct member
  // system_wide tracepoints only: 1+index of the arg holding a tid; the event is dropped unless
  // that tid belongs to a traced process. 0 = off. Keeps external-waker identity (the waker is
  // `current`) while dropping the wakes of every untraced task on the box.
  unsigned int gate_tid_arg;
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
