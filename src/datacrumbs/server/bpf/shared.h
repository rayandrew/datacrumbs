#ifndef DATACRUMBS_SERVER_BPF_SHARED_H
#define DATACRUMBS_SERVER_BPF_SHARED_H

#include <custom_probes_process.h>
#include <datacrumbs/common/constants.h>
#include <datacrumbs/datacrumbs_config.h>

static int DATACRUMBS_TS_KEY = 1;
static int DATACRUMBS_FAILED_EVENTS_KEY = 2;

#define DATACRUMBS_MAX_CAPTURE_ARGS 5
#define DATACRUMBS_MAX_CAPTURE_BYTES 64
#define DATACRUMBS_STACK_DEPTH 32  // frames per captured user stack (bpf_get_stackid slot size)
#define DATACRUMBS_STACKDUMP_BYTES 4000  // user stack bytes per sample (offline DWARF/.eh_frame unwind)
#define DATACRUMBS_STACK_SAMPLE_TYPE 200u  // generic_event_t.type sentinel for a stack-sample record

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
  unsigned int pmu_count;                     // hardware counters read (0 = PMU off)
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

#define MAX_STR_READ_LEN 256

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
