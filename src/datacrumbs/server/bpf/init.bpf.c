#include <datacrumbs/server/bpf/common.h>

SEC("uprobe")
int BPF_UPROBE(trace_client_start) {
  return mark_current_pid_traced();
}

SEC("uprobe")
int BPF_UPROBE(trace_client_stop) {
  return unmark_current_pid_traced();
}

// The client calls these once per sink worker, not per write, so the pair costs two uprobe hits a
// run. Everything the marked thread does below vfs - ext4, block, bio - is then excluded.
SEC("uprobe")
int BPF_UPROBE(trace_io_thread_begin) {
  return mark_current_tid_tracer();
}

SEC("uprobe")
int BPF_UPROBE(trace_io_thread_end) {
  return unmark_current_tid_tracer();
}
