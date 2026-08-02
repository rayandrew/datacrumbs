#pragma once
#include <datacrumbs/datacrumbs_config.h>

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
#include <cstddef>
#include <string>

struct bpf_object;

namespace datacrumbs {

// Mirror the two generic uprobe programs + their maps from the already-loaded skeleton into bpftime
// shm (inits shm on first call, idempotent). Returns 0 on success.
int bpftime_hot_init(struct bpf_object* obj);

// Register a hot uprobe in bpftime: entry+exit attach points on binary+offset bound to the mirrored
// programs with `cookie`, plus a copy of this cookie's config from kernel_cfg_fd into the bpftime
// config map. Returns 0 on success. Injection into the workload is by LD_PRELOAD-ing
// libbpftime-agent.so at launch (its ctor calls bpftime_agent_main); no server-side inject.
int bpftime_hot_attach_uprobe(const std::string& binary, unsigned long offset,
                              unsigned long long cookie, int kernel_cfg_fd);

bool bpftime_hot_active();

// Non-blocking drain of the bpftime output ring into cb(ctx,data,size); call from the server's main
// poll loop so hot events feed the same (single-threaded) event_processor as the kernel ring.
void bpftime_hot_poll(int (*cb)(void*, void*, size_t), void* ctx);

// Mirror kernel pid_map (traced pids) -> bpftime pid_map so the in-target agent's need_tracing gate
// passes. Call periodically from the main loop (the pid set changes as processes start/stop).
void bpftime_hot_sync_pids(int kernel_pid_map_fd);

}  // namespace datacrumbs
#endif
