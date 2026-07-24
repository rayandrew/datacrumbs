#pragma once
#include <datacrumbs/datacrumbs_config.h>

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
#include <string>

struct bpf_object;

namespace datacrumbs {

// Mirror the two generic uprobe programs + their maps from the already-loaded skeleton into
// bpftime shm (inits shm on first call, idempotent). Returns 0 on success.
int bpftime_hot_init(struct bpf_object* obj);

// Register a hot uprobe in bpftime: entry+exit attach points on binary+offset bound to the mirrored
// programs with `cookie`, plus a copy of this cookie's config from kernel_cfg_fd into the bpftime
// config map. Returns 0 on success.
int bpftime_hot_attach_uprobe(const std::string& binary, unsigned long offset,
                              unsigned long long cookie, int kernel_cfg_fd);

bool bpftime_hot_active();

// The agent reaches the target via LD_PRELOAD at launch (its ctor calls bpftime_agent_main), not a
// server-side inject: workloads are already launched with LD_PRELOAD=libdatacrumbs_client.so, so add
// libbpftime-agent.so + AGENT_SO to that chain. (Frida running-pid injection is broken on aarch64.)

// Drain the bpftime output ring on a background thread into cb(ctx, data, size) -- pass the same
// forwarder + event_processor the kernel ring uses so hot events land on the same timeline/pfw.gz.
int bpftime_hot_start_drain(int (*cb)(void*, void*, size_t), void* ctx);
void bpftime_hot_stop_drain();

}  // namespace datacrumbs
#endif
