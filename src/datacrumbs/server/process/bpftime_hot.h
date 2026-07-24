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

}  // namespace datacrumbs
#endif
