#include <datacrumbs/server/process/bpftime_hot.h>

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <datacrumbs/common/logging.h>

#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <map>
#include <thread>
#include <vector>

// Minimal bpftime raw-API decls, kept in sync with runtime/include/bpftime_shm.hpp, so the server
// does not pull bpftime_shm.hpp + boost into its build. Layout of bpf_map_attr and the enum must
// match exactly (passed/ABI'd by value).
namespace bpftime {
struct bpf_map_attr {
  int type = 0;
  uint32_t key_size = 0, value_size = 0, max_ents = 0;
  uint64_t flags = 0;
  uint32_t ifindex = 0, btf_vmlinux_value_type_id = 0, btf_id = 0, btf_key_type_id = 0,
           btf_value_type_id = 0;
  uint64_t map_extra = 0;
  uint32_t kernel_bpf_map_id = 0;
  uint64_t gpu_thread_count = 1024;
};
enum class shm_open_type { SHM_REMOVE_AND_CREATE, SHM_OPEN_ONLY, SHM_NO_CREATE, SHM_CREATE_OR_OPEN };
}  // namespace bpftime
struct ebpf_inst;
// bpftime exports these with C linkage (unmangled names, C++ param types).
extern "C" {
void bpftime_initialize_global_shm(bpftime::shm_open_type);
int bpftime_maps_create(int fd, const char* name, bpftime::bpf_map_attr attr);
int bpftime_progs_create(int fd, const ebpf_inst* insn, size_t cnt, const char* name, int type);
int bpftime_uprobe_create(int fd, int pid, const char* name, uint64_t offset, bool retprobe,
                          size_t ref_ctr_off);
int bpftime_attach_perf_to_bpf_with_cookie(int perf_fd, int bpf_fd, uint64_t cookie);
long bpftime_map_update_elem(int fd, const void* key, const void* value, uint64_t flags);
int bpftime_poll_from_ringbuf(int rb_fd, void* ctx, int (*cb)(void*, void*, size_t));
}

namespace datacrumbs {
namespace {
bool g_inited = false;
int g_entry_prog_id = -1, g_exit_prog_id = -1, g_cfg_map_id = -1, g_output_id = -1, g_pid_map_id = -1,
    g_hwc_ctl_id = -1;
std::map<int, int> g_fd2id;  // kernel map fd -> bpftime map id
std::atomic<bool> g_drain_stop{false};
std::thread g_drain_thread;

int mirror_prog(struct bpf_program* pr) {
  const struct bpf_insn* ins = bpf_program__insns(pr);
  size_t cnt = bpf_program__insn_cnt(pr);
  std::vector<struct bpf_insn> v(ins, ins + cnt);
  for (size_t i = 0; i < cnt; i++) {
    // LDDW with a map pseudo-fd (src 1/2): rewrite kernel fd -> bpftime map id
    if ((v[i].code & 0xff) == 0x18 && (v[i].src_reg == 1 || v[i].src_reg == 2)) {
      auto it = g_fd2id.find(v[i].imm);
      if (it != g_fd2id.end()) v[i].imm = it->second;
    }
  }
  return bpftime_progs_create(-1, reinterpret_cast<const ebpf_inst*>(v.data()), cnt,
                              bpf_program__name(pr), 2 /*KPROBE*/);
}
}  // namespace

int bpftime_hot_init(struct bpf_object* obj) {
  if (g_inited) return 0;
  bpftime_initialize_global_shm(bpftime::shm_open_type::SHM_CREATE_OR_OPEN);
  struct bpf_map* m;
  bpf_object__for_each_map(m, obj) {
    bpftime::bpf_map_attr attr;
    attr.type = static_cast<int>(bpf_map__type(m));
    attr.key_size = bpf_map__key_size(m);
    attr.value_size = bpf_map__value_size(m);
    attr.max_ents = bpf_map__max_entries(m);
    attr.flags = bpf_map__map_flags(m);
    int id = bpftime_maps_create(-1, bpf_map__name(m), attr);
    if (id < 0) {
      DC_LOG_ERROR("bpftime: maps_create %s failed", bpf_map__name(m));
      return -1;
    }
    g_fd2id[bpf_map__fd(m)] = id;
    if (!strcmp(bpf_map__name(m), "event_arg_config_map")) g_cfg_map_id = id;
    if (!strcmp(bpf_map__name(m), "output")) g_output_id = id;
    if (!strcmp(bpf_map__name(m), "pid_map")) g_pid_map_id = id;
    if (!strcmp(bpf_map__name(m), "hwc_ctl")) g_hwc_ctl_id = id;
  }
  struct bpf_program* entry = bpf_object__find_program_by_name(obj, "trace_generic_uprobe_entry");
  struct bpf_program* exit = bpf_object__find_program_by_name(obj, "trace_generic_uprobe_exit");
  if (!entry || !exit) {
    DC_LOG_ERROR("bpftime: uprobe programs not found in skeleton");
    return -1;
  }
  g_entry_prog_id = mirror_prog(entry);
  g_exit_prog_id = mirror_prog(exit);
  if (g_entry_prog_id < 0 || g_exit_prog_id < 0) {
    DC_LOG_ERROR("bpftime: progs_create failed");
    return -1;
  }
  g_inited = true;
  DC_LOG_INFO("bpftime: mirrored uprobe programs into shm (entry=%d exit=%d, %zu maps)",
              g_entry_prog_id, g_exit_prog_id, g_fd2id.size());
  return 0;
}

int bpftime_hot_attach_uprobe(const std::string& binary, unsigned long offset,
                              unsigned long long cookie, int kernel_cfg_fd) {
  if (!g_inited) return -1;
  if (g_cfg_map_id >= 0 && kernel_cfg_fd >= 0) {
    unsigned char buf[256] = {};  // > sizeof(runtime_event_config_t)
    unsigned long long k = cookie;
    if (bpf_map_lookup_elem(kernel_cfg_fd, &k, buf) == 0)
      bpftime_map_update_elem(g_cfg_map_id, &k, buf, 0);
  }
  int pe = bpftime_uprobe_create(-1, -1, binary.c_str(), offset, false, 0);
  int px = bpftime_uprobe_create(-1, -1, binary.c_str(), offset, true, 0);
  if (pe < 0 || px < 0) {
    DC_LOG_ERROR("bpftime: uprobe_create failed (%d/%d)", pe, px);
    return -1;
  }
  bpftime_attach_perf_to_bpf_with_cookie(pe, g_entry_prog_id, cookie);
  bpftime_attach_perf_to_bpf_with_cookie(px, g_exit_prog_id, cookie);
  DC_LOG_INFO("bpftime: registered hot uprobe %s+0x%lx cookie=%llu", binary.c_str(), offset, cookie);
  return 0;
}

bool bpftime_hot_active() { return g_inited; }

int bpftime_hot_sync_hwc_ctl(int kernel_hwc_ctl_fd) {
  if (!g_inited || g_hwc_ctl_id < 0 || kernel_hwc_ctl_fd < 0) return -1;
  for (uint32_t k = 0; k < 2; k++) {
    uint32_t v = 0;
    if (bpf_map_lookup_elem(kernel_hwc_ctl_fd, &k, &v) == 0)
      bpftime_map_update_elem(g_hwc_ctl_id, &k, &v, 0);
  }
  DC_LOG_INFO("bpftime: mirrored hwc_ctl into shm");
  return 0;
}

int bpftime_hot_start_drain(int (*cb)(void*, void*, size_t), void* ctx, int kernel_pid_map_fd) {
  if (!g_inited || g_output_id < 0) return -1;
  g_drain_stop.store(false);
  g_drain_thread = std::thread([cb, ctx, kernel_pid_map_fd]() {
    int since_sync = 0;
    while (!g_drain_stop.load(std::memory_order_relaxed)) {
      bpftime_poll_from_ringbuf(g_output_id, ctx, cb);
      // ~every 200ms mirror the kernel pid_map (traced pids) into the bpftime pid_map
      if (kernel_pid_map_fd >= 0 && g_pid_map_id >= 0 && ++since_sync >= 1000) {
        since_sync = 0;
        uint32_t key = 0, next = 0;
        uint64_t val = 0;
        int ret = bpf_map_get_next_key(kernel_pid_map_fd, nullptr, &next);
        while (ret == 0) {
          if (bpf_map_lookup_elem(kernel_pid_map_fd, &next, &val) == 0)
            bpftime_map_update_elem(g_pid_map_id, &next, &val, 0);
          key = next;
          ret = bpf_map_get_next_key(kernel_pid_map_fd, &key, &next);
        }
      }
      usleep(200);
    }
  });
  DC_LOG_INFO("bpftime: drain thread started (output id=%d, pid_map sync from kernel fd=%d)",
              g_output_id, kernel_pid_map_fd);
  return 0;
}

void bpftime_hot_stop_drain() {
  if (g_drain_thread.joinable()) {
    g_drain_stop.store(true);
    g_drain_thread.join();
  }
}

}  // namespace datacrumbs
#endif
