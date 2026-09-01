#include <datacrumbs/common/constants.h>
#include <datacrumbs/server/process/bpftime_hot.h>

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/server/process/bpf_map_util.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
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
enum class shm_open_type {
  SHM_REMOVE_AND_CREATE,
  SHM_OPEN_ONLY,
  SHM_NO_CREATE,
  SHM_CREATE_OR_OPEN
};
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
int bpftime_perf_event_enable(int fd);
long bpftime_map_update_elem(int fd, const void* key, const void* value, uint64_t flags);
int bpftime_poll_from_ringbuf(int rb_fd, void* ctx, int (*cb)(void*, void*, size_t));
}

namespace datacrumbs {
namespace {
bool g_inited = false;
int g_entry_prog_id = -1, g_exit_prog_id = -1, g_cfg_map_id = -1, g_output_id = -1,
    g_pid_map_id = -1;
std::unordered_map<int, int> g_fd2id;  // kernel map fd -> bpftime map id

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
  // Every knob a caller sets is spelled DATACRUMBS_*; forward onto the names bpftime reads, before
  // it initialises. Not overwritten, so an explicit upstream value still wins.
  static const struct {
    const char* ours;
    const char* theirs;
  } kForward[] = {
      {DATACRUMBS_ENV_BPFTIME_SHM_NAME, DATACRUMBS_BPFTIME_ENV_SHM_NAME},
      {DATACRUMBS_ENV_BPFTIME_SHM_MEMORY_MB, DATACRUMBS_BPFTIME_ENV_SHM_MEMORY_MB},
      {DATACRUMBS_ENV_BPFTIME_VM_NAME, DATACRUMBS_BPFTIME_ENV_VM_NAME},
  };
  for (const auto& f : kForward)
    if (const char* v = std::getenv(f.ours)) setenv(f.theirs, v, 0);
  // The unprivileged workload agent must write the maps shm to register its uprobes, but a root
  // server creates it 0644 -> EACCES; widen it (umask for creation, chmod if it pre-existed).
  const mode_t old_umask = umask(0);
  bpftime_initialize_global_shm(bpftime::shm_open_type::SHM_CREATE_OR_OPEN);
  umask(old_umask);
  const char* shm_name = std::getenv(DATACRUMBS_BPFTIME_ENV_SHM_NAME);
  const std::string shm_path =
      std::string("/dev/shm/") + (shm_name ? shm_name : "bpftime_maps_shm");
  chmod(shm_path.c_str(), 0666);
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
  // The agent only attaches ENABLED perf events; create leaves them disabled, so enable both.
  bpftime_perf_event_enable(pe);
  bpftime_perf_event_enable(px);
  DC_LOG_INFO("bpftime: registered hot uprobe %s+0x%lx cookie=%llu", binary.c_str(), offset,
              cookie);
  return 0;
}

bool bpftime_hot_active() {
  return g_inited;
}

void bpftime_hot_poll(int (*cb)(void*, void*, size_t), void* ctx) {
  if (g_inited && g_output_id >= 0) bpftime_poll_from_ringbuf(g_output_id, ctx, cb);
}

void bpftime_hot_sync_pids(int kernel_pid_map_fd) {
  if (!g_inited || g_pid_map_id < 0 || kernel_pid_map_fd < 0) return;
  for_each_map_entry<uint32_t>(kernel_pid_map_fd, [kernel_pid_map_fd](uint32_t k) {
    uint64_t val = 0;
    if (bpf_map_lookup_elem(kernel_pid_map_fd, &k, &val) == 0)
      bpftime_map_update_elem(g_pid_map_id, &k, &val, 0);
  });
}

}  // namespace datacrumbs
#endif
