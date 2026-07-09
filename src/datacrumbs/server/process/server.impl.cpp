// Internal headers
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/server/process/event_processor.h>
#include <datacrumbs/server/process/telemetry/perf_telemetry_sampler.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>

// std headers
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
#include <errno.h>
#include <linux/perf_event.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <vector>
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
  if (level >= LIBBPF_DEBUG) return 0;
  return vfprintf(stderr, format, args);
}

static bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}

static int handle_event(void* ctx, void* data, size_t data_sz) {
  auto* event_processor = static_cast<datacrumbs::EventProcessor*>(ctx);
  return event_processor->handle_event(data, data_sz);
}

inline static int lookup_and_delete(int map_fd, datacrumbs::EventProcessor* event_processor,
                                    struct string_t* keys, unsigned int* values,
                                    unsigned int batch_size, struct string_t* in_batch) {
  int ret = bpf_map_lookup_and_delete_batch_compat(map_fd, in_batch, &in_batch, keys, values,
                                                   &batch_size, 0);
  if (ret < 0 && errno != ENOENT) {
    perror("bpf_map_lookup_and_delete_batch file_map");
    return -1;
  }
  for (unsigned int i = 0; i < batch_size; ++i) {
    event_processor->update_filename(keys[i].str, values[i]);
  }
  if (ret < 0 && errno == ENOENT) {
    return 0;
  }
  return 1;
}

static volatile bool stop = false;

static void sig_handler(int) {
  stop = true;
  // Async-signal-safe only: DC_LOG locks a mutex + fprintf, so logging here deadlocks if
  // the signal interrupts a thread already holding the log mutex (intermittent shutdown hang).
  static const char msg[] = "\nReceived SIGINT, stopping server loop\n";
  ssize_t n = write(STDERR_FILENO, msg, sizeof(msg) - 1);
  (void)n;
}

static bool split_uprobe_target(const std::string& symbol_with_offset, std::string* symbol_name,
                                unsigned long* offset) {
  const auto pos = symbol_with_offset.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  *symbol_name = symbol_with_offset.substr(0, pos);
  *offset = std::stoul(symbol_with_offset.substr(pos + 1), nullptr, 0);
  return true;
}

static std::string normalize_syscall_name_for_attach(const std::string& function_name) {
  if (function_name.rfind("__x64_sys_", 0) == 0) {
    return function_name.substr(10);
  }
  if (function_name.rfind("sys_", 0) == 0) {
    return function_name.substr(4);
  }
  return function_name;
}

static unsigned int runtime_probe_kind(datacrumbs::ProbeType probe_type) {
  switch (probe_type) {
    case datacrumbs::ProbeType::KPROBE:
      return DATACRUMBS_RUNTIME_PROBE_KIND_KPROBE;
    case datacrumbs::ProbeType::UPROBE:
      return DATACRUMBS_RUNTIME_PROBE_KIND_UPROBE;
    case datacrumbs::ProbeType::SYSCALLS:
      return DATACRUMBS_RUNTIME_PROBE_KIND_SYSCALL;
    case datacrumbs::ProbeType::USDT:
      return DATACRUMBS_RUNTIME_PROBE_KIND_USDT;
    default:
      return 0;
  }
}

static int populate_event_arg_config(
    int map_fd, uint64_t cookie, uint64_t event_id, datacrumbs::ProbeType probe_type,
    const std::vector<datacrumbs::ProbeArgCaptureSpec>* arg_specs) {
  runtime_event_config_t config = {};
  config.event_id = event_id;
  config.probe_kind = runtime_probe_kind(probe_type);
  if (arg_specs != nullptr) {
    config.arg_count = std::min<unsigned int>(arg_specs->size(), DATACRUMBS_MAX_CAPTURE_ARGS);
    for (unsigned int index = 0; index < config.arg_count; ++index) {
      const auto& spec = (*arg_specs)[index];
      config.arg_index[index] = (*arg_specs)[index].index;
      config.arg_offset[index] = spec.offset;
      if (spec.is_pointer) {
        if (is_char_pointer_type(spec.c_type)) {
          config.arg_num_bytes[index] =
              std::min<unsigned int>(spec.num_bytes, DATACRUMBS_MAX_CAPTURE_BYTES);
          config.arg_is_pointer[index] = 1;
        } else if (spec.num_bytes > 0) {
          // non-char pointer: read a scalar struct field at ptr+offset (num_bytes<=8, decoded by
          // writer)
          config.arg_num_bytes[index] = std::min<unsigned int>(spec.num_bytes, 8U);
          config.arg_is_pointer[index] = 1;
        } else {
          config.arg_num_bytes[index] = 0;
          config.arg_is_pointer[index] = 0;
        }
      } else {
        config.arg_num_bytes[index] = std::min<unsigned int>(spec.num_bytes, 8U);
        config.arg_is_pointer[index] = 0;
      }
    }
  }
  if (bpf_map_update_elem(map_fd, &cookie, &config, BPF_ANY) < 0) {
    DC_LOG_ERROR("Failed to populate event_arg_config_map for cookie=%llu event_id=%llu", cookie,
                 event_id);
    return -1;
  }
  return 0;
}

static int attach_runtime_probes(datacrumbs::EventProcessor* event_processor,
                                 struct datacrumbs_bpf* skel) {
  auto config_manager = event_processor->configManager_;
  auto* client_start = bpf_object__find_program_by_name(skel->obj, "trace_client_start");
  auto* client_stop = bpf_object__find_program_by_name(skel->obj, "trace_client_stop");
  auto* kprobe_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_kprobe_entry");
  auto* kprobe_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_kprobe_exit");
  auto* syscall_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_syscall_entry");
  auto* syscall_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_syscall_exit");
  auto* uprobe_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_uprobe_entry");
  auto* uprobe_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_uprobe_exit");
  auto* usdt_entry = bpf_object__find_program_by_name(skel->obj, "trace_generic_usdt_entry");
  auto* usdt_exit = bpf_object__find_program_by_name(skel->obj, "trace_generic_usdt_exit");
  const int event_arg_config_fd = bpf_map__fd(skel->maps.event_arg_config_map);

  if (event_arg_config_fd < 0) {
    DC_LOG_ERROR("Failed to get event_arg_config_map fd: %d", event_arg_config_fd);
    return 1;
  }

  if (!kprobe_entry || !kprobe_exit) {
    DC_LOG_ERROR("Failed to find generic kprobe BPF programs");
    return 1;
  }
  if (!syscall_entry || !syscall_exit) {
    DC_LOG_ERROR("Failed to find generic syscall BPF programs");
    return 1;
  }
  if (!uprobe_entry || !uprobe_exit) {
    DC_LOG_ERROR("Failed to find generic uprobe BPF programs");
    return 1;
  }
  if (!usdt_entry || !usdt_exit) {
    DC_LOG_ERROR("Failed to find generic usdt BPF programs");
    return 1;
  }
  if (!client_start || !client_stop) {
    DC_LOG_ERROR("Failed to find client init BPF programs");
    return 1;
  }

  {
    struct bpf_uprobe_opts start_opts = {};
    start_opts.sz = sizeof(start_opts);
    start_opts.func_name = "datacrumbs_start";
    struct bpf_uprobe_opts stop_opts = {};
    stop_opts.sz = sizeof(stop_opts);
    stop_opts.func_name = "datacrumbs_stop";
    auto* start_link =
        bpf_program__attach_uprobe_opts(client_start, -1, DATACRUMBS_CLIENT_LIB, 0, &start_opts);
    auto* stop_link =
        bpf_program__attach_uprobe_opts(client_stop, -1, DATACRUMBS_CLIENT_LIB, 0, &stop_opts);
    if (libbpf_get_error(start_link) || libbpf_get_error(stop_link)) {
      DC_LOG_ERROR("Failed to attach datacrumbs client hooks for %s", DATACRUMBS_CLIENT_LIB);
      return 1;
    }
  }

  int total_requested = 0;
  int total_attached = 0;
  int total_failed = 0;
  uint64_t cookie = 1;
  bool runtime_probe_state_updated = false;

  for (const auto& probe : config_manager->runtime_probes) {
    for (const auto& function_name : probe->functions) {
      const auto event_id = config_manager->get_runtime_event_id(probe->name, function_name);
      if (!event_id.has_value()) {
        DC_LOG_WARN("Skipping runtime probe without generated event id: %s.%s", probe->name.c_str(),
                    function_name.c_str());
        total_failed += 2;
        continue;
      }

      const uint64_t current_cookie = cookie++;
      if (probe->type == datacrumbs::ProbeType::KPROBE) {
        total_requested += 2;
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_kprobe_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_kprobe_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        auto* entry_link =
            bpf_program__attach_kprobe_opts(kprobe_entry, function_name.c_str(), &entry_opts);
        auto* exit_link =
            bpf_program__attach_kprobe_opts(kprobe_exit, function_name.c_str(), &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::SYSCALLS) {
        total_requested += 2;
        const std::string syscall_name = normalize_syscall_name_for_attach(function_name);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_ksyscall_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_ksyscall_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        auto* entry_link =
            bpf_program__attach_ksyscall(syscall_entry, syscall_name.c_str(), &entry_opts);
        auto* exit_link =
            bpf_program__attach_ksyscall(syscall_exit, syscall_name.c_str(), &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::UPROBE) {
        total_requested += 2;
        auto uprobe = std::dynamic_pointer_cast<datacrumbs::UProbe>(probe);
        std::string symbol_name;
        unsigned long offset = 0;
        const bool has_offset = uprobe && split_uprobe_target(function_name, &symbol_name, &offset);
        if (!uprobe) {
          DC_LOG_WARN("Skipping invalid uprobe config for %s.%s", probe->name.c_str(),
                      function_name.c_str());
          total_failed += 2;
          continue;
        }
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_uprobe_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.bpf_cookie = current_cookie;
        struct bpf_uprobe_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.retprobe = true;
        exit_opts.bpf_cookie = current_cookie;
        if (!has_offset) {
          entry_opts.func_name = function_name.c_str();
          exit_opts.func_name = function_name.c_str();
        }
        auto* entry_link = bpf_program__attach_uprobe_opts(
            uprobe_entry, -1, uprobe->binary_path.c_str(), offset, &entry_opts);
        auto* exit_link = bpf_program__attach_uprobe_opts(
            uprobe_exit, -1, uprobe->binary_path.c_str(), offset, &exit_opts);
        if (libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::USDT) {
        total_requested += 2;
        auto usdt = std::dynamic_pointer_cast<datacrumbs::USDTProbe>(probe);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name)) != 0) {
          total_failed += 2;
          continue;
        }
        struct bpf_usdt_opts entry_opts = {};
        entry_opts.sz = sizeof(entry_opts);
        entry_opts.usdt_cookie = current_cookie;
        struct bpf_usdt_opts exit_opts = {};
        exit_opts.sz = sizeof(exit_opts);
        exit_opts.usdt_cookie = current_cookie;
        auto* entry_link = usdt ? bpf_program__attach_usdt(
                                      usdt_entry, -1, usdt->binary_path.c_str(),
                                      usdt->provider.c_str(), function_name.c_str(), &entry_opts)
                                : nullptr;
        auto* exit_link = usdt ? bpf_program__attach_usdt(usdt_exit, -1, usdt->binary_path.c_str(),
                                                          usdt->provider.c_str(),
                                                          function_name.c_str(), &exit_opts)
                               : nullptr;
        if (!usdt || libbpf_get_error(entry_link) || libbpf_get_error(exit_link)) {
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 2;
          continue;
        }
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else {
        DC_LOG_WARN("Skipping unsupported runtime probe type %d for %s",
                    static_cast<int>(probe->type), probe->name.c_str());
        total_failed += 2;
      }
    }
  }

  if (runtime_probe_state_updated) {
    config_manager->persist_runtime_probe_state();
  }

  DC_LOG_INFO("Runtime probe attachment summary: requested=%d attached=%d failed=%d",
              total_requested, total_attached, total_failed);
  return 0;
}

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
// Encode the configured PMU events via libpfm4 and record them in hwc_ctl
// ([0]=count, [1]=scope). For CPU/BOTH, open one per-cpu event per (cpu, slot)
// into hwc_pmu. The encoded attrs are returned in out_attrs so per-task events
// can be opened lazily per traced tid (TASK/BOTH). 0 on success (incl. none).
static int setup_hw_counters(struct datacrumbs_bpf* skel, const std::vector<std::string>& events,
                             int scope, std::vector<struct perf_event_attr>* out_attrs) {
  if (events.empty()) {
    DC_LOG_INFO("HW counters: none configured");
    return 0;
  }
  std::vector<std::string> active_events = events;
  if (active_events.size() > DATACRUMBS_HW_COUNTER_SLOTS) {
    DC_LOG_WARN("HW counters: %zu requested but only %d slots compiled in; truncating",
                active_events.size(), (int)DATACRUMBS_HW_COUNTER_SLOTS);
    active_events.resize(DATACRUMBS_HW_COUNTER_SLOTS);
  }

  if (pfm_initialize() != PFM_SUCCESS) {
    DC_LOG_ERROR("HW counters: pfm_initialize() failed");
    return -1;
  }

  int ncpu = libbpf_num_possible_cpus();
  if (ncpu < 1) ncpu = 1;

  // One perf fd per (cpu, counter): can exceed the default RLIMIT_NOFILE (1024)
  // on many-core nodes, so raise it to cover the fds plus headroom for libbpf links.
  {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
      const rlim_t need = (rlim_t)ncpu * active_events.size() + 4096;
      if (rl.rlim_cur < need) {
        rl.rlim_cur = (rl.rlim_max == RLIM_INFINITY || rl.rlim_max > need) ? need : rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
          DC_LOG_WARN("HW counters: could not raise RLIMIT_NOFILE to %llu (may hit EMFILE)",
                      (unsigned long long)need);
        }
      }
    }
  }

  const int pmu_fd = bpf_map__fd(skel->maps.hwc_pmu);
  const int ctl_fd = bpf_map__fd(skel->maps.hwc_ctl);
  if (pmu_fd < 0 || ctl_fd < 0) {
    DC_LOG_ERROR("HW counters: failed to get hwc map fds (pmu=%d ctl=%d)", pmu_fd, ctl_fd);
    return -1;
  }

  unsigned int active = 0;
  for (const auto& name : active_events) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    pfm_perf_encode_arg_t arg;
    memset(&arg, 0, sizeof(arg));
    arg.attr = &attr;
    arg.size = sizeof(arg);
    int ret = pfm_get_os_event_encoding(name.c_str(), PFM_PLM0 | PFM_PLM3, PFM_OS_PERF_EVENT, &arg);
    if (ret != PFM_SUCCESS) {
      DC_LOG_ERROR("HW counter '%s' not recognized by libpfm4: %s", name.c_str(),
                   pfm_strerror(ret));
      return -1;
    }
    attr.disabled = 0;  // count immediately
    attr.inherit = 0;
    attr.pinned = 1;  // register-read, no multiplexing; masked out if it can't schedule
    if (out_attrs) out_attrs->push_back(attr);  // for per-task reopening (TASK/BOTH)

    if (scope != 1) {  // CPU or BOTH: open one per-cpu event per cpu
      int opened = 0;
      for (int cpu = 0; cpu < ncpu; ++cpu) {
        int fd =
            syscall(__NR_perf_event_open, &attr, /*pid=*/-1, cpu, /*group_fd=*/-1, /*flags=*/0);
        if (fd < 0) {
          if (cpu == 0) {
            DC_LOG_ERROR(
                "HW counter '%s': perf_event_open(cpu=0) failed: %s. Check "
                "/proc/sys/kernel/perf_event_paranoid (needs <=0, or CAP_PERFMON/root) and that "
                "the "
                "PMU exposes this event.",
                name.c_str(), strerror(errno));
            return -1;
          }
          continue;  // offline cpu etc.
        }
        unsigned int idx = (unsigned int)cpu * DATACRUMBS_HW_COUNTER_SLOTS + active;
        if (bpf_map_update_elem(pmu_fd, &idx, &fd, BPF_ANY) != 0) {
          DC_LOG_ERROR("HW counter '%s': hwc_pmu update failed at cpu=%d: %s", name.c_str(), cpu,
                       strerror(errno));
          close(fd);
          return -1;
        }
        // fd kept open for the server's lifetime (closing it stops the counter).
        ++opened;
      }
      DC_LOG_INFO("HW counter[%u] '%s' opened on %d/%d cpus", active, name.c_str(), opened, ncpu);
    }
    ++active;
  }

  unsigned int key0 = 0, key1 = 1, scope_u = (unsigned int)scope;
  if (bpf_map_update_elem(ctl_fd, &key0, &active, BPF_ANY) != 0 ||
      bpf_map_update_elem(ctl_fd, &key1, &scope_u, BPF_ANY) != 0) {
    DC_LOG_ERROR("HW counters: failed to set hwc_ctl");
    return -1;
  }
  const char* scope_name = scope == 0 ? "cpu" : (scope == 1 ? "task" : "both");
  DC_LOG_PRINT("HW counters active: %u (scope=%s, compiled slots: %d)", active, scope_name,
               (int)DATACRUMBS_HW_COUNTER_SLOTS);
  return 0;
}

// Opens per-task counter events on demand for TASK/BOTH. On a BPF notice it
// opens one event per active counter for the tid (pid=tid, cpu=-1) into
// hwc_pmu_task[slot*SLOTS+s], then publishes tid->slot so BPF starts reading.
struct HwTaskManager {
  int pmu_task_fd = -1;
  int slot_map_fd = -1;
  std::vector<struct perf_event_attr> attrs;
  std::vector<bool> slot_used;
  std::unordered_map<unsigned int, std::pair<unsigned int, std::vector<int>>> open;

  void init(struct datacrumbs_bpf* skel, std::vector<struct perf_event_attr> a) {
    pmu_task_fd = bpf_map__fd(skel->maps.hwc_pmu_task);
    slot_map_fd = bpf_map__fd(skel->maps.hwc_task_slot);
    attrs = std::move(a);
    slot_used.assign(DATACRUMBS_HW_TASK_SLOTS, false);
  }

  int alloc_slot() {
    for (int i = 0; i < (int)slot_used.size(); ++i)
      if (!slot_used[i]) {
        slot_used[i] = true;
        return i;
      }
    return -1;
  }

  void add(unsigned int tid) {
    if (open.count(tid)) return;  // duplicate notice
    int slot = alloc_slot();
    if (slot < 0) {
      DC_LOG_WARN("HW task counters: no free slot for tid=%u (raise DATACRUMBS_HW_TASK_SLOTS)",
                  tid);
      return;
    }
    std::vector<int> fds;
    for (unsigned int s = 0; s < attrs.size(); ++s) {
      struct perf_event_attr attr = attrs[s];
      int fd = syscall(__NR_perf_event_open, &attr, (pid_t)tid, /*cpu=*/-1, /*group_fd=*/-1, 0);
      if (fd < 0) {
        DC_LOG_WARN("HW task counters: perf_event_open(tid=%u) failed: %s", tid, strerror(errno));
        for (int f : fds) close(f);
        slot_used[slot] = false;
        return;
      }
      unsigned int idx = (unsigned int)slot * DATACRUMBS_HW_COUNTER_SLOTS + s;
      if (bpf_map_update_elem(pmu_task_fd, &idx, &fd, BPF_ANY) != 0) {
        close(fd);
        for (int f : fds) close(f);
        slot_used[slot] = false;
        return;
      }
      fds.push_back(fd);
    }
    unsigned int slot_u = (unsigned int)slot;
    bpf_map_update_elem(slot_map_fd, &tid, &slot_u, BPF_ANY);  // BPF begins reading
    open[tid] = {slot_u, std::move(fds)};
  }

  void remove(unsigned int tid) {
    auto it = open.find(tid);
    if (it == open.end()) return;
    bpf_map_delete_elem(slot_map_fd, &tid);
    for (int fd : it->second.second) close(fd);
    slot_used[it->second.first] = false;
    open.erase(it);
  }

  void cleanup() {
    for (auto& kv : open)
      for (int fd : kv.second.second) close(fd);
    open.clear();
  }
};

static int hwc_notify_cb(void* ctx, void* data, size_t sz) {
  if (sz < sizeof(struct hwc_pid_notify_t)) return 0;
  auto* mgr = (HwTaskManager*)ctx;
  auto* n = (struct hwc_pid_notify_t*)data;
  if (n->op == 1)
    mgr->add(n->tid);
  else
    mgr->remove(n->tid);
  return 0;
}
#endif  // DATACRUMBS_ENABLE_HW_COUNTERS

static int main_process(datacrumbs::EventProcessor* event_processor) {
  DC_LOG_TRACE("main: start");
  datacrumbs::utils::Timer timer;
  timer.resumeTime();

  struct datacrumbs_bpf* skel = nullptr;
  struct ring_buffer* rb = nullptr;
  int err = 0;
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  HwTaskManager hw_task_mgr;
  bool hw_task_active = false;
#endif
  libbpf_set_print(libbpf_print_fn);

  skel = datacrumbs_bpf__open();
  if (!skel) {
    DC_LOG_ERROR("Failed to open BPF object");
    return 1;
  }
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  // Size the perf-event-array to ncpu*SLOTS before load (one perf fd per cpu/slot).
  {
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1) ncpu = 1;
    if (bpf_map__set_max_entries(skel->maps.hwc_pmu,
                                 (unsigned int)ncpu * DATACRUMBS_HW_COUNTER_SLOTS) != 0) {
      DC_LOG_ERROR("Failed to size hwc_pmu map");
      datacrumbs_bpf__destroy(skel);
      return 1;
    }
    if (bpf_map__set_max_entries(skel->maps.hwc_pmu_task, (unsigned int)DATACRUMBS_HW_TASK_SLOTS *
                                                              DATACRUMBS_HW_COUNTER_SLOTS) != 0) {
      DC_LOG_ERROR("Failed to size hwc_pmu_task map");
      datacrumbs_bpf__destroy(skel);
      return 1;
    }
  }
#endif
  if (datacrumbs_bpf__load(skel)) {
    DC_LOG_ERROR("Failed to load BPF object");
    datacrumbs_bpf__destroy(skel);
    return 1;
  }

  err = datacrumbs_bpf__attach(skel);
  if (err) {
    DC_LOG_ERROR("Failed to attach BPF skeleton: %d", err);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  err = attach_runtime_probes(event_processor, skel);
  if (err) {
    DC_LOG_ERROR("Failed to attach runtime probes: %d", err);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }

#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  {
    std::vector<struct perf_event_attr> hw_attrs;
    const int hw_scope = (int)event_processor->configManager_->hw_scope;  // 0 cpu,1 task,2 both
    if (setup_hw_counters(skel, event_processor->configManager_->hw_counter_events, hw_scope,
                          &hw_attrs) != 0) {
      DC_LOG_ERROR("Failed to set up hardware counters");
      datacrumbs_bpf__destroy(skel);
      return 1;
    }
    if (hw_scope != 0 && !hw_attrs.empty()) {  // task or both: open per-task on demand
      hw_task_mgr.init(skel, std::move(hw_attrs));
      hw_task_active = true;
    }
  }
#endif

#if !(defined(DATACRUMBS_ENABLE) && (DATACRUMBS_ENABLE == 1))
  DC_LOG_WARN("DATACRUMBS_ENABLE_OPT is OFF. Nothing will be captured");
#endif
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  DC_LOG_PRINT("DataCrumbs in Tracer mode");
#else
  DC_LOG_PRINT("DataCrumbs in Profiler mode");
#endif

#if defined(DATACRUMBS_ENABLE_INCLUSION_PATH) && (DATACRUMBS_ENABLE_INCLUSION_PATH == 1)
  int inclusion_trie = bpf_map__fd(skel->maps.inclusion_path_trie);
  if (inclusion_trie < 0) {
    DC_LOG_ERROR("Failed to get inclusion path trie: %d", inclusion_trie);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  struct string_t* cur_key = nullptr;
  struct string_t next_key = {};
  struct string_t value = {};
  for (;;) {
    err = bpf_map_get_next_key(inclusion_trie, cur_key, &next_key);
    if (err) break;
    bpf_map_delete_elem(inclusion_trie, &next_key);
    cur_key = &next_key;
  }

  std::unordered_map<unsigned int, string_t> inclusion_list;
  const std::string inclusion_paths = event_processor->configManager_->inclusion_paths;
  if (!inclusion_paths.empty()) {
    std::stringstream ss(inclusion_paths);
    std::string path;
    unsigned int idx = 1;
    while (std::getline(ss, path, ':')) {
      if (!path.empty()) {
        string_t s = {};
        size_t copy_len = path.size();
        if (copy_len > sizeof(s.str) - 1) copy_len = sizeof(s.str) - 1;
        strncpy(s.str, path.c_str(), copy_len);
        s.str[copy_len] = '\0';
        s.len = copy_len * 8;
        inclusion_list[idx++] = s;
      }
    }
  }
  for (const auto& pair : inclusion_list) {
    if (bpf_map_update_elem(inclusion_trie, &pair.second, &pair.second, BPF_ANY) < 0) {
      DC_LOG_ERROR("Failed to update inclusion path trie for %s", pair.second.str);
      datacrumbs_bpf__destroy(skel);
      return 1;
    }
  }
  cur_key = nullptr;
  next_key = {};
  for (;;) {
    err = bpf_map_get_next_key(inclusion_trie, cur_key, &next_key);
    if (err) break;
    bpf_map_lookup_elem(inclusion_trie, &next_key, &value);
    DC_LOG_INFO("Trie key: %s, len: %u, value_len: %u", next_key.str, next_key.len, value.len);
    cur_key = &next_key;
  }
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  int failed_events_fd = bpf_map__fd(skel->maps.failed_request);
  if (failed_events_fd < 0) {
    DC_LOG_ERROR("Failed to get failed events fd: %d", failed_events_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event, event_processor, nullptr);
  if (!rb) {
    DC_LOG_ERROR("Failed to create ring buffer");
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  if (hw_task_active &&
      ring_buffer__add(rb, bpf_map__fd(skel->maps.hwc_notify), hwc_notify_cb, &hw_task_mgr) != 0) {
    DC_LOG_ERROR("Failed to add hw_notify ring buffer");
    ring_buffer__free(rb);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
#endif
#else
  INITIALIZE_MAP_1();
#ifdef GET_DATA_2_EXISTS
  INITIALIZE_MAP_2();
#endif
#ifdef GET_DATA_3_EXISTS
  INITIALIZE_MAP_3();
#endif
#ifdef GET_DATA_4_EXISTS
  int profile_4_fd = initialize_map_4(skel);
#endif
#ifdef GET_DATA_5_EXISTS
  int profile_5_fd = initialize_map_5(skel);
#endif
#ifdef GET_DATA_6_EXISTS
  int profile_6_fd = initialize_map_6(skel);
#endif
#ifdef GET_DATA_7_EXISTS
  int profile_7_fd = initialize_map_7(skel);
#endif
#ifdef GET_DATA_8_EXISTS
  int profile_8_fd = initialize_map_8(skel);
#endif
#ifdef GET_DATA_9_EXISTS
  int profile_9_fd = initialize_map_9(skel);
#endif
  int latest_interval_fd = bpf_map__fd(skel->maps.latest_interval);
  if (latest_interval_fd < 0) {
    DC_LOG_ERROR("Failed to get latest interval map fd: %d", latest_interval_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
#endif

  int file_hash_fd = bpf_map__fd(skel->maps.file_map);
  if (file_hash_fd < 0) {
    DC_LOG_ERROR("Failed to get file hash fd: %d", file_hash_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }

  const double elapsed = timer.pauseTime();
  DC_LOG_PRINT("Initialization of DataCrumbs elapsed time: %f seconds", elapsed);
  {
    std::error_code ec;
    std::filesystem::create_directories(
        event_processor->configManager_->server_ready_file.parent_path(), ec);
    std::ofstream ready_output(event_processor->configManager_->server_ready_file);
    if (ready_output.is_open()) {
      ready_output << "ready\n";
    }
  }
  DC_LOG_INFO("DataCrumbs ready to run for user:%s run_id:%s trace_file:%s",
              event_processor->configManager_->user.c_str(),
              event_processor->configManager_->run_id.c_str(),
              event_processor->configManager_->trace_file_path.c_str());

  // Split telemetry tracks by read mechanism: sysfs counters vs perf (uncore).
  std::vector<datacrumbs::TelemetrySource> sysfs_sources;
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  std::vector<datacrumbs::TelemetrySource> perf_sources;
#endif
  for (const auto& src : event_processor->configManager_->telemetry_sources) {
    const bool is_perf = !src.counters.empty() && !src.counters[0].perf_event.empty();
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
    if (is_perf) {
      perf_sources.push_back(src);
      continue;
    }
#else
    (void)is_perf;
#endif
    sysfs_sources.push_back(src);
  }
  const unsigned int telemetry_interval = event_processor->configManager_->telemetry_interval_ms;
  datacrumbs::SysfsTelemetrySampler sysfs_sampler(event_processor->writer_,
                                                  std::move(sysfs_sources), telemetry_interval,
                                                  &event_processor->event_index);
  sysfs_sampler.start();
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  datacrumbs::PerfTelemetrySampler perf_sampler(event_processor->writer_, std::move(perf_sources),
                                                telemetry_interval, &event_processor->event_index);
  perf_sampler.start();
#endif

  signal(SIGINT, sig_handler);
  unsigned int batch_size = 1024;
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
  struct string_t* keys =
      static_cast<struct string_t*>(malloc(batch_size * sizeof(struct string_t)));
  unsigned int* values = static_cast<unsigned int*>(malloc(batch_size * sizeof(unsigned int)));
  struct string_t* in_batch = nullptr;
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 2)
  INITIALIZE_MAP_LOOKUP_1();
#ifdef GET_DATA_2_EXISTS
  INITIALIZE_MAP_LOOKUP_2();
#endif
#ifdef GET_DATA_3_EXISTS
  INITIALIZE_MAP_LOOKUP_3();
#endif
#ifdef GET_DATA_4_EXISTS
  INITIALIZE_MAP_LOOKUP_4();
#endif
#ifdef GET_DATA_5_EXISTS
  INITIALIZE_MAP_LOOKUP_5();
#endif
#ifdef GET_DATA_6_EXISTS
  INITIALIZE_MAP_LOOKUP_6();
#endif
#ifdef GET_DATA_7_EXISTS
  INITIALIZE_MAP_LOOKUP_7();
#endif
#ifdef GET_DATA_8_EXISTS
  INITIALIZE_MAP_LOOKUP_8();
#endif
#ifdef GET_DATA_9_EXISTS
  INITIALIZE_MAP_LOOKUP_9();
#endif
#endif

  unsigned long long last_processed_timestamp = 0;
  while (!stop) {
    err = 0;
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
    err = lookup_and_delete(file_hash_fd, event_processor, keys, values, batch_size, in_batch);
    if (err == -EINTR) {
      err = 0;
      break;
    }
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
    int failed_events = 0;
    err = bpf_map_lookup_elem(failed_events_fd, &DATACRUMBS_FAILED_EVENTS_KEY, &failed_events);
    if (err == 0) {
      event_processor->failed_events = failed_events;
    }
    err = ring_buffer__poll(rb, 10);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      DC_LOG_ERROR("Error polling ring buffer: %d", err);
      break;
    }
#else
    unsigned long long latest_ts = 0;
    err = bpf_map_lookup_elem(latest_interval_fd, &DATACRUMBS_TS_KEY, &latest_ts);
    if (err == 0) {
      if (last_processed_timestamp == 0) {
        last_processed_timestamp = latest_ts;
      }
      if (latest_ts > last_processed_timestamp) {
        last_processed_timestamp = latest_ts;
        LOOKUP_1_CALL();
#ifdef GET_DATA_2_EXISTS
        LOOKUP_2_CALL();
#endif
#ifdef GET_DATA_3_EXISTS
        LOOKUP_3_CALL();
#endif
#ifdef GET_DATA_4_EXISTS
        LOOKUP_4_CALL();
#endif
#ifdef GET_DATA_5_EXISTS
        LOOKUP_5_CALL();
#endif
#ifdef GET_DATA_6_EXISTS
        LOOKUP_6_CALL();
#endif
#ifdef GET_DATA_7_EXISTS
        LOOKUP_7_CALL();
#endif
#ifdef GET_DATA_8_EXISTS
        LOOKUP_8_CALL();
#endif
#ifdef GET_DATA_9_EXISTS
        LOOKUP_9_CALL();
#endif
      }
    }
#endif
  }

  batch_size = 1024 * 1024;
  DC_LOG_INFO("");
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 2)
  DC_LOG_INFO("Collecting remaining profiling events");
  while (LOOKUP_1_CALL() != -1);
#ifdef GET_DATA_2_EXISTS
  while (LOOKUP_2_CALL() != -1);
#endif
#ifdef GET_DATA_3_EXISTS
  while (LOOKUP_3_CALL() != -1);
#endif
#ifdef GET_DATA_4_EXISTS
  while (LOOKUP_4_CALL() != -1);
#endif
#ifdef GET_DATA_5_EXISTS
  while (LOOKUP_5_CALL() != -1);
#endif
#ifdef GET_DATA_6_EXISTS
  while (LOOKUP_6_CALL() != -1);
#endif
#ifdef GET_DATA_7_EXISTS
  while (LOOKUP_7_CALL() != -1);
#endif
#ifdef GET_DATA_8_EXISTS
  while (LOOKUP_8_CALL() != -1);
#endif
#ifdef GET_DATA_9_EXISTS
  while (LOOKUP_9_CALL() != -1);
#endif
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  int failed_events = 0;
  err = bpf_map_lookup_elem(failed_events_fd, &DATACRUMBS_FAILED_EVENTS_KEY, &failed_events);
  if (err == 0) {
    DC_LOG_PRINT("Total %d events failed", failed_events);
  }
#endif

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 0)
  DC_LOG_PRINT("Collecting string metadata from file_map...");
  while (lookup_and_delete(file_hash_fd, event_processor, keys, values, batch_size, in_batch) ==
         1) {
  }
  if (keys) free(keys);
  if (values) free(values);
#endif

  DC_LOG_PRINT("Finalizing DataCrumbs...");
  if (stop) {
    DC_LOG_INFO("Received SIGINT (Ctrl-C), exiting gracefully");
  }
  sysfs_sampler.stop();
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  perf_sampler.stop();
#endif
  timer.resumeTime();
  event_processor->finalize();
  {
    std::error_code ec;
    std::filesystem::remove(event_processor->configManager_->server_ready_file, ec);
  }

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  ring_buffer__free(rb);
#endif
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  hw_task_mgr.cleanup();
#endif
  datacrumbs_bpf__destroy(skel);

  const double finalize_elapsed = timer.pauseTime();
  DC_LOG_PRINT("Finalization and cleanup of DataCrumbs elapsed: %f seconds", finalize_elapsed);
  DC_LOG_PRINT("Failed events: %d", event_processor->failed_events);
  DC_LOG_PRINT("Total events: %llu", event_processor->event_index.load());
  DC_LOG_TRACE("main: end");
  return 0;
}

static int main_call(int argc, char** argv) {
  if (argc < 4) {
    DC_LOG_ERROR("Usage: %s <signed-probes.json.gz> <run-id> <user>", argv[0]);
    return 1;
  }

  const std::string run_id = argv[2];
  const std::string user = argv[3];
  auto config_manager =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance(argv[1], run_id,
                                                                                   user, true);
  if (!config_manager) {
    DC_LOG_ERROR("Failed to initialize runtime configuration manager");
    return 1;
  }
  auto event_processor = datacrumbs::EventProcessor(argv[1]);
  event_processor.configManager_->print_configurations();
  return main_process(&event_processor);
}
