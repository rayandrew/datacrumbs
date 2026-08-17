// Internal headers
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/server/process/bpf_map_util.h>
#include <datacrumbs/server/process/bpftime_hot.h>
#include <datacrumbs/server/process/event_processor.h>
#include <datacrumbs/server/process/plugin_loader.h>
#include <datacrumbs/server/process/telemetry/perf_telemetry_sampler.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>

// system headers
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>

// std headers
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// event_id -> its attached links, so a runaway probe can be fully detached at runtime (auto-detach).
static std::unordered_map<uint64_t, std::vector<struct bpf_link*>> g_runtime_links;

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
  DC_LOG_INFO("\nReceived SIGINT, stopping server loop");
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
    case datacrumbs::ProbeType::TRACEPOINT:
      return DATACRUMBS_RUNTIME_PROBE_KIND_TRACEPOINT;
    case datacrumbs::ProbeType::PERF_EVENT:
      return DATACRUMBS_RUNTIME_PROBE_KIND_PERF_EVENT;
    default:
      return 0;
  }
}

// 1-in-N raw stack dumps -> the prandom mask the BPF side tests. N must be a power of two; anything
// else would silently sample at the next one down, so fall back to every sample and say so.
static unsigned int stack_dump_mask_from_ratio(unsigned int ratio, const char* context) {
  if (ratio <= 1) return 0;
  if ((ratio & (ratio - 1)) != 0) {
    DC_LOG_WARN("%s: stack_dump_ratio=%u is not a power of two; dumping every sample", context,
                ratio);
    return 0;
  }
  return ratio - 1;
}

// Prime, so the sampler cannot lock step with a periodic workload and profile the same phase.
static constexpr unsigned int kDefaultSampleFreq = 997;

static bool resolve_perf_event(const std::string& name, unsigned int* type,
                               unsigned long long* config) {
  if (name == "cpu-clock") {
    *type = PERF_TYPE_SOFTWARE;
    *config = PERF_COUNT_SW_CPU_CLOCK;
  } else if (name == "task-clock") {
    *type = PERF_TYPE_SOFTWARE;
    *config = PERF_COUNT_SW_TASK_CLOCK;
  } else if (name == "cycles" || name == "cpu-cycles") {
    *type = PERF_TYPE_HARDWARE;
    *config = PERF_COUNT_HW_CPU_CYCLES;
  } else if (name == "instructions") {
    *type = PERF_TYPE_HARDWARE;
    *config = PERF_COUNT_HW_INSTRUCTIONS;
  } else {
    return false;
  }
  return true;
}

static int populate_event_arg_config(int map_fd, uint64_t cookie, uint64_t event_id,
                                     datacrumbs::ProbeType probe_type,
                                     const std::vector<datacrumbs::ProbeArgCaptureSpec>* arg_specs,
                                     bool system_wide = false, bool aggregate = false,
                                     bool capture_stack = false,
                                     unsigned int stack_dump_mask = 63) {
  runtime_event_config_t config = {};
  config.event_id = event_id;
  config.probe_kind = runtime_probe_kind(probe_type);
  config.system_wide = system_wide ? 1u : 0u;
  config.aggregate = aggregate ? 1u : 0u;
  config.capture_stack = capture_stack ? 1u : 0u;
  config.stack_dump_mask = stack_dump_mask;
  if (arg_specs != nullptr) {
    config.arg_count = std::min<unsigned int>(arg_specs->size(), DATACRUMBS_MAX_CAPTURE_ARGS);
    for (unsigned int index = 0; index < config.arg_count; ++index) {
      const auto& spec = (*arg_specs)[index];
      config.arg_index[index] = spec.index;
      config.arg_offset[index] = spec.offset;
      if (spec.is_pointer) {
        if (is_char_pointer_type(spec.c_type)) {
          config.arg_num_bytes[index] =
              std::min<unsigned int>(spec.num_bytes, DATACRUMBS_MAX_CAPTURE_BYTES);
          config.arg_is_pointer[index] = 1;
        } else if (spec.num_bytes > 0) {  // scalar struct field read at ptr+offset (<=8 bytes)
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

// Parse a tracepoint's tracefs `format` into arg-capture specs (field label, byte offset, size).
// Scalars (<=8B) -> args; fixed char arrays and __data_loc dynamic strings -> byte capture. Skips the
// common_* header fields. Empty result (unreadable format) leaves the tracepoint with no decoded args.
static std::vector<datacrumbs::ProbeArgCaptureSpec> parse_tracepoint_fields(
    const std::string& category, const std::string& name) {
  std::vector<datacrumbs::ProbeArgCaptureSpec> specs;
  std::ifstream f;
  for (const char* root : {"/sys/kernel/debug/tracing/events", "/sys/kernel/tracing/events"}) {
    f.open(std::string(root) + "/" + category + "/" + name + "/format");
    if (f.is_open()) break;
  }
  if (!f.is_open()) {
    DC_LOG_WARN("tracepoint %s:%s: format unreadable -> fields not decoded", category.c_str(),
                name.c_str());
    return specs;
  }
  static const std::regex re(
      R"(field:([^;]+?)\s+([A-Za-z_]\w*)(\[\d+\])?;\s*offset:(\d+);\s*size:(\d+);\s*signed:(\d+);)");
  std::string line;
  while (std::getline(f, line)) {
    std::smatch m;
    if (!std::regex_search(line, m, re)) continue;
    const std::string type = m[1].str();
    const std::string fname = m[2].str();
    const bool is_array = m[3].matched;
    if (fname.rfind("common_", 0) == 0) continue;
    datacrumbs::ProbeArgCaptureSpec s;
    s.label = fname;
    s.offset = static_cast<unsigned int>(std::stoul(m[4].str()));
    s.num_bytes = static_cast<unsigned int>(std::stoul(m[5].str()));
    const bool is_signed = m[6].str() != "0";
    if (type.find("__data_loc") != std::string::npos) {  // dynamic string: field holds a u32 loc
      s.is_pointer = true;
      s.c_type = "char *";
      s.index = 1;  // marks the two-step __data_loc read in generic_point
      s.num_bytes = DATACRUMBS_MAX_CAPTURE_BYTES;
    } else if (type.find("char") != std::string::npos && is_array) {  // fixed char array -> bytes
      s.is_pointer = true;
      s.c_type = "char *";
    } else if (s.num_bytes <= 8) {  // scalar
      s.is_pointer = false;
      s.c_type = is_signed ? "long long" : "unsigned long long";
    } else {
      continue;  // non-char array / oversized -> skip
    }
    specs.push_back(std::move(s));
    if (specs.size() >= DATACRUMBS_MAX_CAPTURE_ARGS) break;
  }
  return specs;
}

// Destroy the links of a runaway probe: one whose dropped counter keeps climbing past the rate limit
// for kHotChecks consecutive checks. hot_probe_drop only rate-limits it (still fires); this removes
// it. Irreversible for the run; logged. Off with DATACRUMBS_AUTODETACH=0.
static void poll_auto_detach(int probe_guard_fd, datacrumbs::EventProcessor* event_processor) {
  static constexpr unsigned long long kDropsPerCheck = 200000;  // >200k drops/check = runaway
  static constexpr int kHotChecks = 3;                          // sustained over N checks, not a burst
  static std::unordered_map<uint64_t, unsigned long long> last_dropped;
  static std::unordered_map<uint64_t, int> hot_checks;
  if (probe_guard_fd < 0) return;
  auto config_manager = event_processor->configManager_;
  std::vector<uint64_t> detached;
  for (auto& [event_id, links] : g_runtime_links) {
    struct probe_guard_t guard = {};
    uint64_t key = event_id;
    if (bpf_map_lookup_elem(probe_guard_fd, &key, &guard) != 0) continue;
    const unsigned long long prev = last_dropped[event_id];
    last_dropped[event_id] = guard.dropped;
    if (guard.dropped - prev < kDropsPerCheck) {
      hot_checks[event_id] = 0;
      continue;
    }
    if (++hot_checks[event_id] < kHotChecks) continue;
    for (auto* link : links)
      if (link) bpf_link__destroy(link);
    const auto it = config_manager->category_map.find(event_id);
    const std::string name = it != config_manager->category_map.end()
                                 ? it->second.first + "." + it->second.second
                                 : std::to_string(event_id);
    DC_LOG_WARN("auto-detached runaway probe %s (event_id=%llu dropped=%llu)", name.c_str(),
                static_cast<unsigned long long>(event_id), guard.dropped);
    detached.push_back(event_id);
  }
  for (uint64_t event_id : detached) g_runtime_links.erase(event_id);
}

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
// Drain agg_map into COUNTER records for aggregate probes: one record per (event_id, interval)
// bucket with count + summed duration (us). Buckets are deleted as consumed. Keys are snapshotted
// before deleting so concurrent BPF updates don't invalidate the walk.
static void drain_agg_map(int agg_fd, datacrumbs::EventProcessor* event_processor) {
  if (agg_fd < 0 || !event_processor->writer_) return;
  auto config_manager = event_processor->configManager_;
  datacrumbs::for_each_map_entry<struct agg_key_t>(agg_fd, [&](const struct agg_key_t& k) {
    struct agg_value_t v = {};
    if (bpf_map_lookup_elem(agg_fd, &k, &v) != 0) return;
    bpf_map_delete_elem(agg_fd, &k);
    if (config_manager->category_map.find(k.event_id) == config_manager->category_map.end()) return;
    auto* args = new DataCrumbsArgs();
    (*args)["count"] = static_cast<unsigned long long>(v.count);
    (*args)["dur"] = static_cast<unsigned long long>(v.duration_ns / 1000);  // summed us (dftracer key)
    auto* aggregated =
        new datacrumbs::EventWithId(datacrumbs::TracePhase::AGGREGATED, 0, 0, v.pid_tgid, k.event_id,
                                    k.time_interval * DATACRUMBS_TIME_INTERVAL_NS, 0, args);
    event_processor->writer_->push_event(aggregated);
  });
}
#endif

#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
// Route a hot uprobe to the bpftime userspace runtime (opt-in via DC_BPFTIME_HOT). Returns nonzero
// on any failure so the caller falls back to the kernel uprobe - capture is never silently lost.
static int attach_hot_via_bpftime(struct bpf_object* obj, int kernel_cfg_fd,
                                  const std::string& binary, unsigned long offset,
                                  unsigned long long cookie) {
  if (!getenv("DC_BPFTIME_HOT")) return -1;
  if (datacrumbs::bpftime_hot_init(obj) != 0) return -1;
  return datacrumbs::bpftime_hot_attach_uprobe(binary, offset, cookie, kernel_cfg_fd);
}
#endif

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
  auto* tracepoint_prog =
      bpf_object__find_program_by_name(skel->obj, "trace_generic_tracepoint");
  auto* perf_sample_prog = bpf_object__find_program_by_name(skel->obj, "trace_generic_perf_sample");
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
                                      probe->getArgSpecs(function_name), false,
                                      probe->aggregate) != 0) {
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
        g_runtime_links[*event_id].push_back(entry_link);
        g_runtime_links[*event_id].push_back(exit_link);
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::SYSCALLS) {
        total_requested += 2;
        const std::string syscall_name = normalize_syscall_name_for_attach(function_name);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name), false,
                                      probe->aggregate) != 0) {
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
        g_runtime_links[*event_id].push_back(entry_link);
        g_runtime_links[*event_id].push_back(exit_link);
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
                                      probe->getArgSpecs(function_name), false,
                                      probe->aggregate) != 0) {
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
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
        if (uprobe->hot && has_offset &&
            attach_hot_via_bpftime(skel->obj, event_arg_config_fd, uprobe->binary_path, offset,
                                   current_cookie) == 0) {
          config_manager->record_successful_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_attached += 2;
          continue;  // routed to bpftime; skip the kernel uprobe
        }
#endif
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
        g_runtime_links[*event_id].push_back(entry_link);
        g_runtime_links[*event_id].push_back(exit_link);
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::USDT) {
        total_requested += 2;
        auto usdt = std::dynamic_pointer_cast<datacrumbs::USDTProbe>(probe);
        if (populate_event_arg_config(event_arg_config_fd, current_cookie, *event_id, probe->type,
                                      probe->getArgSpecs(function_name), false,
                                      probe->aggregate) != 0) {
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
        g_runtime_links[*event_id].push_back(entry_link);
        g_runtime_links[*event_id].push_back(exit_link);
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 2;
      } else if (probe->type == datacrumbs::ProbeType::TRACEPOINT) {
        total_requested += 1;  // point event -> one attach, not entry+exit
        // function_name is "category:name" (e.g. "sched:sched_switch"); libbpf attaches by (cat,name).
        const auto colon = function_name.find(':');
        const std::string tp_category =
            colon == std::string::npos ? std::string() : function_name.substr(0, colon);
        const std::string tp_name =
            colon == std::string::npos ? function_name : function_name.substr(colon + 1);
        // Decode the tracepoint's fields (offset/size from tracefs format) so generic_point can read
        // them, and register their labels so the writer names them.
        std::vector<datacrumbs::ProbeArgCaptureSpec> tp_fields =
            parse_tracepoint_fields(tp_category, tp_name);
        const std::vector<datacrumbs::ProbeArgCaptureSpec>* tp_specs =
            tp_fields.empty() ? probe->getArgSpecs(function_name) : &tp_fields;
        if (populate_event_arg_config(
                event_arg_config_fd, current_cookie, *event_id, probe->type, tp_specs,
                probe->system_wide, false, probe->capture_stack,
                stack_dump_mask_from_ratio(probe->stack_dump_ratio ? probe->stack_dump_ratio : 64,
                                           function_name.c_str())) != 0) {
          total_failed += 1;
          continue;
        }
        if (!tp_fields.empty()) config_manager->set_runtime_event_arg_specs(*event_id, tp_fields);
        struct bpf_tracepoint_opts tp_opts = {};
        tp_opts.sz = sizeof(tp_opts);
        tp_opts.bpf_cookie = current_cookie;
        auto* tp_link = bpf_program__attach_tracepoint_opts(tracepoint_prog, tp_category.c_str(),
                                                            tp_name.c_str(), &tp_opts);
        if (libbpf_get_error(tp_link)) {
          DC_LOG_WARN("tracepoint attach FAILED %s:%s err=%ld", tp_category.c_str(), tp_name.c_str(),
                      libbpf_get_error(tp_link));
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 1;
          continue;
        }
        g_runtime_links[*event_id].push_back(tp_link);
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 1;
      } else if (probe->type == datacrumbs::ProbeType::PERF_EVENT) {
        total_requested += 1;  // one sampler, fanned out over the online cpus
        unsigned int pe_type = 0;
        unsigned long long pe_config = 0;
        if (perf_sample_prog == nullptr ||
            !resolve_perf_event(function_name, &pe_type, &pe_config)) {
          DC_LOG_WARN(
              "perf_event %s: unknown event (want cpu-clock/task-clock/cycles/instructions)",
              function_name.c_str());
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 1;
          continue;
        }
        const unsigned int sample_freq =
            probe->sample_freq ? probe->sample_freq : kDefaultSampleFreq;
        if (populate_event_arg_config(
                event_arg_config_fd, current_cookie, *event_id, probe->type, nullptr,
                probe->system_wide, false, true,
                stack_dump_mask_from_ratio(probe->stack_dump_ratio, function_name.c_str())) != 0) {
          total_failed += 1;
          continue;
        }
        struct perf_event_attr attr = {};
        attr.size = sizeof(attr);
        attr.type = pe_type;
        attr.config = pe_config;
        attr.freq = 1;
        attr.sample_freq = sample_freq;
        int attached_cpus = 0;
        const int cpu_count = libbpf_num_possible_cpus();
        for (int cpu = 0; cpu < cpu_count; ++cpu) {
          // system-wide (pid=-1) per cpu; the BPF pid gate narrows it to traced processes, so a
          // thread that migrates cpus stays sampled.
          const int perf_fd =
              syscall(__NR_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
          if (perf_fd < 0) continue;  // offline cpu, or the hw event is unavailable here
          struct bpf_perf_event_opts pe_opts = {};
          pe_opts.sz = sizeof(pe_opts);
          pe_opts.bpf_cookie = current_cookie;
          auto* pe_link = bpf_program__attach_perf_event_opts(perf_sample_prog, perf_fd, &pe_opts);
          if (libbpf_get_error(pe_link)) {
            close(perf_fd);
            continue;
          }
          g_runtime_links[*event_id].push_back(pe_link);
          ++attached_cpus;
        }
        if (attached_cpus == 0) {
          DC_LOG_WARN("perf_event %s: attached on 0 cpus (perf_event_paranoid? not root?)",
                      function_name.c_str());
          config_manager->record_invalid_runtime_probe(probe, function_name);
          runtime_probe_state_updated = true;
          total_failed += 1;
          continue;
        }
        DC_LOG_INFO("perf_event %s: sampling at %u Hz on %d cpus", function_name.c_str(),
                    sample_freq, attached_cpus);
        config_manager->record_successful_runtime_probe(probe, function_name);
        runtime_probe_state_updated = true;
        total_attached += 1;
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

static int main_process(datacrumbs::EventProcessor* event_processor) {
  DC_LOG_TRACE("main: start");
  datacrumbs::utils::Timer timer;
  timer.resumeTime();

  struct datacrumbs_bpf* skel = nullptr;
  struct ring_buffer* rb = nullptr;
  int err = 0;
  libbpf_set_print(libbpf_print_fn);

  skel = datacrumbs_bpf__open_and_load();
  if (!skel) {
    DC_LOG_ERROR("Failed to open BPF object");
    return 1;
  }

  // Let plugins prime BPF maps before probes fire (e.g. the pmu plugin fills the perf-event arrays).
  datacrumbs::PluginBpfContext bpf_ctx;
  bpf_ctx.get_map_fd = [skel](const char* name) -> int {
    struct bpf_map* m = bpf_object__find_map_by_name(skel->obj, name);
    return m != nullptr ? bpf_map__fd(m) : -1;
  };
  datacrumbs::run_bpf_ready(bpf_ctx);

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
  datacrumbs::for_each_map_entry<struct string_t>(
      inclusion_trie, [&](const struct string_t& k) { bpf_map_delete_elem(inclusion_trie, &k); });

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
  datacrumbs::for_each_map_entry<struct string_t>(inclusion_trie, [&](const struct string_t& k) {
    struct string_t value = {};
    bpf_map_lookup_elem(inclusion_trie, &k, &value);
    DC_LOG_INFO("Trie key: %s, len: %u, value_len: %u", k.str, k.len, value.len);
  });
#endif

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  int failed_events_fd = bpf_map__fd(skel->maps.failed_request);
  if (failed_events_fd < 0) {
    DC_LOG_ERROR("Failed to get failed events fd: %d", failed_events_fd);
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
  event_processor->stack_map_fd_ = bpf_map__fd(skel->maps.stack_map);
  rb = ring_buffer__new(bpf_map__fd(skel->maps.output), handle_event, event_processor, nullptr);
  if (!rb) {
    DC_LOG_ERROR("Failed to create ring buffer");
    datacrumbs_bpf__destroy(skel);
    return 1;
  }
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

  const int probe_guard_fd = bpf_map__fd(skel->maps.probe_guard);
  const char* autodetach_env = std::getenv("DATACRUMBS_AUTODETACH");
  const bool autodetach = autodetach_env == nullptr || std::strcmp(autodetach_env, "0") != 0;
  time_t last_autodetach = time(nullptr);
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  const int agg_fd = bpf_map__fd(skel->maps.agg_map);
#endif
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
  time_t last_bpftime_sync = time(nullptr);
#endif

  // System-wide interval telemetry as Chrome COUNTER tracks on their own thread. Perf-backed
  // sources (uncore) only exist when hw counters are compiled in; everything else reads sysfs.
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

  unsigned long long last_processed_timestamp = 0;
  while (!stop) {
    err = 0;
#if defined(DATACRUMBS_BPFTIME_COMPATIBLE_FLAG) && (DATACRUMBS_BPFTIME_COMPATIBLE_FLAG == 1)
    // Drain the bpftime output ring into the same single-threaded event_processor as the kernel ring
    // (no extra thread -> no race on the writer). Mirror traced pids on the autodetach cadence.
    datacrumbs::bpftime_hot_poll(handle_event, event_processor);
    if (time(nullptr) - last_bpftime_sync >= 1) {
      last_bpftime_sync = time(nullptr);
      datacrumbs::bpftime_hot_sync_pids(bpf_map__fd(skel->maps.pid_map));
    }
#endif
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
    // wall-clock cadence: under load ring_buffer__poll returns immediately, so an iteration count
    // would fire far faster than 1s and shrink each check's drop delta below the threshold.
    if (time(nullptr) - last_autodetach >= 1) {
      last_autodetach = time(nullptr);
      if (autodetach) poll_auto_detach(probe_guard_fd, event_processor);
      drain_agg_map(agg_fd, event_processor);
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

  sysfs_sampler.stop();
#if defined(DATACRUMBS_ENABLE_HW_COUNTERS) && (DATACRUMBS_ENABLE_HW_COUNTERS == 1)
  perf_sampler.stop();
#endif

  batch_size = 1024 * 1024;
  DC_LOG_INFO("");
#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  drain_agg_map(agg_fd, event_processor);  // flush the final interval buckets before shutdown
#endif
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
  timer.resumeTime();
  event_processor->finalize();
  {
    std::error_code ec;
    std::filesystem::remove(event_processor->configManager_->server_ready_file, ec);
  }

#if defined(DATACRUMBS_MODE) && (DATACRUMBS_MODE == 1)
  ring_buffer__free(rb);
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
  datacrumbs::load_plugins();
  auto event_processor = datacrumbs::EventProcessor(argv[1]);
  event_processor.configManager_->print_configurations();
  return main_process(&event_processor);
}
