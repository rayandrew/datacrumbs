#ifndef DATACRUMBS_COMMON_PLUGIN_API_H
#define DATACRUMBS_COMMON_PLUGIN_API_H

#include <datacrumbs/common/typedefs.h>

#include <cstdint>
#include <functional>

// SPI a datacrumbs plugin compiles against. A plugin is a shared object listed in DATACRUMBS_PLUGINS
// that exports `datacrumbs_plugin_register`; the server dlopens it and calls that symbol with a
// PluginApi bound to the server's own registries. The plugin registers only through the passed api,
// so it never depends on symbol interposition with the executable.

namespace datacrumbs {
struct EventWithId;

// Modifies an event (ts/dur/args) in the writer before serialization, whatever backend produced it.
using EventEnricher = std::function<void(EventWithId*)>;

// Handed to a bpf-ready hook: lets a plugin reach the loaded BPF objects (e.g. to populate a map).
struct PluginBpfContext {
  std::function<int(const char*)> get_map_fd;  // core BPF map fd by name, -1 if absent
};

// Runs once after the skeleton is loaded but before probes attach, so a plugin can prime BPF maps.
using PluginBpfReady = std::function<void(const PluginBpfContext&)>;

// Writes one record. The plugin owns `args` until this returns and the core takes it from there, so
// a plugin never touches the writer or the event index and cannot get the id sequence wrong.
// @p ts_ns is CLOCK_MONOTONIC; the enrichers put it on the global timeline like any other event.
using PluginEmit = std::function<void(uint64_t event_id, uint64_t ts_ns, DataCrumbsArgs* args)>;

// Called on the plugin's own interval for as long as the server runs. Emits whatever it read.
//
// Distinct from an enricher, which only sees events something else produced. A source that is
// neither a probe nor a counter delta - the DPA telemetry API returns a row per device thread - has
// no other way in, and running it inside the server rather than beside the workload is what makes
// it node-scoped and alive between configurations.
using PluginSampler = std::function<void(const PluginEmit&)>;

struct PluginApi {
  // Raised for the sampler additions: a plugin built against 1 does not know register_sampler
  // exists, and one built against 2 must not be loaded by a server that cannot honour it.
  static constexpr uint32_t kAbiVersion = 2;
  uint32_t abi_version;
  void (*register_event_enricher)(EventEnricher);
  void (*register_bpf_ready)(PluginBpfReady);
  // Names a record kind and returns the id the writer labels it with. Call once per kind at
  // registration; the ids come from the same range as the built-in telemetry sources.
  uint64_t (*register_event_name)(const char* category, const char* name, const char* type);
  // Runs @p sampler every @p interval_ms until the server stops.
  void (*register_sampler)(unsigned int interval_ms, PluginSampler);
};
}  // namespace datacrumbs

// Exported by each plugin. Returns false to signal init failure (server logs and skips it).
extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api);

#endif  // DATACRUMBS_COMMON_PLUGIN_API_H
