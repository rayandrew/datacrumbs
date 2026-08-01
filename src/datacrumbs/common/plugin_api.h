#ifndef DATACRUMBS_COMMON_PLUGIN_API_H
#define DATACRUMBS_COMMON_PLUGIN_API_H

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

struct PluginApi {
  static constexpr uint32_t kAbiVersion = 1;
  uint32_t abi_version;
  void (*register_event_enricher)(EventEnricher);
  void (*register_bpf_ready)(PluginBpfReady);
};
}  // namespace datacrumbs

// Exported by each plugin. Returns false to signal init failure (server logs and skips it).
extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api);

#endif  // DATACRUMBS_COMMON_PLUGIN_API_H
