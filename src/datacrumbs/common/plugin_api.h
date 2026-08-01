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

struct PluginApi {
  static constexpr uint32_t kAbiVersion = 1;
  uint32_t abi_version;
  void (*register_event_enricher)(EventEnricher);
};
}  // namespace datacrumbs

// Exported by each plugin. Returns false to signal init failure (server logs and skips it).
extern "C" bool datacrumbs_plugin_register(const datacrumbs::PluginApi* api);

#endif  // DATACRUMBS_COMMON_PLUGIN_API_H
