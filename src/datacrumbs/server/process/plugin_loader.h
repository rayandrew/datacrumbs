#pragma once
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <dlfcn.h>

#include <string>

#include "event_enrichment.h"

namespace datacrumbs {

// Loads each plugin listed in DATACRUMBS_PLUGINS (":"-separated .so paths) and calls its
// datacrumbs_plugin_register. A plugin that fails to load or register is logged and skipped,
// not fatal.
inline void load_plugins() {
  const std::string& spec = Singleton<RuntimeConfigurationManager>::get_instance()->plugins;
  if (spec.empty()) return;

  // A plugin reaches these registries through this struct, not by resolving symbols itself.
  static const PluginApi api{
      PluginApi::kAbiVersion,
      &register_event_enricher,
      &register_bpf_ready,
      [](const char* category, const char* name, const char* type) -> uint64_t {
        return Singleton<RuntimeConfigurationManager>::get_instance()->register_plugin_event(
            category, name, type);
      },
      &register_plugin_sampler,
  };

  for (std::size_t start = 0; start <= spec.size();) {
    std::size_t sep = spec.find(':', start);
    if (sep == std::string::npos) sep = spec.size();
    const std::string path = spec.substr(start, sep - start);
    start = sep + 1;
    if (path.empty()) continue;

    void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
      DC_LOG_ERROR("plugin %s: dlopen failed: %s", path.c_str(), dlerror());
      continue;
    }
    auto* reg =
        reinterpret_cast<bool (*)(const PluginApi*)>(dlsym(handle, "datacrumbs_plugin_register"));
    if (reg == nullptr) {
      DC_LOG_ERROR("plugin %s: missing datacrumbs_plugin_register", path.c_str());
      continue;
    }
    if (!reg(&api)) {
      DC_LOG_ERROR("plugin %s: registration failed", path.c_str());
      continue;
    }
    DC_LOG_INFO("plugin %s: loaded", path.c_str());
  }
}
}  // namespace datacrumbs
