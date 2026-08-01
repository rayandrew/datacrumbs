#pragma once
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/plugin_api.h>
#include <dlfcn.h>

#include <cstdlib>
#include <string>

#include "event_enrichment.h"

namespace datacrumbs {

// dlopen each plugin in DATACRUMBS_PLUGINS (":"-separated .so paths) and call its
// datacrumbs_plugin_register with an api bound to this process's registries. Handles stay open for
// the process lifetime; a plugin that fails to load or register is logged and skipped, not fatal.
inline void load_plugins() {
  const char* list = std::getenv("DATACRUMBS_PLUGINS");
  if (list == nullptr || *list == '\0') return;

  static const PluginApi api{PluginApi::kAbiVersion, &register_event_enricher, &register_bpf_ready};

  const std::string spec(list);
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
    auto* reg = reinterpret_cast<bool (*)(const PluginApi*)>(
        dlsym(handle, "datacrumbs_plugin_register"));
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
