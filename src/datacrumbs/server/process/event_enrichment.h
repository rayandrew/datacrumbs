#pragma once
#include <datacrumbs/common/plugin_api.h>

#include <vector>

namespace datacrumbs {

// The server's enricher registry (EventEnricher defined in plugin_api.h). Enrichers run on every
// event in the writer; registration is not synchronized with the running writer, so register at
// startup only.
inline std::vector<EventEnricher>& event_enrichers() {
  static std::vector<EventEnricher> registry;
  return registry;
}

inline void register_event_enricher(EventEnricher enricher) {
  event_enrichers().push_back(std::move(enricher));
}

inline void run_event_enrichers(EventWithId* event) {
  for (const auto& enricher : event_enrichers()) enricher(event);
}
}  // namespace datacrumbs
