#pragma once
#include <functional>
#include <vector>

namespace datacrumbs {
struct EventWithId;

// An enricher may modify an event (its ts or args) before serialization. It runs on every event in
// the writer, whatever backend produced it. Register at startup; registration is not synchronized
// with the running writer.
using EventEnricher = std::function<void(EventWithId*)>;

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
