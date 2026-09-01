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

// Hooks a plugin registers to prime BPF maps once the skeleton is loaded (see plugin_api.h).
inline std::vector<PluginBpfReady>& bpf_ready_hooks() {
  static std::vector<PluginBpfReady> registry;
  return registry;
}

inline void register_bpf_ready(PluginBpfReady hook) {
  bpf_ready_hooks().push_back(std::move(hook));
}

inline void run_bpf_ready(const PluginBpfContext& ctx) {
  for (const auto& hook : bpf_ready_hooks()) hook(ctx);
}

// Samplers a plugin registers, with the interval it asked for. The server owns the threads: a
// plugin spawning its own would outlive the writer it emits into.
struct PluginSamplerSpec {
  unsigned int interval_ms;
  PluginSampler sampler;
};

inline std::vector<PluginSamplerSpec>& plugin_samplers() {
  static std::vector<PluginSamplerSpec> registry;
  return registry;
}

inline void register_plugin_sampler(unsigned int interval_ms, PluginSampler sampler) {
  plugin_samplers().push_back({interval_ms, std::move(sampler)});
}
}  // namespace datacrumbs
