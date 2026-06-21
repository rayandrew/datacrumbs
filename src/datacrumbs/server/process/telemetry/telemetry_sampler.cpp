#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>
#include <time.h>

#include <chrono>
#include <cstdio>

namespace datacrumbs {

namespace {
// Returns false if the path is unreadable (series skipped this tick).
bool read_u64(const std::string& path, unsigned long long* out) {
  FILE* f = std::fopen(path.c_str(), "r");
  if (!f) return false;
  const bool ok = std::fscanf(f, "%llu", out) == 1;
  std::fclose(f);
  return ok;
}

unsigned long long monotonic_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}
}  // namespace

TelemetrySampler::TelemetrySampler(std::shared_ptr<ChromeWriter> writer,
                                   std::vector<TelemetrySource> sources, unsigned int interval_ms,
                                   std::atomic<uint64_t>* event_index)
    : writer_(std::move(writer)),
      sources_(std::move(sources)),
      interval_ms_(interval_ms ? interval_ms : 100),
      event_index_(event_index) {
  prev_.resize(sources_.size());
  for (size_t i = 0; i < sources_.size(); ++i) prev_[i].assign(sources_[i].counters.size(), 0);
}

TelemetrySampler::~TelemetrySampler() {
  stop();
}

void TelemetrySampler::start() {
  if (sources_.empty() || !writer_) return;
  running_ = true;
  thread_ = std::thread([this] { loop(); });
  DC_LOG_INFO("Telemetry sampler started: %zu source(s) @ %u ms", sources_.size(), interval_ms_);
}

void TelemetrySampler::stop() {
  if (!running_.exchange(false)) return;
  cv_.notify_all();
  if (thread_.joinable()) thread_.join();
}

void TelemetrySampler::loop() {
  bool primed = false;  // first tick only seeds prev_ (no delta yet)
  while (running_) {
    for (size_t s = 0; s < sources_.size(); ++s) {
      auto* args = new DataCrumbsArgs();
      for (size_t c = 0; c < sources_[s].counters.size(); ++c) {
        const auto& ctr = sources_[s].counters[c];
        unsigned long long raw = 0;
        if (!read_u64(ctr.path, &raw)) continue;
        const unsigned long long prev = prev_[s][c];
        prev_[s][c] = raw;
        if (!primed) continue;
        const unsigned long long delta = raw >= prev ? raw - prev : 0;  // counter reset -> 0
        args->emplace(ctr.label, static_cast<unsigned long long>(delta * ctr.scale));
      }
      if (primed && !args->empty()) {
        writer_->push_event(new EventWithId(COUNTER_EVENT, event_index_->fetch_add(1), 0, 0,
                                            sources_[s].event_id, monotonic_ns(), 0, args));
      } else {
        delete args;
      }
    }
    primed = true;
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, std::chrono::milliseconds(interval_ms_), [this] { return !running_; });
  }
}

}  // namespace datacrumbs
