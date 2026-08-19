#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace datacrumbs {

namespace {
unsigned long long monotonic_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}
}  // namespace

TelemetrySampler::TelemetrySampler(std::shared_ptr<ChromeWriter> writer,
                                   std::vector<TelemetrySource> sources, unsigned int interval_ms,
                                   std::atomic<uint64_t>* event_index)
    : sources_(std::move(sources)),
      writer_(std::move(writer)),
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
  on_start();
  running_ = true;
  thread_ = std::thread([this] { loop(); });
  DC_LOG_INFO("Telemetry sampler started: %zu source(s) @ %u ms", sources_.size(), interval_ms_);
}

void TelemetrySampler::stop() {
  if (running_.exchange(false)) {
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    on_stop();
  }
}

void TelemetrySampler::loop() {
  bool primed = false;  // first tick only seeds prev_ (no delta yet)
  while (running_) {
    for (size_t s = 0; s < sources_.size(); ++s) {
      auto* args = new DataCrumbsArgs();
      for (size_t c = 0; c < sources_[s].counters.size(); ++c) {
        unsigned long long raw = 0;
        if (!read_raw(s, c, &raw)) continue;
        const unsigned long long prev = prev_[s][c];
        prev_[s][c] = raw;
        if (!primed) continue;
        const unsigned long long delta = raw >= prev ? raw - prev : 0;  // counter reset -> 0
        args->emplace(sources_[s].counters[c].label,
                      static_cast<unsigned long long>(delta * sources_[s].counters[c].scale));
      }
      if (primed && !args->empty()) {
        writer_->push_event(new EventWithId(TracePhase::COUNTER, event_index_->fetch_add(1), 0, 0,
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

bool SysfsTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  FILE* f = std::fopen(sources_[src].counters[ctr].path.c_str(), "r");
  if (!f) return false;
  const bool ok = std::fscanf(f, "%llu", out) == 1;
  std::fclose(f);
  return ok;
}

namespace {
// One SIOCETHTOOL call. `cmd_block` is an ethtool_* struct whose first member is the command.
bool ethtool_call(int fd, const char* ifname, void* cmd_block) {
  struct ifreq ifr = {};
  std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
  ifr.ifr_data = reinterpret_cast<char*>(cmd_block);
  return ioctl(fd, SIOCETHTOOL, &ifr) == 0;
}

// Number of ETH_SS_STATS strings the device exposes, or -1.
int ethtool_stat_count(int fd, const char* ifname) {
  struct {
    struct ethtool_sset_info hdr;
    uint32_t buf[1];
  } q = {};
  q.hdr.cmd = ETHTOOL_GSSET_INFO;
  q.hdr.sset_mask = 1ULL << ETH_SS_STATS;
  if (!ethtool_call(fd, ifname, &q)) return -1;
  return q.hdr.sset_mask ? static_cast<int>(q.hdr.data[0]) : 0;
}
}  // namespace

void EthtoolTelemetrySampler::on_start() {
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) {
    DC_LOG_WARN("[Telemetry] ethtool: no socket -> driver stats disabled");
    return;
  }
  index_.assign(sources_.size(), {});
  values_.assign(sources_.size(), {});
  for (std::size_t s = 0; s < sources_.size(); ++s) {
    const std::string& dev = sources_[s].name;
    index_[s].assign(sources_[s].counters.size(), -1);
    const int n = ethtool_stat_count(fd_, dev.c_str());
    if (n <= 0) {
      DC_LOG_WARN("[Telemetry] ethtool %s: no ETH_SS_STATS -> skipped", dev.c_str());
      continue;
    }
    std::vector<char> raw(sizeof(struct ethtool_gstrings) +
                          static_cast<std::size_t>(n) * ETH_GSTRING_LEN);
    auto* gs = reinterpret_cast<struct ethtool_gstrings*>(raw.data());
    gs->cmd = ETHTOOL_GSTRINGS;
    gs->string_set = ETH_SS_STATS;
    gs->len = static_cast<uint32_t>(n);
    if (!ethtool_call(fd_, dev.c_str(), gs)) {
      DC_LOG_WARN("[Telemetry] ethtool %s: GSTRINGS failed -> skipped", dev.c_str());
      continue;
    }
    values_[s].assign(static_cast<std::size_t>(n), 0);
    for (std::size_t c = 0; c < sources_[s].counters.size(); ++c) {
      const std::string& want = sources_[s].counters[c].path;  // stat name, not a filesystem path
      for (int i = 0; i < n; ++i) {
        char name[ETH_GSTRING_LEN + 1] = {};
        std::memcpy(name, gs->data + static_cast<std::size_t>(i) * ETH_GSTRING_LEN,
                    ETH_GSTRING_LEN);
        if (want == name) {
          index_[s][c] = i;
          break;
        }
      }
      if (index_[s][c] < 0)
        DC_LOG_WARN("[Telemetry] ethtool %s: no stat '%s'", dev.c_str(), want.c_str());
    }
  }
}

void EthtoolTelemetrySampler::on_stop() {
  if (fd_ >= 0) close(fd_);
  fd_ = -1;
}

// Pull every stat for one source in a single ioctl; per-counter reads index into this.
bool EthtoolTelemetrySampler::refresh(std::size_t src) {
  const std::size_t n = values_[src].size();
  if (n == 0) return false;
  std::vector<char> raw(sizeof(struct ethtool_stats) + n * sizeof(uint64_t));
  auto* st = reinterpret_cast<struct ethtool_stats*>(raw.data());
  st->cmd = ETHTOOL_GSTATS;
  st->n_stats = static_cast<uint32_t>(n);
  if (!ethtool_call(fd_, sources_[src].name.c_str(), st)) return false;
  for (std::size_t i = 0; i < n; ++i) values_[src][i] = st->data[i];
  return true;
}

bool EthtoolTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  if (fd_ < 0 || src >= index_.size()) return false;
  if (ctr == 0 && !refresh(src)) return false;
  const int i = index_[src][ctr];
  if (i < 0 || static_cast<std::size_t>(i) >= values_[src].size()) return false;
  *out = values_[src][static_cast<std::size_t>(i)];
  return true;
}

}  // namespace datacrumbs
