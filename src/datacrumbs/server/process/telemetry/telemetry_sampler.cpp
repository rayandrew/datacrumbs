#include <bpf/bpf.h>
#include <datacrumbs/common/enumerations.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/process/telemetry/telemetry_sampler.h>
#include <linux/ethtool.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <rdma/rdma_netlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
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
  // hdr.data is a kernel zero-length array (linux/ethtool.h); buf[0] is its actual storage.
  return q.hdr.sset_mask ? static_cast<int>(q.buf[0]) : 0;
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

namespace {
// Minimal netlink attribute walk. RDMA nldev replies are nested tables of (type, len, payload).
struct NlAttrView {
  const struct nlattr* a;
  const void* payload() const { return reinterpret_cast<const char*>(a) + NLA_HDRLEN; }
  unsigned int plen() const { return a->nla_len - NLA_HDRLEN; }
};

template <typename F>
void for_each_attr(const void* buf, unsigned int len, F&& fn) {
  const char* p = static_cast<const char*>(buf);
  while (len >= NLA_HDRLEN) {
    const auto* a = reinterpret_cast<const struct nlattr*>(p);
    if (a->nla_len < NLA_HDRLEN || a->nla_len > len) return;
    fn(NlAttrView{a});
    const unsigned int step = NLA_ALIGN(a->nla_len);
    if (step > len) return;
    p += step;
    len -= step;
  }
}

unsigned int attr_type(const NlAttrView& v) {
  return v.a->nla_type & NLA_TYPE_MASK;
}

// Append one attribute to a netlink request buffer.
void put_attr(char* buf, std::size_t& off, unsigned short type, const void* data,
              unsigned short len) {
  auto* a = reinterpret_cast<struct nlattr*>(buf + off);
  a->nla_type = type;
  a->nla_len = static_cast<unsigned short>(NLA_HDRLEN + len);
  std::memcpy(buf + off + NLA_HDRLEN, data, len);
  off += NLA_ALIGN(a->nla_len);
}

// ibdev name -> nldev index, via a RDMA_NLDEV_CMD_GET dump. /sys/class/infiniband/<dev>/index does
// not exist on every kernel (absent on the BlueField DOCA kernels), so netlink is the portable way.
int resolve_dev_index(int fd, unsigned int seq, const std::string& want) {
  char req[128] = {};
  auto* nh = reinterpret_cast<struct nlmsghdr*>(req);
  nh->nlmsg_type = static_cast<unsigned short>(RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_GET));
  nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nh->nlmsg_seq = seq;
  nh->nlmsg_len = NLMSG_HDRLEN;
  if (send(fd, req, nh->nlmsg_len, 0) < 0) return -1;

  std::vector<char> buf(32768);
  int found = -1;
  for (;;) {
    const ssize_t got = recv(fd, buf.data(), buf.size(), 0);
    if (got <= 0) return found;
    unsigned int n = static_cast<unsigned int>(got);
    const auto* h = reinterpret_cast<const struct nlmsghdr*>(buf.data());
    for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
      if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) return found;
      int idx = -1;
      std::string name;
      for_each_attr(NLMSG_DATA(h), NLMSG_PAYLOAD(h, 0), [&](const NlAttrView& a) {
        if (attr_type(a) == RDMA_NLDEV_ATTR_DEV_INDEX) {
          uint32_t v = 0;
          std::memcpy(&v, a.payload(), sizeof(v));
          idx = static_cast<int>(v);
        } else if (attr_type(a) == RDMA_NLDEV_ATTR_DEV_NAME) {
          name.assign(static_cast<const char*>(a.payload()));
        }
      });
      if (!name.empty() && name == want) found = idx;
    }
  }
}
}  // namespace

void RdmaQpTelemetrySampler::on_start() {
  fd_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_RDMA);
  if (fd_ < 0) {
    DC_LOG_WARN("[Telemetry] rdma netlink unavailable -> per-QP counters disabled");
    return;
  }
  struct sockaddr_nl sa = {};
  sa.nl_family = AF_NETLINK;
  if (bind(fd_, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
    close(fd_);
    fd_ = -1;
    return;
  }
  dev_index_.assign(sources_.size(), -1);
  port_.assign(sources_.size(), 1);
  values_.assign(sources_.size(), {});
  for (std::size_t s = 0; s < sources_.size(); ++s) {
    std::string dev = sources_[s].name;
    if (const auto slash = dev.find('/'); slash != std::string::npos) {
      port_[s] = static_cast<unsigned int>(std::strtoul(dev.c_str() + slash + 1, nullptr, 10));
      dev = dev.substr(0, slash);
    }
    dev_index_[s] = resolve_dev_index(fd_, ++seq_, dev);
    if (dev_index_[s] < 0)
      DC_LOG_WARN("[Telemetry] rdma %s: no device index -> per-QP counters skipped", dev.c_str());
  }
}

void RdmaQpTelemetrySampler::on_stop() {
  if (fd_ >= 0) close(fd_);
  fd_ = -1;
}

// One STAT_GET dump for this port; sum each hw counter across the bound counter sets.
bool RdmaQpTelemetrySampler::refresh(std::size_t src) {
  if (fd_ < 0 || dev_index_[src] < 0) return false;
  char req[256] = {};
  auto* nh = reinterpret_cast<struct nlmsghdr*>(req);
  nh->nlmsg_type =
      static_cast<unsigned short>(RDMA_NL_GET_TYPE(RDMA_NL_NLDEV, RDMA_NLDEV_CMD_STAT_GET));
  nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nh->nlmsg_seq = ++seq_;
  std::size_t off = NLMSG_HDRLEN;
  const uint32_t dev = static_cast<uint32_t>(dev_index_[src]);
  const uint32_t port = port_[src];
  const uint32_t res = RDMA_NLDEV_ATTR_RES_QP;
  put_attr(req, off, RDMA_NLDEV_ATTR_DEV_INDEX, &dev, sizeof(dev));
  put_attr(req, off, RDMA_NLDEV_ATTR_PORT_INDEX, &port, sizeof(port));
  put_attr(req, off, RDMA_NLDEV_ATTR_STAT_RES, &res, sizeof(res));
  nh->nlmsg_len = static_cast<unsigned int>(off);
  if (send(fd_, req, off, 0) < 0) return false;

  values_[src].clear();
  std::vector<char> buf(65536);
  bool done = false;
  while (!done) {
    const ssize_t got = recv(fd_, buf.data(), buf.size(), 0);
    if (got <= 0) return !values_[src].empty();
    unsigned int n = static_cast<unsigned int>(got);  // NLMSG_NEXT mutates this
    const auto* h = reinterpret_cast<const struct nlmsghdr*>(buf.data());
    for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
      if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
        done = true;
        break;
      }
      for_each_attr(NLMSG_DATA(h), NLMSG_PAYLOAD(h, 0), [&](const NlAttrView& top) {
        if (attr_type(top) != RDMA_NLDEV_ATTR_STAT_COUNTER) return;
        for_each_attr(top.payload(), top.plen(), [&](const NlAttrView& entry) {
          if (attr_type(entry) != RDMA_NLDEV_ATTR_STAT_COUNTER_ENTRY) return;
          for_each_attr(entry.payload(), entry.plen(), [&](const NlAttrView& f) {
            if (attr_type(f) != RDMA_NLDEV_ATTR_STAT_HWCOUNTERS) return;
            for_each_attr(f.payload(), f.plen(), [&](const NlAttrView& hw) {
              if (attr_type(hw) != RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY) return;
              std::string name;
              unsigned long long val = 0;
              for_each_attr(hw.payload(), hw.plen(), [&](const NlAttrView& kv) {
                if (attr_type(kv) == RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_NAME)
                  name.assign(static_cast<const char*>(kv.payload()));
                else if (attr_type(kv) == RDMA_NLDEV_ATTR_STAT_HWCOUNTER_ENTRY_VALUE)
                  std::memcpy(&val, kv.payload(), sizeof(val));
              });
              if (!name.empty()) values_[src][name] += val;
            });
          });
        });
      });
    }
  }
  return !values_[src].empty();
}

bool RdmaQpTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  if (fd_ < 0 || src >= values_.size()) return false;
  if (ctr == 0 && !refresh(src)) return false;
  const auto it = values_[src].find(sources_[src].counters[ctr].path);
  if (it == values_[src].end()) return false;
  *out = it->second;
  return true;
}

namespace {
struct PmuKind {
  const char* name;
  uint32_t type;
  uint64_t config;
};
const PmuKind kTaskKinds[] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
    {"cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
    {"page-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS},
    {"major-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ},
    {"minor-faults", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN},
    {"context-switches", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES},
    {"task-clock", PERF_TYPE_SOFTWARE, PERF_COUNT_SW_TASK_CLOCK},
};

int task_perf_open(const std::string& name, unsigned int tgid) {
  const PmuKind* kind = nullptr;
  for (const auto& k : kTaskKinds)
    if (name == k.name) kind = &k;
  if (kind == nullptr) return -1;
  struct perf_event_attr attr = {};
  attr.size = sizeof(attr);
  attr.type = kind->type;
  attr.config = kind->config;
  attr.disabled = 0;
  attr.inherit = 1;  // follow threads this process spawns later
  attr.exclude_kernel = 0;
  attr.exclude_hv = 1;
  return static_cast<int>(
      syscall(__NR_perf_event_open, &attr, static_cast<int>(tgid), -1, -1, PERF_FLAG_FD_CLOEXEC));
}
}  // namespace

void TaskPmuTelemetrySampler::on_start() {
  if (pid_map_fd_ < 0)
    DC_LOG_WARN("[Telemetry] task PMU: no pid_map -> per-process counters disabled");
}

void TaskPmuTelemetrySampler::on_stop() {
  for (auto& [tgid, fds] : fds_)
    for (int fd : fds)
      if (fd >= 0) close(fd);
  fds_.clear();
}

// Traced tgids from the BPF pid_map; a process that appears mid-run gets counters from then on.
void TaskPmuTelemetrySampler::refresh_pids(std::size_t src) {
  if (pid_map_fd_ < 0) return;
  unsigned int key = 0, next = 0;
  std::vector<unsigned int> live;
  while (bpf_map_get_next_key(pid_map_fd_, fds_.empty() && key == 0 ? nullptr : &key, &next) == 0) {
    live.push_back(next);
    key = next;
    if (live.size() > 4096) break;
  }
  for (unsigned int tgid : live) {
    if (fds_.count(tgid)) continue;
    std::vector<int> opened;
    for (const auto& c : sources_[src].counters) opened.push_back(task_perf_open(c.label, tgid));
    if (std::any_of(opened.begin(), opened.end(), [](int f) { return f >= 0; })) {
      fds_[tgid] = std::move(opened);
      DC_LOG_INFO("[Telemetry] task PMU: attached to tgid %u", tgid);
    } else {
      for (int f : opened)
        if (f >= 0) close(f);
    }
  }
}

bool TaskPmuTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  if (ctr == 0) refresh_pids(src);
  unsigned long long total = 0;
  bool any = false;
  for (auto& [tgid, fds] : fds_) {
    if (ctr >= fds.size() || fds[ctr] < 0) continue;
    unsigned long long v = 0;
    if (read(fds[ctr], &v, sizeof(v)) == static_cast<ssize_t>(sizeof(v))) {
      total += v;
      any = true;
    }
  }
  if (!any) return false;
  *out = total;
  return true;
}

namespace {

// One whitespace-separated field from a procfs line, 1-indexed as procfs(5) numbers them.
bool field_at(const std::string& line, int index, unsigned long long* out) {
  const char* p = line.c_str();
  for (int i = 1; i < index; ++i) {
    while (*p != '\0' && *p != ' ') ++p;
    while (*p == ' ') ++p;
    if (*p == '\0') return false;
  }
  char* end = nullptr;
  const unsigned long long v = std::strtoull(p, &end, 10);
  if (end == p) return false;
  *out = v;
  return true;
}

// A "key: value" line from /proc/meminfo or /proc/<pid>/status.
bool keyed_value(const std::string& path, const std::string& key, unsigned long long* out) {
  std::ifstream f(path);
  std::string line;
  while (std::getline(f, line)) {
    if (line.compare(0, key.size(), key) != 0 || line[key.size()] != ':') continue;
    return field_at(line.substr(key.size() + 1), 1, out);
  }
  return false;
}

// One field for one pid. utime and stime are fields 14 and 15 of /proc/<pid>/stat and num_threads
// is 20; resident size comes from status instead because stat reports it in pages while status is
// already kB.
bool read_proc_field(const std::string& pid, const std::string& field, unsigned long long* out) {
  if (field.rfind("Vm", 0) == 0) return keyed_value("/proc/" + pid + "/status", field, out);
  static const std::map<std::string, int> kStatField = {
      {"utime", 14}, {"stime", 15}, {"num_threads", 20}, {"minflt", 10}, {"majflt", 12}};
  const auto it = kStatField.find(field);
  if (it == kStatField.end()) return false;
  std::ifstream f("/proc/" + pid + "/stat");
  std::string line;
  if (!std::getline(f, line)) return false;
  // comm is parenthesised and may contain spaces, so index from after the closing paren.
  const std::size_t close = line.rfind(')');
  if (close == std::string::npos) return false;
  return field_at(line.substr(close + 2), it->second - 2, out);
}

}  // namespace

bool ProcTelemetrySampler::read_raw(std::size_t src, std::size_t ctr, unsigned long long* out) {
  const std::string& field = sources_[src].counters[ctr].path;

  if (sources_[src].name == "node") {
    if (field.rfind("mem.", 0) == 0) return keyed_value("/proc/meminfo", field.substr(4), out);
    std::ifstream f("/proc/stat");
    std::string line;
    while (std::getline(f, line)) {
      if (line.rfind("cpu ", 0) == 0) {
        // The aggregate cpu line: "cpu" then user nice system idle iowait irq softirq steal.
        static const char* kCpuFields[] = {"user",   "nice", "system",  "idle",
                                           "iowait", "irq",  "softirq", "steal"};
        for (int i = 0; i < 8; ++i)
          if (field == kCpuFields[i]) return field_at(line, i + 2, out);
        continue;
      }
      if (line.rfind(field + " ", 0) == 0) return field_at(line, 2, out);  // ctxt, processes
    }
    return false;
  }

  // Process scope, summed across the traced tgids exactly as the task PMU sampler does: one value
  // per counter for the workload as a whole, rather than a source per pid that would churn as
  // processes come and go.
  if (pid_map_fd_ < 0) return false;
  unsigned int key = 0, next = 0;
  bool first = true, any = false;
  unsigned long long total = 0;
  std::size_t seen = 0;
  while (bpf_map_get_next_key(pid_map_fd_, first ? nullptr : &key, &next) == 0) {
    first = false;
    key = next;
    if (++seen > 4096) break;
    unsigned long long v = 0;
    if (read_proc_field(std::to_string(next), field, &v)) {
      total += v;
      any = true;
    }
  }
  if (!any) return false;
  *out = total;
  return true;
}

}  // namespace datacrumbs
