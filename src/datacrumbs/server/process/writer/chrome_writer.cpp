#include <datacrumbs/server/process/writer/chrome_writer.h>
// internal headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/compress/zlib_compressor.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <zlib.h>

#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <thread>

namespace {

std::string json_escape(const std::string& input) {
  std::string escaped;
  escaped.reserve(input.size() + 8);
  for (unsigned char ch : input) {
    switch (ch) {
      case '\"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (ch < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
          escaped += buffer;
        } else {
          escaped += static_cast<char>(ch);
        }
    }
  }
  return escaped;
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char byte : bytes) {
    oss << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return oss.str();
}

std::string pointer_json(unsigned long long raw_value) {
  std::ostringstream oss;
  oss << "\"0x" << std::hex << raw_value << "\"";
  return oss.str();
}

bool is_char_pointer_type(const std::string& c_type) {
  return c_type.find("char *") != std::string::npos ||
         c_type.find("const char *") != std::string::npos;
}
bool is_float_type(const std::string& c_type) {
  return c_type == "float";
}
bool is_double_type(const std::string& c_type) {
  return c_type == "double";
}
bool is_signed_type(const std::string& c_type) {
  if (c_type.empty()) return false;
  if (c_type.find("unsigned") != std::string::npos) return false;
  return c_type.find("int") != std::string::npos || c_type.find("long") != std::string::npos ||
         c_type.find("short") != std::string::npos || c_type.find("ssize_t") != std::string::npos ||
         c_type.find("pid_t") != std::string::npos || c_type == "char";
}

std::string decode_scalar_json(const CapturedArgumentValue& value) {
  const unsigned int width = std::min<std::size_t>(value.bytes.size(), sizeof(unsigned long long));
  unsigned long long raw = 0;
  if (width > 0) {
    std::memcpy(&raw, value.bytes.data(), width);
  } else {
    raw = value.raw_value;
  }

  if (is_float_type(value.c_type) && width >= sizeof(float)) {
    float number = 0.0f;
    std::memcpy(&number, value.bytes.data(), sizeof(float));
    return std::to_string(number);
  }
  if (is_double_type(value.c_type) && width >= sizeof(double)) {
    double number = 0.0;
    std::memcpy(&number, value.bytes.data(), sizeof(double));
    return std::to_string(number);
  }
  if (is_signed_type(value.c_type)) {
    long long signed_value = 0;
    switch (width) {
      case 1:
        signed_value = static_cast<signed char>(raw & 0xff);
        break;
      case 2:
        signed_value = static_cast<short>(raw & 0xffff);
        break;
      case 4:
        signed_value = static_cast<int>(raw & 0xffffffffu);
        break;
      default:
        signed_value = static_cast<long long>(raw);
        break;
    }
    return std::to_string(signed_value);
  }
  return std::to_string(raw);
}

std::string serialize_captured_argument(const CapturedArgumentValue& value) {
  if (value.is_pointer) {
    if (value.data_status == 2 && !value.bytes.empty()) {
      if (is_char_pointer_type(value.c_type)) {
        std::string text;
        for (unsigned char ch : value.bytes) {
          if (ch == '\0') break;
          text.push_back(static_cast<char>(ch));
        }
        return "\"" + json_escape(text) + "\"";
      }
      std::ostringstream oss;
      oss << "{\"value\":" << decode_scalar_json(value)
          << ",\"address\":" << pointer_json(value.raw_value) << "}";
      return oss.str();
    }
    return pointer_json(value.raw_value);
  }

  if ((value.data_status == 1 || value.data_status == 2) && !value.bytes.empty()) {
    return decode_scalar_json(value);
  }

  if (!value.bytes.empty()) {
    return "\"0x" + bytes_to_hex(value.bytes) + "\"";
  }

  return std::to_string(value.raw_value);
}

std::string serialize_any_value(const std::any& value) {
  if (value.type() == typeid(int)) {
    return std::to_string(std::any_cast<int>(value));
  } else if (value.type() == typeid(unsigned long long)) {
    return std::to_string(std::any_cast<unsigned long long>(value));
  } else if (value.type() == typeid(unsigned int)) {
    return std::to_string(std::any_cast<unsigned int>(value));
  } else if (value.type() == typeid(uint64_t)) {
    return std::to_string(std::any_cast<uint64_t>(value));
  } else if (value.type() == typeid(float)) {
    return std::to_string(std::any_cast<float>(value));
  } else if (value.type() == typeid(double)) {
    return std::to_string(std::any_cast<double>(value));
  } else if (value.type() == typeid(const char*)) {
    return "\"" + json_escape(std::any_cast<const char*>(value)) + "\"";
  } else if (value.type() == typeid(std::string)) {
    return "\"" + json_escape(std::any_cast<std::string>(value)) + "\"";
  } else if (value.type() == typeid(CapturedArgumentValue)) {
    return serialize_captured_argument(std::any_cast<CapturedArgumentValue>(value));
  } else if (value.type() == typeid(DataCrumbsArgs)) {
    // Nested object, e.g. args.hw = { counter: delta, ... }
    const auto& nested = std::any_cast<const DataCrumbsArgs&>(value);
    std::string out = "{";
    bool first = true;
    for (const auto& [k, v] : nested) {
      if (!first) out += ",";
      out += "\"" + json_escape(k) + "\":" + serialize_any_value(v);
      first = false;
    }
    out += "}";
    return out;
  }
  return "\"<unsupported>\"";
}

}  // namespace

// Specialization of the Singleton instance for KSymCapture.
// This holds the shared pointer to the singleton instance.
template <>
std::shared_ptr<datacrumbs::ChromeWriter>
    datacrumbs::Singleton<datacrumbs::ChromeWriter>::instance = nullptr;

// Specialization of the flag to stop creating new instances of KSymCapture.
template <>
bool datacrumbs::Singleton<datacrumbs::ChromeWriter>::stop_creating_instances = false;

namespace {
// env override for a numeric config; keeps the default if unset/unparseable.
long env_num(const char* name, long dflt) {
  if (const char* e = std::getenv(name)) {
    char* end = nullptr;
    long v = std::strtol(e, &end, 10);
    if (end != e) return v;
  }
  return dflt;
}

// Compress a buffer into a self-contained gzip member. Concatenated members form a
// valid multi-member gzip (Perfetto/gunzip read it as one stream), so members can be
// produced in parallel and appended in any order -- the .pfw is newline-delimited
// objects, no inter-event commas, so order doesn't matter.
std::vector<uint8_t> gzip_block(const std::string& in, int level) {
  z_stream s{};
  if (deflateInit2(&s, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
    throw std::runtime_error("deflateInit2 failed");
  std::vector<uint8_t> out(deflateBound(&s, in.size()));
  s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  s.avail_in = static_cast<uInt>(in.size());
  s.next_out = out.data();
  s.avail_out = static_cast<uInt>(out.size());
  int r = deflate(&s, Z_FINISH);
  deflateEnd(&s);
  if (r != Z_STREAM_END) throw std::runtime_error("deflate failed");
  out.resize(out.size() - s.avail_out);
  return out;
}
}  // namespace

namespace datacrumbs {
ChromeWriter::ChromeWriter()
    : stop_flag_(false), finalized_(false), index_(0), batch_events_(8192), flush_bytes_(1 << 20) {
  // Tunables (env-overridable for testing):
  //  MAX_QUEUE_EVENTS  backpressure bound on the poll->pool queue (0 = unbounded)
  //  WRITER_THREADS    parallel serialize+gzip+write workers
  //  ZLIB_LEVEL        deflate level (default 6; keep gzip for Perfetto)
  max_queue_events_ = static_cast<size_t>(env_num("DATACRUMBS_MAX_QUEUE_EVENTS", 500000));
  zlib_level_ = static_cast<int>(env_num("DATACRUMBS_ZLIB_LEVEL", Z_DEFAULT_COMPRESSION));
  long hw = static_cast<long>(std::thread::hardware_concurrency());
  long nthreads = env_num("DATACRUMBS_WRITER_THREADS", hw > 4 ? hw - 2 : 2);
  if (nthreads < 1) nthreads = 1;

  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  file_ = std::fopen(configManager_->trace_file_path.c_str(), "wb");
  if (!file_) throw std::runtime_error("Failed to open trace file for writing");
  auto pwd = getpwnam(configManager_->user.c_str());
  uid_t uid = pwd ? pwd->pw_uid : static_cast<uid_t>(-1);
  gid_t gid = pwd ? pwd->pw_gid : static_cast<gid_t>(-1);
  chown(configManager_->trace_file_path.c_str(), uid, gid);
  chmod(configManager_->trace_file_path.c_str(), 0660);

  {  // opening bracket as its own gzip member
    auto m = gzip_block("[\n", zlib_level_);
    std::fwrite(m.data(), 1, m.size(), file_);
  }
  map_timesync_snapshot();

  for (long i = 0; i < nthreads; ++i) workers_.emplace_back([this]() { this->worker_loop(); });
}

// mmap the daemon snapshot (best-effort; null -> timestamps stay CLOCK_MONOTONIC).
void ChromeWriter::map_timesync_snapshot() {
  const char* path = std::getenv("DC_TIMESYNC_SNAPSHOT");
  if (!path) path = DC_TIMESYNC_DEFAULT_PATH;
  int fd = ::open(path, O_RDONLY);
  if (fd < 0) {
    DC_LOG_DEBUG("dc_timesync snapshot %s not available; trace stays CLOCK_MONOTONIC", path);
    return;
  }
  void* p = ::mmap(nullptr, sizeof(dc_timesync_snapshot), PROT_READ, MAP_SHARED, fd, 0);
  ::close(fd);
  if (p == MAP_FAILED) return;
  tsync_ = reinterpret_cast<const volatile dc_timesync_snapshot*>(p);
  DC_LOG_PRINT("dc_timesync snapshot mapped from %s", path);
}

// Remap CLOCK_MONOTONIC ns onto the reference PHC via the seqlock snapshot; passthrough if no fix.
unsigned long long ChromeWriter::remap_ts(unsigned long long mono_ns) const {
  if (!tsync_) return mono_ns;
  dc_timesync_snapshot s;
  for (int tries = 0; tries < 4; ++tries) {  // seqlock: retry if a write straddled the read
    unsigned int seq1 = __atomic_load_n(&tsync_->seq, __ATOMIC_ACQUIRE);
    if (seq1 & 1u) continue;  // write in progress
    std::memcpy(&s, const_cast<const dc_timesync_snapshot*>(tsync_), sizeof(s));
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    unsigned int seq2 = __atomic_load_n(&tsync_->seq, __ATOMIC_RELAXED);
    if (seq1 == seq2) {
      if (s.magic != DC_TIMESYNC_MAGIC || !s.valid) return mono_ns;
      long long phc_local = static_cast<long long>(mono_ns) + s.bridge_mono_to_phc_ns;
      long long ref =
          phc_local + s.offset_ns +
          static_cast<long long>(s.skew_ppb * (phc_local - s.anchor_phc_ns) / 1000000000LL);
      return ref < 0 ? 0ull : static_cast<unsigned long long>(ref);
    }
  }
  return mono_ns;  // couldn't get a stable read; stay MONOTONIC this event
}

// Destructor flushes and closes the file, and joins all threads.
ChromeWriter::~ChromeWriter() {
  finalize();
}
void ChromeWriter::finalize() {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (finalized_) {
      return;
    }
    stop_flag_ = true;
    finalized_ = true;
  }
  queue_cv_.notify_all();     // wake all pool threads to drain + exit
  not_full_cv_.notify_all();  // release any producer blocked on backpressure
  for (auto& t : workers_)
    if (t.joinable()) t.join();

  if (file_) {
    auto m = gzip_block("]\n", zlib_level_);
    std::fwrite(m.data(), 1, m.size(), file_);
    std::fclose(file_);
    file_ = nullptr;
  }
  DC_LOG_DEBUG("ChromeWriter finalized");
}

void ChromeWriter::push_event(EventWithId* event) {
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (max_queue_events_)  // backpressure: block the producer until the writer drains
      not_full_cv_.wait(lock,
                        [this] { return event_queue_.size() < max_queue_events_ || stop_flag_; });
    event_queue_.emplace_back(event);
  }
  // Wake a worker for every event: with a multi-consumer pool, notifying only on
  // empty->nonempty leaves most workers parked while one drains the backlog (pathological
  // slowdown at high event rate). One notify/event keeps up to N workers active.
  queue_cv_.notify_one();
}

// Serialize one event to a JSON line (no compress/IO); frees the event. Thread-safe:
// runs on any pool worker (id is atomic; category_map is read-only during tracing).
std::string ChromeWriter::serialize_event(EventWithId* event_with_id) {
  unsigned long id = index_.fetch_add(1) + 1;
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  auto args = event_with_id->args;
  std::string result;

  unsigned int pid = event_with_id->tgid_pid;
  unsigned int tid = event_with_id->tgid_pid >> 32;
  auto it = configManager_->category_map.find(event_with_id->event_id);
  if (it != configManager_->category_map.end()) {
    std::string probe_name = it->second.first;
    std::string function_name = it->second.second;
    if (args != nullptr && event_with_id->event_type == COUNTER_EVENT &&
        args->find("duration") != args->end()) {
      unsigned long long duration = std::any_cast<unsigned int>((*args)["duration"]);
      if (duration > std::numeric_limits<unsigned long long>::max() / 1000) {
        duration = std::numeric_limits<unsigned long long>::max();
      } else {
        duration = static_cast<unsigned long long>(std::floor(duration / 1000.0));
      }
      (*args)["duration"] = duration;
    }
    char buffer[1024];
    // dc_timesync: remap MONOTONIC -> shared reference timeline (passthrough if no fix).
    // Integer divide (not double floor): reference-PHC ns are ~1.8e18 and would trip
    // the old ULLONG_MAX/1000 double-overflow guard and clamp to a sentinel.
    unsigned long long ts_us = remap_ts(event_with_id->ts) / 1000;
    unsigned long long dur_us = 0;
    if (event_with_id->dur > std::numeric_limits<unsigned long long>::max() / 1000) {
      dur_us = std::numeric_limits<unsigned long long>::max();
    } else {
      dur_us = static_cast<unsigned long long>(std::ceil(event_with_id->dur / 1000.0));
    }
    int len = 0;
    if (event_with_id->event_type == COUNTER_EVENT) {
      len = std::snprintf(
          buffer, sizeof(buffer), R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c","ts":%llu)", id,
          function_name.c_str(), probe_name.c_str(), event_with_id->event_type, ts_us);
    } else if (event_with_id->event_type == METADATA_EVENT) {
      len = std::snprintf(buffer, sizeof(buffer), R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c")",
                          id, function_name.c_str(), probe_name.c_str(), event_with_id->event_type);
    } else if (event_with_id->event_type == NORMAL_EVENT) {
      // Normal even
      len = std::snprintf(
          buffer, sizeof(buffer),
          R"({"id":%lu,"name":"%s","cat":"%s","ph":"%c","ts":%llu,"dur":%llu,"pid":%d,"tid":%d)",
          id, function_name.c_str(), probe_name.c_str(), event_with_id->event_type, ts_us, dur_us,
          pid, tid);
    } else {
      len = 0;  // unknown event type -> skip (empty result)
    }

    std::string args_json = "{";

    bool first = true;
    if (args != nullptr && !args->empty()) {
      for (auto pair : *args) {
        const std::string& key = pair.first;
        const std::any& value = pair.second;
        if (!first) args_json += ",";
        args_json += "\"";
        args_json += key;
        args_json += "\":";
        args_json += serialize_any_value(value);
        first = false;
      }
    }
    args_json += "}";

    if (len > 0) result = std::string(buffer, len) + ",\"args\":" + args_json + "}\n";
  }
  // Clock-domain metadata on the first line. global emits the full fit (offset/skew/anchor) so a
  // reader can remap other same-domain-PHC timestamps (e.g. NIC hw_ns) exactly, not just monotonic.
  if (!domain_emitted_.exchange(true)) {
    char meta[256];
    int mlen;
    dc_timesync_snapshot s{};
    if (tsync_) std::memcpy(&s, const_cast<const dc_timesync_snapshot*>(tsync_), sizeof(s));
    if (tsync_ && s.magic == DC_TIMESYNC_MAGIC && s.valid)
      mlen = std::snprintf(
          meta, sizeof(meta),
          R"({"name":"datacrumbs.clock_domain","ph":"M","args":{"domain":"global","ref_id":%u,"self_id":%u,"offset_ns":%lld,"skew_ppb":%lld,"anchor_phc_ns":%lld}})"
          "\n",
          s.ref_id, s.self_id, (long long)s.offset_ns, (long long)s.skew_ppb,
          (long long)s.anchor_phc_ns);
    else
      mlen = std::snprintf(
          meta, sizeof(meta),
          R"({"name":"datacrumbs.clock_domain","ph":"M","args":{"domain":"monotonic"}})"
          "\n");
    if (mlen > 0) result = std::string(meta, mlen) + result;
  }
  if (args != nullptr) {
    delete args;  // Clean up args after use
  }
  if (event_with_id != nullptr) {
    delete event_with_id;  // Clean up event after writing
  }
  return result;
}

// Pool thread: grab up to batch_events_ events under the lock, then serialize + gzip +
// append the member (order-independent since the .pfw is newline-delimited). Single
// bounded queue + backpressure -> parallel compression with no cross-stage coordination.
void ChromeWriter::worker_loop() {
  std::deque<EventWithId*> batch;
  std::string acc;
  while (true) {
    bool stopping = false;
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this] { return !event_queue_.empty() || stop_flag_; });
      if (event_queue_.empty()) {
        stopping = true;  // woken by stop with nothing left
      } else {
        size_t n = std::min(batch_events_, event_queue_.size());
        batch.assign(event_queue_.begin(), event_queue_.begin() + n);
        event_queue_.erase(event_queue_.begin(), event_queue_.begin() + n);
      }
    }
    not_full_cv_.notify_all();  // freed space -> wake producer blocked on backpressure
    for (EventWithId* e : batch)
      if (e != nullptr) acc += serialize_event(e);  // frees e
    batch.clear();
    // Coalesce into ~flush_bytes_ gzip members. At low arrival rate each grab is tiny;
    // one member per grab would mean ~one member per event -> huge per-member gzip
    // overhead + bloated output. Compress only once the accumulator is full (or at stop).
    if (acc.size() >= flush_bytes_ || (stopping && !acc.empty())) {
      auto member = gzip_block(acc, zlib_level_);
      std::lock_guard<std::mutex> lock(file_mutex_);
      std::fwrite(member.data(), 1, member.size(), file_);
      acc.clear();
    }
    if (stopping) break;
  }
}
}  // namespace datacrumbs
