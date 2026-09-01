#include <datacrumbs/server/process/writer/chrome_writer.h>
#include <datacrumbs/server/process/writer/json_escape.h>

#include <chrono>
// internal headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
#include <datacrumbs/common/pfw_format.h>
#include <datacrumbs/common/runtime_configuration_manager.h>
#include <datacrumbs/common/singleton.h>
#include <datacrumbs/common/typedefs.h>
#include <datacrumbs/server/bpf/shared.h>
#include <datacrumbs/server/process/event_enrichment.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {
using datacrumbs::writer::json_escape;

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
  }
  return "\"<unsupported>\"";
}

}  // namespace

namespace datacrumbs {
ChromeWriter::ChromeWriter() : flush_bytes_(1 << 20) {
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();

  // Env-overridable: MAX_QUEUE_EVENTS bounds the backpressure queue (0 = unbounded); ZLIB_LEVEL
  // sets the deflate level (gzip framing kept for Perfetto); WRITER_THREADS scales the
  // serialize+gzip pool (default 1 to keep the server off the traced cores; raise it when the
  // writer is a firehose bottleneck and backpressure would otherwise stall the ring drain).
  max_queue_events_ = static_cast<size_t>(configManager_->max_queue_events);
  // A guard against an unbounded hang, not a sampling policy. Blocking is the deliberate choice
  // here and it has never been observed to fire on this cluster: the run that looked like writer
  // backpressure was a clock-domain mistake elsewhere, and stall_count stayed zero throughout.
  // Thirty seconds is far longer than any real burst, so the trace stays complete in practice while
  // a wedged writer can no longer stop collection for the rest of a run. Lower it deliberately to
  // trade completeness for coverage.
  stall_budget_ = std::chrono::milliseconds(configManager_->stall_budget_ms);
  zlib_level_ = configManager_->zlib_level;
  long nthreads = configManager_->writer_threads;
  if (nthreads < 1) nthreads = 1;

  file_ = std::fopen(configManager_->trace_file_path.c_str(), "wb");
  if (!file_) throw std::runtime_error("Failed to open trace file for writing");
  auto pwd = getpwnam(configManager_->user.c_str());
  uid_t uid = pwd ? pwd->pw_uid : static_cast<uid_t>(-1);
  gid_t gid = pwd ? pwd->pw_gid : static_cast<gid_t>(-1);
  if (chown(configManager_->trace_file_path.c_str(), uid, gid) != 0) {
    DC_LOG_WARN("[ChromeWriter] Failed to chown trace file %s to %s: %s",
                configManager_->trace_file_path.c_str(), configManager_->user.c_str(),
                strerror(errno));
  }
  chmod(configManager_->trace_file_path.c_str(), 0660);

  char host[256] = {0};
  gethostname(host, sizeof(host) - 1);
  hostname_ = host;
  hhash_ = datacrumbs::pfw::hhash(hostname_);
  // dftracer "HH" record: lets the reader resolve this hhash back to the hostname.
  write_member("{\"name\":\"HH\",\"cat\":\"dftracer\",\"type\":\"metadata\",\"ph\":" +
               std::to_string(static_cast<unsigned>(TracePhase::METADATA)) +
               ",\"args\":{\"hhash\":\"" + hhash_ + "\",\"name\":\"" + json_escape(hostname_) +
               "\",\"value\":\"" + hhash_ + "\"}}\n");
  // The unit of ts and dur, chosen at build time. Stated rather than assumed, as dftracer states
  // it, so a reader never has to guess and a change of unit cannot silently rescale a whole trace.
  write_member("{\"name\":\"time_metric\",\"cat\":\"dftracer\",\"type\":\"metadata\",\"ph\":" +
               std::to_string(static_cast<unsigned>(TracePhase::METADATA)) +
               ",\"args\":{\"hhash\":\"" + hhash_ +
               "\",\"name\":\"time_metric\",\"value\":\"" DATACRUMBS_TIME_UNIT "\"}}\n");

  for (long i = 0; i < nthreads; ++i) workers_.emplace_back([this]() { this->worker_loop(); });
}

ChromeWriter::~ChromeWriter() {
  finalize();
}

void ChromeWriter::finalize() {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (finalized_) return;
    stop_flag_ = true;
    finalized_ = true;
  }
  queue_cv_.notify_all();
  not_full_cv_.notify_all();  // release any producer blocked on backpressure
  for (auto& w : workers_)
    if (w.joinable()) w.join();
  if (file_) {
    std::fclose(file_);
    file_ = nullptr;
  }
  DC_LOG_DEBUG("ChromeWriter finalized");
}

void ChromeWriter::push_event(EventWithId* event) {
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (max_queue_events_ > 0 && event_queue_.size() >= max_queue_events_ && !finalized_) {
      // Wait, but not forever. Blocking absorbs a burst without losing anything, which is the
      // point; blocking indefinitely would stop collection for as long as the writer stayed behind,
      // and a trace that stops is not a slower trace, it is a shorter one. The budget is long
      // enough that this only fires when the writer is genuinely wedged, where losing events at a
      // counted rate beats losing the rest of the run.
      const auto t0 = std::chrono::steady_clock::now();
      const bool room = not_full_cv_.wait_for(lock, stall_budget_, [this] {
        return event_queue_.size() < max_queue_events_ || finalized_;
      });
      stall_ns_.fetch_add(
          static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                              std::chrono::steady_clock::now() - t0)
                                              .count()),
          std::memory_order_relaxed);
      stall_count_.fetch_add(1, std::memory_order_relaxed);
      if (!room) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        delete event->args;
        delete event;
        return;
      }
    }
    if (finalized_) {  // worker gone; free rather than enqueue into a dead queue
      delete event->args;
      delete event;
      return;
    }
    event_queue_.emplace_back(event);
  }
  queue_cv_.notify_one();
}

void ChromeWriter::write_member(const std::string& data) {
  if (data.empty()) return;
  std::vector<uint8_t> member = datacrumbs::pfw::gzip_block(data, zlib_level_);
  std::lock_guard<std::mutex> lock(file_mutex_);  // append is serial; members are self-contained
  if (!file_) return;
  if (std::fwrite(member.data(), 1, member.size(), file_) != member.size()) {
    perror("Failed to write gzip member to trace file");
  }
}

// /proc/<pid>/comm, or "" when the process is already gone. Best effort: the server names a pid the
// first time it observes one, which for a short-lived process can be after it exited.
static std::string read_comm(unsigned int pid) {
  char path[64];
  std::snprintf(path, sizeof(path), "/proc/%u/comm", pid);
  FILE* f = std::fopen(path, "r");
  if (f == nullptr) return {};
  char buf[64] = {0};
  const char* got = std::fgets(buf, sizeof(buf), f);
  std::fclose(f);
  if (got == nullptr) return {};
  buf[strcspn(buf, "\n")] = '\0';
  return buf;
}

std::string ChromeWriter::name_process(unsigned int pid, unsigned int tid) {
  const unsigned long long key = (static_cast<unsigned long long>(pid) << 32) | tid;
  bool new_proc = false;
  {
    std::lock_guard<std::mutex> lock(named_mutex_);
    if (!named_.insert(key).second) return {};
    // 0xffffffff is not a valid tid (pid_max is at most 2^22), so it keys the process itself.
    new_proc = named_.insert(static_cast<unsigned long long>(pid) << 32 | 0xffffffffULL).second;
  }
  const unsigned meta = static_cast<unsigned>(TracePhase::METADATA);
  std::string out;
  if (new_proc) {
    // pid 0 is not a process: it is the lane the samplers use for node-level telemetry.
    std::string comm = pid == 0 ? "node" : read_comm(pid);
    if (comm.empty()) comm = "exited";
    out += "{\"name\":\"process_name\",\"cat\":\"dftracer\",\"type\":\"metadata\",\"pid\":" +
           std::to_string(pid) + ",\"tid\":" + std::to_string(tid) +
           ",\"ph\":" + std::to_string(meta) + ",\"args\":{\"hhash\":\"" + hhash_ +
           "\",\"name\":\"process_name\",\"value\":\"" + json_escape(hostname_) + ":" +
           json_escape(comm) + " (" + std::to_string(pid) + ")\"}}\n";
  }
  {
    std::string comm = tid == 0 ? "node" : read_comm(tid);
    if (comm.empty()) comm = "exited";
    out += "{\"name\":\"thread_name\",\"cat\":\"dftracer\",\"type\":\"metadata\",\"pid\":" +
           std::to_string(pid) + ",\"tid\":" + std::to_string(tid) +
           ",\"ph\":" + std::to_string(meta) + ",\"args\":{\"hhash\":\"" + hhash_ +
           "\",\"name\":\"thread_name\",\"value\":\"" + json_escape(comm) + " (" +
           std::to_string(tid) + ")\"}}\n";
  }
  return out;
}

// Serialize one event to a JSON line and free it (and its args). Returns "" for an event whose id
// has no category mapping or whose type is not renderable.
std::string ChromeWriter::serialize_event(EventWithId* event_with_id) {
  std::string line;
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  auto args = event_with_id->args;
  // bpf_get_current_pid_tgid packs (tgid << 32) | pid, where the kernel's pid is the thread and
  // the tgid is the process. These were the other way round, which put a thread id in "pid".
  unsigned int pid = event_with_id->tgid_pid >> 32;
  unsigned int tid = static_cast<unsigned int>(event_with_id->tgid_pid);
  auto it = configManager_->category_map.find(event_with_id->event_id);
  if (it != configManager_->category_map.end()) {
    const unsigned long event_index = ++index_;
    std::string probe_name = it->second.first;
    std::string function_name = it->second.second;
    if (args != nullptr && event_with_id->event_type == TracePhase::COUNTER &&
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
    // Captured in nanoseconds and divided by the unit the build chose, which the trace declares in
    // its time_metric record. Integer math: exact and overflow-free, where a global-epoch ts
    // exceeds double's 2^53 exact range and floor(ts/1e3) would lose ~256ns. dur rounds up so a
    // sub-unit event stays nonzero rather than reading as instantaneous.
    const unsigned long long ts_us = event_with_id->ts / DATACRUMBS_TIME_DIVISOR_NS;
    const unsigned long long dur_us =
        event_with_id->dur / DATACRUMBS_TIME_DIVISOR_NS +
        (event_with_id->dur % DATACRUMBS_TIME_DIVISOR_NS != 0 ? 1 : 0);
    // "id" and "dur" are complete-event only; "type" is the probe's config domain string ("unknown"
    // if unset -- a free-form string so a plugin can contribute its own domain without a core
    // change).
    const auto* rmeta = configManager_->get_runtime_event_metadata(event_with_id->event_id);
    const char* type =
        (rmeta && !rmeta->trace_event_type.empty()) ? rmeta->trace_event_type.c_str() : "unknown";
    const unsigned ph = static_cast<unsigned>(event_with_id->event_type);
    int len = 0;
    if (event_with_id->event_type == TracePhase::COUNTER ||
        event_with_id->event_type == TracePhase::AGGREGATED) {
      // COUNTER and AGGREGATED share dftracer's series schema; only the phase differs.
      len = std::snprintf(
          buffer, sizeof(buffer),
          R"({"name":"%s","cat":"%s","type":"%s","pid":%d,"tid":%d,"ts":%llu,"ph":%u)",
          function_name.c_str(), probe_name.c_str(), type, pid, tid, ts_us, ph);
    } else if (event_with_id->event_type == TracePhase::METADATA) {
      // Metadata records are self-typed; the probe-domain lookup does not apply to them.
      len = std::snprintf(buffer, sizeof(buffer),
                          R"({"name":"%s","cat":"%s","type":"metadata","ph":%u)",
                          function_name.c_str(), probe_name.c_str(), ph);
    } else if (event_with_id->event_type == TracePhase::COMPLETE) {
      len = std::snprintf(
          buffer, sizeof(buffer),
          R"({"id":%lu,"name":"%s","cat":"%s","type":"%s","pid":%d,"tid":%d,"ts":%llu,"dur":%llu,"ph":%u)",
          event_index, function_name.c_str(), probe_name.c_str(), type, pid, tid, ts_us, dur_us,
          ph);
    }

    if (len > 0) {
      // hhash first: every event carries this node's host key, so a record stays attributable to
      // its node after a split, a merge, or any other regrouping that separates it from the HH
      // record at the head of its file. dftracer omits args entirely on an event that has none,
      // which is 9% of a measured trace, but that saving costs per-event node attribution.
      std::string args_json = "{\"hhash\":\"" + hhash_ + "\"";
      if (args != nullptr && !args->empty()) {
        for (auto pair : *args) {
          args_json += ",\"";
          args_json += pair.first;
          args_json += "\":";
          args_json += serialize_any_value(pair.second);
        }
      }
      args_json += "}";
      line = std::string(buffer, len) + ",\"args\":" + args_json + "}\n";
      if (event_with_id->event_type != TracePhase::METADATA) line = name_process(pid, tid) + line;
    }
  }
  delete args;
  delete event_with_id;
  return line;
}

void ChromeWriter::worker_loop() {
  DC_LOG_DEBUG("ChromeWriter worker loop started");
  static constexpr size_t kDrainSlice = 8192;  // bounded grab so a pool shares the queue fairly
  std::string member;
  member.reserve(flush_bytes_ + 4096);
  std::vector<EventWithId*> batch;
  batch.reserve(kDrainSlice);
  while (true) {
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this] { return !event_queue_.empty() || stop_flag_; });
      if (event_queue_.empty() && stop_flag_) break;
      const size_t n = std::min(event_queue_.size(), kDrainSlice);
      for (size_t i = 0; i < n; ++i) {
        batch.push_back(event_queue_.front());
        event_queue_.pop_front();
      }
      if (!event_queue_.empty()) queue_cv_.notify_one();  // more left -> wake a peer worker
    }
    not_full_cv_.notify_all();  // queue drained below bound -> release backpressured producers
    for (EventWithId* event : batch) {
      run_event_enrichers(event);
      member += serialize_event(event);
      if (member.size() >= flush_bytes_) {
        write_member(member);
        member.clear();
      }
    }
    batch.clear();
  }
  if (!member.empty()) write_member(member);  // trailing partial member
  DC_LOG_DEBUG("ChromeWriter worker loop exiting");
}
}  // namespace datacrumbs
