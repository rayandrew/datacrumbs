#include <datacrumbs/server/process/writer/chrome_writer.h>
// internal headers
#include <datacrumbs/common/constants.h>
#include <datacrumbs/common/logging.h>
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

#include <cmath>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <vector>

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
  }
  return "\"<unsupported>\"";
}

// env override for a numeric config; keeps the default if unset or unparseable.
long env_num(const char* name, long dflt) {
  if (const char* e = std::getenv(name)) {
    char* end = nullptr;
    long v = std::strtol(e, &end, 10);
    if (end != e) return v;
  }
  return dflt;
}

// One self-contained gzip member; concatenated members are a valid gzip stream, so a member
// completed before a crash stays readable.
std::vector<uint8_t> gzip_block(const std::string& in, int level) {
  z_stream s{};
  if (deflateInit2(&s, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    throw std::runtime_error("deflateInit2 failed");
  }
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

// dftracer host key: md5(hostname), even-indexed digest bytes in %02x (matches df_logger.h get_hash).
std::string dftracer_hhash(const std::string& hostname) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int dlen = 0;
  EVP_Digest(hostname.data(), hostname.size(), digest, &dlen, EVP_md5(), nullptr);
  char hex[17];
  for (int i = 0; i < 16; i += 2) std::snprintf(hex + i, 3, "%02x", digest[i]);
  hex[16] = '\0';
  return std::string(hex, 16);
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

namespace datacrumbs {
ChromeWriter::ChromeWriter() : flush_bytes_(1 << 20) {
  // Env-overridable for testing: MAX_QUEUE_EVENTS bounds the backpressure queue (0 = unbounded);
  // ZLIB_LEVEL sets the deflate level (gzip framing is kept for Perfetto).
  max_queue_events_ = static_cast<size_t>(env_num("DATACRUMBS_MAX_QUEUE_EVENTS", 500000));
  zlib_level_ = static_cast<int>(env_num("DATACRUMBS_ZLIB_LEVEL", Z_DEFAULT_COMPRESSION));

  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  file_ = std::fopen(configManager_->trace_file_path.c_str(), "wb");
  if (!file_) throw std::runtime_error("Failed to open trace file for writing");
  auto pwd = getpwnam(configManager_->user.c_str());
  uid_t uid = pwd ? pwd->pw_uid : static_cast<uid_t>(-1);
  gid_t gid = pwd ? pwd->pw_gid : static_cast<gid_t>(-1);
  chown(configManager_->trace_file_path.c_str(), uid, gid);
  chmod(configManager_->trace_file_path.c_str(), 0660);

  char host[256] = {0};
  gethostname(host, sizeof(host) - 1);
  hostname_ = host;
  hhash_ = dftracer_hhash(hostname_);
  // dftracer "HH" record: lets the reader resolve this hhash back to the hostname.
  write_member("{\"name\":\"HH\",\"cat\":\"dftracer\",\"type\":\"metadata\",\"ph\":" +
               std::to_string(static_cast<unsigned>(TracePhase::METADATA)) +
               ",\"args\":{\"hhash\":\"" + hhash_ + "\",\"name\":\"" + json_escape(hostname_) +
               "\",\"value\":\"" + hhash_ + "\"}}\n");

  worker_ = std::thread([this]() { this->worker_loop(); });
}

ChromeWriter::~ChromeWriter() { finalize(); }

void ChromeWriter::finalize() {
  {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    if (finalized_) return;
    stop_flag_ = true;
    finalized_ = true;
  }
  queue_cv_.notify_all();
  not_full_cv_.notify_all();  // release any producer blocked on backpressure
  if (worker_.joinable()) worker_.join();
  if (file_) {
    std::fclose(file_);
    file_ = nullptr;
  }
  DC_LOG_DEBUG("ChromeWriter finalized");
}

void ChromeWriter::push_event(EventWithId* event) {
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (max_queue_events_ > 0) {
      not_full_cv_.wait(
          lock, [this] { return event_queue_.size() < max_queue_events_ || finalized_; });
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
  if (data.empty() || !file_) return;
  std::vector<uint8_t> member = gzip_block(data, zlib_level_);
  if (std::fwrite(member.data(), 1, member.size(), file_) != member.size()) {
    perror("Failed to write gzip member to trace file");
  }
}

// Serialize one event to a JSON line and free it (and its args). Returns "" for an event whose id
// has no category mapping or whose type is not renderable.
std::string ChromeWriter::serialize_event(EventWithId* event_with_id) {
  std::string line;
  auto configManager_ =
      datacrumbs::Singleton<datacrumbs::RuntimeConfigurationManager>::get_instance();
  auto args = event_with_id->args;
  unsigned int pid = event_with_id->tgid_pid;
  unsigned int tid = event_with_id->tgid_pid >> 32;
  auto it = configManager_->category_map.find(event_with_id->event_id);
  if (it != configManager_->category_map.end()) {
    index_++;
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
    // ns -> us by integer math: exact and overflow-free (a global-epoch ts exceeds double's 2^53
    // exact range, and floor(ts/1e3) would lose ~256ns there). dur rounds up so sub-us stays nonzero.
    const unsigned long long ts_us = event_with_id->ts / 1000;
    const unsigned long long dur_us =
        event_with_id->dur / 1000 + (event_with_id->dur % 1000 != 0 ? 1 : 0);
    // "id" and "dur" are complete-event only; "type" is the probe's config domain string ("unknown"
    // if unset -- a free-form string so a plugin can contribute its own domain without a core change).
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
          index_, function_name.c_str(), probe_name.c_str(), type, pid, tid, ts_us, dur_us, ph);
    }

    if (len > 0) {
      // hhash first, so every event carries this node's host key for the reader.
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
    }
  }
  delete args;
  delete event_with_id;
  return line;
}

void ChromeWriter::worker_loop() {
  DC_LOG_DEBUG("ChromeWriter worker loop started");
  std::string member;
  member.reserve(flush_bytes_ + 4096);
  std::deque<EventWithId*> batch;
  while (true) {
    {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      queue_cv_.wait(lock, [this] { return !event_queue_.empty() || stop_flag_; });
      if (event_queue_.empty() && stop_flag_) break;
      batch.swap(event_queue_);
    }
    not_full_cv_.notify_all();  // queue drained -> release backpressured producers
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
