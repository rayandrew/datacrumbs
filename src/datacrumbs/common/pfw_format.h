#ifndef DATACRUMBS_COMMON_PFW_FORMAT_H
#define DATACRUMBS_COMMON_PFW_FORMAT_H

#include <openssl/evp.h>
#include <zlib.h>

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

// Shared .pfw wire helpers so every producer (server writer, interposition client) emits the same
// dftracer-compatible format: multi-member gzip of NDJSON, keyed by an md5-derived host hash.

namespace datacrumbs::pfw {

// One self-contained gzip member; the .pfw is these concatenated, so a reader streams member by member.
inline std::vector<uint8_t> gzip_block(const std::string& in, int level = Z_DEFAULT_COMPRESSION) {
  z_stream s{};
  if (deflateInit2(&s, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
    throw std::runtime_error("deflateInit2 failed");
  }
  std::vector<uint8_t> out(deflateBound(&s, in.size()));
  s.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
  s.avail_in = static_cast<uInt>(in.size());
  s.next_out = out.data();
  s.avail_out = static_cast<uInt>(out.size());
  const int r = deflate(&s, Z_FINISH);
  deflateEnd(&s);
  if (r != Z_STREAM_END) throw std::runtime_error("deflate failed");
  out.resize(out.size() - s.avail_out);
  return out;
}

// dftracer host key: md5(hostname), even-indexed digest bytes in %02x (matches df_logger.h get_hash).
inline std::string hhash(const std::string& hostname) {
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int dlen = 0;
  EVP_Digest(hostname.data(), hostname.size(), digest, &dlen, EVP_md5(), nullptr);
  char hex[17];
  for (int i = 0; i < 16; i += 2) std::snprintf(hex + i, 3, "%02x", digest[i]);
  hex[16] = '\0';
  return std::string(hex, 16);
}

}  // namespace datacrumbs::pfw

#endif  // DATACRUMBS_COMMON_PFW_FORMAT_H
