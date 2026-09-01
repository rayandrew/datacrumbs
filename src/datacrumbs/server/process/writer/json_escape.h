// SPDX-License-Identifier: MIT

#ifndef DATACRUMBS_SERVER_PROCESS_WRITER_JSON_ESCAPE_H
#define DATACRUMBS_SERVER_PROCESS_WRITER_JSON_ESCAPE_H

#include <cstdio>
#include <string>

namespace datacrumbs::writer {

// Length of the UTF-8 sequence starting at @p i, or 0 if the bytes there are not valid UTF-8.
// Probe arguments are raw memory, so a captured char* is frequently not text at all; a lone 0x96
// written straight into a JSON string is what made 49 of 71 chunks in a full sweep unparseable.
std::size_t utf8_len(const std::string& s, std::size_t i) {
  const auto b = static_cast<unsigned char>(s[i]);
  std::size_t n = 0;
  if ((b & 0xe0) == 0xc0 && b >= 0xc2) {
    n = 2;
  } else if ((b & 0xf0) == 0xe0) {
    n = 3;
  } else if ((b & 0xf8) == 0xf0 && b <= 0xf4) {
    n = 4;
  } else {
    return 0;
  }
  if (i + n > s.size()) return 0;
  for (std::size_t k = 1; k < n; ++k) {
    if ((static_cast<unsigned char>(s[i + k]) & 0xc0) != 0x80) return 0;
  }
  return n;
}

std::string json_escape(const std::string& input) {
  std::string escaped;
  escaped.reserve(input.size() + 8);
  for (std::size_t i = 0; i < input.size(); ++i) {
    const auto ch = static_cast<unsigned char>(input[i]);
    if (ch >= 0x80) {
      // Real text passes through; anything that is not valid UTF-8 becomes \u00xx, which is still
      // the original byte and, unlike the raw byte, is parseable.
      if (const std::size_t n = utf8_len(input, i); n != 0) {
        escaped.append(input, i, n);
        i += n - 1;
      } else {
        char buffer[8];
        std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
        escaped += buffer;
      }
      continue;
    }
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

}  // namespace datacrumbs::writer

#endif  // DATACRUMBS_SERVER_PROCESS_WRITER_JSON_ESCAPE_H
