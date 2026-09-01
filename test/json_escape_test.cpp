// SPDX-License-Identifier: MIT

// Checks that json_escape produces parseable JSON for input that is not text.
//
// Probe arguments are raw memory, so a captured char* is frequently not UTF-8 at all. A lone 0x96
// written straight into a JSON string made 49 of 71 chunks unparseable in a full sweep. The escaper
// was fixed for that and then never observed working: both smoke runs captured only ASCII, so the
// path that matters was never taken.

#include <datacrumbs/server/process/writer/json_escape.h>

#include <cstdio>
#include <string>
#include <vector>

using datacrumbs::writer::json_escape;

namespace {

int g_checks = 0;
int g_fails = 0;

void check(bool ok, const std::string& what) {
  ++g_checks;
  if (!ok) {
    ++g_fails;
    std::printf("FAIL %s\n", what.c_str());
  }
}

/// Whether @p s is a valid JSON string body: no raw control byte, no unescaped quote or backslash,
/// and every byte at or above 0x80 part of a well-formed UTF-8 sequence.
bool parseable(const std::string& s) {
  for (std::size_t i = 0; i < s.size(); ++i) {
    const auto c = static_cast<unsigned char>(s[i]);
    if (c == '"') return false;
    if (c < 0x20) return false;
    if (c == '\\') {
      if (i + 1 >= s.size()) return false;
      const char n = s[i + 1];
      if (n == 'u') {
        if (i + 5 >= s.size()) return false;
        i += 5;
      } else if (n == '"' || n == '\\' || n == '/' || n == 'b' || n == 'f' || n == 'n' ||
                 n == 'r' || n == 't') {
        i += 1;
      } else {
        return false;
      }
      continue;
    }
    if (c >= 0x80) {
      const std::size_t len = datacrumbs::writer::utf8_len(s, i);
      if (len == 0) return false;
      i += len - 1;
    }
  }
  return true;
}

}  // namespace

int main() {
  // The byte that started this: a lone 0x96 is not valid UTF-8 and must not reach the output raw.
  const std::string lone_96(1, static_cast<char>(0x96));
  check(json_escape(lone_96) == "\\u0096", "lone 0x96 becomes an escape");
  check(parseable(json_escape(lone_96)), "lone 0x96 output is parseable");

  // Real text survives unchanged, so the fix does not mangle the case that was already working.
  check(json_escape("plain ascii") == "plain ascii", "ascii passes through");
  check(json_escape("\xc3\xa9") == "\xc3\xa9", "two byte utf-8 passes through");
  check(json_escape("\xe2\x82\xac") == "\xe2\x82\xac", "three byte utf-8 passes through");
  check(json_escape("\xf0\x9f\x92\xa9") == "\xf0\x9f\x92\xa9", "four byte utf-8 passes through");

  // A truncated sequence is the realistic failure: a probe copies a fixed number of bytes and cuts
  // a character in half.
  check(parseable(json_escape("\xe2\x82")), "truncated three byte sequence is parseable");
  check(parseable(json_escape("ok\xf0\x9f")), "truncated four byte sequence is parseable");

  // Continuation byte with no lead, overlong encoding, and the surrogate and out-of-range leads.
  check(parseable(json_escape("\x80")), "stray continuation byte");
  check(parseable(json_escape("\xc0\xaf")), "overlong encoding rejected");
  check(parseable(json_escape("\xf5\x80\x80\x80")), "lead above U+10FFFF rejected");
  check(parseable(json_escape("\xed\xa0\x80")), "surrogate range is at least parseable");

  check(json_escape("a\"b") == "a\\\"b", "quote escaped");
  check(json_escape("a\\b") == "a\\\\b", "backslash escaped");
  check(json_escape(std::string("a\0b", 3)) == "a\\u0000b", "embedded nul escaped");
  check(json_escape("\n\r\t") == "\\n\\r\\t", "control characters escaped");

  // Every byte value on its own, then every two-byte pair, which covers the lead-plus-continuation
  // decisions exhaustively rather than at the few points a hand-picked list would reach.
  for (int b = 0; b < 256; ++b) {
    const std::string one(1, static_cast<char>(b));
    if (!parseable(json_escape(one))) {
      std::printf("FAIL single byte 0x%02x not parseable\n", b);
      ++g_fails;
    }
    ++g_checks;
  }
  for (int a = 0x80; a < 256; ++a) {
    for (int b = 0; b < 256; ++b) {
      std::string two;
      two += static_cast<char>(a);
      two += static_cast<char>(b);
      if (!parseable(json_escape(two))) {
        std::printf("FAIL pair 0x%02x 0x%02x not parseable\n", a, b);
        ++g_fails;
      }
      ++g_checks;
    }
  }

  std::printf("checks=%d fails=%d\n", g_checks, g_fails);
  return g_fails != 0;
}
