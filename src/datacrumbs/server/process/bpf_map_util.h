#ifndef DATACRUMBS_SERVER_PROCESS_BPF_MAP_UTIL_H
#define DATACRUMBS_SERVER_PROCESS_BPF_MAP_UTIL_H

#include <bpf/bpf.h>

#include <vector>

namespace datacrumbs {

// Calls fn(key) for each key in the map. Keys are copied first, so fn may safely
// delete or update the map.
template <typename KeyT, typename Fn>
inline void for_each_map_entry(int fd, Fn&& fn) {
  if (fd < 0) return;
  std::vector<KeyT> keys;
  KeyT key{};
  KeyT next{};
  int err = bpf_map_get_next_key(fd, nullptr, &next);
  while (err == 0) {
    keys.push_back(next);
    key = next;
    err = bpf_map_get_next_key(fd, &key, &next);
  }
  for (const auto& k : keys) fn(k);
}

}  // namespace datacrumbs

#endif  // DATACRUMBS_SERVER_PROCESS_BPF_MAP_UTIL_H
