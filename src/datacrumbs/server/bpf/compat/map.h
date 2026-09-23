#ifndef DATACRUMBS_SERVER_BPF_COMPAT_H
#define DATACRUMBS_SERVER_BPF_COMPAT_H
#include <bpf/bpf.h>
#include <datacrumbs/datacrumbs_config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if DATACRUMBS_KERNEL_GET_VERSION(5, 6, 0) > DATACRUMBS_KERNEL_VERSION

struct bpf_map_batch_opts;

inline static int bpf_map_lookup_and_delete_batch_compat(int fd, void* in_batch, void* out_batch,
                                                         void* keys, void* values,
                                                         unsigned int* count,
                                                         const struct bpf_map_batch_opts* opts) {
  // Older syscalls do not support batch options.
  (void)opts;

  unsigned int num_to_process = *count;
  unsigned int processed = 0;
  void* current_key = in_batch;
  void* key_ptr = keys;
  void* value_ptr = values;

  if (!count || !keys || !values) {
    errno = EINVAL;
    *count = 0;
    return -1;
  }

  struct bpf_map_info info;
  unsigned int info_len = sizeof(info);
  if (bpf_map_get_info_by_fd(fd, &info, &info_len)) {
    *count = 0;
    return -1;
  }

  while (processed < num_to_process) {
    void* next_key_storage = NULL;
    void* next_key = NULL;

    // bpf_map_get_next_key needs a non-const key pointer.
    if (current_key) {
      next_key_storage = malloc(info.key_size);
      if (!next_key_storage) {
        errno = ENOMEM;
        *count = processed;
        return -1;
      }
      memcpy(next_key_storage, current_key, info.key_size);
    }

    if (bpf_map_get_next_key(fd, next_key_storage, &next_key)) {
      if (next_key_storage) free(next_key_storage);
      if (errno == ENOENT) {
        *count = processed;
        errno = ENOENT;
        return -1;  // -1 marks end-of-map here, not failure.
      }
      *count = processed;
      return -1;
    }

    if (next_key_storage) free(next_key_storage);

    if (bpf_map_lookup_elem(fd, next_key, value_ptr)) {
      // The element may already be deleted by another process.
      continue;
    }

    memcpy(key_ptr, next_key, info.key_size);
    key_ptr += info.key_size;
    value_ptr += info.value_size;

    bpf_map_delete_elem(fd, next_key);

    current_key = next_key;
    processed++;
  }

  *count = processed;

  if (out_batch && processed > 0) {
    // out_batch is the last key processed, for the next batch call.
    memcpy(out_batch, current_key, info.key_size);
    return 1;
  } else {
    errno = ENOENT;
    return -1;
  }

  return 0;
}

inline static int bpf_map_lookup_batch_compat(int fd, void* in_batch, void* out_batch, void* keys,
                                              void* values, unsigned int* count,
                                              const struct bpf_map_batch_opts* opts) {
  // Older syscalls do not support batch options.
  (void)opts;

  unsigned int num_to_process;
  unsigned int processed = 0;
  void* current_key;
  void* key_ptr = keys;
  void* value_ptr = values;
  struct bpf_map_info info;
  unsigned int info_len = sizeof(info);
  void* next_key_storage = NULL;

  if (!count || !keys || !values) {
    errno = EINVAL;
    if (count) *count = 0;
    return -1;
  }

  num_to_process = *count;

  if (bpf_map_get_info_by_fd(fd, &info, &info_len)) {
    *count = 0;
    return -1;
  }

  next_key_storage = malloc(info.key_size);
  if (!next_key_storage) {
    errno = ENOMEM;
    *count = 0;
    return -1;
  }

  current_key = in_batch;

  while (processed < num_to_process) {
    void* next_key_out = NULL;

    if (bpf_map_get_next_key(fd, current_key, next_key_storage)) {
      if (errno == ENOENT) {
        *count = processed;
        free(next_key_storage);
        if (out_batch && processed > 0) {
          memcpy(out_batch, current_key, info.key_size);
        }
        errno = ENOENT;
        return -1;  // -1 marks end-of-map here, not failure.
      }
      *count = processed;
      free(next_key_storage);
      return -1;
    }

    next_key_out = next_key_storage;

    if (bpf_map_lookup_elem(fd, next_key_out, value_ptr)) {
      // The element may already be deleted by another process.
      current_key = next_key_out;
      continue;
    }

    memcpy(key_ptr, next_key_out, info.key_size);

    key_ptr = (char*)key_ptr + info.key_size;
    value_ptr = (char*)value_ptr + info.value_size;

    current_key = next_key_out;
    processed++;
  }

  *count = processed;

  if (out_batch && processed > 0) {
    // out_batch is the last key processed, for the next batch call.
    memcpy(out_batch, current_key, info.key_size);
    free(next_key_storage);
    return 1;
  } else {
    errno = ENOENT;
    return -1;
  }

  free(next_key_storage);
  return 0;
}
#else
#define bpf_map_lookup_and_delete_batch_compat bpf_map_lookup_and_delete_batch
#define bpf_map_lookup_batch_compat bpf_map_lookup_batch
#endif

#endif