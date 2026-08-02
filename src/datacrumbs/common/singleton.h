//
// Created by haridev on 3/28/23.
//

#pragma once
// include first
#include <datacrumbs/datacrumbs_config.h>
// other headers
#include <datacrumbs/common/logging.h>

// std headers
#include <memory>
#include <mutex>
#include <utility>

namespace datacrumbs {

template <typename T>
class Singleton {
 public:
  template <typename... Args>
  static std::shared_ptr<T> get_instance(Args... args) {
    if (stop_creating_instances) {
      DC_LOG_WARN("Attempted to get instance after finalization");
      return nullptr;
    }
    // Concurrent callers must not race on construction (the configurator builds probes in parallel).
    std::call_once(init_flag_,
                   [&]() { instance = std::make_shared<T>(std::forward<Args>(args)...); });
    return instance;
  }

  Singleton& operator=(const Singleton) = delete;
  Singleton(const Singleton&) = delete;

  static void finalize() {
    DC_LOG_INFO("Finalizing Singleton<%s>, no further instances will be created", typeid(T).name());
    stop_creating_instances = true;
  }

 protected:
  static bool stop_creating_instances;
  static std::shared_ptr<T> instance;
  // Per-T (not a function-local: get_instance is variadic, so a local flag would be per-arg-list and
  // a no-arg get_instance() would re-construct instead of reusing get_instance(path, ...)'s instance.
  static inline std::once_flag init_flag_;

  Singleton() {}
};

}  // namespace datacrumbs
