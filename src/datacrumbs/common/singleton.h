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
    if (stop_flag()) {
      DC_LOG_WARN("Attempted to get instance after finalization");
      return nullptr;
    }
    // Concurrent callers must not race on construction (the configurator builds probes in parallel)
    std::call_once(init_flag(),
                   [&]() { instance_ref() = std::make_shared<T>(std::forward<Args>(args)...); });
    return instance_ref();
  }

  /// Borrowed, non-owning, and null until the first get_instance or after finalize.
  ///
  /// This is what a hot path uses. get_instance returns the shared_ptr by value, so calling it per
  /// event costs an atomic increment and decrement, on a path that runs once per traced call.
  static T* get() noexcept { return instance_ref().get(); }

  Singleton& operator=(const Singleton) = delete;
  Singleton(const Singleton&) = delete;

  /// Destroys the instance and refuses to build another.
  ///
  /// Destroying here rather than leaving it to process exit is the point: a T whose destructor
  /// does real work, such as a sink flushing its buffer, must run it at a moment the caller chose.
  /// At exit the order across shared libraries is not defined, and a preloaded library cannot rely
  /// on it.
  static void finalize() {
    // Debug, not info: this runs in every traced process, and a preloaded library writing a
    // mangled type name to somebody else's stderr on exit is noise the tracer should not add.
    DC_LOG_DEBUG("Finalizing Singleton<%s>, no further instances will be created",
                 typeid(T).name());
    stop_flag() = true;
    instance_ref().reset();
  }

 protected:
  // Function-local rather than namespace-scope: a static member would need a definition in some
  // translation unit, and anything constructed before that one runs reaches an instance that does
  // not exist yet. That is not hypothetical here, a preloaded client hit exactly it.
  //
  // These helpers must not be variadic. get_instance is, and a static declared inside it would be
  // one per argument list, so a later get_instance() would build a second instance rather than
  // return the one get_instance(path) already made.
  static std::shared_ptr<T>& instance_ref() {
    static std::shared_ptr<T> instance;
    return instance;
  }
  static bool& stop_flag() {
    static bool stop_creating_instances = false;
    return stop_creating_instances;
  }
  static std::once_flag& init_flag() {
    static std::once_flag flag;
    return flag;
  }

  Singleton() {}
};

}  // namespace datacrumbs
