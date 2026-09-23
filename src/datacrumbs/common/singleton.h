#pragma once
#include <datacrumbs/common/logging.h>
#include <datacrumbs/datacrumbs_config.h>

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
  /// get_instance returns the shared_ptr by value; on the hot path use get() instead, to avoid the
  /// atomic increment and decrement that costs once per traced event.
  static T* get() noexcept { return instance_ref().get(); }

  Singleton& operator=(const Singleton) = delete;
  Singleton(const Singleton&) = delete;

  /// Destroys the instance and refuses to build another.
  /// This runs the destructor now, at a moment the caller chose, rather than at process exit,
  /// where destructor order across shared libraries is undefined and a preloaded library
  /// cannot rely on it.
  static void finalize() {
    // Debug, not info: this runs in every traced process, and a preloaded library writing a
    // mangled type name to somebody else's stderr on exit is noise the tracer should not add.
    DC_LOG_DEBUG("Finalizing Singleton<%s>, no further instances will be created",
                 typeid(T).name());
    stop_flag() = true;
    instance_ref().reset();
  }

 protected:
  // Function-local statics, not members: a member needs a definition in some translation unit,
  // and anything constructed earlier would see no instance yet. These helpers must stay
  // non-variadic too, since get_instance is: a static declared inside it would be one per
  // argument list, breaking the single-instance guarantee.
  // Heap, never destroyed: a static holder's destructor runs at exit() before the library fini
  // that stops the worker threads, which then use a freed instance. finalize() is the only release.
  static std::shared_ptr<T>& instance_ref() {
    static std::shared_ptr<T>& instance = *new std::shared_ptr<T>();
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
