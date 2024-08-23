cmake_minimum_required(VERSION 3.4)
project(datacrumbs LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON CACHE INTERNAL "")

# if(NOT CMAKE_BUILD_TYPE)
#     set(CMAKE_BUILD_TYPE RelWithDebInfo
#         CACHE STRING "Choose the type of build." FORCE)
#     set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
#                  "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
# endif()
#
# if (CMAKE_BUILD_TYPE STREQUAL "Debug")
#  add_definitions(-Wno-format -Wno-format-security -Wno-overflow)
# endif()

set(DFT_EBPF_SRC src/datacrumbs/library.c src/datacrumbs/library.h)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(${PROJECT_NAME} SHARED ${DFT_EBPF_SRC})

add_subdirectory(tests)
