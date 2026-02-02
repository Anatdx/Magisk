cmake_minimum_required(VERSION 3.22)

project(magisk_core LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Paths
get_filename_component(MAGISK_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}" ABSOLUTE)                 # native/src/core
get_filename_component(MAGISK_NATIVE_SRC_DIR "${MAGISK_SRC_DIR}/.." ABSOLUTE)              # native/src
get_filename_component(MAGISK_NATIVE_DIR "${MAGISK_NATIVE_SRC_DIR}/.." ABSOLUTE)          # native
set(MAGISK_GENERATED_DIR "${MAGISK_NATIVE_DIR}/out/generated")
if(DEFINED MAGISK_CMAKE_OUT_DIR)
  set(MAGISK_OUT_DIR "${MAGISK_CMAKE_OUT_DIR}")
else()
  set(MAGISK_OUT_DIR "${CMAKE_BINARY_DIR}/out")
endif()

# ---- base (as built by ndk-build: base.cpp + base-rs.cpp + cxx.cc) ----
add_library(base STATIC
  "${MAGISK_NATIVE_SRC_DIR}/base/base.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/base/base-rs.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/cxx-rs/src/cxx.cc"
)

target_include_directories(base PUBLIC
  "${MAGISK_NATIVE_SRC_DIR}/base/include"
  "${MAGISK_NATIVE_SRC_DIR}/include"
  "${MAGISK_GENERATED_DIR}"
)

target_compile_options(base PRIVATE
  -Wall -Wextra
)

# ---- system_properties ----
add_library(systemproperties STATIC
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/context_node.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/contexts_serialized.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/contexts_split.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/prop_area.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/prop_info.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/property_info_parser.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/system_properties.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/system_property_api.cpp"
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/system_property_set.cpp"
)

target_include_directories(systemproperties PUBLIC
  "${MAGISK_NATIVE_SRC_DIR}/external/system_properties/include"
)

target_compile_options(systemproperties PRIVATE
  -Wall -Wextra
)

# ---- magisk (core process-side) ----
add_executable(magisk
  "${MAGISK_SRC_DIR}/applets.cpp"
  "${MAGISK_SRC_DIR}/scripting.cpp"
  "${MAGISK_SRC_DIR}/sqlite.cpp"
  "${MAGISK_SRC_DIR}/utils.cpp"
  "${MAGISK_SRC_DIR}/magiskd_cpp.cpp"
  "${MAGISK_SRC_DIR}/core-compat.cpp"
  "${MAGISK_SRC_DIR}/resetprop/sys.cpp"
  "${MAGISK_SRC_DIR}/su/su.cpp"
  "${MAGISK_SRC_DIR}/deny/cli.cpp"
  "${MAGISK_SRC_DIR}/deny/utils.cpp"
  "${MAGISK_SRC_DIR}/deny/logcat.cpp"
  "${MAGISK_SRC_DIR}/zygisk_stub.cpp"
)
set_target_properties(magisk PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${MAGISK_OUT_DIR}"
)

target_include_directories(magisk PRIVATE
  "${MAGISK_NATIVE_SRC_DIR}/core/include"
  "${MAGISK_NATIVE_SRC_DIR}/include"
  "${MAGISK_NATIVE_SRC_DIR}/base/include"
  "${MAGISK_GENERATED_DIR}"
)

target_link_libraries(magisk PRIVATE
  base
  systemproperties
  log
  dl
)

# Keep behavior close to ndk-build defaults
target_compile_options(magisk PRIVATE
  -Wall -Wextra
)

# ---- resetprop standalone applet stub ----
add_executable(resetprop
  "${MAGISK_SRC_DIR}/applet_stub.cpp"
  "${MAGISK_SRC_DIR}/resetprop/sys.cpp"
  "${MAGISK_SRC_DIR}/core-compat.cpp"
)
set_target_properties(resetprop PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${MAGISK_OUT_DIR}"
)

target_include_directories(resetprop PRIVATE
  "${MAGISK_NATIVE_SRC_DIR}/core/include"
  "${MAGISK_NATIVE_SRC_DIR}/include"
  "${MAGISK_NATIVE_SRC_DIR}/base/include"
  "${MAGISK_GENERATED_DIR}"
)

target_compile_definitions(resetprop PRIVATE
  APPLET_STUB_MAIN=resetprop_main
)

target_link_libraries(resetprop PRIVATE
  base
  systemproperties
  log
  dl
)

