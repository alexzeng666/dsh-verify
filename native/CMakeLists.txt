cmake_minimum_required(VERSION 3.20)
project(dsh_verify_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  # Static CRT: the helper still loads on target machines without the VC++ runtime installed.
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
  add_compile_options(/W4 /EHsc /utf-8 /permissive-)
  add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
endif()

if(MINGW)
  add_compile_options(-Wall -Wextra -O2)
  add_compile_definitions(UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
  # DLLs with no libgcc/libstdc++ dependency: they run on a bare target machine.
  add_link_options(-static -static-libgcc -static-libstdc++)
endif()

add_subdirectory(third_party/minhook)
add_subdirectory(winproc)
add_subdirectory(crash)
add_subdirectory(hook)

# All artifacts land in native/bin/<arch>/
set(DSH_NATIVE_OUT "${CMAKE_SOURCE_DIR}/bin/$<IF:$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>,x64,x86>")
set_target_properties(crash_helper hook_host PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${DSH_NATIVE_OUT}")
set_target_properties(hook_helper time_helper value_hook PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${DSH_NATIVE_OUT}")
