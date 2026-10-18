add_library(hook_helper SHARED src/payload.cpp)
target_include_directories(hook_helper PRIVATE src ../winproc/include)
target_link_libraries(hook_helper PRIVATE minhook)
set_target_properties(hook_helper PROPERTIES OUTPUT_NAME "hook_helper" PREFIX "")

# Time-shift payload: a separate DLL that reuses the same injector (the host's shift subcommand).
add_library(time_helper SHARED src/time_payload.cpp)
target_include_directories(time_helper PRIVATE src ../winproc/include)
target_link_libraries(time_helper PRIVATE minhook winmm)
set_target_properties(time_helper PROPERTIES OUTPUT_NAME "time_helper" PREFIX "")

# Return-value payload: a minimal hook DSL (the host's hook subcommand).
add_library(value_hook SHARED src/value_payload.cpp)
target_include_directories(value_hook PRIVATE src ../winproc/include)
target_link_libraries(value_hook PRIVATE minhook winproc)
set_target_properties(value_hook PROPERTIES OUTPUT_NAME "value_hook" PREFIX "")

add_executable(hook_host src/host.cpp)
target_include_directories(hook_host PRIVATE src ../winproc/include)
target_link_libraries(hook_host PRIVATE winproc)
