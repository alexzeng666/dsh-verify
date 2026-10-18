add_executable(crash_helper
  src/main.cpp
  src/report.cpp
  src/dump.cpp
  src/walk.cpp
  src/minidump.cpp
)

target_link_libraries(crash_helper PRIVATE winproc dbghelp psapi advapi32)
