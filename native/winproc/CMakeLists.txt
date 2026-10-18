add_library(winproc STATIC
  src/winproc.cpp
)

target_include_directories(winproc PUBLIC include)
target_link_libraries(winproc PUBLIC psapi advapi32)
