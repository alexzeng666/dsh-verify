add_library(minhook STATIC
  src/buffer.c
  src/hook.c
  src/trampoline.c
  src/hde/hde32.c
  src/hde/hde64.c
)

target_include_directories(minhook PUBLIC include)
target_include_directories(minhook PRIVATE src)

if(MSVC)
  target_compile_options(minhook PRIVATE /W3)
else()
  # Vendored third-party code: its warnings are not ours to fix.
  target_compile_options(minhook PRIVATE -w)
endif()
