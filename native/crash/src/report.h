// Unified report struct for crash_helper: all three modes (attach / run / parse) fill it, and main
// serialises it to JSON.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace crash {

struct Frame {
  uint64_t addr = 0;
  std::wstring module;
  uint64_t module_offset = 0;
  std::wstring symbol;
  std::wstring source_file;
  int source_line = 0;
  bool resolved = false;
};

struct ModuleRec {
  uint64_t base = 0;
  uint64_t size = 0;
  std::wstring name;
  std::wstring path;
};

struct Report {
  bool ok = false;
  std::string error;
  std::string mode;  // attach | run | parse
  DWORD pid = 0;
  std::wstring image;
  bool captured = false;
  std::wstring dump_path;
  std::string dump_error;

  bool has_exception = false;
  DWORD exception_code = 0;
  uint64_t exception_address = 0;
  DWORD exception_flags = 0;
  ULONG_PTR exception_params[15]{};
  DWORD exception_param_count = 0;
  DWORD thread_id = 0;

  std::string stack_quality;  // unwind | scan | none
  std::vector<Frame> frames;
  std::vector<ModuleRec> modules;

  bool has_exit = false;
  DWORD exit_code = 0;
};

// Exception code -> human-readable name (ACCESS_VIOLATION etc.).
std::string ExceptionName(DWORD code);

// Serialise to a single line of JSON.
std::string ToJson(const Report& report);

}  // namespace crash
