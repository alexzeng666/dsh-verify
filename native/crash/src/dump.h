// Crash capture: attach the debugger and wait for the exception -> write a minidump -> real stack walk.
#pragma once

#include <windows.h>

#include <string>

#include "report.h"

namespace crash {

// Attach to a live process, wait for it to fault, write the dump and walk the stack.
void AttachAndCapture(DWORD pid, const std::wstring& dump_path, const std::wstring& symbol_path, DWORD timeout_ms,
                      Report* report);

// Start a command line under the debugger, wait for it to fault, write the dump and walk the stack.
// When stdout_path / stderr_path are non-empty, redirect the child's stdout/stderr into those files.
void RunAndCapture(const std::wstring& cmdline, const std::wstring& cwd, const std::wstring& dump_path,
                   const std::wstring& symbol_path, DWORD timeout_ms, const std::wstring& stdout_path,
                   const std::wstring& stderr_path, Report* report);

}  // namespace crash
