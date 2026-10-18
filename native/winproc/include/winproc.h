// native/winproc -- small shared helpers for processes / modules / strings, used by both the crash
// and hook helpers.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wp {

struct ModuleInfo {
  uintptr_t base = 0;
  size_t size = 0;
  std::wstring name;  // module file name
  std::wstring path;  // full path (empty when unavailable)
};

// Enable SeDebugPrivilege. Failure is not fatal: non-elevated targets can still be debugged.
bool EnableDebugPrivilege();

// Process image name (without path); empty string when the process does not exist.
std::wstring ProcessImageName(DWORD pid);

// Enumerate modules. Same-bitness processes go through ToolHelp32; cross-bitness falls back to
// EnumProcessModulesEx.
std::vector<ModuleInfo> EnumModules(DWORD pid);

// Whether the process is 32-bit (WOW64). Returns false when the handle cannot be obtained
// (treated as 64-bit).
bool IsWow64(DWORD pid);

// Win32 error code -> system message.
std::wstring Win32Message(DWORD code);

// String conversion.
std::string ToUtf8(const std::wstring& text);
std::wstring ToWide(const std::string& text);

// Build a JSON string literal (quotes included); control characters escaped, non-ASCII UTF-8
// emitted as-is.
std::string JsonString(const std::string& text);

// Format a pointer/address as a 0x... string.
std::string Hex(uint64_t value);

}  // namespace wp
