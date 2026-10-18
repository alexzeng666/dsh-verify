#include "winproc.h"

#include <psapi.h>
#include <tlhelp32.h>

#include <cstdio>
#include <sstream>

namespace wp {
namespace {

std::wstring FormatWin32(DWORD code) {
  wchar_t* buffer = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<wchar_t*>(&buffer), 0,
      nullptr);
  std::wstring text;
  if (length != 0 && buffer != nullptr) {
    text.assign(buffer, length);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
      text.pop_back();
    }
  }
  if (buffer != nullptr) LocalFree(buffer);
  if (text.empty()) text = L"unknown";
  return text;
}

}  // namespace

bool EnableDebugPrivilege() {
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) == FALSE) {
    return false;
  }
  LUID luid{};
  bool ok = false;
  if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) != FALSE) {
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) != FALSE &&
         GetLastError() == ERROR_SUCCESS;
  }
  CloseHandle(token);
  return ok;
}

std::wstring ProcessImageName(DWORD pid) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return {};
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  std::wstring name;
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      if (entry.th32ProcessID == pid) {
        name.assign(entry.szExeFile);
        break;
      }
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }
  CloseHandle(snapshot);
  return name;
}

std::vector<ModuleInfo> EnumModules(DWORD pid) {
  std::vector<ModuleInfo> modules;

  // Try ToolHelp32 first: lightest for same-bitness, and it yields full paths.
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot != INVALID_HANDLE_VALUE) {
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry) != FALSE) {
      do {
        ModuleInfo info;
        info.base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
        info.size = entry.modBaseSize;
        info.name.assign(entry.szModule);
        info.path.assign(entry.szExePath);
        modules.push_back(std::move(info));
      } while (Module32NextW(snapshot, &entry) != FALSE);
    }
    CloseHandle(snapshot);
  }
  if (!modules.empty()) return modules;

  // Cross-bitness fallback: EnumProcessModulesEx sees both the 32- and 64-bit module lists.
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (process == nullptr) return modules;
  HMODULE handles[1024];
  DWORD needed = 0;
  if (EnumProcessModulesEx(process, handles, sizeof(handles), &needed, LIST_MODULES_ALL) != FALSE) {
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD index = 0; index < count; ++index) {
      MODULEINFO info{};
      if (GetModuleInformation(process, handles[index], &info, sizeof(info)) == FALSE) continue;
      wchar_t path[MAX_PATH]{};
      GetModuleFileNameExW(process, handles[index], path, MAX_PATH);
      ModuleInfo module;
      module.base = reinterpret_cast<uintptr_t>(info.lpBaseOfDll);
      module.size = info.SizeOfImage;
      module.path.assign(path);
      const wchar_t* slash = wcsrchr(path, L'\\');
      module.name.assign(slash != nullptr ? slash + 1 : path);
      modules.push_back(std::move(module));
    }
  }
  CloseHandle(process);
  return modules;
}

bool IsWow64(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) return false;
  BOOL wow64 = FALSE;
  const bool ok = IsWow64Process(process, &wow64) != FALSE && wow64 != FALSE;
  CloseHandle(process);
  return ok;
}

std::wstring Win32Message(DWORD code) { return FormatWin32(code); }

std::string ToUtf8(const std::wstring& text) {
  if (text.empty()) return {};
  const int length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0,
                                         nullptr, nullptr);
  if (length <= 0) return {};
  std::string out(static_cast<size_t>(length), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length, nullptr, nullptr);
  return out;
}

std::wstring ToWide(const std::string& text) {
  if (text.empty()) return {};
  const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (length <= 0) return {};
  std::wstring out(static_cast<size_t>(length), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), length);
  return out;
}

std::string JsonString(const std::string& text) {
  std::string out;
  out.reserve(text.size() + 2);
  out.push_back('"');
  for (const char raw : text) {
    const unsigned char ch = static_cast<unsigned char>(raw);
    switch (ch) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (ch < 0x20) {
          char buffer[8];
          std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch);
          out += buffer;
        } else {
          out.push_back(raw);
        }
    }
  }
  out.push_back('"');
  return out;
}

std::string Hex(uint64_t value) {
  char buffer[24];
  std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
  return buffer;
}

}  // namespace wp
