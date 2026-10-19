// hook_host.exe -- injects hook_helper.dll into the target process, waits for it to finish recording, then prints the result JSON.
//
//   hook_host.exe trace --pid <n> --dll <path> --out <jsonl> [--duration-ms <n>] [--apis "Sleep,CreateFileW"]
//
// Injection uses the most standard sequence: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread(LoadLibraryW).
// Unloading likewise goes through FreeLibrary, to leave as little as possible behind in the target process.
#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "time_protocol.h"
#include "value_hook_protocol.h"
#include "trace_protocol.h"
#include "winproc.h"

namespace {

struct Args {
  DWORD pid = 0;
  std::wstring dll;
  std::wstring out;
  DWORD duration_ms = 60000;
  DWORD api_mask = 0xFFFFFFFFu;
  double factor = 1.0;
  LONGLONG offset_seconds = 0;
  std::wstring api;
  std::wstring module;
  DWORD nth = 0;
  ULONGLONG ret = 0;
};

void PrintUsage() {
  std::fputs(
      "usage:\n"
      "  hook_host trace --pid <n> --dll <path> --out <jsonl> [--duration-ms <n>] [--apis <a,b,c>]\n"
      "  hook_host shift --pid <n> --dll <path> [--factor <f>] [--offset-sec <s>] [--duration-ms <n>] [--out <log>]\n"
      "  hook_host hook  --pid <n> --dll <path> --api <name> [--module <mod.dll>] [--nth <N>] [--ret <value>] "
      "[--duration-ms <n>] [--out <log>]\n",
      stderr);
}

DWORD MaskFromNames(const std::string& names) {
  if (names.empty() || names == "all") return 0xFFFFFFFFu;
  DWORD mask = 0;
  size_t start = 0;
  while (start <= names.size()) {
    const size_t comma = names.find(',', start);
    const std::string token = names.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
    for (DWORD api = 0; api < kApiCount; ++api) {
      if (wp::ToUtf8(ProbeApiName(api)) == token) mask |= (1u << api);
    }
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return mask;
}

uintptr_t FindRemoteModule(DWORD pid, const std::wstring& name) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snapshot == INVALID_HANDLE_VALUE) return 0;
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  uintptr_t base = 0;
  if (Module32FirstW(snapshot, &entry) != FALSE) {
    do {
      if (_wcsicmp(entry.szModule, name.c_str()) == 0) {
        base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
        break;
      }
    } while (Module32NextW(snapshot, &entry) != FALSE);
  }
  CloseHandle(snapshot);
  return base;
}

// The target can run at a lower integrity level than this host (a sandboxed parent, a path-based policy,
// or an AppContainer-ish wrapper). Two independent mechanisms then make a default mapping unopenable from
// inside the target: the DACL (fixed by a NULL DACL) and the mandatory integrity label, which a NULL DACL
// does not touch -- a low-integrity process still cannot open a medium-integrity object for write.
// The label is lowered to Low so the payload can always attach; the object is Local\ (session-scoped) and
// lives only for the duration of one call, so nothing wider is exposed.
struct PermissiveSecurity {
  SECURITY_DESCRIPTOR sd{};
  SECURITY_ATTRIBUTES sa{};
  ACL* sacl = nullptr;
  BYTE low_sid[SECURITY_MAX_SID_SIZE]{};

  PermissiveSecurity() {
    DWORD sid_size = sizeof(low_sid);
    const bool have_low = CreateWellKnownSid(WinLowLabelSid, nullptr, low_sid, &sid_size) != FALSE;
    const DWORD acl_size = sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + (have_low ? sid_size : 0);
    sacl = static_cast<ACL*>(LocalAlloc(LPTR, acl_size));
    if (sacl != nullptr) {
      InitializeAcl(sacl, acl_size, ACL_REVISION);
      if (have_low) AddMandatoryAce(sacl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, low_sid);
    }
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    if (sacl != nullptr) SetSecurityDescriptorSacl(&sd, TRUE, sacl, FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;
  }

  ~PermissiveSecurity() {
    if (sacl != nullptr) LocalFree(sacl);
  }

  PermissiveSecurity(const PermissiveSecurity&) = delete;
  PermissiveSecurity& operator=(const PermissiveSecurity&) = delete;
};

// A low-integrity target cannot create a file in a medium-integrity directory, so the payload's own
// CreateFileW on the output path fails and the run reports records that never reached disk. Creating the
// file here with a low label hands the payload a handle target it is allowed to write.
bool PrepareOutputFile(const std::wstring& path) {
  if (path.empty()) return true;
  PermissiveSecurity security;
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security.sa, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  CloseHandle(file);
  return true;
}

bool InjectDll(HANDLE process, const std::wstring& dll, std::string* error) {
  const SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (remote == nullptr) {
    *error = "VirtualAllocEx failed (Win32 " + std::to_string(GetLastError()) + ")";
    return false;
  }
  if (WriteProcessMemory(process, remote, dll.c_str(), bytes, nullptr) == FALSE) {
    *error = "WriteProcessMemory failed (Win32 " + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
  HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote, 0, nullptr);
  if (thread == nullptr) {
    *error = "CreateRemoteThread failed (Win32 " + std::to_string(GetLastError()) + ")";
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return false;
  }
  WaitForSingleObject(thread, 10000);
  DWORD exit_code = 0;
  GetExitCodeThread(thread, &exit_code);
  CloseHandle(thread);
  VirtualFreeEx(process, remote, 0, MEM_RELEASE);
  if (exit_code == 0) {
    *error = "LoadLibraryW returned 0 in the target (DLL load failed)";
    return false;
  }
  return true;
}

// Did the target exit normally on its own, or did we crash it?
// An exception code from GetExitCodeProcess (>= 0xC0000000) means the process terminated abnormally --
// reporting timeout here would pass off "the tool crashed the target" as "the target finished by itself", i.e. a fault as a conclusion.
bool ExitedWithException(HANDLE process, DWORD* exit_code) {
  DWORD code = STILL_ACTIVE;
  if (!GetExitCodeProcess(process, &code)) return false;
  if (exit_code != nullptr) *exit_code = code;
  return code != STILL_ACTIVE && code >= 0xC0000000u;
}

void EjectDll(HANDLE process, DWORD pid, const std::wstring& dll) {
  const std::wstring name = dll.substr(dll.find_last_of(L'\\') + 1);
  const uintptr_t base = FindRemoteModule(pid, name);
  if (base == 0) return;
  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  auto free_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "FreeLibrary"));
  HANDLE thread = CreateRemoteThread(process, nullptr, 0, free_library, reinterpret_cast<void*>(base), 0, nullptr);
  if (thread != nullptr) {
    WaitForSingleObject(thread, 5000);
    CloseHandle(thread);
  }
}

}  // namespace

int RunTrace(const Args& args, const std::string& apis);
int RunShift(const Args& args);
int RunHook(const Args& args);

int main(int argc, char** argv) {
  Args args;
  std::string apis = "all";
  double factor = 1.0;
  LONGLONG offset_seconds = 0;

  if (argc < 2) {
    PrintUsage();
    return 2;
  }
  const std::string mode = argv[1];
  if (mode != "trace" && mode != "shift" && mode != "hook") {
    PrintUsage();
    return 2;
  }

  for (int index = 2; index < argc; ++index) {
    const std::string key = argv[index];
    auto next = [&](std::string* value) -> bool {
      if (index + 1 >= argc) return false;
      *value = argv[++index];
      return true;
    };
    std::string value;
    if (key == "--pid") {
      if (!next(&value)) return 2;
      args.pid = static_cast<DWORD>(std::stoul(value));
    } else if (key == "--dll") {
      if (!next(&value)) return 2;
      args.dll = wp::ToWide(value);
    } else if (key == "--out") {
      if (!next(&value)) return 2;
      args.out = wp::ToWide(value);
    } else if (key == "--duration-ms") {
      if (!next(&value)) return 2;
      args.duration_ms = static_cast<DWORD>(std::stoul(value));
    } else if (key == "--apis") {
      if (!next(&apis)) return 2;
    } else if (key == "--factor") {
      if (!next(&value)) return 2;
      factor = std::stod(value);
    } else if (key == "--offset-sec") {
      if (!next(&value)) return 2;
      offset_seconds = static_cast<LONGLONG>(std::stoll(value));
    } else if (key == "--api") {
      if (!next(&value)) return 2;
      args.api = wp::ToWide(value);
    } else if (key == "--module") {
      if (!next(&value)) return 2;
      args.module = wp::ToWide(value);
    } else if (key == "--nth") {
      if (!next(&value)) return 2;
      args.nth = static_cast<DWORD>(std::stoul(value));
    } else if (key == "--ret") {
      if (!next(&value)) return 2;
      args.ret = std::stoull(value, nullptr, 0);  // accepts a 0x prefix as well as decimal
    }
  }
  args.api_mask = MaskFromNames(apis);
  args.factor = factor;
  args.offset_seconds = offset_seconds;

  if (mode == "trace") return RunTrace(args, apis);
  if (mode == "shift") return RunShift(args);
  return RunHook(args);
}

int RunTrace(const Args& args, const std::string& apis) {
  (void)apis;
  auto fail = [](const std::string& message) {
    std::printf("{\"ok\":false,\"error\":%s}\n", wp::JsonString(message).c_str());
    std::fflush(stdout);
    return 1;
  };

  if (args.pid == 0 || args.dll.empty() || args.out.empty()) {
    PrintUsage();
    return 2;
  }

  wp::EnableDebugPrivilege();

  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, args.pid);
  if (process == nullptr) {
    return fail("OpenProcess failed (Win32 " + std::to_string(GetLastError()) + "): the target may have exited or admin rights may be required");
  }

  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_PROBE_MAPPING_PREFIX L"%lu", args.pid);
  PermissiveSecurity security;
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security.sa, PAGE_READWRITE, 0, sizeof(ProbeConfig), mapping_name);
  if (mapping == nullptr) {
    CloseHandle(process);
    return fail("CreateFileMapping failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  auto* config = static_cast<ProbeConfig*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                        sizeof(ProbeConfig)));
  if (config == nullptr) {
    CloseHandle(mapping);
    CloseHandle(process);
    return fail("MapViewOfFile failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  ZeroMemory(config, sizeof(ProbeConfig));
  config->state = kProbeIdle;
  config->duration_ms = args.duration_ms;
  config->api_mask = args.api_mask;
  wcsncpy_s(config->out_path, args.out.c_str(), _TRUNCATE);
  PrepareOutputFile(args.out);

  std::string error;
  const bool injected = InjectDll(process, args.dll, &error);
  if (!injected) {
    UnmapViewOfFile(config);
    CloseHandle(mapping);
    CloseHandle(process);
    return fail(error);
  }
  const std::wstring dll_name = args.dll.substr(args.dll.find_last_of(L'\\') + 1);
  const bool loaded = FindRemoteModule(args.pid, dll_name) != 0;

  // Wait for the DLL to finish flushing its records; allow 15 extra seconds on top of its own duration.
  const DWORD deadline = GetTickCount() + args.duration_ms + 15000;
  LONG state = kProbeIdle;
  while (GetTickCount() < deadline) {
    state = config->state;
    if (state == kProbeDone || state == kProbeFailed) break;
    if (WaitForSingleObject(process, 200) == WAIT_OBJECT_0) {
      // The target exited on its own: the records inside the DLL may not be on disk yet.
      break;
    }
  }
  state = config->state;
  DWORD exit_code = STILL_ACTIVE;
  const bool crashed = ExitedWithException(process, &exit_code);
  if (crashed && state != kProbeDone) state = kProbeFailed;
  // Still Idle after the grace period means the payload never opened the shared config: the DLL loaded but
  // never attached. Reporting "timeout" would blame the target for the verifier's own failure.
  const bool attached = state != kProbeIdle;
  if (!attached) state = kProbeFailed;

  EjectDll(process, args.pid, args.dll);

  const DWORD records = config->records_written;
  const DWORD failures = config->hook_failures;
  const bool done = state == kProbeDone;
  std::printf(
      "{\"ok\":%s,\"state\":\"%s\",\"records\":%lu,\"hook_failures\":%lu,\"pid\":%lu,\"out_path\":%s,"
      "\"duration_ms\":%lu,\"attached\":%s,\"dll_loaded\":%s,\"target_exited\":%s,\"exit_code\":\"0x%08lX\"}\n",
      done ? "true" : "false", done ? "done" : (state == kProbeFailed ? "failed" : "timeout"), records, failures,
      args.pid, wp::JsonString(wp::ToUtf8(args.out)).c_str(), args.duration_ms, attached ? "true" : "false",
      loaded ? "true" : "false", exit_code != STILL_ACTIVE ? "true" : "false", exit_code);
  std::fflush(stdout);

  UnmapViewOfFile(config);
  CloseHandle(mapping);
  CloseHandle(process);
  return done ? 0 : 1;
}

// ── shift: speed the target process's clock up / down / into the future ────────────────────────────────
int RunShift(const Args& args) {
  auto fail = [](const std::string& message) {
    std::printf("{\"ok\":false,\"error\":%s}\n", wp::JsonString(message).c_str());
    std::fflush(stdout);
    return 1;
  };

  if (args.pid == 0 || args.dll.empty()) {
    PrintUsage();
    return 2;
  }

  wp::EnableDebugPrivilege();

  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, args.pid);
  if (process == nullptr) {
    return fail("OpenProcess failed (Win32 " + std::to_string(GetLastError()) + "): the target may have exited or admin rights may be required");
  }

  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_TIME_MAPPING_PREFIX L"%lu", args.pid);
  PermissiveSecurity security;
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security.sa, PAGE_READWRITE, 0, sizeof(TimeConfig), mapping_name);
  if (mapping == nullptr) {
    CloseHandle(process);
    return fail("CreateFileMapping failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  auto* config = static_cast<TimeConfig*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(TimeConfig)));
  if (config == nullptr) {
    CloseHandle(mapping);
    CloseHandle(process);
    return fail("MapViewOfFile failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  ZeroMemory(config, sizeof(TimeConfig));
  config->state = kTimeIdle;
  config->mode = args.offset_seconds != 0 ? 1 : 0;
  config->factor = args.factor > 0.0 ? args.factor : 1.0;
  config->offset_100ns = args.offset_seconds * 10000000LL;  // seconds -> 100ns
  config->duration_ms = args.duration_ms;
  if (!args.out.empty()) {
    wcsncpy_s(config->out_path, args.out.c_str(), _TRUNCATE);
    PrepareOutputFile(args.out + L".log");
  }

  std::string error;
  if (!InjectDll(process, args.dll, &error)) {
    UnmapViewOfFile(config);
    CloseHandle(mapping);
    CloseHandle(process);
    return fail(error);
  }
  const std::wstring dll_name = args.dll.substr(args.dll.find_last_of(L'\\') + 1);
  const bool loaded = FindRemoteModule(args.pid, dll_name) != 0;

  const DWORD deadline = GetTickCount() + args.duration_ms + 15000;
  LONG state = kTimeIdle;
  while (GetTickCount() < deadline) {
    state = config->state;
    if (state == kTimeDone || state == kTimeFailed) break;
    if (WaitForSingleObject(process, 200) == WAIT_OBJECT_0) break;
  }
  state = config->state;
  DWORD exit_code = STILL_ACTIVE;
  const bool crashed = ExitedWithException(process, &exit_code);
  if (crashed && state != kTimeDone) state = kTimeFailed;
  const bool attached = state != kTimeIdle;
  if (!attached) state = kTimeFailed;

  EjectDll(process, args.pid, args.dll);

  const bool done = state == kTimeDone;
  std::printf(
      "{\"ok\":%s,\"state\":\"%s\",\"pid\":%lu,\"mode\":\"%s\",\"factor\":%.4f,\"offset_sec\":%lld,"
      "\"hooks_installed\":%lu,\"hook_failures\":%lu,\"calls\":%ld,\"duration_ms\":%lu,\"attached\":%s,"
      "\"dll_loaded\":%s,\"target_exited\":%s,\"exit_code\":\"0x%08lX\"}\n",
      done ? "true" : "false", done ? "done" : (state == kTimeFailed ? "failed" : "timeout"), args.pid,
      config->mode == 1 ? "offset" : "factor", args.factor, static_cast<long long>(args.offset_seconds),
      config->hooks_installed, config->hook_failures, config->calls, args.duration_ms, attached ? "true" : "false",
      loaded ? "true" : "false", exit_code != STILL_ACTIVE ? "true" : "false", exit_code);
  std::fflush(stdout);

  UnmapViewOfFile(config);
  CloseHandle(mapping);
  CloseHandle(process);
  return done ? 0 : 1;
}
// ── hook: override one API's return value with the given value ─────────────────────────────────────
int RunHook(const Args& args) {
  auto fail = [](const std::string& message) {
    std::printf("{\"ok\":false,\"error\":%s}\n", wp::JsonString(message).c_str());
    std::fflush(stdout);
    return 1;
  };

  if (args.pid == 0 || args.dll.empty() || args.api.empty()) {
    PrintUsage();
    return 2;
  }

  wp::EnableDebugPrivilege();

  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, args.pid);
  if (process == nullptr) {
    return fail("OpenProcess failed (Win32 " + std::to_string(GetLastError()) + "): the target may have exited or admin rights may be required");
  }

  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_VALUEHOOK_MAPPING_PREFIX L"%lu", args.pid);
  PermissiveSecurity security;
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security.sa, PAGE_READWRITE, 0, sizeof(ValueHookConfig), mapping_name);
  if (mapping == nullptr) {
    CloseHandle(process);
    return fail("CreateFileMapping failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  auto* config = static_cast<ValueHookConfig*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                             sizeof(ValueHookConfig)));
  if (config == nullptr) {
    CloseHandle(mapping);
    CloseHandle(process);
    return fail("MapViewOfFile failed (Win32 " + std::to_string(GetLastError()) + ")");
  }
  ZeroMemory(config, sizeof(ValueHookConfig));
  config->state = kValueHookIdle;
  config->nth = args.nth;
  config->ret = args.ret;
  config->duration_ms = args.duration_ms;
  wcsncpy_s(config->api, args.api.c_str(), _TRUNCATE);
  if (!args.module.empty()) wcsncpy_s(config->module, args.module.c_str(), _TRUNCATE);
  if (!args.out.empty()) {
    wcsncpy_s(config->out_path, args.out.c_str(), _TRUNCATE);
    PrepareOutputFile(args.out + L".log");
  }

  std::string error;
  if (!InjectDll(process, args.dll, &error)) {
    UnmapViewOfFile(config);
    CloseHandle(mapping);
    CloseHandle(process);
    return fail(error);
  }
  const std::wstring dll_name = args.dll.substr(args.dll.find_last_of(L'\\') + 1);
  const bool loaded = FindRemoteModule(args.pid, dll_name) != 0;

  const DWORD deadline = GetTickCount() + args.duration_ms + 15000;
  LONG state = kValueHookIdle;
  while (GetTickCount() < deadline) {
    state = config->state;
    if (state == kValueHookDone || state == kValueHookFailed) break;
    if (WaitForSingleObject(process, 200) == WAIT_OBJECT_0) break;
  }
  state = config->state;
  DWORD exit_code = STILL_ACTIVE;
  const bool crashed = ExitedWithException(process, &exit_code);
  if (crashed && state != kValueHookDone) state = kValueHookFailed;
  const bool attached = state != kValueHookIdle;
  if (!attached) state = kValueHookFailed;

  EjectDll(process, args.pid, args.dll);

  const DWORD calls_seen = config->calls_seen;
  const DWORD calls_overridden = config->calls_overridden;
  const DWORD installed = config->hooks_installed;
  const DWORD failures = config->hook_failures;
  const bool done = state == kValueHookDone;
  std::printf(
      "{\"ok\":%s,\"state\":\"%s\",\"pid\":%lu,\"api\":%s,\"nth\":%lu,\"ret\":\"0x%llX\","
      "\"hooks_installed\":%lu,\"hook_failures\":%lu,\"calls_seen\":%lu,\"calls_overridden\":%lu,"
      "\"duration_ms\":%lu,\"attached\":%s,\"dll_loaded\":%s,\"target_exited\":%s,\"exit_code\":\"0x%08lX\"}\n",
      done ? "true" : "false", done ? "done" : (state == kValueHookFailed ? "failed" : "timeout"), args.pid,
      wp::JsonString(wp::ToUtf8(args.api)).c_str(), args.nth,
      static_cast<unsigned long long>(args.ret), installed, failures, calls_seen, calls_overridden,
      args.duration_ms, attached ? "true" : "false", loaded ? "true" : "false",
      exit_code != STILL_ACTIVE ? "true" : "false", exit_code);
  std::fflush(stdout);

  UnmapViewOfFile(config);
  CloseHandle(mapping);
  CloseHandle(process);
  return done ? 0 : 1;
}
