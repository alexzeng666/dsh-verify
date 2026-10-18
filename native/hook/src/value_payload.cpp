// value_hook.dll -- minimal hook DSL: return-value override only.
//
// Why typed detours rather than a generic thunk: overriding a return value either skips the original function (returning
// the faked value directly) or calls it and overwrites rax. The former needs no argument list, the latter does -- and
// "override only" means the caller sees the faked result, so skipping the original suffices and also keeps its side effects out of the branch under test.
//
// The cost: the supported APIs are a whitelist (12 common entries); anything else is reported as an error, we do not pretend to hook it.
#include <windows.h>

#include <MinHook.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "winproc.h"

#include "value_hook_protocol.h"

namespace {

ValueHookConfig* g_config = nullptr;
HANDLE g_mapping = nullptr;
volatile LONG g_stopping = 0;

// ── original functions ────────────────────────────────────────────────────────────────
using RegQueryValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegOpenKeyExWFn = LONG(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegCreateKeyExWFn = LONG(WINAPI*)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY,
                                        LPDWORD);
using RegSetValueExWFn = LONG(WINAPI*)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using GetTickCount64Fn = ULONGLONG(WINAPI*)();
using WaitForSingleObjectFn = DWORD(WINAPI*)(HANDLE, DWORD);
using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                       LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

RegQueryValueExWFn Real_RegQueryValueExW = nullptr;
RegOpenKeyExWFn Real_RegOpenKeyExW = nullptr;
RegCreateKeyExWFn Real_RegCreateKeyExW = nullptr;
RegSetValueExWFn Real_RegSetValueExW = nullptr;
CreateFileWFn Real_CreateFileW = nullptr;
OpenProcessFn Real_OpenProcess = nullptr;
LoadLibraryWFn Real_LoadLibraryW = nullptr;
GetProcAddressFn Real_GetProcAddress = nullptr;
VirtualAllocFn Real_VirtualAlloc = nullptr;
GetTickCount64Fn Real_GetTickCount64 = nullptr;
WaitForSingleObjectFn Real_WaitForSingleObject = nullptr;
CreateProcessWFn Real_CreateProcessW = nullptr;

void StepLog(const char* text) {
  if (g_config == nullptr || g_config->out_path[0] == L'\0') return;
  wchar_t path[600];
  wcsncpy_s(path, g_config->out_path, _TRUNCATE);
  wcscat_s(path, L".log");
  HANDLE file = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) return;
  DWORD written = 0;
  WriteFile(file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
  WriteFile(file, "\n", 1, &written, nullptr);
  CloseHandle(file);
}

/** Whether this call should fake the return value. */
bool ShouldOverride() {
  if (g_config == nullptr) return false;
  const DWORD seen = static_cast<DWORD>(InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_config->calls_seen)));
  const DWORD nth = g_config->nth;
  const bool override = (nth == 0) || (seen == nth);
  if (override) InterlockedIncrement(reinterpret_cast<volatile LONG*>(&g_config->calls_overridden));
  return override;
}

// ── detours: signatures are hard-coded per target API, the return width follows from the signature ──────────────────────
LSTATUS WINAPI Hook_RegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data,
                                     LPDWORD bytes) {
  if (ShouldOverride()) return static_cast<LSTATUS>(g_config->ret);
  return Real_RegQueryValueExW(key, name, reserved, type, data, bytes);
}

LONG WINAPI Hook_RegOpenKeyExW(HKEY key, LPCWSTR subkey, DWORD options, REGSAM access, PHKEY result) {
  if (ShouldOverride()) return static_cast<LONG>(g_config->ret);
  return Real_RegOpenKeyExW(key, subkey, options, access, result);
}

LONG WINAPI Hook_RegCreateKeyExW(HKEY key, LPCWSTR subkey, DWORD reserved, LPWSTR class_name, DWORD options,
                                 REGSAM access, LPSECURITY_ATTRIBUTES attributes, PHKEY result, LPDWORD disposition) {
  if (ShouldOverride()) return static_cast<LONG>(g_config->ret);
  return Real_RegCreateKeyExW(key, subkey, reserved, class_name, options, access, attributes, result, disposition);
}

LONG WINAPI Hook_RegSetValueExW(HKEY key, LPCWSTR name, DWORD reserved, DWORD type, const BYTE* data, DWORD bytes) {
  if (ShouldOverride()) return static_cast<LONG>(g_config->ret);
  return Real_RegSetValueExW(key, name, reserved, type, data, bytes);
}

HANDLE WINAPI Hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES attributes,
                               DWORD disposition, DWORD flags, HANDLE template_file) {
  if (ShouldOverride()) return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(g_config->ret));
  return Real_CreateFileW(name, access, share, attributes, disposition, flags, template_file);
}

HANDLE WINAPI Hook_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
  if (ShouldOverride()) return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(g_config->ret));
  return Real_OpenProcess(access, inherit, pid);
}

HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name) {
  if (ShouldOverride()) return reinterpret_cast<HMODULE>(static_cast<ULONG_PTR>(g_config->ret));
  return Real_LoadLibraryW(name);
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE module, LPCSTR name) {
  if (ShouldOverride()) return reinterpret_cast<FARPROC>(static_cast<ULONG_PTR>(g_config->ret));
  return Real_GetProcAddress(module, name);
}

LPVOID WINAPI Hook_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect) {
  if (ShouldOverride()) return reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(g_config->ret));
  return Real_VirtualAlloc(address, size, type, protect);
}

ULONGLONG WINAPI Hook_GetTickCount64() {
  if (ShouldOverride()) return g_config->ret;
  return Real_GetTickCount64();
}

DWORD WINAPI Hook_WaitForSingleObject(HANDLE handle, DWORD milliseconds) {
  if (ShouldOverride()) return static_cast<DWORD>(g_config->ret);
  return Real_WaitForSingleObject(handle, milliseconds);
}

BOOL WINAPI Hook_CreateProcessW(LPCWSTR application, LPWSTR command_line, LPSECURITY_ATTRIBUTES process_attributes,
                                LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment,
                                LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION info) {
  if (ShouldOverride()) return static_cast<BOOL>(g_config->ret);
  return Real_CreateProcessW(application, command_line, process_attributes, thread_attributes, inherit, flags,
                             environment, cwd, startup, info);
}

// ── API whitelist ─────────────────────────────────────────────────────────────
struct ApiSpec {
  const wchar_t* module;
  const char* name;   // MinHook's MH_CreateHookApi wants a narrow string
  LPVOID detour;
  LPVOID* original;
};

const ApiSpec kApis[] = {
    {L"advapi32.dll", "RegQueryValueExW", reinterpret_cast<LPVOID>(&Hook_RegQueryValueExW),
     reinterpret_cast<LPVOID*>(&Real_RegQueryValueExW)},
    {L"advapi32.dll", "RegOpenKeyExW", reinterpret_cast<LPVOID>(&Hook_RegOpenKeyExW),
     reinterpret_cast<LPVOID*>(&Real_RegOpenKeyExW)},
    {L"advapi32.dll", "RegCreateKeyExW", reinterpret_cast<LPVOID>(&Hook_RegCreateKeyExW),
     reinterpret_cast<LPVOID*>(&Real_RegCreateKeyExW)},
    {L"advapi32.dll", "RegSetValueExW", reinterpret_cast<LPVOID>(&Hook_RegSetValueExW),
     reinterpret_cast<LPVOID*>(&Real_RegSetValueExW)},
    {L"kernel32.dll", "CreateFileW", reinterpret_cast<LPVOID>(&Hook_CreateFileW),
     reinterpret_cast<LPVOID*>(&Real_CreateFileW)},
    {L"kernel32.dll", "OpenProcess", reinterpret_cast<LPVOID>(&Hook_OpenProcess),
     reinterpret_cast<LPVOID*>(&Real_OpenProcess)},
    {L"kernel32.dll", "LoadLibraryW", reinterpret_cast<LPVOID>(&Hook_LoadLibraryW),
     reinterpret_cast<LPVOID*>(&Real_LoadLibraryW)},
    {L"kernel32.dll", "GetProcAddress", reinterpret_cast<LPVOID>(&Hook_GetProcAddress),
     reinterpret_cast<LPVOID*>(&Real_GetProcAddress)},
    {L"kernel32.dll", "VirtualAlloc", reinterpret_cast<LPVOID>(&Hook_VirtualAlloc),
     reinterpret_cast<LPVOID*>(&Real_VirtualAlloc)},
    {L"kernel32.dll", "GetTickCount64", reinterpret_cast<LPVOID>(&Hook_GetTickCount64),
     reinterpret_cast<LPVOID*>(&Real_GetTickCount64)},
    {L"kernel32.dll", "WaitForSingleObject", reinterpret_cast<LPVOID>(&Hook_WaitForSingleObject),
     reinterpret_cast<LPVOID*>(&Real_WaitForSingleObject)},
    {L"kernel32.dll", "CreateProcessW", reinterpret_cast<LPVOID>(&Hook_CreateProcessW),
     reinterpret_cast<LPVOID*>(&Real_CreateProcessW)},
};

const ApiSpec* FindSpec(const char* name) {
  for (const ApiSpec& spec : kApis) {
    if (_stricmp(spec.name, name) == 0) return &spec;
  }
  return nullptr;
}

// Install the hook by real address rather than by module + export name.
//
// GetProcAddress follows forwarders automatically and returns the **final implementation address** (many APIs in kernel32/advapi32
// are forwarded to kernelbase). So resolving the address first and then placing MH_CreateHook is more reliable than MH_CreateHookApi:
// local implementation or forwarded export, the hook lands on the address the target process actually jumps to.
MH_STATUS CreateHookResolved(LPCWSTR module, LPCSTR name, LPVOID detour, LPVOID* original) {
  const wchar_t* candidates[] = {module, L"kernelbase.dll", L"kernel32.dll"};
  for (const wchar_t* candidate : candidates) {
    if (candidate == nullptr || candidate[0] == L'\0') continue;
    HMODULE mod = GetModuleHandleW(candidate);
    if (mod == nullptr) continue;
    FARPROC target = GetProcAddress(mod, name);
    if (target == nullptr) continue;
    const MH_STATUS status = MH_CreateHook(reinterpret_cast<LPVOID>(target), detour, original);
    if (status == MH_OK) return status;
  }
  return MH_ERROR_FUNCTION_NOT_FOUND;
}

DWORD WINAPI Worker(LPVOID) {
  const DWORD pid = GetCurrentProcessId();
  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_VALUEHOOK_MAPPING_PREFIX L"%lu", pid);
  g_mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mapping_name);
  if (g_mapping == nullptr) return 1;
  g_config = static_cast<ValueHookConfig*>(MapViewOfFile(g_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                                                        sizeof(ValueHookConfig)));
  if (g_config == nullptr) return 1;

  const std::string api_name = wp::ToUtf8(g_config->api);

  {
    char line[256];
    std::snprintf(line, sizeof(line), "worker: api=%s nth=%lu ret=0x%llX", api_name.c_str(),
                  static_cast<unsigned long>(g_config->nth), static_cast<unsigned long long>(g_config->ret));
    StepLog(line);
  }

  const ApiSpec* spec = FindSpec(api_name.c_str());
  if (spec == nullptr) {
    StepLog("worker: unsupported API (outside the whitelist)");
    g_config->hook_failures = 1;
    g_config->state = kValueHookFailed;
    return 1;
  }

  if (MH_Initialize() != MH_OK) {
    g_config->state = kValueHookFailed;
    return 1;
  }

  const LPCWSTR module = g_config->module[0] != L'\0' ? g_config->module : spec->module;
  const MH_STATUS status = CreateHookResolved(module, spec->name, spec->detour, spec->original);
  if (status != MH_OK) {
    char line[128];
    std::snprintf(line, sizeof(line), "worker: MH_CreateHookApi failed status=%d", static_cast<int>(status));
    StepLog(line);
    g_config->hook_failures = 1;
    g_config->state = kValueHookFailed;
    MH_Uninitialize();
    return 1;
  }
  if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
    g_config->hook_failures = 1;
    g_config->state = kValueHookFailed;
    MH_Uninitialize();
    return 1;
  }
  g_config->hooks_installed = 1;
  g_config->state = kValueHookRunning;
  StepLog("worker: hook installed, state=running");

  const DWORD started = GetTickCount();
  while (g_stopping == 0) {
    const DWORD elapsed = GetTickCount() - started;
    if (elapsed >= g_config->duration_ms) break;
    Sleep(200);
  }

  MH_DisableHook(MH_ALL_HOOKS);
  Sleep(100);
  MH_Uninitialize();
  g_config->state = kValueHookDone;
  StepLog("worker: done");
  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (thread != nullptr) CloseHandle(thread);
  }
  return TRUE;
}
