// hook_helper.dll -- injected into the target process to inline-hook and record API calls.
//
// Design notes (all of them hard-won):
// - DllMain only calls CreateThread; MinHook init / hook installation / flushing all happen on the worker thread:
//   doing heavy work under the loader lock deadlocks.
// - One hook failing does not block the rest (another program having grabbed the slot first is normal); the failure count goes back to the host.
// - Records go into the DLL's own ring buffer and the worker thread flushes incrementally once a second -- a mid-run crash of the target still loses nothing already recorded.
#include <windows.h>

#include <MinHook.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "trace_protocol.h"

namespace {

ProbeConfig* g_config = nullptr;
HANDLE g_mapping = nullptr;
CallRecord* g_records = nullptr;
volatile LONG g_index = 0;
volatile LONG g_stopping = 0;
DWORD g_written = 0;
HANDLE g_file = INVALID_HANDLE_VALUE;

// ── original functions ────────────────────────────────────────────────────────────────
using SleepFn = void(WINAPI*)(DWORD);
using GetTickCount64Fn = ULONGLONG(WINAPI*)();
using QueryPerformanceCounterFn = BOOL(WINAPI*)(LARGE_INTEGER*);
using CreateFileWFn = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using ReadFileFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
using WriteFileFn = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using LoadLibraryWFn = HMODULE(WINAPI*)(LPCWSTR);
using GetProcAddressFn = FARPROC(WINAPI*)(HMODULE, LPCSTR);
using RegOpenKeyExWFn = LONG(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using CreateProcessWFn = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                       LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using VirtualAllocFn = LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD);
using RegQueryValueExWFn = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using HeapAllocFn = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);

SleepFn Real_Sleep = nullptr;
GetTickCount64Fn Real_GetTickCount64 = nullptr;
QueryPerformanceCounterFn Real_QueryPerformanceCounter = nullptr;
CreateFileWFn Real_CreateFileW = nullptr;
ReadFileFn Real_ReadFile = nullptr;
WriteFileFn Real_WriteFile = nullptr;
LoadLibraryWFn Real_LoadLibraryW = nullptr;
GetProcAddressFn Real_GetProcAddress = nullptr;
RegOpenKeyExWFn Real_RegOpenKeyExW = nullptr;
CreateProcessWFn Real_CreateProcessW = nullptr;
VirtualAllocFn Real_VirtualAlloc = nullptr;
RegQueryValueExWFn Real_RegQueryValueExW = nullptr;
HeapAllocFn Real_HeapAlloc = nullptr;

// The timestamp must travel a path that **never passes through our own hooks**: GetTickCount64 is itself on the hooked list.
//
// Once the "try kernelbase!X first" change landed at 21:59, that path broke: CaptureClock grabs the
// address of kernelbase!GetTickCount64, and CreateHookResolved now precisely **prefers** to put the detour
// on that kernelbase address -- so g_clock actually points at our own Hook_GetTickCount64:
//     Now() -> Hook_GetTickCount64 -> Acquire() -> Now() -> ...
// The target died of stack overflow right after injection (DLL loaded fine, hooks installed too, but the process was gone in 70ms).
//
// Fix: add a per-thread re-entry gate. While the recorder's own path (the timestamp read) is running, Acquire() returns null,
// and the detour only calls the original function without recording -- no more recursion.
thread_local int g_reentry = 0;

using ClockFn = ULONGLONG(WINAPI*)();
ClockFn g_clock = nullptr;

ULONGLONG Now() {
  ++g_reentry;
  const ULONGLONG value = g_clock != nullptr ? g_clock() : GetTickCount64();
  --g_reentry;
  return value;
}

// Pin the clock function down during init (no hooks are installed yet at this point).
void CaptureClock() {
  HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
  HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
  if (kernelbase != nullptr) g_clock = reinterpret_cast<ClockFn>(GetProcAddress(kernelbase, "GetTickCount64"));
  if (g_clock == nullptr && kernel32 != nullptr) {
    g_clock = reinterpret_cast<ClockFn>(GetProcAddress(kernel32, "GetTickCount64"));
  }
}

CallRecord* Acquire() {
  // The recorder's own call path (the timestamp read inside Now()) must not enter the recorder again: that is an infinite loop.
  if (g_reentry > 0) return nullptr;
  if (g_records == nullptr || g_stopping != 0) return nullptr;
  const LONG index = InterlockedIncrement(&g_index) - 1;
  if (index >= DSH_PROBE_MAX_RECORDS) return nullptr;
  CallRecord* record = &g_records[index];
  record->api = 0;
  record->tid = GetCurrentThreadId();
  record->ts = Now();
  record->args[0] = record->args[1] = record->args[2] = record->args[3] = 0;
  record->ret = 0;
  record->text[0] = L'\0';
  return record;
}

void SetText(CallRecord* record, const wchar_t* text) {
  if (record == nullptr || text == nullptr) return;
  wcsncpy_s(record->text, DSH_PROBE_TEXT_CHARS, text, _TRUNCATE);
}

void SetTextAnsi(CallRecord* record, const char* text) {
  if (record == nullptr || text == nullptr) return;
  MultiByteToWideChar(CP_ACP, 0, text, -1, record->text, DSH_PROBE_TEXT_CHARS);
  record->text[DSH_PROBE_TEXT_CHARS - 1] = L'\0';
}

// ── hooks ──────────────────────────────────────────────────────────────────
void WINAPI Hook_Sleep(DWORD milliseconds) {
  if (CallRecord* record = Acquire()) {
    record->api = kApiSleep;
    record->args[0] = milliseconds;
  }
  Real_Sleep(milliseconds);
}

ULONGLONG WINAPI Hook_GetTickCount64() {
  const ULONGLONG value = Real_GetTickCount64();
  if (CallRecord* record = Acquire()) {
    record->api = kApiGetTickCount64;
    record->ret = value;
  }
  return value;
}

BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* counter) {
  const BOOL ok = Real_QueryPerformanceCounter(counter);
  if (CallRecord* record = Acquire()) {
    record->api = kApiQueryPerformanceCounter;
    record->args[0] = reinterpret_cast<ULONGLONG>(counter);
    record->ret = counter != nullptr ? static_cast<ULONGLONG>(counter->QuadPart) : 0;
  }
  return ok;
}

HANDLE WINAPI Hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                               DWORD flags, HANDLE template_file) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiCreateFileW;
    record->args[0] = access;
    record->args[1] = share;
    record->args[2] = disposition;
    SetText(record, name);
  }
  const HANDLE handle = Real_CreateFileW(name, access, share, sa, disposition, flags, template_file);
  if (record != nullptr) record->ret = reinterpret_cast<ULONGLONG>(handle);
  return handle;
}

BOOL WINAPI Hook_ReadFile(HANDLE file, LPVOID buffer, DWORD bytes, LPDWORD read, LPOVERLAPPED overlapped) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiReadFile;
    record->args[0] = reinterpret_cast<ULONGLONG>(file);
    record->args[1] = bytes;
  }
  const BOOL ok = Real_ReadFile(file, buffer, bytes, read, overlapped);
  if (record != nullptr) {
    record->ret = ok != FALSE ? (read != nullptr ? *read : bytes) : 0;
  }
  return ok;
}

BOOL WINAPI Hook_WriteFile(HANDLE file, LPCVOID buffer, DWORD bytes, LPDWORD written, LPOVERLAPPED overlapped) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiWriteFile;
    record->args[0] = reinterpret_cast<ULONGLONG>(file);
    record->args[1] = bytes;
  }
  const BOOL ok = Real_WriteFile(file, buffer, bytes, written, overlapped);
  if (record != nullptr) {
    record->ret = ok != FALSE ? (written != nullptr ? *written : bytes) : 0;
  }
  return ok;
}

HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiLoadLibraryW;
    SetText(record, name);
  }
  const HMODULE module = Real_LoadLibraryW(name);
  if (record != nullptr) record->ret = reinterpret_cast<ULONGLONG>(module);
  return module;
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE module, LPCSTR name) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiGetProcAddress;
    record->args[0] = reinterpret_cast<ULONGLONG>(module);
    SetTextAnsi(record, name);
  }
  const FARPROC address = Real_GetProcAddress(module, name);
  if (record != nullptr) record->ret = reinterpret_cast<ULONGLONG>(address);
  return address;
}

LONG WINAPI Hook_RegOpenKeyExW(HKEY key, LPCWSTR subkey, DWORD options, REGSAM access, PHKEY result) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiRegOpenKeyExW;
    record->args[0] = reinterpret_cast<ULONGLONG>(key);
    record->args[1] = access;
    SetText(record, subkey);
  }
  const LONG status = Real_RegOpenKeyExW(key, subkey, options, access, result);
  if (record != nullptr) record->ret = static_cast<ULONGLONG>(static_cast<LONG>(status));
  return status;
}

BOOL WINAPI Hook_CreateProcessW(LPCWSTR application, LPWSTR command_line, LPSECURITY_ATTRIBUTES process_attributes,
                                LPSECURITY_ATTRIBUTES thread_attributes, BOOL inherit, DWORD flags, LPVOID environment,
                                LPCWSTR cwd, LPSTARTUPINFOW startup, LPPROCESS_INFORMATION info) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiCreateProcessW;
    record->args[0] = flags;
    SetText(record, command_line != nullptr ? command_line : application);
  }
  const BOOL ok = Real_CreateProcessW(application, command_line, process_attributes, thread_attributes, inherit, flags,
                                      environment, cwd, startup, info);
  if (record != nullptr) {
    record->ret = ok != FALSE && info != nullptr ? info->dwProcessId : 0;
  }
  return ok;
}

LPVOID WINAPI Hook_VirtualAlloc(LPVOID address, SIZE_T size, DWORD type, DWORD protect) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiVirtualAlloc;
    record->args[0] = size;
    record->args[1] = protect;
  }
  const LPVOID result = Real_VirtualAlloc(address, size, type, protect);
  if (record != nullptr) record->ret = reinterpret_cast<ULONGLONG>(result);
  return result;
}

LSTATUS WINAPI Hook_RegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD reserved, LPDWORD type, LPBYTE data,
                                     LPDWORD bytes) {
  CallRecord* record = Acquire();
  if (record != nullptr) {
    record->api = kApiRegQueryValueExW;
    record->args[0] = reinterpret_cast<ULONGLONG>(key);
    record->args[1] = reinterpret_cast<ULONGLONG>(name);
    SetText(record, name);
  }
  const LSTATUS status = Real_RegQueryValueExW(key, name, reserved, type, data, bytes);
  if (record != nullptr) record->ret = static_cast<ULONGLONG>(status);
  return status;
}

// ── flush to disk ───────────────────────────────────────────────────────────────────
void AppendUtf8(std::vector<char>* out, const wchar_t* text) {
  if (text == nullptr) return;
  const int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
  if (length <= 1) return;
  const size_t offset = out->size();
  out->resize(offset + static_cast<size_t>(length - 1));
  WideCharToMultiByte(CP_UTF8, 0, text, -1, out->data() + offset, length, nullptr, nullptr);
}

void AppendEscaped(std::vector<char>* out, const wchar_t* text) {
  std::vector<char> raw;
  AppendUtf8(&raw, text);
  for (const char ch : raw) {
    if (ch == '"' || ch == '\\') {
      out->push_back('\\');
      out->push_back(ch);
    } else if (static_cast<unsigned char>(ch) < 0x20) {
      out->push_back(' ');
    } else {
      out->push_back(ch);
    }
  }
}

void AppendLiteral(std::vector<char>* out, const char* text) {
  out->insert(out->end(), text, text + std::strlen(text));
}

void AppendHex(std::vector<char>* out, ULONGLONG value) {
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "\"0x%llX\"", static_cast<unsigned long long>(value));
  out->insert(out->end(), buffer, buffer + std::strlen(buffer));
}

// Our own flushing goes through the raw WriteFile: otherwise our own log-writing calls would pollute the records.
void RawWrite(HANDLE file, const char* data, DWORD bytes) {
  if (file == INVALID_HANDLE_VALUE || data == nullptr || bytes == 0) return;
  DWORD written = 0;
  if (Real_WriteFile != nullptr) {
    Real_WriteFile(file, data, bytes, &written, nullptr);
  } else {
    WriteFile(file, data, bytes, &written, nullptr);
  }
}

void StepLog(const char* text) {
  if (g_config == nullptr || g_config->out_path[0] == L'\0') return;
  wchar_t log_path[600];
  wcsncpy_s(log_path, g_config->out_path, _TRUNCATE);
  wcscat_s(log_path, L".log");
  // Our own logging must not go through the hooked CreateFileW: otherwise we would record ourselves into the trace.
  HANDLE file = Real_CreateFileW != nullptr
                    ? Real_CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                       FILE_ATTRIBUTE_NORMAL, nullptr)
                    : CreateFileW(log_path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return;
  RawWrite(file, text, static_cast<DWORD>(std::strlen(text)));
  RawWrite(file, "\n", 1);
  CloseHandle(file);
}

void FlushRecords(bool final_flush) {
  const LONG index = InterlockedCompareExchange(&g_index, 0, 0);
  const DWORD count = index <= 0 ? 0 : static_cast<DWORD>(index);
  if (count <= g_written) return;

  std::vector<char> chunk;
  chunk.reserve(64 * 1024);
  for (DWORD at = g_written; at < count; ++at) {
    const CallRecord& record = g_records[at];
    chunk.push_back('{');
    const char* name = "unknown";
    switch (record.api) {
      case kApiSleep: name = "Sleep"; break;
      case kApiGetTickCount64: name = "GetTickCount64"; break;
      case kApiQueryPerformanceCounter: name = "QueryPerformanceCounter"; break;
      case kApiCreateFileW: name = "CreateFileW"; break;
      case kApiReadFile: name = "ReadFile"; break;
      case kApiWriteFile: name = "WriteFile"; break;
      case kApiLoadLibraryW: name = "LoadLibraryW"; break;
      case kApiGetProcAddress: name = "GetProcAddress"; break;
      case kApiRegOpenKeyExW: name = "RegOpenKeyExW"; break;
      case kApiCreateProcessW: name = "CreateProcessW"; break;
      case kApiVirtualAlloc: name = "VirtualAlloc"; break;
      case kApiRegQueryValueExW: name = "RegQueryValueExW"; break;
      default: break;
    }
    AppendLiteral(&chunk, "\"api\":\"");
    chunk.insert(chunk.end(), name, name + std::strlen(name));
    AppendLiteral(&chunk, "\",\"tid\":");
    char number[32];
    std::snprintf(number, sizeof(number), "%lu", static_cast<unsigned long>(record.tid));
    chunk.insert(chunk.end(), number, number + std::strlen(number));
    AppendLiteral(&chunk, ",\"ts\":");
    std::snprintf(number, sizeof(number), "%llu", static_cast<unsigned long long>(record.ts));
    chunk.insert(chunk.end(), number, number + std::strlen(number));
    AppendLiteral(&chunk, ",\"args\":[");
    for (int slot = 0; slot < 4; ++slot) {
      if (slot != 0) chunk.push_back(',');
      AppendHex(&chunk, record.args[slot]);
    }
    AppendLiteral(&chunk, "],\"ret\":");
    AppendHex(&chunk, record.ret);
    AppendLiteral(&chunk, ",\"text\":\"");
    AppendEscaped(&chunk, record.text);
    AppendLiteral(&chunk, "\"}\n");
    g_written = at + 1;
  }
  (void)final_flush;

  RawWrite(g_file, chunk.data(), static_cast<DWORD>(chunk.size()));
  if (g_config != nullptr) g_config->records_written = g_written;
}

// ── worker thread ───────────────────────────────────────────────────────────────
// Many APIs in kernel32 are forwarded to kernelbase: the loader resolves imports straight to the implementing module,
// and then a hook on the kernel32 forwarder stub is never called at all. So try kernelbase first, and fall back to the given module.
MH_STATUS CreateHookResolved(LPCWSTR module, LPCSTR name, LPVOID detour, LPVOID* original) {
  if (_wcsicmp(module, L"kernel32.dll") == 0) {
    const MH_STATUS status = MH_CreateHookApi(L"kernelbase.dll", name, detour, original);
    if (status == MH_OK) return status;
  }
  return MH_CreateHookApi(module, name, detour, original);
}
struct HookSpec {
  DWORD api;
  LPCWSTR module;
  LPCSTR name;
  LPVOID detour;
  LPVOID* original;
};

DWORD WINAPI Worker(LPVOID) {
  // The earliest diagnostic line: even before the config mapping is in hand, it must prove the worker thread really started.
  {
    wchar_t boot_path[512];
    const DWORD length = GetTempPathW(512, boot_path);
    if (length > 0 && length < 400) {
      wcscat_s(boot_path, L"dsh_verify_probe_boot.log");
      HANDLE boot = CreateFileW(boot_path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
      if (boot != INVALID_HANDLE_VALUE) {
        RawWrite(boot, "worker started\n", 15);
        CloseHandle(boot);
      }
    }
  }

  const DWORD pid = GetCurrentProcessId();
  CaptureClock();
  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_PROBE_MAPPING_PREFIX L"%lu", pid);
  g_mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mapping_name);
  if (g_mapping == nullptr) return 1;
  g_config = static_cast<ProbeConfig*>(MapViewOfFile(g_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(ProbeConfig)));
  if (g_config == nullptr) return 1;
  StepLog("worker: config mapped");

  g_records = static_cast<CallRecord*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                                sizeof(CallRecord) * DSH_PROBE_MAX_RECORDS));
  if (g_records == nullptr) {
    g_config->state = kProbeFailed;
    return 1;
  }

  g_file = CreateFileW(g_config->out_path, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, nullptr);
  StepLog("worker: output file opened");

  if (MH_Initialize() != MH_OK) {
    StepLog("worker: MH_Initialize failed");
    g_config->state = kProbeFailed;
    g_config->hook_failures = 0xFFFF;
    return 1;
  }
  StepLog("worker: minhook initialized");

  const HookSpec specs[] = {
      {kApiSleep, L"kernel32.dll", "Sleep", reinterpret_cast<LPVOID>(&Hook_Sleep), reinterpret_cast<LPVOID*>(&Real_Sleep)},
      {kApiGetTickCount64, L"kernel32.dll", "GetTickCount64", reinterpret_cast<LPVOID>(&Hook_GetTickCount64),
       reinterpret_cast<LPVOID*>(&Real_GetTickCount64)},
      {kApiQueryPerformanceCounter, L"kernel32.dll", "QueryPerformanceCounter",
       reinterpret_cast<LPVOID>(&Hook_QueryPerformanceCounter), reinterpret_cast<LPVOID*>(&Real_QueryPerformanceCounter)},
      {kApiCreateFileW, L"kernel32.dll", "CreateFileW", reinterpret_cast<LPVOID>(&Hook_CreateFileW),
       reinterpret_cast<LPVOID*>(&Real_CreateFileW)},
      {kApiReadFile, L"kernel32.dll", "ReadFile", reinterpret_cast<LPVOID>(&Hook_ReadFile),
       reinterpret_cast<LPVOID*>(&Real_ReadFile)},
      {kApiWriteFile, L"kernel32.dll", "WriteFile", reinterpret_cast<LPVOID>(&Hook_WriteFile),
       reinterpret_cast<LPVOID*>(&Real_WriteFile)},
      {kApiLoadLibraryW, L"kernel32.dll", "LoadLibraryW", reinterpret_cast<LPVOID>(&Hook_LoadLibraryW),
       reinterpret_cast<LPVOID*>(&Real_LoadLibraryW)},
      {kApiGetProcAddress, L"kernel32.dll", "GetProcAddress", reinterpret_cast<LPVOID>(&Hook_GetProcAddress),
       reinterpret_cast<LPVOID*>(&Real_GetProcAddress)},
      {kApiRegOpenKeyExW, L"advapi32.dll", "RegOpenKeyExW", reinterpret_cast<LPVOID>(&Hook_RegOpenKeyExW),
       reinterpret_cast<LPVOID*>(&Real_RegOpenKeyExW)},
      {kApiCreateProcessW, L"kernel32.dll", "CreateProcessW", reinterpret_cast<LPVOID>(&Hook_CreateProcessW),
       reinterpret_cast<LPVOID*>(&Real_CreateProcessW)},
      {kApiVirtualAlloc, L"kernel32.dll", "VirtualAlloc", reinterpret_cast<LPVOID>(&Hook_VirtualAlloc),
       reinterpret_cast<LPVOID*>(&Real_VirtualAlloc)},
      {kApiRegQueryValueExW, L"advapi32.dll", "RegQueryValueExW", reinterpret_cast<LPVOID>(&Hook_RegQueryValueExW),
       reinterpret_cast<LPVOID*>(&Real_RegQueryValueExW)},
      // Note: do **not** put HeapAlloc into this table.
      // The recorder itself (Acquire / SetText / std::string / printf) all go through HeapAlloc,
      // and once it is hooked and enabled, the very step of installing hooks triggers itself:
      //   HeapAlloc -> Hook_HeapAlloc -> Acquire -> Now -> ... hangs outright (measured: a full default run always hangs,
      //   a named subset is fine -- because the subset does not contain it).
  };

  // Install them one by one: if another program has already hooked one API, only that one is lost, the rest still go in.
  for (const HookSpec& spec : specs) {
    if ((g_config->api_mask & (1u << spec.api)) == 0) continue;
    if (CreateHookResolved(spec.module, spec.name, spec.detour, spec.original) != MH_OK) {
      ++g_config->hook_failures;
      continue;
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) ++g_config->hook_failures;
  }
  g_config->state = kProbeRunning;
  StepLog("worker: hooks installed, state=running");

  const DWORD started = GetTickCount();
  while (g_stopping == 0) {
    const DWORD elapsed = GetTickCount() - started;
    if (elapsed >= g_config->duration_ms) break;
    // Our own worker thread avoids the hooked Sleep, so its own waits do not end up in the log either.
    if (Real_Sleep != nullptr) {
      Real_Sleep(1000);
    } else {
      Sleep(1000);
    }
    FlushRecords(false);
  }

  InterlockedExchange(&g_stopping, 1);
  // First let the hooks pass straight through, then wait a moment so other threads can walk out of the detour, and only then uninstall.
  MH_DisableHook(MH_ALL_HOOKS);
  Sleep(200);
  FlushRecords(true);
  if (g_file != INVALID_HANDLE_VALUE) CloseHandle(g_file);
  g_file = INVALID_HANDLE_VALUE;
  MH_Uninitialize();
  g_config->state = kProbeDone;
  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
  (void)instance;
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(instance);
    // Under the loader lock only start the thread; all the heavy work happens on the worker thread.
    HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (thread != nullptr) CloseHandle(thread);
  }
  return TRUE;
}
