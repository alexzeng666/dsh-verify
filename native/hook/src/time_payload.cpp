// time_helper.dll -- speed up / slow down / shift into the future the target process's clock.
//
// Two strategies run in parallel:
//   1) Shorten the waits: divide the duration of Sleep / Wait* / SetTimer / SetWaitableTimer / timeSetEvent by the factor
//   2) Speed up the clock: multiply GetTickCount / QPC / FILETIME style readings by the factor, plus a fixed offset in offset mode
//
// Rebasing: the first time each clock is called, anchor baseReal = baseHook = the real value; afterwards
// virtual = baseHook + (real - baseReal) * factor. When the factor changes mid-run, re-anchor on the last observed value
// so virtual time stays continuous across that switch (no jump).
#include <windows.h>
#include <mmsystem.h>

#include <MinHook.h>

#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>

#include "time_protocol.h"

namespace {

TimeConfig* g_config = nullptr;
HANDLE g_mapping = nullptr;
double g_factor = 1.0;
LONGLONG g_offset_100ns = 0;
volatile LONG g_stopping = 0;

void StepLog(const char* text);  // forward declaration: used inside hooks, implementation lives in the second half of the file

// ── original functions ────────────────────────────────────────────────────────────────
using GetTickCountFn = DWORD(WINAPI*)();
using GetTickCount64Fn = ULONGLONG(WINAPI*)();
using TimeGetTimeFn = DWORD(WINAPI*)();
using QueryPerformanceCounterFn = BOOL(WINAPI*)(LARGE_INTEGER*);
using GetSystemTimeAsFileTimeFn = void(WINAPI*)(LPFILETIME);
using GetSystemTimePreciseAsFileTimeFn = void(WINAPI*)(LPFILETIME);
using GetMessageTimeFn = LONG(WINAPI*)();
using GetSystemTimeFn = void(WINAPI*)(LPSYSTEMTIME);
using GetLocalTimeFn = void(WINAPI*)(LPSYSTEMTIME);
using SleepFn = void(WINAPI*)(DWORD);
using SleepExFn = DWORD(WINAPI*)(DWORD, BOOL);
using WaitForSingleObjectFn = DWORD(WINAPI*)(HANDLE, DWORD);
using WaitForSingleObjectExFn = DWORD(WINAPI*)(HANDLE, DWORD, BOOL);
using WaitForMultipleObjectsFn = DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD);
using WaitForMultipleObjectsExFn = DWORD(WINAPI*)(DWORD, const HANDLE*, BOOL, DWORD, BOOL);
using SetTimerFn = UINT_PTR(WINAPI*)(HWND, UINT_PTR, UINT, TIMERPROC);
using SetWaitableTimerFn = BOOL(WINAPI*)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID, BOOL);
using SetWaitableTimerExFn = BOOL(WINAPI*)(HANDLE, const LARGE_INTEGER*, LONG, PTIMERAPCROUTINE, LPVOID,
                                           PREASON_CONTEXT, ULONG);
using TimeSetEventFn = MMRESULT(WINAPI*)(UINT, UINT, LPTIMECALLBACK, DWORD_PTR, UINT);

GetTickCountFn Real_GetTickCount = nullptr;
GetTickCount64Fn Real_GetTickCount64 = nullptr;
TimeGetTimeFn Real_timeGetTime = nullptr;
QueryPerformanceCounterFn Real_QueryPerformanceCounter = nullptr;
GetSystemTimeAsFileTimeFn Real_GetSystemTimeAsFileTime = nullptr;
GetSystemTimePreciseAsFileTimeFn Real_GetSystemTimePreciseAsFileTime = nullptr;
GetMessageTimeFn Real_GetMessageTime = nullptr;
GetSystemTimeFn Real_GetSystemTime = nullptr;
GetLocalTimeFn Real_GetLocalTime = nullptr;
SleepFn Real_Sleep = nullptr;
SleepExFn Real_SleepEx = nullptr;
WaitForSingleObjectFn Real_WaitForSingleObject = nullptr;
WaitForSingleObjectExFn Real_WaitForSingleObjectEx = nullptr;
WaitForMultipleObjectsFn Real_WaitForMultipleObjects = nullptr;
WaitForMultipleObjectsExFn Real_WaitForMultipleObjectsEx = nullptr;
SetTimerFn Real_SetTimer = nullptr;
SetWaitableTimerFn Real_SetWaitableTimer = nullptr;
SetWaitableTimerExFn Real_SetWaitableTimerEx = nullptr;
TimeSetEventFn Real_timeSetEvent = nullptr;

// ── rebasing ─────────────────────────────────────────────────────────────────
struct Anchor {
  ULONGLONG baseReal;
  ULONGLONG baseHook;
  ULONGLONG lastReal;
  ULONGLONG lastHook;
  bool anchored;
};

Anchor g_tick{};
Anchor g_tick64{};
Anchor g_timeGetTime{};
Anchor g_qpc{};
Anchor g_filetime{};
Anchor g_filetimePrecise{};
Anchor g_messageTime{};

ULONGLONG Scaled(Anchor* anchor, ULONGLONG real) {
  if (anchor->anchored && g_factor != 1.0) {
    const long double delta = static_cast<long double>(real - anchor->baseReal);
    const ULONGLONG scaled = static_cast<ULONGLONG>(delta * static_cast<long double>(g_factor));
    anchor->lastReal = real;
    anchor->lastHook = anchor->baseHook + scaled;
    return anchor->lastHook;
  }
  if (!anchor->anchored) {
    anchor->baseReal = real;
    anchor->baseHook = real;
    anchor->anchored = true;
  }
  anchor->lastReal = real;
  anchor->lastHook = real;
  return real;
}

// Re-anchor: on a factor change, use the last observed value as the new base so virtual time continues from where it is.
void ReanchorAll() {
  for (Anchor* anchor : {&g_tick, &g_tick64, &g_timeGetTime, &g_qpc, &g_filetime, &g_filetimePrecise, &g_messageTime}) {
    if (!anchor->anchored) continue;
    anchor->baseReal = anchor->lastReal;
    anchor->baseHook = anchor->lastHook;
  }
}

ULONGLONG ApplyOffset(ULONGLONG value) {
  if (g_offset_100ns == 0) return value;
  const LONGLONG shifted = static_cast<LONGLONG>(value) + g_offset_100ns;
  return static_cast<ULONGLONG>(shifted);
}

DWORD ScaledDuration(DWORD milliseconds) {
  if (milliseconds == 0 || milliseconds == INFINITE || g_factor <= 0.0) return milliseconds;
  const double scaled = static_cast<double>(milliseconds) / g_factor;
  if (scaled < 1.0) return 1;
  if (scaled > 4294967294.0) return 4294967294u;
  return static_cast<DWORD>(scaled);
}

// ── clock hooks ─────────────────────────────────────────────────────────────
DWORD WINAPI Hook_GetTickCount() {
  return static_cast<DWORD>(Scaled(&g_tick, Real_GetTickCount()));
}

ULONGLONG WINAPI Hook_GetTickCount64() {
  return Scaled(&g_tick64, Real_GetTickCount64());
}

DWORD WINAPI Hook_timeGetTime() {
  return static_cast<DWORD>(Scaled(&g_timeGetTime, Real_timeGetTime()));
}

BOOL WINAPI Hook_QueryPerformanceCounter(LARGE_INTEGER* counter) {
  const BOOL ok = Real_QueryPerformanceCounter(counter);
  if (ok != FALSE && counter != nullptr) {
    counter->QuadPart = static_cast<LONGLONG>(Scaled(&g_qpc, static_cast<ULONGLONG>(counter->QuadPart)));
  }
  return ok;
}

void WINAPI Hook_GetSystemTimeAsFileTime(LPFILETIME time) {
  if (g_config != nullptr) InterlockedIncrement(&g_config->calls);
  Real_GetSystemTimeAsFileTime(time);
  if (time == nullptr) return;
  const ULONGLONG real = (static_cast<ULONGLONG>(time->dwHighDateTime) << 32) | time->dwLowDateTime;
  const ULONGLONG value = ApplyOffset(Scaled(&g_filetime, real));
  static volatile LONG logged = 0;
  if (InterlockedCompareExchange(&logged, 1, 0) == 0) {
    char line[192];
    std::snprintf(line, sizeof(line), "filetime: real=%llu value=%llu offset=%lld", (unsigned long long)real,
                  (unsigned long long)value, static_cast<long long>(g_offset_100ns));
    StepLog(line);
  }
  time->dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFu);
  time->dwHighDateTime = static_cast<DWORD>(value >> 32);
}

void WINAPI Hook_GetSystemTimePreciseAsFileTime(LPFILETIME time) {
  Real_GetSystemTimePreciseAsFileTime(time);
  if (time == nullptr) return;
  const ULONGLONG real = (static_cast<ULONGLONG>(time->dwHighDateTime) << 32) | time->dwLowDateTime;
  const ULONGLONG value = ApplyOffset(Scaled(&g_filetimePrecise, real));
  time->dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFu);
  time->dwHighDateTime = static_cast<DWORD>(value >> 32);
}

LONG WINAPI Hook_GetMessageTime() {
  return static_cast<LONG>(Scaled(&g_messageTime, static_cast<ULONGLONG>(Real_GetMessageTime())));
}

void WINAPI Hook_GetSystemTime(LPSYSTEMTIME time) {
  if (time == nullptr) {
    Real_GetSystemTime(time);
    return;
  }
  FILETIME file_time{};
  Real_GetSystemTimeAsFileTime(&file_time);
  const ULONGLONG real = (static_cast<ULONGLONG>(file_time.dwHighDateTime) << 32) | file_time.dwLowDateTime;
  const ULONGLONG value = ApplyOffset(Scaled(&g_filetime, real));
  file_time.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFFu);
  file_time.dwHighDateTime = static_cast<DWORD>(value >> 32);
  FileTimeToSystemTime(&file_time, time);
}

void WINAPI Hook_GetLocalTime(LPSYSTEMTIME time) {
  if (g_config != nullptr) InterlockedIncrement(&g_config->calls_local);
  if (time == nullptr) {
    Real_GetLocalTime(time);
    return;
  }
  SYSTEMTIME utc{};
  Hook_GetSystemTime(&utc);
  SystemTimeToTzSpecificLocalTime(nullptr, &utc, time);
}

// ── wait / timer hooks ────────────────────────────────────────────────────
void WINAPI Hook_Sleep(DWORD milliseconds) { Real_Sleep(ScaledDuration(milliseconds)); }

DWORD WINAPI Hook_SleepEx(DWORD milliseconds, BOOL alertable) {
  return Real_SleepEx(ScaledDuration(milliseconds), alertable);
}

DWORD WINAPI Hook_WaitForSingleObject(HANDLE handle, DWORD milliseconds) {
  return Real_WaitForSingleObject(handle, ScaledDuration(milliseconds));
}

DWORD WINAPI Hook_WaitForSingleObjectEx(HANDLE handle, DWORD milliseconds, BOOL alertable) {
  return Real_WaitForSingleObjectEx(handle, ScaledDuration(milliseconds), alertable);
}

DWORD WINAPI Hook_WaitForMultipleObjects(DWORD count, const HANDLE* handles, BOOL wait_all, DWORD milliseconds) {
  return Real_WaitForMultipleObjects(count, handles, wait_all, ScaledDuration(milliseconds));
}

DWORD WINAPI Hook_WaitForMultipleObjectsEx(DWORD count, const HANDLE* handles, BOOL wait_all, DWORD milliseconds,
                                           BOOL alertable) {
  return Real_WaitForMultipleObjectsEx(count, handles, wait_all, ScaledDuration(milliseconds), alertable);
}

UINT_PTR WINAPI Hook_SetTimer(HWND window, UINT_PTR id, UINT elapse, TIMERPROC procedure) {
  return Real_SetTimer(window, id, ScaledDuration(elapse), procedure);
}

BOOL WINAPI Hook_SetWaitableTimer(HANDLE timer, const LARGE_INTEGER* due, LONG period, PTIMERAPCROUTINE routine,
                                  LPVOID parameter, BOOL resume) {
  LARGE_INTEGER scaled{};
  const LARGE_INTEGER* use = due;
  if (due != nullptr && due->QuadPart < 0) {
    // Negative = relative time (100ns units), scaled by the factor.
    const double value = static_cast<double>(-due->QuadPart) / g_factor;
    scaled.QuadPart = -static_cast<LONGLONG>(value < 1.0 ? 1.0 : value);
    use = &scaled;
  }
  return Real_SetWaitableTimer(timer, use, period, routine, parameter, resume);
}

BOOL WINAPI Hook_SetWaitableTimerEx(HANDLE timer, const LARGE_INTEGER* due, LONG period, PTIMERAPCROUTINE routine,
                                    LPVOID parameter, PREASON_CONTEXT context, ULONG flags) {
  LARGE_INTEGER scaled{};
  const LARGE_INTEGER* use = due;
  if (due != nullptr && due->QuadPart < 0) {
    const double value = static_cast<double>(-due->QuadPart) / g_factor;
    scaled.QuadPart = -static_cast<LONGLONG>(value < 1.0 ? 1.0 : value);
    use = &scaled;
  }
  return Real_SetWaitableTimerEx(timer, use, period, routine, parameter, context, flags);
}

MMRESULT WINAPI Hook_timeSetEvent(UINT delay, UINT resolution, LPTIMECALLBACK callback, DWORD_PTR user, UINT event_type) {
  return Real_timeSetEvent(ScaledDuration(delay), resolution, callback, user, event_type);
}

// ── flush to disk (diagnostics) ─────────────────────────────────────────────────────────
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

struct HookSpec {
  LPCWSTR module;
  LPCSTR name;
  LPVOID detour;
  LPVOID* original;
};

// Many APIs in kernel32 are forwarded to kernelbase: the loader resolves imports straight to the implementing module,
// and then a hook on the kernel32 forwarder stub is never called at all. So try kernelbase first, and fall back to the given module.
MH_STATUS CreateHookResolved(LPCWSTR module, LPCSTR name, LPVOID detour, LPVOID* original) {
  if (_wcsicmp(module, L"kernel32.dll") == 0) {
    const MH_STATUS status = MH_CreateHookApi(L"kernelbase.dll", name, detour, original);
    if (status == MH_OK) return status;
  }
  return MH_CreateHookApi(module, name, detour, original);
}

DWORD WINAPI Worker(LPVOID) {
  const DWORD pid = GetCurrentProcessId();
  wchar_t mapping_name[128];
  wsprintfW(mapping_name, DSH_TIME_MAPPING_PREFIX L"%lu", pid);
  g_mapping = OpenFileMappingW(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, mapping_name);
  if (g_mapping == nullptr) return 1;
  g_config = static_cast<TimeConfig*>(MapViewOfFile(g_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(TimeConfig)));
  if (g_config == nullptr) return 1;

  g_factor = g_config->factor > 0.0 ? g_config->factor : 1.0;
  g_offset_100ns = g_config->offset_100ns;
  {
    char line[160];
    std::snprintf(line, sizeof(line), "worker: factor=%.3f offset100ns=%lld mode=%ld", g_factor,
                  static_cast<long long>(g_offset_100ns), static_cast<long>(g_config->mode));
    StepLog(line);
  }

  if (MH_Initialize() != MH_OK) {
    g_config->state = kTimeFailed;
    return 1;
  }

  const HookSpec specs[] = {
      {L"kernel32.dll", "GetTickCount", reinterpret_cast<LPVOID>(&Hook_GetTickCount),
       reinterpret_cast<LPVOID*>(&Real_GetTickCount)},
      {L"kernel32.dll", "GetTickCount64", reinterpret_cast<LPVOID>(&Hook_GetTickCount64),
       reinterpret_cast<LPVOID*>(&Real_GetTickCount64)},
      {L"winmm.dll", "timeGetTime", reinterpret_cast<LPVOID>(&Hook_timeGetTime),
       reinterpret_cast<LPVOID*>(&Real_timeGetTime)},
      {L"kernel32.dll", "QueryPerformanceCounter", reinterpret_cast<LPVOID>(&Hook_QueryPerformanceCounter),
       reinterpret_cast<LPVOID*>(&Real_QueryPerformanceCounter)},
      {L"kernel32.dll", "GetSystemTimeAsFileTime", reinterpret_cast<LPVOID>(&Hook_GetSystemTimeAsFileTime),
       reinterpret_cast<LPVOID*>(&Real_GetSystemTimeAsFileTime)},
      {L"kernel32.dll", "GetSystemTimePreciseAsFileTime",
       reinterpret_cast<LPVOID>(&Hook_GetSystemTimePreciseAsFileTime),
       reinterpret_cast<LPVOID*>(&Real_GetSystemTimePreciseAsFileTime)},
      {L"user32.dll", "GetMessageTime", reinterpret_cast<LPVOID>(&Hook_GetMessageTime),
       reinterpret_cast<LPVOID*>(&Real_GetMessageTime)},
      {L"kernel32.dll", "GetSystemTime", reinterpret_cast<LPVOID>(&Hook_GetSystemTime),
       reinterpret_cast<LPVOID*>(&Real_GetSystemTime)},
      {L"kernel32.dll", "GetLocalTime", reinterpret_cast<LPVOID>(&Hook_GetLocalTime),
       reinterpret_cast<LPVOID*>(&Real_GetLocalTime)},
      {L"kernel32.dll", "Sleep", reinterpret_cast<LPVOID>(&Hook_Sleep), reinterpret_cast<LPVOID*>(&Real_Sleep)},
      {L"kernel32.dll", "SleepEx", reinterpret_cast<LPVOID>(&Hook_SleepEx), reinterpret_cast<LPVOID*>(&Real_SleepEx)},
      {L"kernel32.dll", "WaitForSingleObject", reinterpret_cast<LPVOID>(&Hook_WaitForSingleObject),
       reinterpret_cast<LPVOID*>(&Real_WaitForSingleObject)},
      {L"kernel32.dll", "WaitForSingleObjectEx", reinterpret_cast<LPVOID>(&Hook_WaitForSingleObjectEx),
       reinterpret_cast<LPVOID*>(&Real_WaitForSingleObjectEx)},
      {L"kernel32.dll", "WaitForMultipleObjects", reinterpret_cast<LPVOID>(&Hook_WaitForMultipleObjects),
       reinterpret_cast<LPVOID*>(&Real_WaitForMultipleObjects)},
      {L"kernel32.dll", "WaitForMultipleObjectsEx", reinterpret_cast<LPVOID>(&Hook_WaitForMultipleObjectsEx),
       reinterpret_cast<LPVOID*>(&Real_WaitForMultipleObjectsEx)},
      {L"user32.dll", "SetTimer", reinterpret_cast<LPVOID>(&Hook_SetTimer), reinterpret_cast<LPVOID*>(&Real_SetTimer)},
      {L"kernel32.dll", "SetWaitableTimer", reinterpret_cast<LPVOID>(&Hook_SetWaitableTimer),
       reinterpret_cast<LPVOID*>(&Real_SetWaitableTimer)},
      {L"kernel32.dll", "SetWaitableTimerEx", reinterpret_cast<LPVOID>(&Hook_SetWaitableTimerEx),
       reinterpret_cast<LPVOID*>(&Real_SetWaitableTimerEx)},
      {L"winmm.dll", "timeSetEvent", reinterpret_cast<LPVOID>(&Hook_timeSetEvent),
       reinterpret_cast<LPVOID*>(&Real_timeSetEvent)},
  };

  for (const HookSpec& spec : specs) {
    char line[128];
    std::snprintf(line, sizeof(line), "hook %s", spec.name);
    if (CreateHookResolved(spec.module, spec.name, spec.detour, spec.original) != MH_OK) {
      ++g_config->hook_failures;
      StepLog((std::string(line) + ": failed").c_str());
      continue;
    }
    ++g_config->hooks_installed;
    StepLog((std::string(line) + ": ok").c_str());
  }
  if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) ++g_config->hook_failures;
  ReanchorAll();
  g_config->state = kTimeRunning;
  StepLog("worker: hooks installed, state=running");

  const DWORD started = GetTickCount();
  while (g_stopping == 0) {
    const DWORD elapsed = GetTickCount() - started;
    if (elapsed >= g_config->duration_ms) break;
    if (Real_Sleep != nullptr) {
      Real_Sleep(500);
    } else {
      Sleep(500);
    }
  }

  MH_DisableHook(MH_ALL_HOOKS);
  Sleep(200);
  MH_Uninitialize();
  g_config->state = kTimeDone;
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
