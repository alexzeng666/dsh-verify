// Shared protocol between host and the injected DLL. Both sides must interpret that named file mapping by this layout.
#pragma once

#include <windows.h>

#define DSH_PROBE_MAPPING_PREFIX L"Local\\dsh_verify_probe_"
#define DSH_PROBE_MAX_RECORDS 65536
#define DSH_PROBE_TEXT_CHARS 96

enum ProbeState : LONG {
  kProbeIdle = 0,     // host has written the config, waiting for the DLL to come up
  kProbeRunning = 1,  // hooks installed, recording
  kProbeDone = 2,     // records flushed to disk
  kProbeFailed = 3,   // init failed (see hook_failures)
};

enum ProbeApi : DWORD {
  kApiSleep = 0,
  kApiGetTickCount64 = 1,
  kApiQueryPerformanceCounter = 2,
  kApiCreateFileW = 3,
  kApiReadFile = 4,
  kApiWriteFile = 5,
  kApiLoadLibraryW = 6,
  kApiGetProcAddress = 7,
  kApiRegOpenKeyExW = 8,
  kApiCreateProcessW = 9,
  kApiVirtualAlloc = 10,
  kApiRegQueryValueExW = 11,
  kApiCount = 12,
};

struct CallRecord {
  DWORD api;
  DWORD tid;
  ULONGLONG ts;
  ULONGLONG args[4];
  ULONGLONG ret;
  wchar_t text[DSH_PROBE_TEXT_CHARS];
};

struct ProbeConfig {
  volatile LONG state;
  DWORD duration_ms;
  DWORD api_mask;
  DWORD records_written;
  DWORD hook_failures;
  DWORD reserved;
  wchar_t out_path[512];
};

inline const wchar_t* ProbeApiName(DWORD api) {
  switch (api) {
    case kApiSleep: return L"Sleep";
    case kApiGetTickCount64: return L"GetTickCount64";
    case kApiQueryPerformanceCounter: return L"QueryPerformanceCounter";
    case kApiCreateFileW: return L"CreateFileW";
    case kApiReadFile: return L"ReadFile";
    case kApiWriteFile: return L"WriteFile";
    case kApiLoadLibraryW: return L"LoadLibraryW";
    case kApiGetProcAddress: return L"GetProcAddress";
    case kApiRegOpenKeyExW: return L"RegOpenKeyExW";
    case kApiCreateProcessW: return L"CreateProcessW";
    case kApiVirtualAlloc: return L"VirtualAlloc";
    case kApiRegQueryValueExW: return L"RegQueryValueExW";
    default: return L"unknown";
  }
}
