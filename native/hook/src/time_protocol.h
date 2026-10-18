// Shared protocol between host and time_helper.dll.
#pragma once

#include <windows.h>

#define DSH_TIME_MAPPING_PREFIX L"Local\\dsh_verify_time_"

enum TimeState : LONG {
  kTimeIdle = 0,
  kTimeRunning = 1,
  kTimeDone = 2,
  kTimeFailed = 3,
};

struct TimeConfig {
  volatile LONG state;
  LONG mode;              // 0 = factor, 1 = offset
  double factor;          // 1.0 = real speed; 2.0 = twice as fast; 0.5 = half speed
  LONGLONG offset_100ns;  // FILETIME units (100ns), positive = shift into the future
  DWORD duration_ms;
  DWORD hooks_installed;
  DWORD hook_failures;
  volatile LONG calls;   // diagnostics: how many times GetSystemTimeAsFileTime was called
  volatile LONG calls_local;  // diagnostics: how many times GetLocalTime was called
  wchar_t out_path[512];
};
