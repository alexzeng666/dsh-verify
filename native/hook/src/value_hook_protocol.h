// Shared protocol between host and value_hook.dll.
//
// Minimal DSL: return-value override only, no argument rewriting.
//   when: 0 = override every call; N = override only on the Nth call
//   ret : the value to fake (truncated to the target function's return width)
#pragma once

#include <windows.h>

#define DSH_VALUEHOOK_MAPPING_PREFIX L"Local\\dsh_verify_valuehook_"

enum ValueHookState : LONG {
  kValueHookIdle = 0,
  kValueHookRunning = 1,
  kValueHookDone = 2,
  kValueHookFailed = 3,
};

struct ValueHookConfig {
  volatile LONG state;
  DWORD nth;               // 0 = override every call, N = override only the Nth
  ULONGLONG ret;           // the faked return value
  DWORD calls_seen;        // how many times the target function was called
  DWORD calls_overridden;  // how many of those got the faked value
  DWORD duration_ms;
  DWORD hook_failures;
  DWORD hooks_installed;
  wchar_t module[64];      // e.g. advapi32.dll; empty means infer from the built-in table
  wchar_t api[128];        // e.g. RegQueryValueExW
  wchar_t out_path[512];
};
