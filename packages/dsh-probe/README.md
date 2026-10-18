# dsh-probe

Shows which APIs a process calls, and with what arguments.

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-probe
```

## Usage

```
verify_trace(pid=12345)                                       # all APIs, 60s by default
verify_trace(pid=12345, api_pattern="File", duration_ms=5000)
verify_trace(pid=12345, api_pattern="/^(Read|Write)File$/", duration_ms=10000)
verify_trace(pid=12345, apis="Sleep,CreateFileW", duration_ms=3000)

verify_hook(pid=12345, api="RegQueryValueExW", action={ when: "always", ret: 5 })
verify_hook(pid=12345, api="CreateFileW", action={ when: { nth: 3 }, ret: -1 })
```

`api_pattern` is a case-insensitive substring match; write `/regex/` to match by regex; empty or
`*` means all.

## verify_hook

It only **changes return values**, never arguments:
`action = { when: "always" | { nth: N }, ret: <value> }`.

Returning a forged value skips the original call without having to know the parameter list;
changing arguments would mean decoding each API's signature one by one, and the cost far
outweighs the benefit. Hence a **12-entry allowlist with typed detours**, and anything outside it
is reported as unsupported rather than half-hooked:

`RegQueryValueExW` · `RegOpenKeyExW` · `RegCreateKeyExW` · `RegSetValueExW` ·
`CreateFileW` · `OpenProcess` · `LoadLibraryW` · `GetProcAddress` · `VirtualAlloc` ·
`GetTickCount64` · `WaitForSingleObject` · `CreateProcessW`

`ret` takes a number or `"0x..."`; negatives like `-1` are truncated to the target's return width
(HANDLE-typed ones end up as `INVALID_HANDLE_VALUE`). Hooks are removed at `duration_ms`, and the
report states how many calls were seen and how many were changed.

## Traced APIs

`Sleep` `GetTickCount64` `QueryPerformanceCounter` `CreateFileW` `ReadFile` `WriteFile`
`LoadLibraryW` `GetProcAddress` `RegOpenKeyExW` `CreateProcessW` `VirtualAlloc` `HeapAlloc`

`apis` hooks only what is listed; everything else is left untouched, so it costs nothing.

## Return

`VerifyFragment`. `detail` holds `records`, `matched`, `counts` (per-API), `samples`,
`hook_failures` and `trace_path` (the full JSONL).

## Behavior

- Hooks install one at a time: if something else already hooked an API, only that one is lost and
  `hook_failures` reports it; the rest install normally.
- Records flush once a second, so a target that crashes midway still yields what was captured.
- Early exit, injection failure, or no matching records all still produce a conclusion.
- 32-bit targets are not supported — the helper is x64.
