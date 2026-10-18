# dsh-timelab

Speeds up, slows down, or shifts the target process's clock.

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-timelab
```

## Usage

```
verify_timeshift(pid=12345, offset_sec=3456000)            # 40 days forward
verify_timeshift(pid=12345, offset_sec=-86400)             # 1 day back
verify_timeshift(pid=12345, factor=5, duration_ms=10000)   # 5x speed
```

Pick either `offset_sec` or `factor`. Hooks are removed at `duration_ms`.

## Covered APIs (19)

| Category | APIs |
|---|---|
| Reads | `GetTickCount` `GetTickCount64` `timeGetTime` `QueryPerformanceCounter` `GetSystemTimeAsFileTime` `GetSystemTimePreciseAsFileTime` `GetMessageTime` `GetSystemTime` `GetLocalTime` |
| Waits | `Sleep` `SleepEx` `WaitForSingleObject` `WaitForSingleObjectEx` `WaitForMultipleObjects` `WaitForMultipleObjectsEx` |
| Timers | `SetTimer` `SetWaitableTimer` `SetWaitableTimerEx` `timeSetEvent` |

## Algorithm

**Reads** use four-point baseline re-anchoring: the first call sets
`baseReal = baseHook = real`, after which `virtual = baseHook + (real - baseReal) × factor`;
offset mode adds a fixed offset on top. On a factor change it re-anchors on the last observed
value, so virtual time stays continuous across the switch.

**Waits / timers** take duration ÷ factor, with `INFINITE` and `0` passed through unchanged.

## Return

`VerifyFragment`. `detail` holds `mode`, `hooks_installed`, `hook_failures`, `covered_apis`
and `log_path`.

## Behavior

- kernel32's forwarded APIs (`Sleep`, `GetSystemTimeAsFileTime` and friends) are really
  implemented in kernelbase: the hook tries kernelbase first and falls back to the given module.
  Otherwise it installs but never fires.
- Hooks install one at a time; a failure loses only that one, counted in `hook_failures`.
- Early exit, injection failure, or not a single hook installed all still produce a conclusion.
- 32-bit targets are not supported.
