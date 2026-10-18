# dsh-quota

Caps the CPU, memory and wall clock a command may use, and kills it once it goes over.

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-quota
```

## Usage

```
verify_limit(cmd="npm run build", cpu_percent=50, memory_mb=2048, timeout_sec=60)
```

All three are optional; an omitted one falls back to `defaultCpuPercent` / `defaultMemoryMb` /
`defaultTimeoutSec` in the plugin config.

## What it does

- **CPU** — hard cap via `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`, relative to one core
  (100 = a full core).
- **Memory** — `JOB_OBJECT_LIMIT_PROCESS_MEMORY` plus `JOB_OBJECT_LIMIT_JOB_MEMORY`, so child
  processes count too.
- **Wall clock** — `TerminateJobObject` kills the whole job on expiry, leaving no orphaned children.

A limit that cannot be applied (old OS, restricted container) logs a warning and the run proceeds:
the verifier's own failure must not block the agent. On non-Windows it returns `result: "error"`
instead of throwing.

## Return

`VerifyFragment`. `detail` carries `run` (pid, exit code, reason, peak CPU, peak memory, CPU
time), `limits` (what was actually in effect), `output` (stdout/stderr tails) and `warnings`
(which limit could not be applied). Stdout/stderr are also written next to the fragment as
`VQ-xxx.stdout.log` / `.stderr.log`.
