# dsh-crashlab

Attribution report after a process dies abnormally: exit-code semantics, event log, minidump call
stack.

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-crashlab
```

## Usage

```
verify_attribution(cmd="D:\\proj\\out\\crash_null.exe 300")  # run under the debugger (recommended)
verify_attribution(pid=12345)                       # live process: attach and wait
verify_attribution(dump_path="D:\\proj\\crash.dmp")  # parse an existing dump
```

Pick one of `cmd` / `pid` / `dump_path`. `cmd` is the least work — no racing to attach.

## The three layers

| Layer | Mechanism | When unavailable |
|---|---|---|
| L1 | Exit code, termination reason and stderr patterns left in `.verify/` | Absent unless `verify_limit` has run |
| L2 | `wevtutil` reads Application Error / .NET Runtime / WER | Logging off, or access denied |
| L3 | `crash_helper.exe`: MiniDumpWriteDump + StackWalk64 + dbghelp symbols | Helper missing, or the process already exited |

`detail.levels` reports which of the three were obtained. That is everything this package
produces — turning a crash address into pseudocode is a separate step you can take yourself by
handing `detail.crash_frame` to `dsh-reverse`.

## Return

`VerifyFragment`. `detail` holds `levels`, `exception` (code / address / parameters), `frames`
(call stack with module offsets, symbols and source lines), `source_hint`, `crash_frame`,
`eventlog`, `dump_path` and `l1`.

## Behavior

- Process already exited → L1/L2 only, and the report says plainly that no call stack is
  available instead of pretending to have one.
- Attached, no crash before the timeout → `pass`, stating "no crash observed within N seconds".
- In dump mode, missing unwind information falls back to stack scanning and marks
  `stack_quality: scan` (a real unwind is `unwind`).
- A failing layer only removes that layer. With no helper at all it returns `result: "error"`
  instead of throwing.
