# dsh-verify

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Windows x64](https://img.shields.io/badge/platform-Windows%20x64-lightgrey.svg)](#limits)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-brightgreen.svg)](package.json)

Your coding agent says "fixed it" after seeing a clean build. It has no way to know whether the fix
actually works — and neither do you, short of re-running everything yourself.

These plugins give it a way to find out, and to hand you something you can check.

```
agent:  "Fixed the config parser. Build is clean."

you:    verify_run(cmd: "build/app.exe")

        exit 0xC0000005   ACCESS_VIOLATION
        #0  parse_json    src/config.c:12    <- the line it just edited
        #1  load_config   src/config.c:22
        #2  main          src/main.c:34

agent:  "...it crashes. Looking again."
```

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-verify
```

Windows x64. One package, twelve tools. The four sub-packages are its dependencies — installing
them separately double-registers their tools.

## The twelve

| | |
|---|---|
| **Run** | `verify_run` — exit code, stdout/stderr, and the stack when it crashes |
| **Assert** | `verify_assert_exit` · `verify_assert_stdout` · `verify_assert_file` · `verify_assert_json` · `verify_assert_screenshot` |
| **Report** | `verify_report` — folds the run history into one page |
| **Constrain** | `verify_limit` — CPU / memory / wall-clock caps; kills the whole job on overrun |
| **Explain** | `verify_attribution` — why it died: exit semantics, event log, minidump stack |
| **Inspect** | `verify_trace` — which APIs it called, with arguments |
| **Force** | `verify_hook` — override one API's return value (12-entry whitelist) |
| **Bend time** | `verify_timeshift` — speed up, slow down, or shift the target's clock |

## Evidence, not claims

Every run writes to `.verify/` in the workspace:

```
.verify/
  fragments.jsonl     one JSON line per verification
  timeline.jsonl      started / exited / killed / crashed / attached / shifted
  V-001.stdout.log
  V-001.stderr.log
  V-001.dmp           only when it crashed
```

`verify_report` reads them back. So "verified" becomes something you can audit next week, not a
sentence you have to take on faith.

## Why not just run the command

You can. For a build that exits 0 or 1, that is enough.

It stops being enough when:

- **The program crashes.** A shell gives you `exit code 1`. This gives you the frame and the
  source line.
- **The command hangs or eats the machine.** You get a cap and a clean kill instead of a dead
  session.
- **The conclusion is "the output contained X".** That is a claim, and claims need a record.

## Limits

- **Windows x64 only.** No 32-bit targets, no other platforms.
- **Native helpers ship prebuilt** — installing needs no compiler. Rebuilding them needs cmake
  plus mingw-w64; see [native/README.md](native/README.md).
- **`verify_hook` covers 12 fixed APIs.** Anything else is reported as unsupported rather than
  half-hooked.
- **Tracing a JIT runtime needs a narrower API set.** `verify_trace` hooks inline, and in node/V8
  hooking `QueryPerformanceCounter` terminates the process with `STATUS_BREAKPOINT`. Pass `apis`
  without it; every other API in the list is safe there.
- **The agent still has to call these tools.** A system-prompt rule nudges it to, but nothing
  forces it. What the tools guarantee is that when it *does* verify, the result is real.

## Packages

| Package | Provides |
|---|---|
| `dsh-verify` | run, assert, report — the umbrella |
| `dsh-quota` | `verify_limit` |
| `dsh-crashlab` | `verify_attribution` |
| `dsh-probe` | `verify_trace`, `verify_hook` |
| `dsh-timelab` | `verify_timeshift` |
| `dsh-verify-contract` | shared types; not published |

Each installs on its own. They couple only through
[`packages/dsh-verify-contract/src/index.d.ts`](packages/dsh-verify-contract/src/index.d.ts).

## License

MIT — see [LICENSE](LICENSE). Bundled MinHook is BSD-2-Clause; see
[native/third_party/minhook/LICENSE.txt](native/third_party/minhook/LICENSE.txt).
