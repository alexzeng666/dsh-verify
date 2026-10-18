# dsh-verify

When the agent says "I fixed it", this runs it for real.

The umbrella package: it strings `dsh-quota` / `dsh-crashlab` / `dsh-probe` / `dsh-timelab` into
**one verification = run + assert + a readable report**, and injects a "verify before declaring
completion" rule into the system prompt.

## Install

```powershell
dsh plugin --profile "$env:DSH_PROFILE" add @alexzeng666/dsh-verify
```

The other four are declared in this package's `dependencies` and land in the profile automatically.
Do not install them separately — this package's patch inserts them, and mounting them twice
reports "tool already registered".

## Tools

| Tool | In one line |
|---|---|
| `verify_run` | Run a command; get exit code, stdout/stderr, and on a crash the stack and source lines |
| `verify_assert_exit` | Assert the exit code — a number, `0`, or `nonzero` |
| `verify_assert_stdout` | Assert the output contains or lacks text; `/regex/` supported |
| `verify_assert_file` | Assert existence, content, or sha256 |
| `verify_assert_json` | Assert the value at a JSON pointer |
| `verify_assert_screenshot` | Pixel comparison against a baseline PNG — decodes PNG itself, no vision dependency |
| `verify_report` | Fold `.verify/fragments.jsonl` into one readable report |

Assertions target **the most recent `verify_run`** unless you pin one with `run_id` (like `V-001`).

## Flow

```
verify_run(cmd="npm test")
  └─ crash_helper.exe run           the command runs under the debugger
       ├─ exit code + stdout/stderr → files
       └─ crashed → minidump + StackWalk64 → call stack / module / source line
verify_assert_*                     read the latest run's fragment back and assert on it
verify_report                       fold fragments.jsonl into one report
```

`verify_run` goes through `crash_helper` rather than spawning the process itself, so that "run +
attribution" come out of a single step. Otherwise the agent would have to start the process and
then race to attach — and those few hundred milliseconds are enough for the target to die.

## Return

Everything returns `VerifyFragment`. `verify_report`'s `detail` carries `total` / `by_result` /
`by_source` / `recent`.

## System prompt

The plugin injects a block of verification discipline via
`ctx.systemPrompt.section({ name: 'verify:policy', order: 3040, ... })`: run `verify_*` before
declaring completion, state conclusions alongside evidence, and know the difference between
`error` and `fail`. Turn it off with `promptInjection: false` in the plugin config.
