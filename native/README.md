# native

The binaries in `packages/*/vendor/x64/` are built from here. **Plugin users never need this
directory** — the binaries ship with the package.

```
winproc/      shared static library: process / module / handle / debug privilege / UTF-8 / JSON
crash/        crash_helper.exe   attach / run / parse; MiniDumpWriteDump + StackWalk64
hook/         hook_host.exe      host: trace / shift / hook
              hook_helper.dll    recorder for trace
              time_helper.dll    time control
              value_hook.dll     return-value rewriting for verify_hook
third_party/  minhook (BSD-2, vendored)
```

Artifacts land in:

| Artifact | Destination |
|---|---|
| `crash_helper.exe` | `dsh-crashlab`, `dsh-verify` |
| `hook_host.exe` | `dsh-probe`, `dsh-timelab` |
| `hook_helper.dll`, `value_hook.dll` | `dsh-probe` |
| `time_helper.dll` | `dsh-timelab` |

## Build

Needs **cmake** on PATH plus a C/C++ compiler.

```powershell
pwsh native/build.ps1            # x64
```

**Toolchain, preferred:** unpack a portable mingw-w64 build (winlibs UCRT + posix-seh) into
`tools/mingw64/` — gitignored, no admin rights needed. `build.ps1` searches `tools/mingw64/` and
`tools/` recursively for `g++.exe`.

**Fallback:** with no mingw present, `build.ps1` uses a local MSVC + Windows SDK. It must include
the x64 CRT libraries — with only the ARM components installed, `lib\x64` is empty and linking
fails.

The script points `TMP`/`TEMP` at `native/build/tmp`; in restricted sessions `%TEMP%` may not be
writable and gcc fails outright.

## 32-bit

Not built. `build.ps1` has a `Win32` mapping, but the helper side has no WOW64 support, so 32-bit
targets are unverified — adding it needs an i686 toolchain, a WOW64 branch in the helpers, and
cross-bitness injection detection.
