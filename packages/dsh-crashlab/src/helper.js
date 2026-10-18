/**
 * Invocation wrapper for crash_helper.exe.
 *
 * The helper is a native binary (vendor/<arch>/crash_helper.exe), single-shot, JSON over stdio:
 *   attach --pid N --out <dump> [--symbol-path P] [--timeout-ms N]
 *   parse  --dump <file> [--symbol-path P]
 * It never crashes the host itself: every failure comes back as { ok: false, error }.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const ARCH_DIR = process.arch === 'x64' ? 'x64' : process.arch === 'ia32' ? 'x86' : process.arch;

/** Path to the helper binary (selected by host bitness). */
export function helperPath() {
  return join(packageRoot, 'vendor', ARCH_DIR, 'crash_helper.exe');
}

export function helperAvailable() {
  return process.platform === 'win32' && existsSync(helperPath());
}

function runHelper(args, timeoutMs) {
  return new Promise((done) => {
    const exe = helperPath();
    if (!existsSync(exe)) {
      done({ ok: false, error: `native helper not found: ${exe} (build one with native/build.ps1)` });
      return;
    }
    execFile(
      exe,
      args,
      { windowsHide: true, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout, stderr) => {
        const text = String(stdout ?? '').trim();
        const line = text.split('\n').filter((item) => item.trim() !== '').pop();
        if (line) {
          try {
            done(JSON.parse(line));
            return;
          } catch {
            /* fall through to the unified error below */
          }
        }
        if (error) {
          done({
            ok: false,
            error: `crash_helper invocation failed: ${error.killed ? 'timeout' : error.message}${stderr ? ` (${String(stderr).trim().slice(0, 400)})` : ''}`,
          });
          return;
        }
        done({ ok: false, error: `crash_helper returned no JSON (stdout: ${text.slice(0, 200)})` });
      },
    );
  });
}

export function attachAndCapture({ pid, dumpPath, symbolPath, timeoutMs }) {
  const args = ['attach', '--pid', String(pid), '--out', dumpPath, '--timeout-ms', String(timeoutMs)];
  if (symbolPath) args.push('--symbol-path', symbolPath);
  return runHelper(args, timeoutMs + 15_000);
}

/** Launch a command under the debugger and wait for it to crash (the agent does not have to race to attach). */
export function runAndCapture({ command, cwd, dumpPath, symbolPath, timeoutMs }) {
  const args = ['run', '--out', dumpPath, '--timeout-ms', String(timeoutMs)];
  if (cwd) args.push('--cwd', cwd);
  if (symbolPath) args.push('--symbol-path', symbolPath);
  // The helper joins everything after `--` into a command line by argv, so split on whitespace here and pass it through.
  const parts = String(command).trim().split(/\s+/);
  // CreateProcessW's executable search does not use lpCurrentDirectory, so a relative path is simply not found:
  // when the first segment is relative, resolve it against the workspace first.
  if (parts[0] && !isAbsolute(parts[0])) {
    parts[0] = resolve(cwd ?? process.cwd(), parts[0]);
  }
  args.push('--', ...parts);
  return runHelper(args, timeoutMs + 15_000);
}

export function parseDump({ dumpPath, symbolPath }) {
  const args = ['parse', '--dump', dumpPath];
  if (symbolPath) args.push('--symbol-path', symbolPath);
  return runHelper(args, 30_000);
}
