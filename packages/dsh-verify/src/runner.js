/**
 * Wrapper around crash_helper.exe's run mode: execute a command under the debugger.
 *
 * Why the orchestration package uses crash_helper instead of spawning directly:
 * one call returns the exit code, stdout/stderr and the crash stack together, so the
 * agent does not have to run first and race to attach afterwards.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ARCH_DIR = process.arch === 'x64' ? 'x64' : process.arch === 'ia32' ? 'x86' : process.arch;

export function helperPath() {
  const local = join(packageRoot, 'vendor', ARCH_DIR, 'crash_helper.exe');
  if (existsSync(local)) return local;
  // Development fallback: the copy shipped with crashlab in the monorepo.
  const sibling = join(packageRoot, '..', 'dsh-crashlab', 'vendor', ARCH_DIR, 'crash_helper.exe');
  return existsSync(sibling) ? sibling : local;
}

export function runnerAvailable() {
  return process.platform === 'win32' && existsSync(helperPath());
}

/**
 * Run one command under the debugger.
 * @param {{command: string, cwd: string, dumpPath: string, stdoutPath: string, stderrPath: string,
 *          timeoutMs: number, symbolPath?: string}} options
 */
export function runCommand({ command, cwd, dumpPath, stdoutPath, stderrPath, timeoutMs, symbolPath }) {
  return new Promise((done) => {
    const exe = helperPath();
    if (!existsSync(exe)) {
      done({ ok: false, error: `native helper not found: ${exe} (build one with native/build.ps1)` });
      return;
    }
    const parts = String(command).trim().split(/\s+/);
    // CreateProcessW resolves the executable against the **caller's** (crash_helper's)
    // current directory, not the --cwd child working directory. Relative paths must be
    // absolutized first, otherwise files inside cwd are reported as not found.
    if (parts[0] && !/^[A-Za-z]:[\\/]/.test(parts[0]) && !parts[0].startsWith('\\\\')) {
      if (/[\\/]/.test(parts[0])) {
        parts[0] = resolve(cwd, parts[0]);
      } else {
        // Bare file name: absolutize it when cwd really contains it; otherwise let the system search PATH (cmd / node / npm).
        const candidate = join(cwd, parts[0]);
        if (existsSync(candidate)) parts[0] = candidate;
      }
    }
    const args = [
      'run',
      '--out',
      dumpPath,
      '--cwd',
      cwd,
      '--stdout',
      stdoutPath,
      '--stderr',
      stderrPath,
      '--timeout-ms',
      String(timeoutMs),
    ];
    if (symbolPath) args.push('--symbol-path', symbolPath);
    args.push('--', ...parts);

    execFile(
      exe,
      args,
      { windowsHide: true, timeout: timeoutMs + 30_000, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout, stderr) => {
        const text = String(stdout ?? '').trim();
        const line = text.split('\n').filter((item) => item.trim() !== '').pop();
        if (line) {
          try {
            done(JSON.parse(line));
            return;
          } catch {
            /* fall through to the shared error path below */
          }
        }
        if (error) {
          done({
            ok: false,
            error: `crash_helper invocation failed: ${error.killed ? 'timed out' : error.message}${stderr ? ` (${String(stderr).trim().slice(0, 300)})` : ''}`,
          });
          return;
        }
        done({ ok: false, error: `crash_helper returned no JSON (stdout: ${text.slice(0, 200)})` });
      },
    );
  });
}
