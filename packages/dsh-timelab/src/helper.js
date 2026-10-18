/**
 * Call wrappers for hook_host.exe / time_helper.dll.
 *
 * The injector is the same one dsh-probe ships, but build.ps1 copies hook_host.exe into this
 * package's own vendor dir, so at runtime there is no cross-package lookup and no dependency on it.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ARCH_DIR = process.arch === 'x64' ? 'x64' : process.arch === 'ia32' ? 'x86' : process.arch;

export function hostPath() {
  const local = join(packageRoot, 'vendor', ARCH_DIR, 'hook_host.exe');
  if (existsSync(local)) return local;
  // Development fallback: run probe's copy straight out of the monorepo.
  const sibling = join(packageRoot, '..', 'dsh-probe', 'vendor', ARCH_DIR, 'hook_host.exe');
  return existsSync(sibling) ? sibling : local;
}

export function dllPath() {
  return join(packageRoot, 'vendor', ARCH_DIR, 'time_helper.dll');
}

export function timeLabAvailable() {
  return process.platform === 'win32' && existsSync(hostPath()) && existsSync(dllPath());
}

/**
 * @param {{pid: number, factor?: number, offsetSec?: number, durationMs: number, outPath?: string}} options
 */
export function shiftProcess({ pid, factor, offsetSec, durationMs, outPath }) {
  return new Promise((done) => {
    const host = hostPath();
    if (!existsSync(host)) {
      done({ ok: false, error: `native helper missing: ${host} (build one with native/build.ps1)` });
      return;
    }
    const args = ['shift', '--pid', String(pid), '--dll', dllPath(), '--duration-ms', String(durationMs)];
    if (Number.isFinite(factor) && factor > 0) args.push('--factor', String(factor));
    if (Number.isFinite(offsetSec) && offsetSec !== 0) args.push('--offset-sec', String(offsetSec));
    if (outPath) args.push('--out', outPath);

    execFile(
      host,
      args,
      { windowsHide: true, timeout: durationMs + 30_000, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
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
            error: `hook_host call failed: ${error.killed ? 'timed out' : error.message}${stderr ? ` (${String(stderr).trim().slice(0, 300)})` : ''}`,
          });
          return;
        }
        done({ ok: false, error: `hook_host returned no JSON (stdout: ${text.slice(0, 200)})` });
      },
    );
  });
}
