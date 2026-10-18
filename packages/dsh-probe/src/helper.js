/**
 * Wrappers around hook_host.exe / hook_helper.dll.
 *
 * The host handles injection and teardown; the DLL records inside the target process and writes
 * results as JSONL, one record per line:
 *   {"api":"CreateFileW","tid":10332,"ts":120311609,"args":["0x40000000",...],"ret":"0xDC","text":"api_target.tmp"}
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ARCH_DIR = process.arch === 'x64' ? 'x64' : process.arch === 'ia32' ? 'x86' : process.arch;

export function hostPath() {
  return join(packageRoot, 'vendor', ARCH_DIR, 'hook_host.exe');
}

export function dllPath() {
  return join(packageRoot, 'vendor', ARCH_DIR, 'hook_helper.dll');
}

export function valueHookDllPath() {
  return join(packageRoot, 'vendor', ARCH_DIR, 'value_hook.dll');
}

/** Whether this machine can do injection tracing. */
export function probeAvailable() {
  return process.platform === 'win32' && existsSync(hostPath()) && existsSync(dllPath());
}

/**
 * Run a trace inside the target process.
 * @param {{pid: number, outPath: string, durationMs: number, apis?: string}} options
 * @returns {Promise<{ok: boolean, state?: string, records?: number, hook_failures?: number, dll_loaded?: boolean, error?: string}>}
 */
export function traceProcess({ pid, outPath, durationMs, apis }) {
  return new Promise((done) => {
    const host = hostPath();
    if (!existsSync(host)) {
      done({ ok: false, error: `native helper not found: ${host} (build one with native/build.ps1)` });
      return;
    }
    const args = [
      'trace',
      '--pid',
      String(pid),
      '--dll',
      dllPath(),
      '--out',
      outPath,
      '--duration-ms',
      String(durationMs),
    ];
    if (apis) args.push('--apis', apis);

    execFile(
      host,
      args,
      { windowsHide: true, timeout: durationMs + 30_000, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout, stderr) => {
        const text = String(stdout ?? '').trim();
        const line = text.split('\n').filter((item) => item.trim() !== '').pop();
        if (line) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.ok === false && !parsed.error) parsed.error = 'hook_host reported failure';
            done(parsed);
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

/**
 * Override an API's return value to a fixed value (minimal hook DSL: return value only).
 * @param {{pid: number, api: string, nth?: number, ret: number|bigint, durationMs: number, outPath?: string}} options
 */
export function hookValue({ pid, api, nth, ret, durationMs, outPath }) {
  return new Promise((done) => {
    const host = hostPath();
    if (!existsSync(host)) {
      done({ ok: false, error: `native helper not found: ${host} (build one with native/build.ps1)` });
      return;
    }
    const dll = valueHookDllPath();
    if (!existsSync(dll)) {
      done({ ok: false, error: `value_hook.dll not found: ${dll} (build one with native/build.ps1)` });
      return;
    }
    const args = [
      'hook',
      '--pid',
      String(pid),
      '--dll',
      dll,
      '--api',
      api,
      '--nth',
      String(Number.isFinite(nth) ? nth : 0),
      '--ret',
      `0x${BigInt(ret).toString(16)}`,
      '--duration-ms',
      String(durationMs),
    ];
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
