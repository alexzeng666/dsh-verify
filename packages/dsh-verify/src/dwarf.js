/**
 * DWARF fallback symbolization: dbghelp only eats PDB, while targets built by gcc/mingw are DWARF.
 *
 * Approach: use the module's preferred ImageBase to turn the runtime address into a static address,
 * then hand it to addr2line to resolve the function name and "file:line". **Only fill in what
 * dbghelp did not resolve**, never overwrite PDB results.
 *
 * Where addr2line comes from: explicit argument → env var DSH_ADDR2LINE → in-repo tools/mingw64 →
 * addr2line on PATH. If none of them exist, skip (keep only the module offset) and do not block
 * attribution.
 *
 * Deliberately duplicated in dsh-crashlab and dsh-verify: the two packages must stay
 * independently installable, and cross-package code sharing is limited to the contract
 * types. Do not hoist this into a shared module - keep the two copies in sync by hand.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readPreferredImageBase } from './pe.js';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** Find addr2line; returns an empty string when not found. */
export function findAddr2line(explicit) {
  const candidates = [];
  if (typeof explicit === 'string' && explicit.trim() !== '') candidates.push(explicit.trim());
  if (process.env.DSH_ADDR2LINE) candidates.push(process.env.DSH_ADDR2LINE);
  candidates.push(join(packageRoot, '..', '..', 'tools', 'mingw64', 'bin', 'addr2line.exe'));
  candidates.push('addr2line');
  for (const candidate of candidates) {
    if (candidate === 'addr2line') return candidate; // leave it to PATH resolution; the caller degrades on failure
    if (existsSync(candidate)) return candidate;
  }
  return '';
}

function runAddr2line(exe, modulePath, addresses) {
  return new Promise((done) => {
    execFile(
      exe,
      ['-e', modulePath, '-f', '-C', ...addresses.map((value) => `0x${value.toString(16).toUpperCase()}`)],
      { windowsHide: true, timeout: 20_000, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' },
      (error, stdout) => {
        if (error) {
          done({ ok: false, error: error.message });
          return;
        }
        const lines = String(stdout ?? '').split('\n').map((line) => line.trim());
        const resolved = [];
        for (let index = 0; index + 1 < lines.length; index += 2) {
          const symbol = lines[index];
          const location = lines[index + 1] ?? '';
          const match = /^(.*):(\d+)(?: \(discriminator \d+\))?$/.exec(location);
          resolved.push({
            symbol: symbol && symbol !== '??' ? symbol : '',
            source_file: match ? match[1] : '',
            source_line: match ? Number(match[2]) : 0,
          });
        }
        done({ ok: true, resolved });
      },
    );
  });
}

/**
 * Fill DWARF symbols into frames that have none.
 * @param {{frames: any[], modules: any[], addr2linePath?: string}} options
 * @returns {Promise<{frames: any[], used: boolean, error?: string}>}
 */
export async function enrichFramesWithDwarf({ frames, modules, addr2linePath }) {
  if (!Array.isArray(frames) || frames.length === 0) return { frames, used: false };

  const pending = frames.filter((frame) => !frame.symbol && !frame.source_file && frame.module && frame.module_offset);
  if (pending.length === 0) return { frames, used: false };

  const exe = findAddr2line(addr2linePath);
  if (exe === '') return { frames, used: false, error: 'no addr2line' };

  // Group by module: one addr2line invocation per module.
  const byModule = new Map();
  for (const frame of pending) {
    const module = (modules ?? []).find((item) => item.name === frame.module);
    if (!module?.path || !existsSync(module.path)) continue;
    const list = byModule.get(module.path) ?? [];
    list.push(frame);
    byModule.set(module.path, list);
  }

  let used = false;
  let lastError;
  for (const [modulePath, list] of byModule) {
    const preferred = readPreferredImageBase(modulePath);
    const runtimeBase = Number((modules ?? []).find((item) => item.path === modulePath)?.base ?? 0);
    if (!preferred || !runtimeBase) continue;

    const addresses = list.map((frame) => preferred + Number.parseInt(String(frame.addr), 16) - runtimeBase);
    const result = await runAddr2line(exe, modulePath, addresses);
    if (!result.ok) {
      lastError = result.error;
      continue;
    }
    list.forEach((frame, index) => {
      const hit = result.resolved[index];
      if (!hit) return;
      if (hit.symbol && !frame.symbol) {
        frame.symbol = hit.symbol;
        used = true;
      }
      if (hit.source_file && !frame.source_file) {
        frame.source_file = hit.source_file;
        frame.source_line = hit.source_line;
        used = true;
      }
    });
  }

  return { frames, used, error: used ? undefined : lastError };
}
