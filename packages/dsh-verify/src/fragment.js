/**
 * Fragment numbering, persistence, read-back and human-readable formatting.
 *
 * Contract in @alexzeng666/dsh-verify-contract: fragments go to `<workspace>/.verify/fragments.jsonl`,
 * the timeline to `<workspace>/.verify/timeline.jsonl` — one JSON per line, append-only.
 *
 * Every package carries its own copy (packages couple only through the contract and
 * share no runtime modules).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const counters = new Map();

/**
 * Produce the next id.
 *
 * On the first call for a workspace and prefix, scan that workspace's fragments.jsonl
 * for the highest id with the same prefix and add one — otherwise the counter resets
 * after a plugin reload and ids collide with existing fragments starting at V-001
 * (locateRun would then pick the wrong one).
 * Afterwards it increments in memory, keyed by `${workspace}|${prefix}`.
 */
export function nextId(prefix, workspace) {
  const key = `${workspace ?? ''}|${prefix}`;
  const cached = counters.get(key);
  let next;
  if (cached === undefined) {
    let max = 0;
    try {
      const file = join(workspace ?? '.', '.verify', 'fragments.jsonl');
      const text = readFileSync(file, 'utf8');
      const pattern = new RegExp(`"verify_id"\\s*:\\s*"${prefix}(\\d+)"`, 'g');
      for (const match of text.matchAll(pattern)) {
        const value = Number(match[1]);
        if (Number.isFinite(value) && value > max) max = value;
      }
    } catch {
      // no history (brand-new workspace): start at 1
    }
    next = max + 1;
  } else {
    next = cached + 1;
  }
  counters.set(key, next);
  return `${prefix}${String(next).padStart(3, '0')}`;
}

/** Workspace root: session cwd first, then host cwd. Never a hard-coded path. */
export function resolveWorkspace(exec) {
  const cwd = exec?.agent?.session?.header?.cwd;
  if (typeof cwd === 'string' && cwd.trim() !== '') return resolve(cwd);
  return resolve(process.cwd());
}

export function verifyDir(workspace) {
  return join(workspace, '.verify');
}

/**
 * Ensure the .verify directory exists and return its path.
 *
 * This must run before any evidence file is written: with the directory missing,
 * redirecting a child's stdout/stderr to .verify/xxx.log **fails silently** (the
 * command still runs, no file appears) and every later assertion collapses.
 * That is exactly the first run in a fresh workspace, so do not assume
 * "appendJsonl will create it anyway".
 */
export function ensureVerifyDir(workspace) {
  const dir = verifyDir(workspace);
  mkdirSync(dir, { recursive: true });
  return dir;
}

/** Append one JSON line; never throws. */
export function appendJsonl(workspace, file, entry) {
  try {
    const dir = verifyDir(workspace);
    mkdirSync(dir, { recursive: true });
    appendFileSync(join(dir, file), `${JSON.stringify(entry)}\n`, 'utf8');
    return true;
  } catch {
    return false;
  }
}

/** Read a jsonl back (bad lines skipped); returns [] when the file is missing. */
export function readJsonl(workspace, file) {
  const path = join(verifyDir(workspace), file);
  if (!existsSync(path)) return [];
  const entries = [];
  try {
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      const text = line.trim();
      if (text === '') continue;
      try {
        entries.push(JSON.parse(text));
      } catch {
        /* skip partial or malformed lines */
      }
    }
  } catch {
    return [];
  }
  return entries;
}

export function formatMs(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value < 0) return '0ms';
  if (value < 1000) return `${Math.round(value)}ms`;
  if (value < 60_000) return `${(value / 1000).toFixed(1)}s`;
  const minutes = Math.floor(value / 60_000);
  const seconds = ((value % 60_000) / 1000).toFixed(1);
  return `${minutes}m${seconds}s`;
}

/**
 * Scrub a value into lossless JSON: drop undefined, stringify BigInt, turn
 * NaN/Infinity into null. Tool return values must survive lossless serialization
 * by the framework, otherwise the whole call fails.
 */
export function toJsonSafe(value) {
  if (value === null) return null;
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return value;
  if (type === 'number') return Number.isFinite(value) ? value : null;
  if (type === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(toJsonSafe).filter((item) => item !== undefined);
  if (type === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      if (item === undefined) continue;
      const safe = toJsonSafe(item);
      if (safe !== undefined) out[key] = safe;
    }
    return out;
  }
  return undefined;
}
