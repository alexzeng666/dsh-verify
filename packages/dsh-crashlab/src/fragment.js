/**
 * Fragment numbering, persistence, read-back, and human-readable formatting.
 *
 * Contract: see @alexzeng666/dsh-verify-contract. Fragments are written to
 * `<workspace>/.verify/fragments.jsonl`, the timeline to `<workspace>/.verify/timeline.jsonl`,
 * one JSON per line, append-only.
 *
 * Every package carries its own copy (packages couple only through the contract, never through
 * shared runtime modules).
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const counters = new Map();

/**
 * Produce the next id.
 *
 * On the first call for a given workspace and prefix, scan that workspace's fragments.jsonl for
 * the highest number with the same prefix and add 1 — otherwise the counter resets after a plugin
 * reload and ids fall back to V-001, colliding with existing fragments (locateRun then picks the
 * wrong one). After that, increment in memory keyed by `${workspace}|${prefix}`.
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
      // no prior fragments (brand-new workspace): start at 1
    }
    next = max + 1;
  } else {
    next = cached + 1;
  }
  counters.set(key, next);
  return `${prefix}${String(next).padStart(3, '0')}`;
}

/** Workspace root: prefer the session working directory, otherwise the host cwd. No hard-coded paths. */
export function resolveWorkspace(exec) {
  const cwd = exec?.agent?.session?.header?.cwd;
  if (typeof cwd === 'string' && cwd.trim() !== '') return resolve(cwd);
  return resolve(process.cwd());
}

export function verifyDir(workspace) {
  return join(workspace, '.verify');
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

/** Read back a jsonl (bad lines skipped); returns [] when the file does not exist. */
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
        /* half-written or bad lines are skipped outright: persistence is a bonus and must not affect attribution */
      }
    }
  } catch {
    return [];
  }
  return entries;
}

export function formatBytes(bytes) {
  const value = Number(bytes);
  if (!Number.isFinite(value) || value <= 0) return '0 B';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  if (value < 1024 * 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MB`;
  return `${(value / 1024 / 1024 / 1024).toFixed(2)} GB`;
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
 * Scrub a value into "lossless JSON": drop undefined, stringify BigInt, turn NaN/Infinity into null.
 *
 * Tool return values must be serializable by the framework without loss — a single `undefined`
 * field fails the whole call, and a verify tool must never block the agent because one of its own
 * fields was not scrubbed.
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

/**
 * Ensure the `.verify` directory exists and return its path.
 *
 * Call this before writing any evidence file: when the directory is missing, redirecting child
 * process output to `.verify/xxx.log` fails silently (the command still runs, the file is never
 * created) and every later assertion collapses. A brand-new workspace's first run is exactly that
 * case, so do not count on "appendJsonl will create it anyway" — it runs while recording the
 * fragment, one step too late.
 */
export function ensureVerifyDir(workspace) {
  const dir = verifyDir(workspace);
  mkdirSync(dir, { recursive: true });
  return dir;
}
