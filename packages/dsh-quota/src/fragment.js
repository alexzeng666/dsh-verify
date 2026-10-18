/**
 * Fragment numbering, persistence, and human-readable formatting.
 *
 * See @alexzeng666/dsh-verify-contract for the contract: fragments go to `<workspace>/.verify/fragments.jsonl`,
 * the timeline to `<workspace>/.verify/timeline.jsonl` — one JSON per line, append-only.
 *
 * Every package carries its own copy of this file (packages couple only through the contract,
 * never through a shared runtime module), so the implementation here has to stay small; when it
 * changes, the five packages each change their own.
 */
import { appendFileSync, mkdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** In-package auto-increment counter: resets to zero on process restart, never persisted. */
const counters = new Map();

/**
 * Produce the next id.
 *
 * On the first call for a given workspace and prefix, scan that workspace's fragments.jsonl for the
 * highest id with the same prefix and add one — otherwise the counter resets to zero after a plugin
 * reload and ids start again at V-001, colliding with existing fragments (locateRun would pick the
 * wrong one). After that it increments in memory keyed by `${workspace}|${prefix}`.
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
      // No history yet (brand-new workspace): start at 1
    }
    next = max + 1;
  } else {
    next = cached + 1;
  }
  counters.set(key, next);
  return `${prefix}${String(next).padStart(3, '0')}`;
}

/**
 * Decide the workspace root: prefer the session working directory, otherwise the host process cwd.
 * **Never hardcode a path.**
 */
export function resolveWorkspace(exec) {
  const cwd = exec?.agent?.session?.header?.cwd;
  if (typeof cwd === 'string' && cwd.trim() !== '') return resolve(cwd);
  return resolve(process.cwd());
}

export function verifyDir(workspace) {
  return join(workspace, '.verify');
}

/**
 * Append one line of JSON. Does not throw on failure — persisting is a bonus, not the verification itself.
 * @returns Whether the write succeeded.
 */
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
 * Make sure the `.verify` directory exists and return its path.
 *
 * Call this before writing any evidence file: if the directory is missing, redirecting child output
 * to `.verify/xxx.log` fails silently (the command still runs, the file never appears) and every
 * downstream assertion falls over. That is exactly the situation on the first run in a fresh
 * workspace, and you cannot rely on "appendJsonl creates it anyway" — that runs when the fragment is
 * recorded, one step too late.
 */
export function ensureVerifyDir(workspace) {
  const dir = verifyDir(workspace);
  mkdirSync(dir, { recursive: true });
  return dir;
}
