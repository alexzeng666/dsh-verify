/**
 * L1 attribution context: pull "what this pid was verified against before" out of `.verify/`.
 *
 * Why read files instead of asking the caller: after a command finishes, quota writes the exit
 * code and termination reason into timeline/fragments; crashlab can then match purely by pid,
 * without the agent passing a pile of parameters by hand (the cross-package correlation
 * convention from contract §3).
 */
import { readJsonl } from './fragment.js';

const STDERR_PATTERNS = [
  { pattern: /access violation|0xC0000005/i, hint: 'access violation (ACCESS_VIOLATION)' },
  { pattern: /stack overflow|0xC00000FD/i, hint: 'stack overflow (STACK_OVERFLOW)' },
  { pattern: /integer divide by zero|0xC0000094/i, hint: 'integer divide by zero (INTEGER_DIVIDE_BY_ZERO)' },
  { pattern: /heap corruption|0xC0000374/i, hint: 'heap corruption (HEAP_CORRUPTION)' },
  { pattern: /segmentation fault|SIGSEGV/i, hint: 'segmentation fault (SIGSEGV)' },
  { pattern: /abort\(\)|SIGABRT|abnormal program termination/i, hint: 'process aborted (abort)' },
  { pattern: /assertion failed|AssertionError/i, hint: 'assertion failed' },
  { pattern: /unhandled exception|terminate called/i, hint: 'unhandled exception' },
  { pattern: /ERR_MEMORY_ALLOCATION_FAILED|Failed to allocate memory|bad_alloc|out of memory/i, hint: 'memory allocation failed' },
];

/**
 * Correlate quota fragments and timeline entries by pid.
 * @returns {{ exit_code?: number, reason?: string, summary?: string, killed_reason?: string, stderr_tail?: string, cmd?: string }}
 */
export function lookupContext(workspace, pid) {
  const context = {};
  if (!Number.isFinite(pid) || pid <= 0) return context;

  const fragments = readJsonl(workspace, 'fragments.jsonl');
  for (let index = fragments.length - 1; index >= 0; index -= 1) {
    const fragment = fragments[index];
    const run = fragment?.detail?.run;
    if (run?.pid === pid) {
      context.exit_code = run.exit_code;
      context.reason = run.reason;
      context.summary = fragment.summary;
      context.stderr_tail = fragment?.detail?.output?.stderr_tail ?? '';
      context.cmd = fragment?.detail?.cmd;
      context.verify_id = fragment.verify_id;
      break;
    }
  }

  const timeline = readJsonl(workspace, 'timeline.jsonl');
  for (let index = timeline.length - 1; index >= 0; index -= 1) {
    const entry = timeline[index];
    if (entry?.pid !== pid) continue;
    if (entry.event === 'killed') {
      context.killed_reason = entry?.detail?.reason;
      if (context.exit_code === undefined) context.exit_code = entry?.detail?.exit_code;
      break;
    }
    if (entry.event === 'exited' && context.exit_code === undefined) {
      context.exit_code = entry?.detail?.exit_code;
      break;
    }
  }

  const haystack = `${context.stderr_tail ?? ''}\n${context.summary ?? ''}`;
  const hints = [];
  for (const item of STDERR_PATTERNS) {
    if (item.pattern.test(haystack)) hints.push(item.hint);
  }
  if (hints.length > 0) context.stderr_hints = hints;
  return context;
}
