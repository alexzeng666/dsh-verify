/**
 * Aggregation layer: collects the fragments scattered through
 * `.verify/fragments.jsonl` into one human-readable report.
 *
 * Contract §1.1 says the aggregation layer **does not parse detail** — detail.kind is
 * read only where orchestration requires it ("find the previous run"); everything else
 * looks at top-level fields only (source / result / summary / elapsed_ms).
 */
import { formatMs } from './fragment.js';

const RESULT_RANK = { pass: 0, fail: 1, error: 2 };

/** Find the most recent verify_run fragment (the orchestrator asserts against it next). */
export function findLastRun(fragments) {
  for (let index = fragments.length - 1; index >= 0; index -= 1) {
    const fragment = fragments[index];
    if (fragment?.source === 'orchestrator' && fragment?.detail?.kind === 'run') return fragment;
  }
  return undefined;
}

/** Overall verdict: the worst result wins. */
export function worstResult(results) {
  let worst = 'pass';
  for (const result of results) {
    if ((RESULT_RANK[result] ?? 0) > (RESULT_RANK[worst] ?? 0)) worst = result;
  }
  return worst;
}

/**
 * Aggregate fragments.
 * @param {any[]} fragments - all fragments, in write order.
 * @param {{since?: number, limit?: number}} options
 */
export function aggregate(fragments, options = {}) {
  const since = Number.isFinite(options.since) ? options.since : 0;
  const limit = Number.isFinite(options.limit) ? options.limit : 40;
  const relevant = fragments.filter((fragment) => {
    if (!fragment || typeof fragment !== 'object') return false;
    if (!fragment.verify_id || !fragment.result) return false;
    return true;
  });
  const byResult = { pass: 0, fail: 0, error: 0 };
  const bySource = {};
  for (const fragment of relevant) {
    byResult[fragment.result] = (byResult[fragment.result] ?? 0) + 1;
    bySource[fragment.source] = (bySource[fragment.source] ?? 0) + 1;
  }
  const recent = relevant.slice(-limit);
  return {
    total: relevant.length,
    by_result: byResult,
    by_source: bySource,
    recent,
    result: relevant.length === 0 ? 'error' : worstResult(relevant.map((fragment) => fragment.result)),
    since,
  };
}

export function formatReport(value) {
  const detail = value.detail ?? {};
  const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
  lines.push(
    `  ${value.verify_id} · ${detail.total ?? 0} fragments total: ` +
      `pass ${detail.by_result?.pass ?? 0} · fail ${detail.by_result?.fail ?? 0} · error ${detail.by_result?.error ?? 0}`,
  );
  const sources = Object.entries(detail.by_source ?? {})
    .map(([source, count]) => `${source} ${count}`)
    .join(' · ');
  if (sources) lines.push(`  sources: ${sources}`);

  const recent = Array.isArray(detail.recent) ? detail.recent : [];
  if (recent.length > 0) {
    lines.push('  details:');
    for (const fragment of recent) {
      const mark = fragment.result === 'pass' ? '✓' : fragment.result === 'fail' ? '✗' : '!';
      lines.push(`    ${mark} ${fragment.verify_id} [${fragment.source}] ${fragment.summary}`);
    }
    if (detail.total > recent.length) lines.push(`    ...(${detail.total - recent.length} older entries not shown)`);
  }
  lines.push(`  total elapsed: ${formatMs(detail.elapsed_total_ms ?? 0)}`);
  return lines.join('\n');
}
