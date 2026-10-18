/**
 * dsh-probe · `verify_trace`
 *
 * Injects hook_helper.dll into the target process, records calls to the selected APIs and their
 * arguments over a time window, and returns a human-readable VerifyFragment (contract: the
 * @alexzeng666/dsh-verify-contract).
 *
 * The whole chain is fail-open: injection failure / target exit / no matching records all produce
 * a verdict instead of throwing.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

import { appendJsonl, formatMs, nextId, readJsonl, resolveWorkspace, toJsonSafe, ensureVerifyDir, verifyDir } from './fragment.js';
import { hookValue, probeAvailable, traceProcess } from './helper.js';

export const name = 'dsh-probe';

export const inject = ['tools'];

export const Config = z.object({
  defaultDurationMs: z.number().default(60000),
  apis: z.string().default('all'),
  maxSamples: z.number().default(12),
});

const parameters = {
  pid: {
    type: 'integer',
    required: true,
    description: 'Process id to observe (must already be running).',
  },
  api_pattern: {
    type: 'string',
    description:
      'Which APIs to filter: substring match (case-insensitive, e.g. "File" hits CreateFileW/ReadFile/WriteFile); ' +
      'wrap in /regex/ to match by regex; empty or "*" means all.',
  },
  duration_ms: {
    type: 'integer',
    description: 'Trace duration in milliseconds; defaults to the plugin-configured defaultDurationMs.',
  },
  apis: {
    type: 'string',
    description:
      'Only hook these APIs (comma-separated, e.g. "Sleep,CreateFileW"); defaults to the plugin-configured apis. ' +
      'Available: Sleep / GetTickCount64 / QueryPerformanceCounter / CreateFileW / ReadFile / WriteFile / ' +
      'LoadLibraryW / GetProcAddress / RegOpenKeyExW / RegQueryValueExW / CreateProcessW / VirtualAlloc.',
  },
};

const outputSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    source: { type: 'string', required: true },
    verify_id: { type: 'string', required: true },
    result: { type: 'string', required: true, description: 'pass / fail / error' },
    summary: { type: 'string', required: true },
    detail: { type: 'object', additionalProperties: true, required: true },
    evidence: { type: 'array', items: { type: 'string' }, required: true },
    elapsed_ms: { type: 'integer', required: true },
  },
};

/** Substring / regex / match-all. */
function buildMatcher(pattern) {
  const text = String(pattern ?? '').trim();
  if (text === '' || text === '*') return () => true;
  if (text.length > 2 && text.startsWith('/') && text.endsWith('/')) {
    try {
      const regex = new RegExp(text.slice(1, -1), 'i');
      return (api) => regex.test(String(api));
    } catch {
      /* a broken regex falls back to substring matching */
    }
  }
  const needle = text.toLowerCase();
  return (api) => String(api).toLowerCase().includes(needle);
}

function formatCall(record, baseTs) {
  const offset = Number.isFinite(record.ts) && Number.isFinite(baseTs) ? record.ts - baseTs : 0;
  const args = Array.isArray(record.args) ? record.args.filter((value) => value !== '0x0') : [];
  const parts = [];
  if (record.text) parts.push(JSON.stringify(record.text));
  parts.push(...args);
  const call = `${record.api}(${parts.join(', ')})`;
  const result = record.ret && record.ret !== '0x0' ? ` → ${record.ret}` : '';
  return `+${formatMs(offset)} [${record.tid}] ${call}${result}`;
}

function report(value) {
  const detail = value.detail ?? {};
  const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
  lines.push(
    `  ${value.verify_id} · pid ${detail.pid ?? '?'} · ${formatMs(value.elapsed_ms)} elapsed · ` +
      `${detail.records ?? 0} records${detail.matched !== undefined ? ` (${detail.matched} matched)` : ''}` +
      (detail.hook_failures ? ` · hook failures: ${detail.hook_failures}` : ''),
  );

  const counts = detail.counts ?? {};
  const top = Object.entries(counts)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([api, count]) => `${api} ${count}`);
  if (top.length > 0) lines.push(`  distribution: ${top.join(' · ')}`);

  const samples = Array.isArray(detail.samples) ? detail.samples : [];
  if (samples.length > 0) {
    lines.push('  samples:');
    for (const sample of samples) lines.push(`    ${sample}`);
    if (detail.matched > samples.length) lines.push(`    … (${detail.matched} matched in total; full records in the evidence file)`);
  }

  if (detail.trace_path) lines.push(`  evidence: ${detail.trace_path}`);
  for (const warning of detail.warnings ?? []) lines.push(`  warning: ${warning}`);
  return lines.join('\n');
}

export function apply(ctx, config) {
  const cfg = config ?? {};

  ctx.tools.register(
    defineTool({
      name: 'verify_trace',
      description:
        'See what APIs any process is calling and with what arguments: injects the hook DLL into the target process and records calls to the selected APIs over a time window. ' +
        'Use it when you want to know "what is it actually doing" or "why is it slow"; the report carries the call distribution, argument samples, and the full record file.',
      parameters,
      output: {
        schema: outputSchema,
        render: (_args, value) => [{ type: 'text', text: report(value) }],
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const verifyId = nextId('VP-', workspace);
        const pid = Number(args?.pid);
        const durationMs = Number.isFinite(args?.duration_ms)
          ? Number(args.duration_ms)
          : Number(cfg.defaultDurationMs ?? 60000);
        const apis = String(args?.apis ?? cfg.apis ?? 'all').trim() || 'all';
        const maxSamples = Number.isFinite(cfg.maxSamples) ? Number(cfg.maxSamples) : 12;
        const pattern = String(args?.api_pattern ?? '');
        const warnings = [];

        const tracePath = join(verifyDir(workspace), `${verifyId}.trace.jsonl`);

        try {
          if (!Number.isFinite(pid) || pid <= 0) throw new Error('a valid pid is required');
          if (!probeAvailable()) {
            throw new Error('native helper unavailable (not built, or platform mismatch): hook_host.exe + hook_helper.dll required');
          }

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'probe',
            event: 'attached',
            pid,
            detail: { verify_id: verifyId, duration_ms: durationMs, apis },
          });

          ensureVerifyDir(workspace);
          const traced = await traceProcess({ pid, outPath: tracePath, durationMs, apis });
          if (traced?.ok === false && traced?.state === undefined) {
            throw new Error(traced.error ?? 'injection failed');
          }
          if (traced.dll_loaded === false) warnings.push('the DLL never appeared in the target module list');
          const targetCrashed = traced.state === 'failed' && traced.target_exited === true;
          if (traced.state === 'failed' && !targetCrashed) warnings.push('DLL initialization failed (see hook_failures below)');
          if (traced.state === 'timeout') warnings.push('the target exited before the trace ended; only the records already flushed are available');
          if (traced.hook_failures) warnings.push(`${traced.hook_failures} hooks failed to install (most likely already claimed by another tool)`);

          const records = readJsonl(workspace, `${verifyId}.trace.jsonl`);
          const matcher = buildMatcher(pattern);
          const matched = records.filter((record) => matcher(record.api));
          const counts = {};
          for (const record of matched) counts[record.api] = (counts[record.api] ?? 0) + 1;
          const baseTs = matched.length > 0 ? Number(matched[0].ts) : 0;
          const samples = matched.slice(0, maxSamples).map((record) => formatCall(record, baseTs));

          // The verdict looks at two things only: whether there are records, and whether we crashed the target.
          // A target that exits **normally** ahead of time (it finished on its own) is not a failure — the records
          // are real, so report pass + a warning.
          const noRecords = records.length === 0;
          const earlyExit = traced.target_exited === true && !targetCrashed;
          const traceBroken = noRecords || targetCrashed;
          const actualMs = Date.now() - startedAt;
          const exitCode = traced.exit_code ?? '?';
          if (targetCrashed) warnings.push(`target terminated abnormally (exit code ${exitCode}): the recorder may have crashed it`);

          const kinds = Object.keys(counts).length;
          const filterNote = pattern ? `, filter ${pattern}` : '';
          let summary;
          if (noRecords && targetCrashed) {
            summary = `verifier did not complete: target terminated abnormally (${exitCode}) and not a single record was captured`;
          } else if (noRecords) {
            summary = `verifier did not complete: no records captured at all (state=${traced?.state ?? '?'})`;
          } else if (targetCrashed) {
            summary = `target terminated abnormally (${exitCode}): ${records.length} records captured but the data is unreliable — the recorder may have crashed it`;
          } else if (earlyExit) {
            // The actual elapsed time must be used here: when the target exits early, quoting the requested duration as "within 20.0s" would be a lie.
            summary = `captured ${matched.length} calls (target exited early; actual coverage ${formatMs(actualMs)})${filterNote}`;
          } else {
            summary =
              matched.length > 0
                ? `captured ${matched.length} calls (within ${formatMs(durationMs)}, ${kinds} APIs)${filterNote}`
                : `no calls captured${pattern ? ` matching ${pattern}` : ''} (traced for ${formatMs(durationMs)})`;
          }

          const detail = {
            pid,
            duration_ms: durationMs,
            actual_ms: actualMs,
            apis,
            pattern,
            state: traced?.state,
            target_exited: traced?.target_exited,
            exit_code: traced?.exit_code,
            records: records.length,
            matched: matched.length,
            counts,
            samples,
            hook_failures: traced.hook_failures ?? 0,
            trace_path: existsSync(tracePath) ? tracePath : undefined,
            warnings,
          };

          const value = {
            source: 'probe',
            verify_id: verifyId,
            result: traceBroken ? 'error' : 'pass',
            summary,
            detail,
            evidence: existsSync(tracePath) ? [tracePath] : [],
            elapsed_ms: Date.now() - startedAt,
          };

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'probe',
            event: 'detached',
            pid,
            detail: { verify_id: verifyId, records: records.length, matched: matched.length },
          });
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        } catch (error) {
          const value = {
            source: 'probe',
            verify_id: verifyId,
            result: 'error',
            summary: `verifier did not complete: ${error?.message ?? error} (this is not a verdict about the subject under test)`,
            detail: {
              pid,
              duration_ms: durationMs,
              apis,
              pattern,
              warnings,
              error: { name: error?.name ?? 'Error', message: error?.message ?? String(error) },
            },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          };
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_hook: minimal hook DSL, return value only ────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_hook',
      description:
        'Override the return value of an API inside the target process to a fixed value (minimal hook DSL: return value only, arguments untouched). ' +
        'Use it to exercise degraded branches such as "access denied / file not found / load failed" — without actually changing system state. ' +
        'action is a structured object: { when: "always" | {nth: N}, ret: <return value> }. ' +
        'Supported APIs: RegQueryValueExW / RegOpenKeyExW / RegCreateKeyExW / RegSetValueExW / CreateFileW / ' +
        'OpenProcess / LoadLibraryW / GetProcAddress / VirtualAlloc / GetTickCount64 / WaitForSingleObject / CreateProcessW.',
      parameters: {
        pid: { type: 'integer', required: true, description: 'Target process id (must already be running).' },
        api: {
          type: 'string',
          required: true,
          description: 'Name of the API whose return value to override (see the whitelist in the tool description); names outside the whitelist are reported as unsupported.',
        },
        action: {
          type: 'object',
          additionalProperties: true,
          required: true,
          description:
            '{"when":"always"|{"nth":N},"ret":<return value>}. when defaults to always; nth is the 1-based call index, only the Nth call is changed. ' +
            'ret accepts a number or a "0x..." string (e.g. ERROR_ACCESS_DENIED = 5, INVALID_HANDLE_VALUE = -1).',
        },
        duration_ms: {
          type: 'integer',
          description: 'How long the hook stays active, in milliseconds; it is removed automatically when the time is up. Defaults to the plugin-configured defaultDurationMs.',
        },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => {
          const detail = value.detail ?? {};
          const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
          lines.push(
            `  ${value.verify_id} · pid ${detail.pid ?? '?'} · ${detail.api ?? '?'} → ${detail.ret_hex ?? '?'}` +
              ` · ${formatMs(value.elapsed_ms)} elapsed`,
          );
          lines.push(
            `  calls: ${detail.calls_seen ?? 0} seen, ${detail.calls_overridden ?? 0} overridden` +
              (detail.hook_failures ? ` · hook failures: ${detail.hook_failures}` : ''),
          );
          if (detail.log_path) lines.push(`  log: ${detail.log_path}`);
          for (const warning of detail.warnings ?? []) lines.push(`  warning: ${warning}`);
          return [{ type: 'text', text: lines.join('\n') }];
        },
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const verifyId = nextId('VP-', workspace);
        const pid = Number(args?.pid);
        const api = String(args?.api ?? '').trim();
        const durationMs = Number.isFinite(args?.duration_ms)
          ? Number(args.duration_ms)
          : Number(cfg.defaultDurationMs ?? 60000);
        const warnings = [];
        const logPath = join(verifyDir(workspace), `${verifyId}.hook.log`);

        try {
          if (!Number.isFinite(pid) || pid <= 0) throw new Error('a valid pid is required');
          if (api === '') throw new Error('api is required');

          const action = args?.action ?? {};
          const when = action.when ?? 'always';
          let nth = 0;
          if (when === 'always' || when === undefined || when === null) {
            nth = 0;
          } else if (typeof when === 'number') {
            nth = Math.max(1, Math.trunc(when));
          } else if (typeof when === 'object' && Number.isFinite(when.nth)) {
            nth = Math.max(1, Math.trunc(Number(when.nth)));
          } else {
            throw new Error(`when only supports "always" or {"nth": N}, got ${JSON.stringify(when)}`);
          }

          const rawRet = action.ret;
          if (rawRet === undefined || rawRet === null) throw new Error('action.ret is required');
          let ret;
          try {
            ret = typeof rawRet === 'string' ? BigInt(rawRet.trim()) : BigInt(Math.trunc(Number(rawRet)));
          } catch {
            throw new Error(`ret is not an integer: ${JSON.stringify(rawRet)}`);
          }

          if (!probeAvailable()) throw new Error('native helper unavailable: hook_host.exe + value_hook.dll required');

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'probe',
            event: 'hooked',
            pid,
            detail: { verify_id: verifyId, api, nth, ret: `0x${ret.toString(16)}`, duration_ms: durationMs },
          });

          const hooked = await hookValue({ pid, api, nth, ret, durationMs, outPath: logPath });
          if (hooked?.ok === false && hooked?.state === undefined) throw new Error(hooked.error ?? 'injection failed');
          if (hooked.dll_loaded === false) warnings.push('the DLL never appeared in the target module list');
          if (hooked.state === 'failed') warnings.push('DLL initialization failed: the API is not on the whitelist, or the hook could not be installed');
          if (hooked.state === 'timeout') warnings.push('the target exited before the hook window ended; the active window ended early');
          if (hooked.calls_overridden === 0 && hooked.state === 'done') {
            warnings.push('nothing was overridden: the target never called this API during the window');
          }

          const overridden = Number(hooked.calls_overridden ?? 0);
          const seen = Number(hooked.calls_seen ?? 0);
          const summary =
            hooked.state === 'failed'
              ? `hook not installed: ${api} (most likely not on the whitelist, or another tool already claimed that API)`
              : overridden > 0
                ? `overrode the return value of ${api} to 0x${ret.toString(16)} (${overridden}/${seen} calls within ${formatMs(durationMs)})`
                : `hook installed, but the target never called ${api} within ${formatMs(durationMs)}`;

          const value = {
            source: 'probe',
            verify_id: verifyId,
            result: hooked.state === 'failed' ? 'error' : 'pass',
            summary,
            detail: {
              pid,
              api,
              when: nth === 0 ? 'always' : `nth:${nth}`,
              ret_hex: `0x${ret.toString(16)}`,
              calls_seen: seen,
              calls_overridden: overridden,
              duration_ms: durationMs,
              hook_failures: hooked.hook_failures ?? 0,
              log_path: existsSync(logPath) ? logPath : undefined,
              warnings,
            },
            evidence: existsSync(logPath) ? [logPath] : [],
            elapsed_ms: Date.now() - startedAt,
          };
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        } catch (error) {
          const value = {
            source: 'probe',
            verify_id: verifyId,
            result: 'error',
            summary: `verifier did not complete: ${error?.message ?? error} (this is not a verdict about the subject under test)`,
            detail: {
              pid,
              api,
              duration_ms: durationMs,
              warnings,
              error: { name: error?.name ?? 'Error', message: error?.message ?? String(error) },
            },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          };
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        }
      },
    }),
  );
}
