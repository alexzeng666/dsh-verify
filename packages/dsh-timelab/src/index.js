/**
 * dsh-timelab · `verify_timeshift`
 *
 * Speed up / slow down / push the target process clock into the future: inject time_helper.dll and
 * hook 17+ time APIs. Wait-style APIs scale by duration; read-style APIs re-anchor on four baselines
 * then scale or offset.
 *
 * The whole chain is fail-open: injection failure / target exit / zero hooks installed all still
 * produce a verdict instead of throwing.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

import { appendJsonl, formatMs, nextId, resolveWorkspace, toJsonSafe, ensureVerifyDir, verifyDir } from './fragment.js';
import { shiftProcess, timeLabAvailable } from './helper.js';

export const name = 'dsh-timelab';

export const inject = ['tools'];

export const Config = z.object({
  defaultDurationMs: z.number().default(60000),
  defaultFactor: z.number().default(1),
});

const parameters = {
  pid: {
    type: 'integer',
    required: true,
    description: 'Process id to shift (must already be running).',
  },
  offset_sec: {
    type: 'integer',
    description: 'Seconds to push the clock forward (positive) or back (negative). Typical use: +40 days = 3456000. Mutually exclusive with factor.',
  },
  factor: {
    type: 'number',
    description: 'Multiplier: 2 = twice as fast, 0.5 = half speed. Mutually exclusive with offset_sec.',
  },
  duration_ms: {
    type: 'integer',
    description: 'How long the shift lasts in milliseconds; hooks are removed automatically when it expires. Defaults to the plugin config defaultDurationMs.',
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

/** Turn second counts like 40 days into plain language. */
function describeShift(offsetSec, factor) {
  if (Number.isFinite(offsetSec) && offsetSec !== 0) {
    const abs = Math.abs(offsetSec);
    const direction = offsetSec > 0 ? 'forward' : 'backward';
    if (abs >= 86400) return `${direction} ${(abs / 86400).toFixed(1)} days`;
    if (abs >= 3600) return `${direction} ${(abs / 3600).toFixed(1)} hours`;
    return `${direction} ${abs} seconds`;
  }
  if (Number.isFinite(factor) && factor > 0 && factor !== 1) return `factor ${factor}×`;
  return 'unspecified (no shift)';
}

function report(value) {
  const detail = value.detail ?? {};
  const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
  lines.push(
    `  ${value.verify_id} · pid ${detail.pid ?? '?'} · elapsed ${formatMs(value.elapsed_ms)} · ` +
      `mode ${detail.mode ?? '?'}`,
  );
  lines.push(
    `  hooks: ${detail.hooks_installed ?? 0} installed` +
      (detail.hook_failures ? ` · ${detail.hook_failures} failed (usually already claimed by other software)` : ''),
  );
  const apis = Array.isArray(detail.covered_apis) ? detail.covered_apis : [];
  if (apis.length > 0) lines.push(`  covered: ${apis.join(' · ')}`);
  if (detail.log_path) lines.push(`  log: ${detail.log_path}`);
  for (const warning of detail.warnings ?? []) lines.push(`  warning: ${warning}`);
  return lines.join('\n');
}

const COVERED_APIS = [
  'GetTickCount',
  'GetTickCount64',
  'timeGetTime',
  'QueryPerformanceCounter',
  'GetSystemTimeAsFileTime',
  'GetSystemTimePreciseAsFileTime',
  'GetMessageTime',
  'GetSystemTime',
  'GetLocalTime',
  'Sleep',
  'SleepEx',
  'WaitForSingleObject',
  'WaitForSingleObjectEx',
  'WaitForMultipleObjects',
  'WaitForMultipleObjectsEx',
  'SetTimer',
  'SetWaitableTimer',
  'SetWaitableTimerEx',
  'timeSetEvent',
];

export function apply(ctx, config) {
  const cfg = config ?? {};

  ctx.tools.register(
    defineTool({
      name: 'verify_timeshift',
      description:
        'Speed up / slow down / push the target process clock into the future: hook 19 time APIs; wait-style ' +
        'ones scale by duration, read-style ones scale or offset via a re-anchor algorithm. Use it to verify ' +
        'trial-period checks, timeout logic, and time-related defects. Hooks are removed automatically when ' +
        'the window expires; the report states which installed and how many failed.',
      parameters,
      output: {
        schema: outputSchema,
        render: (_args, value) => [{ type: 'text', text: report(value) }],
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const verifyId = nextId('VT-', workspace);
        const pid = Number(args?.pid);
        const durationMs = Number.isFinite(args?.duration_ms)
          ? Number(args.duration_ms)
          : Number(cfg.defaultDurationMs ?? 60000);
        const offsetSec = Number.isFinite(args?.offset_sec) ? Number(args.offset_sec) : 0;
        const factor = Number.isFinite(args?.factor) ? Number(args.factor) : Number(cfg.defaultFactor ?? 1);
        const warnings = [];
        const logPath = join(verifyDir(workspace), `${verifyId}.shift.log`);

        try {
          if (!Number.isFinite(pid) || pid <= 0) throw new Error('a valid pid is required');
          if (offsetSec === 0 && (factor <= 0 || factor === 1)) {
            throw new Error('supply at least one of offset_sec or factor (and it must not mean "no shift")');
          }
          if (!timeLabAvailable()) {
            throw new Error('native helper unavailable (not built, or platform mismatch): hook_host.exe + time_helper.dll required');
          }

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'timelab',
            event: 'shifted',
            pid,
            detail: { verify_id: verifyId, offset_sec: offsetSec, factor, duration_ms: durationMs },
          });

          ensureVerifyDir(workspace);
          const shifted = await shiftProcess({ pid, factor, offsetSec, durationMs, outPath: logPath });
          if (shifted?.ok === false && shifted?.state === undefined) throw new Error(shifted.error ?? 'injection failed');
          if (shifted.dll_loaded === false) warnings.push('the DLL never showed up in the target module list');
          // attached === false: the DLL loaded but never opened the shared config, which is a verifier-side
          // failure (usually a target at a lower integrity level), not a property of the target.
          const attached = shifted.attached !== false;
          if (!attached) {
            warnings.push('the payload never attached: the target could not open the shared config (a target running at a lower integrity level is the usual cause)');
          } else if (shifted.state === 'failed') {
            warnings.push('DLL init failed (MinHook did not start)');
          }
          if (shifted.state === 'timeout' && shifted.target_exited === true) {
            warnings.push('target exited before the shift ended; the shift window closed early');
          }
          if (shifted.hook_failures) warnings.push(`${shifted.hook_failures} hook(s) failed to install`);

          const installed = Number(shifted.hooks_installed ?? 0);
          const mode = Number.isFinite(offsetSec) && offsetSec !== 0 ? 'offset' : 'factor';
          const description = describeShift(offsetSec, factor);
          const summary = !attached
            ? `verifier did not complete: the payload loaded into pid ${pid} but never attached to the shared config`
            : installed > 0
              ? `shifted pid ${pid} clock ${description} (active for ${formatMs(durationMs)}, ${installed} APIs)`
              : `no hooks installed at all: ${pid} could not be hooked (the target may resolve these APIs somewhere MinHook cannot reach, or another tool already claimed them)`;

          const value = {
            source: 'timelab',
            verify_id: verifyId,
            result: !attached ? 'error' : installed > 0 ? 'pass' : 'error',
            summary,
            detail: {
              pid,
              mode,
              offset_sec: offsetSec,
              factor,
              duration_ms: durationMs,
              attached,
              hooks_installed: installed,
              hook_failures: shifted.hook_failures ?? 0,
              covered_apis: COVERED_APIS,
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
            source: 'timelab',
            verify_id: verifyId,
            result: 'error',
            summary: `verifier did not run: ${error?.message ?? error} (this is not a verdict on the target)`,
            detail: {
              pid,
              offset_sec: offsetSec,
              factor,
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
