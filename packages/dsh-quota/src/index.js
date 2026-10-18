/**
 * dsh-quota · `verify_limit`
 *
 * Puts resource caps (CPU rate / memory peak / wall-clock duration) on a command run for the agent;
 * on overrun it kills the entire Job and returns a human-readable VerifyFragment (contract in
 * @alexzeng666/dsh-verify-contract).
 */
import { existsSync } from 'node:fs';
import os from 'node:os';

import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

import { appendJsonl, formatBytes, formatMs, nextId, resolveWorkspace, ensureVerifyDir, verifyDir } from './fragment.js';
import { runLimited } from './job.js';

export const name = 'dsh-quota';

export const inject = ['tools'];

export const Config = z.object({
  defaultCpuPercent: z.number().default(50),
  defaultMemoryMb: z.number().default(2048),
  defaultTimeoutSec: z.number().default(60),
});

const parameters = {
  cmd: {
    type: 'string',
    required: true,
    description: 'Command line to run, executed as cmd.exe /d /s /c (npm run build and the like work as-is).',
  },
  cpu_percent: {
    type: 'integer',
    description: 'CPU cap percentage, measured against whole-machine capacity (100 = all cores, 50 on an 8-core machine = at most 4 cores). Defaults to the plugin config defaultCpuPercent.',
  },
  memory_mb: {
    type: 'integer',
    description: 'Memory cap in MB (peak Job committed memory, including child processes). Defaults to the plugin config defaultMemoryMb.',
  },
  timeout_sec: {
    type: 'integer',
    description: 'Wall-clock cap in seconds; on expiry the entire Job is killed. Defaults to the plugin config defaultTimeoutSec.',
  },
};

const outputSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    source: { type: 'string', required: true, description: 'Always quota' },
    verify_id: { type: 'string', required: true, description: 'Of the form VQ-001' },
    result: { type: 'string', required: true, description: 'pass / fail / error' },
    summary: { type: 'string', required: true, description: 'One-line human-readable conclusion' },
    detail: { type: 'object', additionalProperties: true, required: true, description: 'Package-private fields; not parsed upstream' },
    evidence: { type: 'array', items: { type: 'string' }, required: true, description: 'Paths where stdout/stderr were persisted' },
    elapsed_ms: { type: 'integer', required: true, description: 'Time the verification itself took' },
  },
};

function oneLine(run, limits) {
  const head =
    run.reason === 'timeout'
      ? `command killed on timeout: ${limits.timeout_sec}s wall-clock cap, actually ran ${formatMs(run.wall_ms)}`
      : run.reason === 'cancel'
        ? `command terminated after cancellation (ran ${formatMs(run.wall_ms)})`
        : run.exit_code === 0
          ? `command exited normally in ${formatMs(run.wall_ms)}`
          : `command exited non-zero (${run.exit_code}) in ${formatMs(run.wall_ms)}`;
  return `${head}; CPU avg ${run.avg_cpu_percent_of_total ?? 0}% · memory peak ${formatBytes(run.peak_memory_bytes)}`;
}

function report(value) {
  const detail = value.detail ?? {};
  const run = detail.run ?? {};
  const limits = detail.limits ?? {};
  const cores = detail.host_cores ?? os.cpus().length;
  const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
  lines.push(
    `  ${value.verify_id} · elapsed ${formatMs(value.elapsed_ms)} · exit: ${run.describe_exit ?? 'unknown'}` +
      ` (code ${run.exit_code ?? '?'} / ${run.exit_code_hex ?? '?'})`,
  );
  lines.push(
    `  CPU: instantaneous peak ${run.peak_cpu_percent_of_total ?? 0}% · avg ${run.avg_cpu_percent_of_total ?? 0}%` +
      ` (of whole-machine ${cores}-core capacity; per-core normalized peak ${run.peak_cpu_percent ?? 0}%)`,
  );
  lines.push(
    `  Memory: peak ${formatBytes(run.peak_memory_bytes ?? 0)}` + (limits.memory_mb ? ` (cap ${limits.memory_mb} MB)` : ''),
  );
  lines.push(
    `  Caps: CPU ${limits.cpu_percent ? `${limits.cpu_percent}% (whole-machine capacity)` : 'unset'} · ` +
      `wall clock ${limits.timeout_sec ? `${limits.timeout_sec}s` : 'unset'}`,
  );
  const out = detail.output ?? {};
  lines.push(
    `  Output: stdout ${formatBytes(out.stdout_bytes ?? 0)} · stderr ${formatBytes(out.stderr_bytes ?? 0)}` +
      (value.evidence?.length ? `\n    ${value.evidence.join('\n    ')}` : ' (not persisted)'),
  );
  if (detail.suspected?.memory_limit_hit) {
    const used = limits.memory_mb ? Math.round(((run.peak_memory_bytes ?? 0) / (limits.memory_mb * 1024 * 1024)) * 100) : 0;
    lines.push(`  Suspected: hit the memory cap (peak reached ${used}% of the cap); most likely exited on allocation failure`);
  }
  for (const warning of detail.warnings ?? []) lines.push(`  Warning: ${warning}`);
  return lines.join('\n');
}

export function apply(ctx, config) {
  const cfg = config ?? {};

  ctx.tools.register(
    defineTool({
      name: 'verify_limit',
      description:
        'Run a command within resource caps: CPU percentage, memory MB, wall-clock seconds. Overruns are killed automatically; returns a VerifyFragment.' +
        'Use it to prove "it actually runs and does not saturate the machine" after changing code; the report carries the actual peak CPU/memory and the exit reason.',
      parameters,
      output: {
        schema: outputSchema,
        render: (_args, value) => [{ type: 'text', text: report(value) }],
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const verifyId = nextId('VQ-', workspace);
        const timeoutSec = Number.isFinite(args?.timeout_sec)
          ? Number(args.timeout_sec)
          : Number(cfg.defaultTimeoutSec ?? 60);
        const limits = {
          cpu_percent: Number.isFinite(args?.cpu_percent) ? Number(args.cpu_percent) : Number(cfg.defaultCpuPercent ?? 50),
          memory_mb: Number.isFinite(args?.memory_mb) ? Number(args.memory_mb) : Number(cfg.defaultMemoryMb ?? 2048),
          timeout_sec: timeoutSec,
        };
        const cmd = String(args?.cmd ?? '').trim();

        appendJsonl(workspace, 'timeline.jsonl', {
          ts: Date.now(),
          source: 'quota',
          event: 'started',
          detail: { cmd, limits, verify_id: verifyId },
        });

        try {
          ensureVerifyDir(workspace);
          const run = await runLimited({
            command: cmd,
            cwd: workspace,
            env: { ...process.env },
            cpuPercent: limits.cpu_percent,
            memoryMb: limits.memory_mb,
            timeoutSec: limits.timeout_sec,
            outputDir: verifyDir(workspace),
            id: verifyId,
            signal: exec?.signal,
          });

          const memoryLimitHit =
            limits.memory_mb > 0 &&
            run.exit_code !== 0 &&
            (run.peak_memory_bytes >= limits.memory_mb * 1024 * 1024 * 0.8 ||
              /ERR_MEMORY_ALLOCATION_FAILED|Failed to allocate memory|out of memory|bad_alloc|COMMITMENT_LIMIT/i.test(
                run.stderr.tail ?? '',
              ));
          const passed = run.exit_code === 0 && run.reason === 'exited';
          const peakTotal = Number((run.peak_cpu_percent / os.cpus().length).toFixed(1));
          const avgTotal =
            run.wall_ms > 0
              ? Number(((run.cpu_time_ms / run.wall_ms / os.cpus().length) * 100).toFixed(1))
              : 0;

          const evidence = [run.stdout.path, run.stderr.path].filter((path) => Boolean(path) && existsSync(path));

          const summary = oneLine({ ...run, peak_cpu_percent_of_total: peakTotal, avg_cpu_percent_of_total: avgTotal }, limits);
          const value = {
            source: 'quota',
            verify_id: verifyId,
            result: passed ? 'pass' : 'fail',
            summary,
            detail: {
              cmd,
              cwd: workspace,
              host_cores: os.cpus().length,
              limits,
              limits_effective: run.limits.effective,
              run: {
                pid: run.pid,
                exit_code: run.exit_code,
                exit_code_hex: run.exit_code_hex,
                reason: run.reason,
                describe_exit: run.describe_exit,
                wall_ms: run.wall_ms,
                cpu_time_ms: run.cpu_time_ms,
                peak_cpu_percent: run.peak_cpu_percent,
                peak_cpu_percent_of_total: peakTotal,
                avg_cpu_percent_of_total: avgTotal,
                peak_memory_bytes: run.peak_memory_bytes,
              },
              suspected: { memory_limit_hit: memoryLimitHit },
              output: {
                stdout_bytes: run.stdout.bytes,
                stderr_bytes: run.stderr.bytes,
                stdout_tail: run.stdout.tail,
                stderr_tail: run.stderr.tail,
              },
              warnings: run.warnings,
            },
            evidence,
            elapsed_ms: Date.now() - startedAt,
          };

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'quota',
            event: run.reason === 'exited' ? 'exited' : 'killed',
            pid: run.pid,
            detail:
              run.reason === 'exited'
                ? { exit_code: run.exit_code, verify_id: verifyId }
                : { reason: run.reason, limits, exit_code: run.exit_code, verify_id: verifyId },
          });
          appendJsonl(workspace, 'fragments.jsonl', value);
          return value;
        } catch (error) {
          // fail-open: a verifier that breaks still has to produce a conclusion, just marked error.
          const value = {
            source: 'quota',
            verify_id: verifyId,
            result: 'error',
            summary: `verifier failed to run: ${error?.message ?? error} (this is not a conclusion about the command under test)`,
            detail: {
              cmd,
              cwd: workspace,
              limits,
              error: { name: error?.name ?? 'Error', message: error?.message ?? String(error) },
            },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          };
          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'quota',
            event: 'error',
            detail: { verify_id: verifyId, message: value.detail.error.message },
          });
          appendJsonl(workspace, 'fragments.jsonl', value);
          return value;
        }
      },
    }),
  );
}
