/**
 * dsh-crashlab · `verify_attribution`
 *
 * Produce an attribution report after a process dies abnormally, filling in three layers progressively:
 *   L1 exit-code semantics + stderr patterns (reads the fragments/timeline quota left in .verify)
 *   L2 Windows event log (Application Error / .NET Runtime / WER)
 *   L3 minidump (native helper: MiniDumpWriteDump + StackWalk64 + dbghelp symbols)
 *
 * `detail.crash_frame` is the handoff point if the caller wants to decompile the crash site with
 * dsh-reverse - that is the caller's step, not a layer this package produces.
 *
 * The whole chain is fail-open: any layer that cannot be obtained is simply one layer short; a conclusion
 * is still produced, only marked error or with a degraded explanation.
 */
import { existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

import { lookupContext } from './context.js';
import { enrichFramesWithDwarf } from './dwarf.js';
import { lookupCrashEvent } from './eventlog.js';
import { appendJsonl, formatMs, nextId, resolveWorkspace, toJsonSafe, ensureVerifyDir, verifyDir } from './fragment.js';
import { attachAndCapture, helperAvailable, parseDump, runAndCapture } from './helper.js';

export const name = 'dsh-crashlab';

export const inject = ['tools'];

export const Config = z.object({
  defaultTimeoutMs: z.number().default(30000),
  symbolPath: z.string().default(''),
  addr2linePath: z.string().default(''),
});

const parameters = {
  cmd: {
    type: 'string',
    description:
      'Run this command line directly under the debugger and wait for it to crash (no need to race to attach). ' +
      'Three-way choice with pid / dump_path. On this path L2 event log is unavailable (a debugger-owned process does not go through WER), but a full minidump and call stack are obtained.',
  },
  pid: {
    type: 'integer',
    description: 'Process id to attribute. A live process gets a debugger attached and waited on; an already-exited process goes through L1/L2 (no call stack).',
  },
  dump_path: {
    type: 'string',
    description: 'Path to an existing .dmp. When given, only that dump is parsed and pid is ignored.',
  },
  timeout_ms: {
    type: 'integer',
    description: 'Upper bound in milliseconds to wait for the crash after attaching the debugger; defaults to the plugin config defaultTimeoutMs.',
  },
  symbol_path: {
    type: 'string',
    description: 'Symbol search path (directory containing the PDB); defaults to the plugin config symbolPath.',
  },
  addr2line_path: {
    type: 'string',
    description:
      'Path to the addr2line executable, used to resolve DWARF source lines for gcc/mingw targets that have no PDB; ' +
      'defaults to the plugin config addr2linePath, then falls back to the in-repo tools/mingw64, and finally PATH.',
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

/** The two parameters of 0xC0000005: access type + target address. */
function describeAccessViolation(params) {
  if (!Array.isArray(params) || params.length < 2) return '';
  const kind = String(params[0]).toLowerCase();
  const address = String(params[1]);
  if (kind === '0x0' || kind === '0') return `read ${address}`;
  if (kind === '0x1' || kind === '1') return `write ${address}`;
  if (kind === '0x8' || kind === '8') return `execute ${address}`;
  return `access ${address}`;
}

/** Pick the frame that looks most like code as the crash site (skipping system modules). */
function pickCrashFrame(frames, modules) {
  if (!Array.isArray(frames) || frames.length === 0) return undefined;
  const systemModules = new Set(['ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'ucrtbase.dll', 'msvcrt.dll']);
  return frames.find((frame) => frame.module && !systemModules.has(String(frame.module).toLowerCase())) ?? frames[0];
}

function report(value) {
  const detail = value.detail ?? {};
  const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
  const levels = detail.levels ?? {};
  lines.push(
    `  ${value.verify_id} · took ${formatMs(value.elapsed_ms)} · attribution layers ` +
      `${['L1', 'L2', 'L3'].filter((key) => levels[key]).join(' ') || 'none'}`,
  );

  const exception = detail.exception;
  if (exception?.code_hex) {
    const extra = exception.code_hex === '0xC0000005' ? ` (${describeAccessViolation(exception.params)})` : '';
    lines.push(`  exception: ${exception.code_hex} ${exception.name ?? ''}${extra}`);
  }

  const frames = Array.isArray(detail.frames) ? detail.frames : [];
  if (frames.length > 0) {
    lines.push('  call stack:');
    for (const frame of frames.slice(0, 8)) {
      const location = frame.source_file ? `  ${frame.source_file}:${frame.source_line}` : '';
      const symbol = frame.symbol || `${frame.module}+${frame.module_offset}`;
      lines.push(`    #${frame.index} ${symbol}${location}`);
    }
    if (frames.length > 8) lines.push(`    … (${frames.length} frames total; full list in detail.frames)`);
  }

  if (detail.source_hint) lines.push(`  source: ${detail.source_hint}`);
  if (detail.crash_frame) lines.push(`  crash site: ${detail.crash_frame}`);
  if (detail.modules_total) lines.push(`  modules: ${detail.modules_sample?.join(' · ') ?? ''} (${detail.modules_total} total)`);

  const event = detail.eventlog;
  if (event?.found) {
    lines.push(
      `  event log: ${event.provider ?? 'Application Error'} · ${event.app ?? ''} · ` +
        `module ${event.module || '?'} · exception code ${event.exception_code || '?'} · offset ${event.offset || '?'}` +
        (event.time ? ` · event time ${event.time}` : ''),
    );
  } else if (event?.error) {
    lines.push(`  event log: unreadable (${event.error})`);
  } else if (event) {
    // Not found: state both "why" and "what it costs", otherwise the user assumes attribution is incomplete.
    const windowText = detail.eventlog_window_ms ? ` (only events from the last ${formatMs(detail.eventlog_window_ms)})` : '';
    const polled = Number(detail.eventlog_polled_ms ?? 0);
    lines.push(
      polled > 0
        ? `  L2 miss: polled ${polled / 1000} times (${formatMs(polled)} total) and the event log still has no record of this crash${windowText}`
        : detail.eventlog_window_ms && detail.eventlog_window_ms <= 5000
          ? `  L2 miss: the WER event for this run has not been persisted yet (the system writes it asynchronously, usually a few seconds later); the call stack comes from L3 and is unaffected${windowText}`
          : `  L2 miss: no matching crash record in the event log${windowText}`,
    );
  }

  if (detail.l1?.exit_code !== undefined) {
    lines.push(
      `  L1: exit code ${detail.l1.exit_code}` +
        (detail.l1.killed_reason ? ` · termination reason ${detail.l1.killed_reason}` : '') +
        (detail.l1.stderr_hints?.length ? ` · stderr hits: ${detail.l1.stderr_hints.join(', ')}` : ''),
    );
  }

  if (detail.dump_path) lines.push(`  dump: ${detail.dump_path}`);
  for (const warning of detail.warnings ?? []) lines.push(`  warning: ${warning}`);
  return lines.join('\n');
}

/** Liveness probe: if kill(pid, 0) does not throw, the process is alive. */
function isAlive(pid) {
  if (!Number.isFinite(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function apply(ctx, config) {
  const cfg = config ?? {};

  ctx.tools.register(
    defineTool({
      name: 'verify_attribution',
      description:
        'Produce an attribution report for a process crash: exit-code semantics / Windows event log / minidump call stack (with modules and source lines). ' +
        'Pass a live pid to attach a debugger and wait for the crash; pass dump_path to parse an existing dump. ' +
        'Use it when a failure cannot just be called FAILED — the report has to point at a concrete module and source line.',
      parameters,
      output: {
        schema: outputSchema,
        render: (_args, value) => [{ type: 'text', text: report(value) }],
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const verifyId = nextId('VC-', workspace);
        const dumpPath = String(args?.dump_path ?? '').trim();
        const cmd = String(args?.cmd ?? '').trim();
        const pid = Number.isFinite(args?.pid) ? Number(args.pid) : undefined;
        const timeoutMs = Number.isFinite(args?.timeout_ms) ? Number(args.timeout_ms) : Number(cfg.defaultTimeoutMs ?? 30000);
        const symbolPath = String(args?.symbol_path ?? cfg.symbolPath ?? '').trim();
        const addr2linePath = String(args?.addr2line_path ?? cfg.addr2linePath ?? '').trim();

        const levels = { L1: false, L2: false, L3: false };
        const warnings = [];
        const detail = { levels, warnings };
        const evidence = [];
        let exception;
        let frames = [];
        let modules = [];
        let stackQuality = 'none';
        let image;
        let observedCrash = false;

        try {
          // ── L3 / L2: dump parsing or live-process capture ──────────────────────────────
          if (dumpPath !== '') {
            if (!existsSync(dumpPath)) throw new Error(`dump not found: ${dumpPath}`);
            const parsed = await parseDump({ dumpPath, symbolPath });
            if (parsed?.ok === false) throw new Error(parsed.error ?? 'dump parsing failed');
            exception = parsed.exception;
            frames = Array.isArray(parsed.frames) ? parsed.frames : [];
            modules = Array.isArray(parsed.modules) ? parsed.modules : [];
            stackQuality = parsed.stack_quality ?? 'none';
            // Only count L3 when something was actually resolved: parse returns ok for corrupt files too, so true would be fake evidence.
            levels.L3 = frames.length > 0 || modules.length > 0;
            observedCrash = Boolean(exception?.code_hex);
            detail.dump_path = dumpPath;
            detail.modules_total = parsed.modules?.length ?? 0;
            detail.modules_sample = (parsed.modules ?? []).slice(0, 6).map((item) => item.name);
            evidence.push(dumpPath);
          } else if (cmd !== '') {
            // Run the command directly under the debugger: the agent does not have to race to attach.
            ensureVerifyDir(workspace);
            const outPath = join(verifyDir(workspace), `${verifyId}.dmp`);
            const captured = await runAndCapture({
              command: cmd,
              cwd: workspace,
              dumpPath: outPath,
              symbolPath,
              timeoutMs,
            });
            if (captured?.ok) {
              exception = captured.exception;
              frames = Array.isArray(captured.frames) ? captured.frames : [];
              modules = Array.isArray(captured.modules) ? captured.modules : [];
              stackQuality = captured.stack_quality ?? 'none';
              image = captured.image || image;
              observedCrash = Boolean(exception?.code_hex);
              if (captured.captured) {
                detail.dump_path = outPath;
                evidence.push(outPath);
                // Only count L3 when something was actually resolved: parse returns ok for corrupt files too, so true would be fake evidence.
            levels.L3 = frames.length > 0 || modules.length > 0;
              } else if (captured.dump_error) {
                warnings.push(`dump was not written: ${captured.dump_error}`);
              }
              detail.modules_total = modules.length;
              detail.modules_sample = modules.slice(0, 6).map((item) => item.name);
              detail.exit_code = captured.exit?.code;
              if (!observedCrash) warnings.push(`ran to completion without crashing (exit ${captured.exit?.code_hex ?? '?'})`);
            } else {
              warnings.push(`native capture failed: ${captured?.error ?? 'unknown reason'}`);
            }
          } else if (Number.isFinite(pid) && pid > 0) {
            detail.l1 = lookupContext(workspace, pid);
            levels.L1 = detail.l1.exit_code !== undefined || Boolean(detail.l1.killed_reason);

            if (isAlive(pid) && helperAvailable()) {
              ensureVerifyDir(workspace);
            const outPath = join(verifyDir(workspace), `${verifyId}.dmp`);
              const captured = await attachAndCapture({ pid, dumpPath: outPath, symbolPath, timeoutMs });
              if (captured?.ok) {
                exception = captured.exception;
                frames = Array.isArray(captured.frames) ? captured.frames : [];
                modules = Array.isArray(captured.modules) ? captured.modules : [];
                stackQuality = captured.stack_quality ?? 'none';
                image = captured.image || image;
                observedCrash = Boolean(exception?.code_hex);
                if (captured.captured) {
                  detail.dump_path = outPath;
                  evidence.push(outPath);
                  // Only count L3 when something was actually resolved: parse returns ok for corrupt files too, so true would be fake evidence.
            levels.L3 = frames.length > 0 || modules.length > 0;
                } else if (captured.dump_error) {
                  warnings.push(`dump was not written: ${captured.dump_error}`);
                }
                detail.modules_total = captured.modules?.length ?? 0;
                detail.modules_sample = (captured.modules ?? []).slice(0, 6).map((item) => item.name);
                if (!observedCrash) warnings.push(`waited ${formatMs(timeoutMs)} without a crash`);
              } else {
                warnings.push(`native capture failed: ${captured?.error ?? 'unknown reason'}`);
              }
            } else if (!isAlive(pid)) {
              warnings.push('process already exited, no call stack available (no debugger was attached at crash time); falling back to L1/L2 attribution');
            } else if (!helperAvailable()) {
              warnings.push('native helper unavailable (not built or wrong platform), skipping L3');
            }
          } else {
            throw new Error('one of cmd, pid, or dump_path is required');
          }

          // ── L2: event log ────────────────────────────────────────────────
          //
          // The window must be chosen per path, otherwise an old event is picked up as evidence for
          // this run (false positive): the same-named program crashed on path A ten minutes ago and
          // crashes on path B now, and offset/module/exception code all "look right", because it is
          // the same binary — that kind of error is far more dangerous than a plain failure.
          //   cmd / live pid → the crash can only happen after we start: since = startedAt - 1000
          //   exited pid / dump_path → the crash may predate our attach: keep 15 minutes
          const liveRun = cmd !== '' || (Number.isFinite(pid) && pid > 0 && isAlive(pid));
          const eventSince = liveRun ? startedAt - 1000 : startedAt - 15 * 60 * 1000;
          let eventlog = await lookupCrashEvent({
            image,
            pid: Number.isFinite(pid) ? pid : undefined,
            since: eventSince,
          });

          // Do not poll when L3 got a stack: whatever L2 can provide (module + offset + exception
          // code) is already covered by L3, and waiting 3 seconds for nothing is pointless. Only when
          // L3 failed (no dump / process killed by the system / PPL process) is L2 the only way to
          // get "module + offset", and then waiting a few seconds is well worth it.
          const l3Failed = frames.length === 0 || (stackQuality ?? 'none') === 'none';
          let polledMs = 0;
          if (l3Failed && !eventlog?.found) {
            for (let attempt = 0; attempt < 3 && !eventlog?.found; attempt += 1) {
              await new Promise((done) => setTimeout(done, 1000));
              polledMs += 1000;
              eventlog = await lookupCrashEvent({
                image,
                pid: Number.isFinite(pid) ? pid : undefined,
                since: eventSince,
              });
            }
          }

          detail.eventlog = eventlog;
          detail.eventlog_window_ms = liveRun ? 1000 : 15 * 60 * 1000;
          detail.eventlog_polled_ms = polledMs;
          levels.L2 = Boolean(eventlog?.found);
          if (eventlog?.found && !exception?.code_hex) {
            exception = {
              code_hex: eventlog.exception_code,
              name: '',
              params: [],
              address: eventlog.offset,
            };
            observedCrash = true;
          }

          // ── symbols: fill DWARF for what dbghelp could not resolve (gcc/mingw targets) ────────────
          const dwarf = await enrichFramesWithDwarf({ frames, modules, addr2linePath });
          frames = dwarf.frames;
          if (dwarf.used) {
            detail.source_kind = 'dwarf';
          } else if (frames.some((frame) => frame.source_file)) {
            detail.source_kind = 'pdb';
          } else if (frames.length > 0) {
            detail.source_kind = 'none';
            if (dwarf.error) warnings.push(`no source line: ${dwarf.error}`);
          }

          // ── conclusion ───────────────────────────────────────────────────────
          const crashFrame = pickCrashFrame(frames, detail.modules_sample);
          if (crashFrame) {
            detail.crash_frame = `${crashFrame.module || '?'}+${crashFrame.module_offset}`;
            if (crashFrame.source_file) detail.source_hint = `${crashFrame.source_file}:${crashFrame.source_line}`;
            if (crashFrame.symbol) detail.source_hint = detail.source_hint ?? crashFrame.symbol;
          }
          detail.exception = exception;
          detail.frames = frames.map((frame, index) => ({ ...frame, index }));
          detail.stack_quality = stackQuality;
          detail.pid = pid;
          detail.image = image;

          let result;
          let summary;
          const dumpEmpty = dumpPath !== '' && frames.length === 0 && modules.length === 0;
          if (observedCrash) {
            result = 'fail';
            const where = detail.crash_frame ? ` · crash site ${detail.crash_frame}` : '';
            const source = detail.source_hint ? ` · source ${detail.source_hint}` : '';
            summary = `process crashed: ${exception?.code_hex ?? '?'} ${exception?.name ?? ''}${where}${source}`.replace(/\s+/g, ' ');
          } else if (Number.isFinite(pid) && detail.l1?.exit_code !== undefined && detail.l1.exit_code !== 0) {
            result = 'fail';
            const hints = detail.l1.stderr_hints?.length ? ` (stderr hits: ${detail.l1.stderr_hints.join(', ')})` : '';
            summary = `process exited non-zero (${detail.l1.exit_code})${hints} but there is no call stack (process already exited or no debugger attached)`;
          } else if (Number.isFinite(pid) && detail.l1?.exit_code === 0) {
            result = 'pass';
            summary = 'process exited normally (0), nothing to attribute';
          } else if (cmd !== '') {
            const exitCode = detail.exit_code;
            result = exitCode === 0 || exitCode === undefined ? 'pass' : 'fail';
            summary =
              exitCode === 0 || exitCode === undefined
                ? 'command ran to completion, nothing to attribute'
                : `command exited non-zero (${exitCode}) but there is no exception record`;
          } else if (Number.isFinite(pid) && isAlive(pid)) {
            result = 'pass';
            summary = `no crash observed within ${formatMs(timeoutMs)}; process still running`;
          } else if (dumpEmpty) {
            // A dump was given but nothing was resolved: this is not "no crash evidence", it is the verifier failing to look.
            result = 'error';
            summary = 'verifier did not complete: no stack or module could be parsed from the dump (may not be a minidump, or the file is corrupt)';
          } else {
            result = 'pass';
            summary = 'no crash evidence found';
          }

          const value = {
            source: 'crashlab',
            verify_id: verifyId,
            result,
            summary,
            detail,
            evidence,
            elapsed_ms: Date.now() - startedAt,
          };

          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'crashlab',
            event: observedCrash ? 'crashed' : 'observed',
            pid: Number.isFinite(pid) ? pid : undefined,
            detail: {
              verify_id: verifyId,
              exception_code: exception?.code_hex,
              fault_addr: detail.crash_frame,
              levels,
            },
          });
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        } catch (error) {
          const value = {
            source: 'crashlab',
            verify_id: verifyId,
            result: 'error',
            summary: `verifier did not complete: ${error?.message ?? error} (this is not a conclusion about the subject under test)`,
            detail: { ...detail, error: { name: error?.name ?? 'Error', message: error?.message ?? String(error) } },
            evidence,
            elapsed_ms: Date.now() - startedAt,
          };
          appendJsonl(workspace, 'fragments.jsonl', value);
          return toJsonSafe(value);
        } finally {
          // Do not leave empty dump files in the workspace (failure paths may leave a 0-byte file behind).
          try {
            const leftover = join(verifyDir(workspace), `${verifyId}.dmp`);
            if (existsSync(leftover) && !detail.dump_path) unlinkSync(leftover);
          } catch {
            /* cleanup failure does not affect the conclusion */
          }
        }
      },
    }),
  );
}
