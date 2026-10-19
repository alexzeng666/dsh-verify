/**
 * dsh-verify · orchestration package
 *
 * Each of the four sub-packages answers exactly one question (does it run / why did it
 * crash / what is it doing / is the timing right); this layer wires them into what an
 * agent actually needs: **one verification = run + assert + one human-readable report**.
 *
 * Tool names are frozen (contract §0): verify_run / verify_assert_exit / verify_assert_stdout /
 * verify_assert_file / verify_assert_json / verify_assert_screenshot / verify_report.
 */
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readFileSync, readSync, statSync, writeFileSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

import z from '@deepseek-ai/schemastery';
import { defineTool } from '@deepseek-ai/dsh-tools';

import {
  appendJsonl,
  ensureVerifyDir,
  formatMs,
  nextId,
  readJsonl,
  resolveWorkspace,
  toJsonSafe,
  verifyDir,
} from './fragment.js';
import { enrichFramesWithDwarf } from './dwarf.js';
import { diffPng } from './png.js';
import { aggregate, findLastRun, formatReport } from './report.js';
import { runCommand, runnerAvailable } from './runner.js';

export const name = 'dsh-verify';

export const inject = ['tools', 'systemPrompt'];

export const Config = z.object({
  promptInjection: z.boolean().default(true),
  defaultTimeoutMs: z.number().default(120000),
  maxReportEntries: z.number().default(40),
});

const PROMPT = [
  '## Verification discipline (dsh-verify)',
  '',
  'Before claiming "fixed / done / working", actually run the verify_* tools so the conclusion carries its own evidence:',
  '',
  '- Changed code: `verify_run(cmd="<build or test command>")` runs the command and, on a crash, hands back the stack and source lines directly.',
  '- Need an assertion: `verify_assert_exit` / `verify_assert_stdout` / `verify_assert_file` / `verify_assert_json` / `verify_assert_screenshot`; assertions target the most recent `verify_run` by default.',
  '- Suspect resources (never finishes, eats all memory): `verify_limit`.',
  '- Target crashed outside verify_run: `verify_attribution(pid=...)`.',
  '- Want to know what a process is doing: `verify_trace(pid=...)`.',
  '- Time-related (trial period / timeout logic): `verify_timeshift(pid=...)`.',
  '- Before reporting: `verify_report()` gives the user a traceable report.',
  '',
  'The report is for humans: state what was verified, what the conclusion is, and where the evidence lives. When a verification tool itself fails the result is `error` (not `fail`) — do not describe an environment problem as a code problem.',
].join('\n');

const parametersRun = {
  cmd: {
    type: 'string',
    required: true,
    description:
      'Command line to run (executed in the workspace). Builds, tests and scripts all work. ' +
      '**Executed directly via CreateProcessW, never through a shell**: builtins (echo / dir / type / copy / set / cd), ' +
      'pipes `|`, `&&` and variable expansion `%VAR%` do not work — wrap it in cmd /d /s /c "<command>" when needed, ' +
      'or pass shell=true and this tool wraps it for you.',
  },
  encoding: {
    type: 'string',
    enum: ['auto', 'utf8', 'gb18030', 'gbk', 'binary'],
    description:
      'Output decoding, defaults to auto: when UTF-8 produces replacement characters (U+FFFD), fall back to gb18030, then gbk; ' +
      'binary returns bytes as latin1. detail.encoding records the one actually used.',
  },
  shell: {
    type: 'boolean',
    description:
      'Defaults to false. When true, cmd is written into a temporary .cmd script and executed with cmd /d /s /c — ' +
      'pipes, &&, redirection and %VAR% expansion all work. Prefer this path when the command needs quotes; ' +
      'do not hand-build cmd /c (cmd.exe does not honour \\" escaping).',
  },
  timeout_ms: {
    type: 'integer',
    description: 'Wall-clock limit in milliseconds; the process is killed when reached. Defaults to the plugin config defaultTimeoutMs.',
  },
  cwd: {
    type: 'string',
    description: 'Working directory; defaults to the current session workspace.',
  },
  expect_exit: {
    type: 'integer',
    description:
      'Expected exit code, 0 by default. Negative tests must pass it — when checking that the program should reject this input (unknown argument, invalid config, insufficient permission), ' +
      'a non-zero return is the correct behaviour; without expect_exit the run is recorded as fail and becomes indistinguishable from a real bug.',
  },
  scope: {
    type: 'string',
    enum: ['quick', 'full'],
    description:
      'quick (default): exit code + stdout/stderr tail + crash stack. ' +
      'full: keeps the whole stdout/stderr (quick keeps only the tail), no stack-frame truncation, plus a sampled module list. ' +
      'No automatic decisions — the caller explicitly chooses whether it needs more evidence.',
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

// verify_run does not go through a shell: builtins are never found here (CreateProcessW reports Win32 2).
// When hit, give one explicit fix instead of making the agent guess.
const SHELL_BUILTINS = new Set(['echo', 'dir', 'type', 'copy', 'set', 'cd']);

function shellHint(command, useShell) {
  if (useShell) return '';
  const first = String(command ?? '').trim().split(/\s+/)[0]?.toLowerCase() ?? '';
  if (!SHELL_BUILTINS.has(first)) return '';
  return ' · this is a shell builtin and verify_run does not use a shell; write it as cmd /d /s /c "..." or add shell=true';
}

function textReport(lines) {
  return [{ type: 'text', text: lines.join('\n') }];
}

/** Truncate long text; the report keeps only a readable slice. */
function tail(text, limit = 4000) {
  const value = String(text ?? '');
  return value.length <= limit ? value : `...(truncated, first ${value.length - limit} chars omitted)\n${value.slice(-limit)}`;
}

/** Is it a regular file (a same-named directory does not count: existsSync is true yet redirection still fails). */
function isRegularFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

const ENCODINGS = new Set(['auto', 'utf8', 'gb18030', 'gbk', 'binary']);

/** The first position may be half a character left by truncation (possible when reading only the tail); U+FFFD anywhere else means decoding failed. */
function hasReplacement(text) {
  return text.replace(/^\uFFFD/, '').includes('\uFFFD');
}

/**
 * Decode bytes. auto policy: when UTF-8 yields U+FFFD, fall back to gb18030 (a GBK
 * superset), then gbk. Node's built-in TextDecoder supports gb18030 / gbk, zero deps.
 */
function decodeText(buffer, encoding = 'auto') {
  const mode = ENCODINGS.has(encoding) ? encoding : 'auto';
  if (mode === 'binary') return { text: buffer.toString('latin1'), encoding: 'binary' };
  if (mode !== 'auto') {
    try {
      return { text: new TextDecoder(mode).decode(buffer), encoding: mode };
    } catch {
      /* fall through to auto */
    }
  }
  const utf8 = new TextDecoder('utf-8').decode(buffer);
  if (!hasReplacement(utf8)) return { text: utf8, encoding: 'utf8' };
  for (const candidate of ['gb18030', 'gbk']) {
    try {
      const text = new TextDecoder(candidate).decode(buffer);
      if (!hasReplacement(text)) return { text, encoding: candidate };
    } catch {
      /* try the next one */
    }
  }
  return { text: utf8, encoding: 'utf8-lossy' };
}

/** Read only the last keepBytes bytes — never the whole file, so a huge file cannot blow up the string. */
function readTailBytes(path, keepBytes) {
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd).size;
    const start = Math.max(0, size - keepBytes);
    const length = size - start;
    const buffer = Buffer.allocUnsafe(length);
    let read = 0;
    while (read < length) {
      const chunk = readSync(fd, buffer, read, length - read, start + read);
      if (chunk <= 0) break;
      read += chunk;
    }
    return { buffer: buffer.subarray(0, read), truncated: start > 0, size };
  } finally {
    closeSync(fd);
  }
}

/**
 * Read the file tail and decode it.
 * @returns {{ text: string, encoding: string, truncated: boolean, size: number, error?: string }}
 * A failed read returns error instead of a silent empty string — "nothing read" and
 * "read an empty value" must stay distinguishable.
 */
function readTextFile(path, limit = 200_000, encoding = 'auto') {
  try {
    const { buffer, truncated, size } = readTailBytes(path, Math.max(limit * 4, 4));
    const decoded = decodeText(buffer, encoding);
    // Truncation happens after decoding: slicing by bytes would cut double-byte characters in half.
    const cleaned = decoded.text.replace(/^\uFFFD/, '');
    const text = cleaned.length > limit ? cleaned.slice(-limit) : cleaned;
    return { text, encoding: decoded.encoding, truncated, size };
  } catch (error) {
    return { text: '', encoding: 'none', truncated: false, size: 0, error: error?.message ?? String(error) };
  }
}

function matchPattern(text, pattern) {
  const value = String(pattern ?? '');
  if (value.length > 2 && value.startsWith('/') && value.endsWith('/')) {
    try {
      const regex = new RegExp(value.slice(1, -1));
      return { matched: regex.test(text), kind: 'regex' };
    } catch {
      /* malformed regex: fall back to substring */
    }
  }
  return { matched: text.includes(value), kind: 'substring' };
}

/** Dot paths like "a.b[0].c". */
function resolvePointer(value, pointer) {
  const path = String(pointer ?? '').trim();
  if (path === '' || path === '/') return { found: true, value };
  let current = value;
  for (const token of path.replace(/^\//, '').split(/[./]/)) {
    if (token === '') continue;
    const match = /^([^[\]]*)(?:\[(\d+)\])?$/.exec(token);
    if (!match) return { found: false };
    const key = match[1];
    if (key !== '') {
      if (current === null || typeof current !== 'object' || !(key in current)) return { found: false };
      current = current[key];
    }
    if (match[2] !== undefined) {
      const index = Number(match[2]);
      if (!Array.isArray(current) || index >= current.length) return { found: false };
      current = current[index];
    }
  }
  return { found: true, value: current };
}

/** Resolve the assertion target: use run_id when given, otherwise the most recent verify_run. */
function locateRun(workspace, runId) {
  const fragments = readJsonl(workspace, 'fragments.jsonl');
  if (typeof runId === 'string' && runId.trim() !== '') {
    const wanted = runId.trim();
    for (let index = fragments.length - 1; index >= 0; index -= 1) {
      if (fragments[index]?.verify_id === wanted) return fragments[index];
    }
    return undefined;
  }
  return findLastRun(fragments);
}

function makeAssertFragment({ id, startedAt, kind, summary, passed, detail, evidence }) {
  return {
    source: 'orchestrator',
    verify_id: id,
    result: passed === undefined ? 'error' : passed ? 'pass' : 'fail',
    summary,
    detail: { kind: 'assert', assert: kind, ...detail },
    evidence: evidence ?? [],
    elapsed_ms: Date.now() - startedAt,
  };
}

export function apply(ctx, config) {
  const cfg = config ?? {};

  if (cfg.promptInjection !== false) {
  // ── System prompt: self-inject the "verify before declaring completion" rule ───
    ctx.systemPrompt.section({
      name: 'verify:policy',
      order: 3040,
      interpolate: false,
      text: () => (cfg.promptInjection === false ? '' : PROMPT),
    });
  }

  const record = (workspace, fragment) => {
    appendJsonl(workspace, 'fragments.jsonl', fragment);
    return fragment;
  };

  // ── verify_run ────────────────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_run',
      description:
        'Run one command and produce evidence: exit code, stdout/stderr, and on a crash the stack and source lines directly. ' +
        'Call it first when you need to prove the code really runs; later verify_assert_* calls target this run by default.',
      parameters: parametersRun,
      output: {
        schema: outputSchema,
        render: (_args, value) => {
          const detail = value.detail ?? {};
          const lines = [`[${value.result.toUpperCase()}] ${value.summary}`];
          lines.push(
            `  ${value.verify_id} · took ${formatMs(value.elapsed_ms)} · exit ${detail.exit_code ?? '?'}` +
              (detail.exit_code_hex ? ` (${detail.exit_code_hex})` : ''),
          );
          const frames = Array.isArray(detail.frames) ? detail.frames : [];
          if (frames.length > 0) {
            lines.push('  stack:');
            for (const frame of frames.slice(0, 6)) {
              const where = frame.source_file ? `  ${frame.source_file}:${frame.source_line}` : '';
              lines.push(`    #${frame.index} ${frame.symbol || `${frame.module}+${frame.module_offset}`}${where}`);
            }
          }
          if (detail.stdout_tail) {
            lines.push('  stdout tail:');
            for (const line of String(detail.stdout_tail).trimEnd().split('\n').slice(-6)) lines.push(`    ${line}`);
          }
          if (detail.stderr_tail) {
            lines.push('  stderr tail:');
            for (const line of String(detail.stderr_tail).trimEnd().split('\n').slice(-6)) lines.push(`    ${line}`);
          }
          if (value.evidence?.length) lines.push(`  evidence:\n    ${value.evidence.join('\n    ')}`);
          return textReport(lines);
        },
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        const cmd = String(args?.cmd ?? '').trim();
        const timeoutMs = Number.isFinite(args?.timeout_ms)
          ? Number(args.timeout_ms)
          : Number(cfg.defaultTimeoutMs ?? 120000);
        // A relative cwd is relative to the workspace, like every other path argument in the suite: resolving
        // it against the host process cwd instead makes CreateProcessW fail with Win32 267 (ERROR_DIRECTORY)
        // for a directory that plainly exists where the caller pointed.
        const rawCwd = String(args?.cwd ?? '').trim();
        const cwd = rawCwd === '' ? workspace : isAbsolute(rawCwd) ? rawCwd : resolve(workspace, rawCwd);
        const expectExit = Number.isFinite(args?.expect_exit) ? Number(args.expect_exit) : undefined;
        const scope = String(args?.scope ?? 'quick').toLowerCase() === 'full' ? 'full' : 'quick';
        const useShell = args?.shell === true;
        const encoding = String(args?.encoding ?? 'auto').toLowerCase();

        const dir = verifyDir(workspace);
        const dumpPath = join(dir, `${id}.dmp`);
        const stdoutPath = join(dir, `${id}.stdout.log`);
        const stderrPath = join(dir, `${id}.stderr.log`);

        try {
          if (cmd === '') throw new Error('cmd is required');
          if (!runnerAvailable()) throw new Error('native helper unavailable (not built or wrong platform): crash_helper.exe is required');
          // Checked here so a bad cwd is reported as a bad cwd instead of surfacing as an opaque
          // CreateProcessW failure from inside the native helper.
          if (!existsSync(cwd)) throw new Error(`cwd does not exist: ${cwd}`);
          if (!statSync(cwd).isDirectory()) throw new Error(`cwd is not a directory: ${cwd}`);

          // The directory must exist before spawning: stdout/stderr are redirected to
          // files under .verify, and a missing directory makes redirection fail silently
          // (that was the old behaviour — first run in a fresh workspace, the command
          // succeeded yet stdout_tail was empty and every later assertion collapsed).
          ensureVerifyDir(workspace);

          // shell=true: write the command into a temporary .cmd script and hand it to cmd.
          // Why not "cmd /c <verbatim command>": cmd.exe does not honour CommandLineToArgvW's
          // \" escaping, so quotes get misaligned when pasted in verbatim; a script file needs
          // no escaping at all and %VAR% / pipes / && keep working.
          let effectiveCommand = cmd;
          let scriptPath;
          if (useShell) {
            scriptPath = join(dir, `${id}.shell.cmd`);
            writeFileSync(scriptPath, `@echo off\r\n${cmd}\r\n`, 'utf8');
            effectiveCommand = `cmd /d /s /c "${scriptPath}"`;
          }

          const run = await runCommand({
            command: effectiveCommand,
            cwd,
            dumpPath,
            stdoutPath,
            stderrPath,
            timeoutMs,
            symbolPath: cwd,
          });
          if (run?.ok === false && run?.state === undefined) throw new Error(run.error ?? 'failed to start');

          const crashed = Boolean(run.exception?.code_hex);
          const exitCode = run.exit?.code ?? run.exception?.code ?? 0;
          let frames = Array.isArray(run.frames) ? run.frames : [];
          // dbghelp only reads PDB: gcc/mingw targets carry none, so fill DWARF symbols with addr2line.
          const dwarf = await enrichFramesWithDwarf({
            frames,
            modules: Array.isArray(run.modules) ? run.modules : [],
          });
          frames = dwarf.frames.map((frame, index) => ({ ...frame, index }));
          const crashFrame = frames.find((frame) => frame.module && !/^(ntdll|kernel32|kernelbase|ucrtbase)\.dll$/i.test(frame.module)) ?? frames[0];
          const textLimit = scope === 'full' ? 200_000 : 4000;
          const stdoutRead = readTextFile(stdoutPath, textLimit, encoding);
          const stderrRead = readTextFile(stderrPath, textLimit, encoding);
          const stdoutTail = tail(stdoutRead.text, textLimit);
          const stderrTail = tail(stderrRead.text, textLimit);
          // A failed read (huge file / permissions) must not count as "output was empty": that states a fault as a conclusion.
          const readError = stdoutRead.error ?? stderrRead.error;
          // No evidence file at all ⇒ redirection failed: this is not "the command finished",
          // it is the verifier failing to run. Report error — reporting pass would let later
          // assertions judge against empty stdout and produce entirely false conclusions.
          const evidenceMissing = !isRegularFile(stdoutPath) && !isRegularFile(stderrPath);
          // Note: the event log is **not consulted** here. Commands under verify_run run
          // attached to a debugger, and debugger-held processes bypass WER, so no new event
          // log record appears (confirmed empirically). The event log belongs to the
          // verify_attribution path, where the target does not run under our debugger.

          let result;
          let summary;
          if (evidenceMissing) {
            result = 'error';
            summary = 'verifier did not run: no stdout/stderr evidence file was created (redirection failed)';
          } else if (readError) {
            result = 'error';
            summary = `verifier did not run: reading stdout/stderr failed (${readError})`;
          } else if (crashed) {
            result = 'fail';
            const where = crashFrame ? ` · crash at ${crashFrame.module}+${crashFrame.module_offset}` : '';
            const source = crashFrame?.source_file ? ` · source ${crashFrame.source_file}:${crashFrame.source_line}` : '';
            summary = `command crashed: ${run.exception.code_hex} ${run.exception.name ?? ''}${where}${source}`.replace(/\s+/g, ' ');
          } else if (expectExit !== undefined && exitCode === expectExit) {
            // Negative test passed: the expected non-zero code is correct behaviour and must not fall into the "non-zero exit" branch below.
            result = 'pass';
            summary = `command exited ${exitCode}, matching expect_exit, in ${formatMs(Date.now() - startedAt)}`;
          } else if (expectExit !== undefined && exitCode !== expectExit) {
            result = 'fail';
            summary = `command exited ${exitCode}, expected ${expectExit}`;
          } else if (exitCode !== 0) {
            result = 'fail';
            summary = `command exited non-zero: ${exitCode}`;
            if (exitCode === 2) summary += shellHint(cmd, useShell);
            // The classic negative-test trap: the program returns non-zero as intended yet is recorded as fail.
            if (expectExit === undefined) {
              summary += ' · if this failure is expected (negative test), pass expect_exit=N to record it as pass';
            }
          } else {
            result = 'pass';
            summary = `command exited normally (0) in ${formatMs(Date.now() - startedAt)}`;
          }

          const evidence = [stdoutPath, stderrPath].filter((path) => existsSync(path));
          if (existsSync(dumpPath) && run.captured) evidence.push(dumpPath);
          if (scriptPath && existsSync(scriptPath)) evidence.push(scriptPath);

          const value = {
            source: 'orchestrator',
            verify_id: id,
            result,
            summary,
            detail: {
              kind: 'run',
              scope,
              cmd,
              cwd,
              shell: useShell,
              shell_script: scriptPath,
              encoding: stdoutRead.encoding,
              encoding_stderr: stderrRead.encoding === stdoutRead.encoding ? undefined : stderrRead.encoding,
              stdout_truncated: stdoutRead.truncated,
              exit_code: exitCode,
              exit_code_hex: run.exit?.code_hex ?? run.exception?.code_hex,
              crashed,
              exception: run.exception,
              frames: frames.slice(0, scope === 'full' ? frames.length : 24),
              modules_total: Array.isArray(run.modules) ? run.modules.length : undefined,
              modules_sample:
                scope === 'full' && Array.isArray(run.modules)
                  ? run.modules.slice(0, 12).map((item) => `${item.name}@${item.base}`)
                  : undefined,
              crash_frame: crashFrame ? `${crashFrame.module}+${crashFrame.module_offset}` : undefined,
              source_hint: crashFrame?.source_file ? `${crashFrame.source_file}:${crashFrame.source_line}` : undefined,
              stack_quality: run.stack_quality,
              stdout_path: stdoutPath,
              stderr_path: stderrPath,
              stdout_tail: stdoutTail,
              stderr_tail: stderrTail,
              dump_path: run.captured ? dumpPath : undefined,
              timeout_ms: timeoutMs,
            },
            evidence,
            elapsed_ms: Date.now() - startedAt,
          };
          record(workspace, value);
          appendJsonl(workspace, 'timeline.jsonl', {
            ts: Date.now(),
            source: 'orchestrator',
            event: crashed ? 'crashed' : 'exited',
            pid: run.pid,
            detail: { verify_id: id, exit_code: exitCode, cmd },
          });
          return toJsonSafe(value);
        } catch (error) {
          const message = String(error?.message ?? error);
          // Win32 2 = ERROR_FILE_NOT_FOUND. Split on the first token; do not report a bad
          // path as "you need a shell":
          //   shell builtin (echo/dir/...) → suggest cmd /d /s /c or shell=true
          //   anything else (.bat / .exe / mistyped relative path) → report the missing
          //   executable plus the current working directory
          const firstToken = String(cmd ?? '').trim().split(/\s+/)[0] ?? '';
          const notFound = /Win32 2\b|\u627e\u4e0d\u5230|\u4e0d\u662f\u6709\u6548\u7684 Win32 \u5e94\u7528/i.test(message);
          let hint = '';
          if (notFound) {
            hint =
              shellHint(cmd, useShell) ||
              ` · executable not found: ${firstToken} (current working directory: ${cwd}). Check the path or use an absolute one.`;
          }
          const value = {
            source: 'orchestrator',
            verify_id: id,
            result: 'error',
            summary: `verifier did not run: ${message} (this is not a verdict about the command under test)${hint}`,
            detail: { kind: 'run', cmd, cwd, shell: useShell, error: { name: error?.name, message } },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          };
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_assert_exit ────────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_assert_exit',
      description: 'Assert the exit code of the most recent verify_run. expect takes a number, or "0" / "nonzero".',
      parameters: {
        expect: {
          type: 'string',
          required: true,
          description: 'Expected exit code: a number, or "0" (must succeed), "nonzero" (must fail).',
        },
        run_id: {
          type: 'string',
          description: 'verify_id of a specific run (V-001); defaults to the most recent verify_run.',
        },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport([`[${value.result.toUpperCase()}] ${value.summary}`]),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const run = locateRun(workspace, args?.run_id);
          if (!run) throw new Error('no verify_run record available: run verify_run first');
          const exitCode = Number(run.detail?.exit_code);
          const expect = String(args?.expect ?? '').trim().toLowerCase();
          let passed;
          let expectText;
          if (expect === '0' || expect === 'zero') {
            passed = exitCode === 0;
            expectText = '0';
          } else if (expect === 'nonzero' || expect === 'fail') {
            passed = exitCode !== 0;
            expectText = 'non-zero';
          } else {
            const wanted = Number(expect);
            if (!Number.isFinite(wanted)) throw new Error(`expect is neither a number nor 0/nonzero: ${args?.expect}`);
            passed = exitCode === wanted;
            expectText = String(wanted);
          }
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'exit',
            passed,
            summary: passed
              ? `exit code matches expectation (${expectText})`
              : `exit code ${exitCode}, expected ${expectText} (from ${run.verify_id})`,
            detail: { run_id: run.verify_id, expect: expectText, actual: exitCode },
            evidence: run.evidence ?? [],
          });
          record(workspace, value);
          return toJsonSafe(value);
        } catch (error) {
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'exit',
            summary: `assertion did not run: ${error?.message ?? error}`,
            detail: { error: { message: error?.message } },
          });
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_assert_stdout ──────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_assert_stdout',
      description:
        'Assert that the most recent verify_run output does (or does not) contain some text. pattern is a substring; write /regex/ to match as a regex.',
      parameters: {
        pattern: { type: 'string', required: true, description: 'Text to look for: a substring, or /regex/.' },
        stream: { type: 'string', description: 'Which stream to inspect: stdout (default) / stderr / both.' },
        negate: { type: 'boolean', description: 'true asserts the text must not appear.' },
        run_id: { type: 'string', description: 'verify_id of a specific run; defaults to the most recent one.' },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport([`[${value.result.toUpperCase()}] ${value.summary}`]),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const run = locateRun(workspace, args?.run_id);
          if (!run) throw new Error('no verify_run record available: run verify_run first');
          const stream = String(args?.stream ?? 'stdout').toLowerCase();
          const stdout = String(run.detail?.stdout_tail ?? '');
          const stderr = String(run.detail?.stderr_tail ?? '');
          const haystack = stream === 'both' ? `${stdout}\n${stderr}` : stream === 'stderr' ? stderr : stdout;
          const { matched, kind } = matchPattern(haystack, args?.pattern);
          const passed = args?.negate ? !matched : matched;
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'stdout',
            passed,
            summary: passed
              ? `output ${args?.negate ? 'does not contain' : 'contains'} "${args?.pattern}" (${stream}, ${kind})`
              : `output ${args?.negate ? 'contains' : 'does not contain'} "${args?.pattern}" (${stream}, ${kind})`,
            detail: {
              run_id: run.verify_id,
              stream,
              pattern: args?.pattern,
              match_kind: kind,
              negate: Boolean(args?.negate),
              stdout_bytes: stdout.length,
              stderr_bytes: stderr.length,
            },
            evidence: run.evidence ?? [],
          });
          record(workspace, value);
          return toJsonSafe(value);
        } catch (error) {
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'stdout',
            summary: `assertion did not run: ${error?.message ?? error}`,
            detail: { error: { message: error?.message } },
          });
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_assert_file ────────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_assert_file',
      description: 'Assert that a file exists / does not exist, that its content contains some text, or that its sha256 equals a given value. Paths are relative to the workspace.',
      parameters: {
        path: { type: 'string', required: true, description: 'File path (relative to the workspace or absolute).' },
        exists: { type: 'boolean', description: 'Whether it should exist; defaults to true.' },
        contains: { type: 'string', description: 'Text the file content is expected to contain.' },
        sha256: { type: 'string', description: 'Expected sha256 (hex).' },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport([`[${value.result.toUpperCase()}] ${value.summary}`]),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const raw = String(args?.path ?? '').trim();
          if (raw === '') throw new Error('path is required');
          const target = isAbsolute(raw) ? raw : resolve(workspace, raw);
          const shouldExist = args?.exists !== false;
          const present = existsSync(target);
          const checks = [];
          let passed = present === shouldExist;
          checks.push(`${shouldExist ? 'should exist' : 'should not exist'}: actually ${present ? 'exists' : 'missing'}`);

          if (passed && present && typeof args?.contains === 'string') {
            const read = readTextFile(target, 4 * 1024 * 1024);
            if (read.error) throw new Error(`read failed: ${read.error}`);
            const hit = read.text.includes(args.contains);
            passed = passed && hit;
            checks.push(`contains "${args.contains}": ${hit ? 'yes' : 'no'}`);
          }
          if (passed && present && typeof args?.sha256 === 'string' && args.sha256.trim() !== '') {
            const digest = createHash('sha256').update(readFileSync(target)).digest('hex');
            const hit = digest.toLowerCase() === args.sha256.trim().toLowerCase();
            passed = passed && hit;
            checks.push(`sha256: ${hit ? 'matches' : `mismatch (actual ${digest})`}`);
          }

          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'file',
            passed,
            summary: `${raw} ${passed ? 'meets expectations' : 'does not meet expectations'} (${checks.join('; ')})`,
            detail: { path: target, exists: present, checks },
            evidence: present ? [target] : [],
          });
          record(workspace, value);
          return toJsonSafe(value);
        } catch (error) {
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'file',
            summary: `assertion did not run: ${error?.message ?? error}`,
            detail: { error: { message: error?.message } },
          });
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_assert_json ────────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_assert_json',
      description: 'Assert that the value at a dot path in a JSON file equals the given value (pointer such as "build.status" or "items[0].id").',
      parameters: {
        path: { type: 'string', required: true, description: 'JSON file path (relative to the workspace or absolute).' },
        pointer: { type: 'string', description: 'Dot path; empty means the whole document.' },
        equals: { type: 'string', description: 'Expected value (parsed as JSON; compared as a string when it is not valid JSON).' },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport([`[${value.result.toUpperCase()}] ${value.summary}`]),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const raw = String(args?.path ?? '').trim();
          if (raw === '') throw new Error('path is required');
          const target = isAbsolute(raw) ? raw : resolve(workspace, raw);
          if (!existsSync(target)) throw new Error(`file not found: ${target}`);
          let document;
          try {
            document = JSON.parse(readFileSync(target, 'utf8'));
          } catch (error) {
            throw new Error(`not valid JSON: ${error.message}`);
          }
          const located = resolvePointer(document, args?.pointer);
          if (!located.found) throw new Error(`path ${args?.pointer} does not exist in the document`);

          let expected;
          const text = String(args?.equals ?? '');
          try {
            expected = JSON.parse(text);
          } catch {
            expected = text;
          }
          const actual = located.value;
          const passed = JSON.stringify(actual) === JSON.stringify(expected);
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'json',
            passed,
            summary: passed
              ? `${raw}${args?.pointer ? ` at ${args.pointer}` : ''} equals ${JSON.stringify(expected)}`
              : `${raw}${args?.pointer ? ` at ${args.pointer}` : ''} is ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`,
            detail: { path: target, pointer: args?.pointer ?? '', actual, expected },
            evidence: [target],
          });
          record(workspace, value);
          return toJsonSafe(value);
        } catch (error) {
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'json',
            summary: `assertion did not run: ${error?.message ?? error}`,
            detail: { error: { message: error?.message } },
          });
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_assert_screenshot ──────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_assert_screenshot',
      description:
        'Screenshot pixel comparison: passes when the differing-pixel ratio between the actual and expected PNGs does not exceed threshold. ' +
        'Purely local computation (PNG decoded in-house), no vision dependency.',
      parameters: {
        actual: { type: 'string', required: true, description: 'Actual screenshot path (relative to the workspace or absolute).' },
        expected: { type: 'string', required: true, description: 'Baseline screenshot path.' },
        threshold: { type: 'number', description: 'Allowed differing-pixel ratio (0.001 = one in a thousand); defaults to 0.' },
        tolerance: { type: 'integer', description: 'Allowed per-channel delta (0-255); defaults to 0 (strict equality).' },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport([`[${value.result.toUpperCase()}] ${value.summary}`]),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const actualRaw = String(args?.actual ?? '').trim();
          const expectedRaw = String(args?.expected ?? '').trim();
          if (actualRaw === '' || expectedRaw === '') throw new Error('actual and expected are required');
          const actual = isAbsolute(actualRaw) ? actualRaw : resolve(workspace, actualRaw);
          const expected = isAbsolute(expectedRaw) ? expectedRaw : resolve(workspace, expectedRaw);
          for (const path of [actual, expected]) {
            if (!existsSync(path)) throw new Error(`file not found: ${path}`);
          }
          const threshold = Number.isFinite(args?.threshold) ? Number(args.threshold) : 0;
          const tolerance = Number.isFinite(args?.tolerance) ? Number(args.tolerance) : 0;
          const diff = diffPng(actual, expected, tolerance);
          const passed = !diff.size_mismatch && diff.ratio <= threshold;
          const percent = (diff.ratio * 100).toFixed(3);
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'screenshot',
            passed,
            summary: diff.size_mismatch
              ? `size mismatch: ${diff.actual.width}×${diff.actual.height} vs ${diff.expected.width}×${diff.expected.height}`
              : passed
                ? `pixels match (difference ${percent}% <= threshold ${(threshold * 100).toFixed(3)}%)`
                : `pixels differ: ${diff.differing}/${diff.total} pixels differ (${percent}% > threshold ${(threshold * 100).toFixed(3)}%)`,
            detail: { actual, expected, threshold, tolerance, ...diff },
            evidence: [actual, expected],
          });
          record(workspace, value);
          return toJsonSafe(value);
        } catch (error) {
          const value = makeAssertFragment({
            id,
            startedAt,
            kind: 'screenshot',
            summary: `assertion did not run: ${error?.message ?? error}`,
            detail: { error: { message: error?.message } },
          });
          record(workspace, value);
          return toJsonSafe(value);
        }
      },
    }),
  );

  // ── verify_report ─────────────────────────────────────────────────────
  ctx.tools.register(
    defineTool({
      name: 'verify_report',
      description:
        'Aggregate the fragments in the workspace .verify/fragments.jsonl into one human-readable report: how many passed, how many failed, what each conclusion is. ' +
        'Call it to close out before reporting to the user.',
      parameters: {
        limit: { type: 'integer', description: 'Maximum number of detail entries to list (most recent); defaults to the plugin config maxReportEntries.' },
        since_ms: { type: 'integer', description: 'Only consider fragments from the last this-many milliseconds; omitted means all.' },
      },
      output: {
        schema: outputSchema,
        render: (_args, value) => textReport(formatReport(value).split('\n')),
      },
      execute: async (args, exec) => {
        const startedAt = Date.now();
        const workspace = resolveWorkspace(exec);
        const id = nextId('V-', workspace);
        try {
          const fragments = readJsonl(workspace, 'fragments.jsonl');
          const limit = Number.isFinite(args?.limit) ? Number(args.limit) : Number(cfg.maxReportEntries ?? 40);
          // Fragments carry no timestamp (the contract keeps ts in the timeline), so time filtering first queries the timeline for verify_ids.
          let filtered = fragments;
          if (Number.isFinite(args?.since_ms)) {
            const since = Date.now() - Number(args.since_ms);
            const timeline = readJsonl(workspace, 'timeline.jsonl');
            const recentIds = new Set(
              timeline.filter((entry) => Number(entry?.ts ?? 0) >= since).map((entry) => entry?.detail?.verify_id),
            );
            filtered = fragments.filter((fragment) => recentIds.has(fragment?.verify_id));
          }
          const summary = aggregate(filtered, { limit });
          const elapsedTotal = filtered.reduce((sum, fragment) => sum + Number(fragment?.elapsed_ms ?? 0), 0);
          // The top-level result only answers "did any of these fragments fail": pass / fail.
          // error is reserved for catch (the report itself did not run) — error fragments are
          // already counted in the summary, and a top-level [ERROR] would make the agent
          // assume the report tool is broken and retry.
          const reportResult = summary.by_result.fail > 0 ? 'fail' : 'pass';
          const value = {
            source: 'orchestrator',
            verify_id: id,
            result: reportResult,
            summary:
              summary.total === 0
                ? 'the workspace has no verification fragments yet'
                : `${summary.total} fragments: pass ${summary.by_result.pass} · fail ${summary.by_result.fail} · error ${summary.by_result.error}`,
            detail: { kind: 'report', ...summary, result: reportResult, elapsed_total_ms: elapsedTotal },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          };
          return toJsonSafe(value);
        } catch (error) {
          return toJsonSafe({
            source: 'orchestrator',
            verify_id: id,
            result: 'error',
            summary: `report did not run: ${error?.message ?? error}`,
            detail: { kind: 'report', error: { message: error?.message } },
            evidence: [],
            elapsed_ms: Date.now() - startedAt,
          });
        }
      },
    }),
  );
}
