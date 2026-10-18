/**
 * Windows Job Object resource-capped executor.
 *
 * Why not ctx.subprocess: its SubprocessSpawnSpec only has argv / cwd / stdio /
 * graceMs / signal / env — no resource cap fields, and no way to reach the Job handle. CPU rate and
 * memory caps can only be set on the Job itself, so this goes straight through the Koffi binding table
 * in @deepseek-ai/dsh-win32-process (it already binds CreateJobObjectW / SetInformationJobObject /
 * QueryInformationJobObject / TerminateJobObject / AssignProcessToJobObject; all that is missing is
 * the structs, hand-packed into Buffers using the x64 layout).
 *
 * Three hard constraints:
 * - Child stdio goes to **temporary files**, not pipes — a full pipe wedges the child, and a
 *   verification tool must not have that kind of deadlock surface.
 * - On wall-clock expiry, TerminateJobObject kills the **entire Job**, not just the main process,
 *   so no orphaned children are left behind.
 * - Failure to set a cap (old OS / restricted container) does not throw; it degrades to a warning
 *   and keeps running (fail-open).
 */
import { closeSync, openSync, readSync, statSync } from 'node:fs';
import { join } from 'node:path';

import {
  closeHandleChecked,
  loadWin32ProcessBindings,
  pollProcessExit,
  spawnCurrentTokenJobProcess,
  terminateJob,
} from '@deepseek-ai/dsh-win32-process';

// Information classes for SetInformationJobObject / QueryInformationJobObject.
const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1;
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9;
const JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION = 15;

// JOBOBJECT_BASIC_LIMIT_INFORMATION.LimitFlags
const LIMIT_PROCESS_MEMORY = 0x0100;
const LIMIT_JOB_MEMORY = 0x0200;
const LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

// JOBOBJECT_CPU_RATE_CONTROL_INFORMATION.ControlFlags
const CPU_RATE_ENABLE = 0x1;
const CPU_RATE_HARD_CAP = 0x4;

// x64 struct sizes and key offsets (checked field by field against the C definitions for
// CreateProcess/JobObject).
const EXTENDED_LIMIT_BYTES = 144;
const EXTENDED_LIMIT_FLAGS_OFFSET = 16; // BasicLimitInformation.LimitFlags
const EXTENDED_LIMIT_PROCESS_MEMORY_OFFSET = 112;
const EXTENDED_LIMIT_JOB_MEMORY_OFFSET = 120;
const EXTENDED_LIMIT_PEAK_PROCESS_MEMORY_OFFSET = 128;
const ACCOUNTING_BYTES = 48;
const ACCOUNTING_TOTAL_USER_TIME_OFFSET = 0; // 100ns
const ACCOUNTING_TOTAL_KERNEL_TIME_OFFSET = 8; // 100ns
const ACCOUNTING_ACTIVE_PROCESSES_OFFSET = 40;
const CPU_RATE_BYTES = 8;

const POLL_MS = 200;
const KILL_GRACE_MS = 5000;
const TAIL_BYTES = 8192;

/** Read the tail of a file (at most maxBytes); returns an empty string on failure. */
function readTail(path, maxBytes = TAIL_BYTES) {
  try {
    const size = statSync(path).size;
    if (size <= 0) return '';
    const start = Math.max(0, size - maxBytes);
    const length = size - start;
    const buffer = Buffer.alloc(length);
    const fd = openSync(path, 'r');
    try {
      readSync(fd, buffer, 0, length, start);
    } finally {
      closeSync(fd);
    }
    return buffer.toString('utf8');
  } catch {
    return '';
  }
}

/** File size in bytes; returns 0 on failure. */
function fileSize(path) {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

/** Query the Job's accumulated CPU time (100ns units) and live process count. */
function readAccounting(api, job) {
  const info = Buffer.alloc(ACCOUNTING_BYTES);
  if (api.queryInformationJobObject(job, JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION, info, info.length, null) === 0) {
    return undefined;
  }
  return {
    cpu100ns: info.readBigInt64LE(ACCOUNTING_TOTAL_USER_TIME_OFFSET) + info.readBigInt64LE(ACCOUNTING_TOTAL_KERNEL_TIME_OFFSET),
    activeProcesses: info.readUInt32LE(ACCOUNTING_ACTIVE_PROCESSES_OFFSET),
  };
}

/** Query the Job's peak process memory (bytes). */
function readPeakMemory(api, job) {
  const info = Buffer.alloc(EXTENDED_LIMIT_BYTES);
  if (api.queryInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, info, info.length, null) === 0) {
    return undefined;
  }
  return Number(info.readBigUInt64LE(EXTENDED_LIMIT_PEAK_PROCESS_MEMORY_OFFSET));
}

/** Read back the CPU rate control actually in effect on the Job (diagnostic: tells "never set" apart from "set but not effective"). */
function readCpuRate(api, job) {
  const info = Buffer.alloc(CPU_RATE_BYTES);
  if (api.queryInformationJobObject(job, JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION, info, info.length, null) === 0) {
    return undefined;
  }
  return { control_flags: info.readUInt32LE(0), cpu_rate: info.readUInt32LE(4) };
}

/** Read back the memory caps actually in effect on the Job. */
function readMemoryLimits(api, job) {
  const info = Buffer.alloc(EXTENDED_LIMIT_BYTES);
  if (api.queryInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, info, info.length, null) === 0) {
    return undefined;
  }
  return {
    limit_flags: info.readUInt32LE(EXTENDED_LIMIT_FLAGS_OFFSET),
    process_memory_limit: Number(info.readBigUInt64LE(EXTENDED_LIMIT_PROCESS_MEMORY_OFFSET)),
    job_memory_limit: Number(info.readBigUInt64LE(EXTENDED_LIMIT_JOB_MEMORY_OFFSET)),
  };
}

/**
 * Install the CPU rate hard cap and the memory caps on the Job. Each item stands alone; a failure
 * only drops that item.
 * @returns What took effect plus the warning texts.
 */
function applyLimits(api, job, { cpuPercent, memoryMb }) {
  const applied = { cpu_percent: null, memory_mb: null, effective: {} };
  const warnings = [];

  if (Number.isFinite(memoryMb) && memoryMb > 0) {
    const bytes = BigInt(Math.round(memoryMb * 1024 * 1024));
    const info = Buffer.alloc(EXTENDED_LIMIT_BYTES);
    info.writeUInt32LE(LIMIT_KILL_ON_JOB_CLOSE | LIMIT_JOB_MEMORY | LIMIT_PROCESS_MEMORY, EXTENDED_LIMIT_FLAGS_OFFSET);
    info.writeBigUInt64LE(bytes, EXTENDED_LIMIT_PROCESS_MEMORY_OFFSET);
    info.writeBigUInt64LE(bytes, EXTENDED_LIMIT_JOB_MEMORY_OFFSET);
    if (api.setInformationJobObject(job, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, info, info.length) === 0) {
      warnings.push(`memory cap ${memoryMb} MB was not applied (SetInformationJobObject Win32 ${api.getLastError()}); observing only this run, no enforcement`);
    } else {
      applied.memory_mb = memoryMb;
    }
  }

  if (Number.isFinite(cpuPercent) && cpuPercent > 0) {
    const rate = Math.max(1, Math.min(10000, Math.round(cpuPercent * 100)));
    const info = Buffer.alloc(CPU_RATE_BYTES);
    info.writeUInt32LE(CPU_RATE_ENABLE | CPU_RATE_HARD_CAP, 0);
    info.writeUInt32LE(rate, 4);
    if (api.setInformationJobObject(job, JOB_OBJECT_CPU_RATE_CONTROL_INFORMATION, info, info.length) === 0) {
      warnings.push(`CPU cap ${cpuPercent}% was not applied (SetInformationJobObject Win32 ${api.getLastError()}); observing only this run, no enforcement`);
    } else {
      applied.cpu_percent = cpuPercent;
    }
  }

  applied.effective = {
    cpu_rate: readCpuRate(api, job),
    memory: readMemoryLimits(api, job),
  };

  return { applied, warnings };
}

/** Turn a uint32 exit code into plain language. */
function describeExit(exitCode, reason) {
  if (reason === 'timeout') return 'terminated by verify_limit on the wall-clock cap';
  if (reason === 'cancel') return 'terminated after the caller cancelled';
  if (exitCode === 0) return 'exited normally';
  if (exitCode >= 0x80000000) return `abnormal exit 0x${(exitCode >>> 0).toString(16).toUpperCase()} (usually a crash or a kill)`;
  return `non-zero exit ${exitCode}`;
}

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/**
 * Run one command within Job Object resource caps.
 *
 * @param options.command - Command-line string to execute (goes through cmd.exe /d /s /c).
 * @param options.cpuPercent - CPU cap percentage (relative to a single core); 0 or absent means unset.
 * @param options.memoryMb - Memory cap in MB; 0 or absent means unset.
 * @param options.outputDir - Directory where stdout/stderr are persisted.
 * @param options.id - Fragment id, used for the output file names.
 * @returns Execution facts (pass/fail is not decided here).
 */
export async function runLimited(options) {
  if (process.platform !== 'win32') {
    throw new Error(`resource caps rely on Windows Job Objects; current platform is ${process.platform}`);
  }

  const {
    command,
    cwd,
    env = process.env,
    cpuPercent = 0,
    memoryMb = 0,
    timeoutSec = 60,
    outputDir,
    id,
    signal,
  } = options;

  const shell = env.ComSpec || process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe';
  const stdoutPath = join(outputDir, `${id}.stdout.log`);
  const stderrPath = join(outputDir, `${id}.stderr.log`);

  // The command line is **not spliced into the CreateProcess command line**: cmd.exe does not honor
  // CommandLineToArgvW's \" escaping, so quoted commands (powershell -Command "...") get mangled.
  // Instead it goes through environment-variable expansion:
  // cmd /d /s /c %DSH_VERIFY_CMD% — the token passed in carries no quotes; cmd parses the original text itself.
  const childEnv = { ...env, DSH_VERIFY_CMD: command };

  const stdinFd = openSync('\\\\.\\NUL', 'r');
  const stdoutFd = openSync(stdoutPath, 'w');
  const stderrFd = openSync(stderrPath, 'w');

  const api = loadWin32ProcessBindings();
  const warnings = [];
  let spawned;
  try {
    spawned = spawnCurrentTokenJobProcess(api, {
      command: shell,
      args: ['/d', '/s', '/c', '%DSH_VERIFY_CMD%'],
      applicationName: shell,
      cwd,
      env: childEnv,
      stdio: { stdin: stdinFd, stdout: stdoutFd, stderr: stderrFd },
    });
  } finally {
    for (const fd of [stdinFd, stdoutFd, stderrFd]) {
      try {
        closeSync(fd);
      } catch {
        /* Failing to close this end in the parent does not affect the child */
      }
    }
  }

  const { pid, process: processHandle, job } = spawned;
  const limits = applyLimits(api, job, { cpuPercent, memoryMb });
  warnings.push(...limits.warnings);

  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    // Close the Job: kill-on-close sweeps up leftover child processes too, so no orphans remain.
    try {
      closeHandleChecked(api, job, 'job');
    } catch (error) {
      warnings.push(`failed to close the Job: ${error.message}`);
    }
    try {
      closeHandleChecked(api, processHandle, 'process');
    } catch {
      /* Failing to close the process handle does not affect the conclusion */
    }
  };

  const startedAt = Date.now();
  let lastCpu100ns = 0n;
  let lastSampleAt = startedAt;
  let peakCpuPercent = 0;
  let peakMemoryBytes = 0;
  let exitCode;
  let reason = 'exited';
  let timedOut = false;

  const sample = () => {
    const accounting = readAccounting(api, job);
    if (accounting !== undefined) {
      const now = Date.now();
      const wallMs = now - lastSampleAt;
      if (wallMs > 0) {
        const deltaMs = Number(accounting.cpu100ns - lastCpu100ns) / 10_000;
        const percent = (deltaMs / wallMs) * 100;
        if (Number.isFinite(percent) && percent > peakCpuPercent) peakCpuPercent = percent;
      }
      lastCpu100ns = accounting.cpu100ns;
      lastSampleAt = now;
    }
    const peak = readPeakMemory(api, job);
    if (peak !== undefined && peak > peakMemoryBytes) peakMemoryBytes = peak;
  };

  try {
    for (;;) {
      const polled = pollProcessExit(api, processHandle);
      if (polled !== undefined) {
        exitCode = polled;
        break;
      }

      const elapsed = Date.now() - startedAt;
      if (timeoutSec > 0 && elapsed >= timeoutSec * 1000) {
        timedOut = true;
        reason = 'timeout';
        warnings.push(`wall clock reached ${timeoutSec}s; terminated the entire Job`);
        terminateJob(api, job, 1);
        const deadline = Date.now() + KILL_GRACE_MS;
        while (Date.now() < deadline) {
          const after = pollProcessExit(api, processHandle);
          if (after !== undefined) {
            exitCode = after;
            break;
          }
          await sleep(POLL_MS);
        }
        if (exitCode === undefined) exitCode = 1;
        break;
      }

      if (signal?.aborted) {
        reason = 'cancel';
        terminateJob(api, job, 1);
        const deadline = Date.now() + KILL_GRACE_MS;
        while (Date.now() < deadline) {
          const after = pollProcessExit(api, processHandle);
          if (after !== undefined) {
            exitCode = after;
            break;
          }
          await sleep(POLL_MS);
        }
        if (exitCode === undefined) exitCode = 1;
        break;
      }

      await sleep(Math.min(POLL_MS, Math.max(1, timeoutSec * 1000 - elapsed)));
      sample();
    }

    sample();
    const finalAccounting = readAccounting(api, job);
    const cpuTimeMs = finalAccounting === undefined ? 0 : Number(finalAccounting.cpu100ns) / 10_000;
    const leftovers = finalAccounting?.activeProcesses ?? 0;
    const finalPeak = readPeakMemory(api, job);
    if (finalPeak !== undefined && finalPeak > peakMemoryBytes) peakMemoryBytes = finalPeak;

    const wallMs = Date.now() - startedAt;

    release();

    if (leftovers > 0) warnings.push(`the Job still held ${leftovers} processes when the command exited; cleaned up as well`);

    return {
      pid,
      exit_code: exitCode,
      exit_code_hex: `0x${(exitCode >>> 0).toString(16).toUpperCase().padStart(8, '0')}`,
      reason,
      timed_out: timedOut,
      wall_ms: wallMs,
      cpu_time_ms: cpuTimeMs,
      peak_cpu_percent: Number(peakCpuPercent.toFixed(1)),
      peak_memory_bytes: peakMemoryBytes,
      limits: limits.applied,
      warnings,
      stdout: { path: stdoutPath, bytes: fileSize(stdoutPath), tail: readTail(stdoutPath) },
      stderr: { path: stderrPath, bytes: fileSize(stderrPath), tail: readTail(stderrPath) },
      describe_exit: describeExit(exitCode, reason),
    };
  } finally {
    // The error path must release the Job too, otherwise child processes outlive the host's exit.
    release();
  }
}
