#include "dump.h"

#include <dbghelp.h>

#include <cstdio>
#include <vector>

#include "walk.h"
#include "winproc.h"

namespace crash {
namespace {

// The debugger gets an initial breakpoint with the first CreateProcess event; it does not mean
// the target actually crashed.
bool IsInitialBreakpoint(const EXCEPTION_DEBUG_INFO& info) {
  return info.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT && info.dwFirstChance != FALSE;
}

bool WriteDump(HANDLE process, DWORD pid, const std::wstring& path, EXCEPTION_POINTERS* pointers, DWORD thread_id,
               std::string* error) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    *error = "CreateFileW failed (Win32 " + std::to_string(GetLastError()) + ")";
    return false;
  }
  MINIDUMP_EXCEPTION_INFORMATION exception{};
  exception.ThreadId = thread_id;
  exception.ExceptionPointers = pointers;
  exception.ClientPointers = FALSE;
  const MINIDUMP_TYPE type = static_cast<MINIDUMP_TYPE>(MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory |
                                                       MiniDumpWithProcessThreadData | MiniDumpNormal);
  const BOOL ok = MiniDumpWriteDump(process, pid, file, type, pointers == nullptr ? nullptr : &exception, nullptr, nullptr);
  const DWORD last = ok == FALSE ? GetLastError() : 0;
  CloseHandle(file);
  if (ok == FALSE) {
    *error = "MiniDumpWriteDump failed (Win32 " + std::to_string(last) + ")";
    return false;
  }
  return true;
}

void FillModules(DWORD pid, Report* report) {
  report->modules.clear();
  for (const wp::ModuleInfo& info : wp::EnumModules(pid)) {
    ModuleRec module;
    module.base = info.base;
    module.size = info.size;
    module.name = info.name;
    module.path = info.path;
    report->modules.push_back(std::move(module));
  }
}

void FillException(const EXCEPTION_DEBUG_INFO& info, DWORD thread_id, Report* report) {
  const EXCEPTION_RECORD& record = info.ExceptionRecord;
  report->has_exception = true;
  report->exception_code = record.ExceptionCode;
  report->exception_address = reinterpret_cast<uint64_t>(record.ExceptionAddress);
  report->exception_flags = record.ExceptionFlags;
  report->exception_param_count = record.NumberParameters > 15 ? 15 : record.NumberParameters;
  for (DWORD index = 0; index < report->exception_param_count; ++index) {
    report->exception_params[index] = record.ExceptionInformation[index];
  }
  report->thread_id = thread_id;
}

// Debug loop shared by attach and run.
void DebugLoop(HANDLE process, DWORD pid, bool attached, const std::wstring& dump_path,
               const std::wstring& symbol_path, DWORD timeout_ms, Report* report) {
  const DWORD started = GetTickCount();
  bool captured = false;
  bool finished = false;
  DEBUG_EVENT event{};

  while (!finished) {
    const DWORD elapsed = GetTickCount() - started;
    if (elapsed >= timeout_ms) {
      report->error = "timed out waiting for a crash (no exception within " + std::to_string(timeout_ms) + "ms)";
      if (!attached) TerminateProcess(process, 1);
      break;
    }
    const DWORD remaining = timeout_ms - elapsed;
    if (WaitForDebugEvent(&event, remaining) == FALSE) {
      report->error = "timed out waiting for a crash (no exception within " + std::to_string(timeout_ms) + "ms)";
      if (!attached) TerminateProcess(process, 1);
      break;
    }

    DWORD continue_status = DBG_CONTINUE;
    switch (event.dwDebugEventCode) {
      case CREATE_PROCESS_DEBUG_EVENT:
        if (event.u.CreateProcessInfo.hFile != nullptr) CloseHandle(event.u.CreateProcessInfo.hFile);
        break;
      case EXCEPTION_DEBUG_EVENT: {
        if (IsInitialBreakpoint(event.u.Exception)) break;
        if (!captured) {
          captured = true;
          FillException(event.u.Exception, event.dwThreadId, report);
          FillModules(pid, report);

          // Context of the crashing thread: needed both to write the dump and to walk the stack.
          CONTEXT context{};
          HANDLE thread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
          bool have_context = false;
          if (thread != nullptr) {
            SuspendThread(thread);
            context.ContextFlags = CONTEXT_FULL;
            have_context = GetThreadContext(thread, &context) != FALSE;
          }

          if (!dump_path.empty()) {
            EXCEPTION_POINTERS pointers{const_cast<EXCEPTION_RECORD*>(&event.u.Exception.ExceptionRecord),
                                        have_context ? &context : nullptr};
            report->captured =
                WriteDump(process, pid, dump_path, have_context ? &pointers : nullptr, event.dwThreadId,
                          &report->dump_error);
            if (report->captured) report->dump_path = dump_path;
          }

          if (have_context) {
            if (SymStart(process, symbol_path)) {
              WalkLiveStack(process, thread, &context, wp::IsWow64(pid), &report->frames, 48);
              SymStop(process);
              // Frames dbghelp could not resolve (in-house modules without a PDB): at least fill in
              // module + offset.
              for (Frame& frame : report->frames) {
                if (frame.module.empty()) ModuleOfAddress(report->modules, frame.addr, &frame);
              }
              report->stack_quality = report->frames.empty() ? "none" : "unwind";
            } else {
              report->stack_quality = "none";
            }
          } else {
            report->stack_quality = "none";
          }

          if (thread != nullptr) {
            ResumeThread(thread);
            CloseHandle(thread);
          }
        }
        // Do not swallow the exception: let the target terminate the way it normally would, i.e.
        // behave exactly as if no debugger were attached.
        continue_status = DBG_EXCEPTION_NOT_HANDLED;
        break;
      }
      case EXIT_PROCESS_DEBUG_EVENT:
        report->has_exit = true;
        report->exit_code = event.u.ExitProcess.dwExitCode;
        finished = true;
        break;
      default:
        break;
    }
    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status);
  }
}

}  // namespace

void AttachAndCapture(DWORD pid, const std::wstring& dump_path, const std::wstring& symbol_path, DWORD timeout_ms,
                      Report* report) {
  report->mode = "attach";
  report->pid = pid;
  report->image = wp::ProcessImageName(pid);
  wp::EnableDebugPrivilege();

  if (DebugActiveProcess(pid) == FALSE) {
    report->error = "DebugActiveProcess failed (Win32 " + std::to_string(GetLastError()) +
                    "): the target may have already exited, the bitness may not match, or admin rights are required";
    return;
  }
  DebugSetProcessKillOnExit(FALSE);

  HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (process == nullptr) {
    report->error = "OpenProcess failed (Win32 " + std::to_string(GetLastError()) + ")";
    DebugActiveProcessStop(pid);
    return;
  }

  DebugLoop(process, pid, true, dump_path, symbol_path, timeout_ms, report);

  CloseHandle(process);
  DebugActiveProcessStop(pid);
  report->ok = report->error.empty();
}

void RunAndCapture(const std::wstring& cmdline, const std::wstring& cwd, const std::wstring& dump_path,
                   const std::wstring& symbol_path, DWORD timeout_ms, const std::wstring& stdout_path,
                   const std::wstring& stderr_path, Report* report) {
  report->mode = "run";
  wp::EnableDebugPrivilege();

  std::vector<wchar_t> buffer(cmdline.begin(), cmdline.end());
  buffer.push_back(L'\0');

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);

  // Redirect the child's stdout/stderr to files: a debugger cannot both capture the output and
  // keep the handles clean. Handing it to files is the least trouble, and it also avoids a full
  // pipe stalling the target.
  HANDLE stdout_file = INVALID_HANDLE_VALUE;
  HANDLE stderr_file = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES inherit{};
  inherit.nLength = sizeof(inherit);
  inherit.bInheritHandle = TRUE;
  if (!stdout_path.empty()) {
    stdout_file = CreateFileW(stdout_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  }
  if (!stderr_path.empty()) {
    stderr_file = CreateFileW(stderr_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  }
  const bool redirect = stdout_file != INVALID_HANDLE_VALUE || stderr_file != INVALID_HANDLE_VALUE;
  if (redirect) {
    startup.dwFlags |= STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = stdout_file != INVALID_HANDLE_VALUE ? stdout_file : GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = stderr_file != INVALID_HANDLE_VALUE ? stderr_file : GetStdHandle(STD_ERROR_HANDLE);
  }

  PROCESS_INFORMATION info{};
  const DWORD flags = DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT;
  if (CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, redirect ? TRUE : FALSE, flags, nullptr,
                     cwd.empty() ? nullptr : cwd.c_str(), &startup, &info) == FALSE) {
    report->error = "CreateProcessW failed (Win32 " + std::to_string(GetLastError()) + ")";
    if (stdout_file != INVALID_HANDLE_VALUE) CloseHandle(stdout_file);
    if (stderr_file != INVALID_HANDLE_VALUE) CloseHandle(stderr_file);
    return;
  }
  CloseHandle(info.hThread);
  report->pid = info.dwProcessId;
  report->image = wp::ProcessImageName(info.dwProcessId);

  DebugLoop(info.hProcess, info.dwProcessId, false, dump_path, symbol_path, timeout_ms, report);

  CloseHandle(info.hProcess);
  if (stdout_file != INVALID_HANDLE_VALUE) CloseHandle(stdout_file);
  if (stderr_file != INVALID_HANDLE_VALUE) CloseHandle(stderr_file);
  report->ok = report->error.empty();
}

}  // namespace crash
