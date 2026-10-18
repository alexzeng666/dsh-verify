// crash_helper - native helper for crash capture and analysis.
//
// Three modes, all of which print a single line of JSON to stdout:
//   crash_helper.exe attach --pid <n> --out <dump> [--symbol-path <p>] [--timeout-ms <n>]
//   crash_helper.exe run --out <dump> [--cwd <dir>] [--symbol-path <p>] [--timeout-ms <n>] -- <cmd...>
//   crash_helper.exe parse --dump <file> [--symbol-path <p>]
//
// Why not a DLL: this is a one-shot task, and spawning a process plus passing JSON over stdio is
// the least trouble; a failure cannot pollute the host either.
#include <fcntl.h>
#include <io.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "dump.h"
#include "minidump.h"
#include "report.h"
#include "winproc.h"

namespace {

struct Args {
  std::wstring mode;
  DWORD pid = 0;
  std::wstring out;
  std::wstring dump;
  std::wstring cwd;
  std::wstring symbol_path;
  std::wstring stdout_path;
  std::wstring stderr_path;
  DWORD timeout_ms = 30000;
  std::wstring command;
};

void PrintUsage() {
  std::fputs(
      "usage:\n"
      "  crash_helper attach --pid <n> --out <dump> [--symbol-path <p>] [--timeout-ms <n>]\n"
      "  crash_helper run --out <dump> [--cwd <dir>] [--symbol-path <p>] [--timeout-ms <n>] -- <cmd...>\n"
      "  crash_helper parse --dump <file> [--symbol-path <p>]\n",
      stderr);
}

bool ParseArgs(int argc, char** argv, Args* args) {
  if (argc < 2) return false;
  args->mode = wp::ToWide(argv[1]);
  for (int index = 2; index < argc; ++index) {
    const std::wstring key = wp::ToWide(argv[index]);
    auto next = [&](std::wstring* value) -> bool {
      if (index + 1 >= argc) return false;
      *value = wp::ToWide(argv[++index]);
      return true;
    };
    if (key == L"--pid") {
      std::wstring value;
      if (!next(&value)) return false;
      args->pid = static_cast<DWORD>(wcstoul(value.c_str(), nullptr, 10));
    } else if (key == L"--out") {
      if (!next(&args->out)) return false;
    } else if (key == L"--dump") {
      if (!next(&args->dump)) return false;
    } else if (key == L"--cwd") {
      if (!next(&args->cwd)) return false;
    } else if (key == L"--stdout") {
      if (!next(&args->stdout_path)) return false;
    } else if (key == L"--stderr") {
      if (!next(&args->stderr_path)) return false;
    } else if (key == L"--symbol-path") {
      if (!next(&args->symbol_path)) return false;
    } else if (key == L"--timeout-ms") {
      std::wstring value;
      if (!next(&value)) return false;
      args->timeout_ms = static_cast<DWORD>(wcstoul(value.c_str(), nullptr, 10));
    } else if (key == L"--") {
      std::wstring command;
      for (int rest = index + 1; rest < argc; ++rest) {
        if (!command.empty()) command.push_back(L' ');
        const std::wstring piece = wp::ToWide(argv[rest]);
        if (piece.find(L' ') != std::wstring::npos) {
          command.push_back(L'"');
          command.append(piece);
          command.push_back(L'"');
        } else {
          command.append(piece);
        }
      }
      args->command = command;
      break;
    }
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  // The JSON is a UTF-8 byte stream; the CRT must not reinterpret it as UTF-16.
  _setmode(_fileno(stdout), _O_BINARY);

  Args args;
  if (!ParseArgs(argc, argv, &args)) {
    PrintUsage();
    return 2;
  }

  crash::Report report;
  if (args.mode == L"attach") {
    if (args.pid == 0 || args.out.empty()) {
      PrintUsage();
      return 2;
    }
    crash::AttachAndCapture(args.pid, args.out, args.symbol_path, args.timeout_ms, &report);
  } else if (args.mode == L"run") {
    if (args.out.empty() || args.command.empty()) {
      PrintUsage();
      return 2;
    }
    crash::RunAndCapture(args.command, args.cwd, args.out, args.symbol_path, args.timeout_ms, args.stdout_path,
                         args.stderr_path, &report);
  } else if (args.mode == L"parse") {
    if (args.dump.empty()) {
      PrintUsage();
      return 2;
    }
    crash::ParseDump(args.dump, args.symbol_path, &report);
  } else {
    PrintUsage();
    return 2;
  }

  const std::string json = crash::ToJson(report);
  std::fwrite(json.data(), 1, json.size(), stdout);
  std::fputc('\n', stdout);
  std::fflush(stdout);
  return report.ok ? 0 : 1;
}
