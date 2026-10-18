#include "walk.h"

#include <dbghelp.h>

#include <cstdio>
#include <vector>

#include "winproc.h"

namespace crash {
namespace {

constexpr DWORD kMaxSymName = 512;

struct SymbolBuffer {
  SYMBOL_INFOW info{};
  wchar_t name[kMaxSymName]{};
};

}  // namespace

bool SymStart(HANDLE process, const std::wstring& symbol_path) {
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_NO_PROMPTS |
                SYMOPT_FAIL_CRITICAL_ERRORS);
  const wchar_t* path = symbol_path.empty() ? nullptr : symbol_path.c_str();
  return SymInitializeW(process, path, TRUE) != FALSE;
}

void SymStop(HANDLE process) { SymCleanup(process); }

void ModuleOfAddress(const std::vector<ModuleRec>& modules, uint64_t address, Frame* frame) {
  for (const ModuleRec& module : modules) {
    if (address >= module.base && address < module.base + module.size) {
      frame->module = module.name;
      frame->module_offset = address - module.base;
      return;
    }
  }
}

void ResolveAddress(HANDLE process, uint64_t address, Frame* frame) {
  frame->addr = address;
  SymbolBuffer buffer;
  buffer.info.SizeOfStruct = sizeof(SYMBOL_INFOW);
  buffer.info.MaxNameLen = kMaxSymName;
  DWORD64 displacement = 0;
  if (SymFromAddrW(process, address, &displacement, &buffer.info) != FALSE) {
    frame->symbol.assign(buffer.info.Name);
    frame->resolved = true;
  }
  DWORD line_displacement = 0;
  IMAGEHLP_LINEW64 line{};
  line.SizeOfStruct = sizeof(line);
  if (SymGetLineFromAddrW64(process, address, &line_displacement, &line) != FALSE) {
    frame->source_file.assign(line.FileName);
    frame->source_line = static_cast<int>(line.LineNumber);
  }
}

void WalkLiveStack(HANDLE process, HANDLE thread, CONTEXT* context, bool is_wow64, std::vector<Frame>* frames,
                   int max_frames) {
  // This helper is an x64 build: CONTEXT only carries Rip/Rsp/Rbp. A 32-bit target needs
  // WOW64_CONTEXT, which is a separate path (left for phase 3); until then report "no stack"
  // honestly instead of returning a misaligned one.
  if (is_wow64) return;

  STACKFRAME64 stack_frame{};
  stack_frame.AddrPC.Offset = context->Rip;
  stack_frame.AddrPC.Mode = AddrModeFlat;
  stack_frame.AddrFrame.Offset = context->Rbp;
  stack_frame.AddrFrame.Mode = AddrModeFlat;
  stack_frame.AddrStack.Offset = context->Rsp;
  stack_frame.AddrStack.Mode = AddrModeFlat;

  CONTEXT local = *context;
  for (int index = 0; index < max_frames; ++index) {
    if (StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &stack_frame, &local, nullptr,
                    SymFunctionTableAccess64, SymGetModuleBase64, nullptr) == FALSE) {
      break;
    }
    if (stack_frame.AddrPC.Offset == 0) break;
    Frame frame;
    ResolveAddress(process, stack_frame.AddrPC.Offset, &frame);
    frames->push_back(std::move(frame));
    if (stack_frame.AddrReturn.Offset == 0) break;
  }
}

}  // namespace crash
