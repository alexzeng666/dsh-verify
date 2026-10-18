#include "minidump.h"

#include <dbghelp.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "walk.h"
#include "winproc.h"

namespace crash {
namespace {

struct MappedFile {
  HANDLE file = INVALID_HANDLE_VALUE;
  HANDLE mapping = nullptr;
  const uint8_t* base = nullptr;
  ~MappedFile() {
    if (base != nullptr) UnmapViewOfFile(base);
    if (mapping != nullptr) CloseHandle(mapping);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  }
};

std::wstring ReadMinidumpString(const uint8_t* base, RVA rva) {
  if (rva == 0) return {};
  const auto* text = reinterpret_cast<const MINIDUMP_STRING*>(base + rva);
  const size_t chars = text->Length / sizeof(WCHAR);
  return std::wstring(text->Buffer, chars);
}

bool FindStream(const uint8_t* base, ULONG type, void** stream, ULONG* size) {
  return MiniDumpReadDumpStream(const_cast<uint8_t*>(base), type, nullptr, stream, size) != FALSE;
}

// Find a range covering `address` in the dump's memory streams and copy it out.
bool ReadMemoryRange(const uint8_t* base, uint64_t address, size_t want, std::vector<uint8_t>* out) {
  void* raw = nullptr;
  ULONG size = 0;
  if (FindStream(base, Memory64ListStream, &raw, &size)) {
    const auto* list = static_cast<const MINIDUMP_MEMORY64_LIST*>(raw);
    uint64_t offset = list->BaseRva;
    for (ULONG64 index = 0; index < list->NumberOfMemoryRanges; ++index) {
      const MINIDUMP_MEMORY_DESCRIPTOR64& item = list->MemoryRanges[index];
      if (address >= item.StartOfMemoryRange && address < item.StartOfMemoryRange + item.DataSize) {
        const uint64_t skip = address - item.StartOfMemoryRange;
        const size_t available = static_cast<size_t>(std::min<uint64_t>(item.DataSize - skip, want));
        out->assign(base + offset + skip, base + offset + skip + available);
        return true;
      }
      offset += item.DataSize;
    }
    return false;
  }
  if (FindStream(base, MemoryListStream, &raw, &size)) {
    const auto* list = static_cast<const MINIDUMP_MEMORY_LIST*>(raw);
    for (ULONG index = 0; index < list->NumberOfMemoryRanges; ++index) {
      const MINIDUMP_MEMORY_DESCRIPTOR& item = list->MemoryRanges[index];
      if (address >= item.StartOfMemoryRange && address < item.StartOfMemoryRange + item.Memory.DataSize) {
        const uint64_t skip = address - item.StartOfMemoryRange;
        const size_t available =
            static_cast<size_t>(std::min<uint64_t>(item.Memory.DataSize - skip, want));
        out->assign(base + item.Memory.Rva + skip, base + item.Memory.Rva + skip + available);
        return true;
      }
      (void)size;
    }
  }
  return false;
}

}  // namespace

void ParseDump(const std::wstring& path, const std::wstring& symbol_path, Report* report) {
  report->mode = "parse";
  report->dump_path = path;

  MappedFile mapped;
  mapped.file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (mapped.file == INVALID_HANDLE_VALUE) {
    report->error = "cannot open dump file (Win32 " + std::to_string(GetLastError()) + ")";
    return;
  }
  LARGE_INTEGER file_size{};
  GetFileSizeEx(mapped.file, &file_size);
  if (file_size.QuadPart <= 0) {
    report->error = "dump file is empty";
    return;
  }
  mapped.mapping = CreateFileMappingW(mapped.file, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (mapped.mapping == nullptr) {
    report->error = "CreateFileMapping failed (Win32 " + std::to_string(GetLastError()) + ")";
    return;
  }
  mapped.base = static_cast<const uint8_t*>(MapViewOfFile(mapped.mapping, FILE_MAP_READ, 0, 0, 0));
  if (mapped.base == nullptr) {
    report->error = "MapViewOfFile failed (Win32 " + std::to_string(GetLastError()) + ")";
    return;
  }

  void* stream = nullptr;
  ULONG stream_size = 0;

  // Module list
  if (FindStream(mapped.base, ModuleListStream, &stream, &stream_size)) {
    const auto* list = static_cast<const MINIDUMP_MODULE_LIST*>(stream);
    for (ULONG index = 0; index < list->NumberOfModules; ++index) {
      const MINIDUMP_MODULE& item = list->Modules[index];
      ModuleRec module;
      module.base = item.BaseOfImage;
      module.size = item.SizeOfImage;
      module.path = ReadMinidumpString(mapped.base, item.ModuleNameRva);
      const wchar_t* slash = wcsrchr(module.path.c_str(), L'\\');
      module.name.assign(slash != nullptr ? slash + 1 : module.path.c_str());
      report->modules.push_back(std::move(module));
    }
  }

  // Exception
  uint64_t stack_pointer = 0;
  bool have_context = false;
  CONTEXT context{};
  if (FindStream(mapped.base, ExceptionStream, &stream, &stream_size)) {
    const auto* exception = static_cast<const MINIDUMP_EXCEPTION_STREAM*>(stream);
    const MINIDUMP_EXCEPTION& record = exception->ExceptionRecord;
    report->has_exception = true;
    report->exception_code = record.ExceptionCode;
    report->exception_address = record.ExceptionAddress;
    report->exception_flags = record.ExceptionFlags;
    report->exception_param_count = record.NumberParameters > 15 ? 15 : record.NumberParameters;
    for (DWORD index = 0; index < report->exception_param_count; ++index) {
      report->exception_params[index] = static_cast<ULONG_PTR>(record.ExceptionInformation[index]);
    }
    report->thread_id = exception->ThreadId;
  }

  // Context of the faulting thread (to get the stack pointer)
  if (FindStream(mapped.base, ThreadListStream, &stream, &stream_size)) {
    const auto* list = static_cast<const MINIDUMP_THREAD_LIST*>(stream);
    for (ULONG index = 0; index < list->NumberOfThreads; ++index) {
      const MINIDUMP_THREAD& thread = list->Threads[index];
      if (report->thread_id != 0 && thread.ThreadId != report->thread_id) continue;
      if (thread.ThreadContext.DataSize == 0) continue;
      const size_t bytes = std::min<size_t>(thread.ThreadContext.DataSize, sizeof(CONTEXT));
      std::memcpy(&context, mapped.base + thread.ThreadContext.Rva, bytes);
      have_context = true;
      stack_pointer = static_cast<uint64_t>(context.Rsp);
      if (report->thread_id == 0) report->thread_id = thread.ThreadId;
      break;
    }
  }

  // Symbolication: load the dump's modules from their original paths (a PDB sitting next to them
  // yields source lines).
  const bool symbols = SymStart(GetCurrentProcess(), symbol_path);
  if (symbols) {
    for (const ModuleRec& module : report->modules) {
      if (module.path.empty()) continue;
      if (GetFileAttributesW(module.path.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
      SymLoadModuleExW(GetCurrentProcess(), nullptr, module.path.c_str(), nullptr, module.base, module.size,
                       nullptr, 0);
    }
  }

  // Stack scan: the dump carries no unwind info, so the only option is to scan the stack for
  // return addresses that fall inside a module.
  if (have_context && stack_pointer != 0) {
    std::vector<uint8_t> stack;
    if (ReadMemoryRange(mapped.base, stack_pointer, 64 * 1024, &stack) && !stack.empty()) {
      const size_t words = stack.size() / sizeof(uint64_t);
      uint64_t previous = 0;
      for (size_t index = 0; index < words && report->frames.size() < 48; ++index) {
        uint64_t value = 0;
        std::memcpy(&value, stack.data() + index * sizeof(uint64_t), sizeof(uint64_t));
        if (value < 0x10000) continue;
        bool in_module = false;
        for (const ModuleRec& module : report->modules) {
          if (value >= module.base && value < module.base + module.size) {
            in_module = true;
            break;
          }
        }
        if (!in_module) continue;
        if (value == previous) continue;
        previous = value;
        Frame frame;
        frame.addr = value;
        if (symbols) {
          ResolveAddress(GetCurrentProcess(), value, &frame);
        }
        ModuleOfAddress(report->modules, value, &frame);
        report->frames.push_back(std::move(frame));
      }
      report->stack_quality = report->frames.empty() ? "none" : "scan";
    }
  }
  if (report->stack_quality.empty()) report->stack_quality = "none";
  if (symbols) SymStop(GetCurrentProcess());

  report->ok = true;
}

}  // namespace crash
