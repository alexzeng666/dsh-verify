#include "report.h"

#include <cstdio>

#include "winproc.h"

namespace crash {
namespace {

std::string Utf8(const std::wstring& text) { return wp::ToUtf8(text); }

void AppendFrame(std::string* out, const Frame& frame, bool last) {
  *out += "{";
  *out += "\"addr\":";
  *out += wp::JsonString(wp::Hex(frame.addr));
  *out += ",\"module\":";
  *out += wp::JsonString(Utf8(frame.module));
  *out += ",\"module_offset\":";
  *out += wp::JsonString(wp::Hex(frame.module_offset));
  *out += ",\"symbol\":";
  *out += wp::JsonString(Utf8(frame.symbol));
  *out += ",\"source_file\":";
  *out += wp::JsonString(Utf8(frame.source_file));
  *out += ",\"source_line\":";
  *out += std::to_string(frame.source_line);
  *out += ",\"resolved\":";
  *out += frame.resolved ? "true" : "false";
  *out += last ? "}" : "},";
}

}  // namespace

std::string ExceptionName(DWORD code) {
  switch (code) {
    case 0xC0000005: return "ACCESS_VIOLATION";
    case 0xC0000006: return "IN_PAGE_ERROR";
    case 0xC000001D: return "ILLEGAL_INSTRUCTION";
    case 0xC0000017: return "NO_MEMORY";
    case 0xC0000025: return "NONCONTINUABLE_EXCEPTION";
    case 0xC000008C: return "ARRAY_BOUNDS_EXCEEDED";
    case 0xC000008D: return "FLOAT_DENORMAL_OPERAND";
    case 0xC000008E: return "FLOAT_DIVIDE_BY_ZERO";
    case 0xC0000090: return "FLOAT_INVALID_OPERATION";
    case 0xC0000094: return "INTEGER_DIVIDE_BY_ZERO";
    case 0xC0000095: return "INTEGER_OVERFLOW";
    case 0xC0000096: return "PRIVILEGED_INSTRUCTION";
    case 0xC00000FD: return "STACK_OVERFLOW";
    case 0xC0000374: return "HEAP_CORRUPTION";
    case 0xC0000409: return "STACK_BUFFER_OVERRUN";
    case 0xC0000602: return "FAIL_FAST_EXCEPTION";
    case 0x80000003: return "BREAKPOINT";
    case 0x80000004: return "SINGLE_STEP";
    case 0xE06D7363: return "CPP_EXCEPTION";
    default: break;
  }
  char buffer[16];
  std::snprintf(buffer, sizeof(buffer), "0x%08lX", static_cast<unsigned long>(code));
  return buffer;
}

std::string ToJson(const Report& report) {
  std::string out = "{";
  out += "\"ok\":";
  out += report.ok ? "true" : "false";
  out += ",\"error\":";
  out += wp::JsonString(report.error);
  out += ",\"mode\":";
  out += wp::JsonString(report.mode);
  out += ",\"pid\":";
  out += std::to_string(report.pid);
  out += ",\"image\":";
  out += wp::JsonString(Utf8(report.image));
  out += ",\"captured\":";
  out += report.captured ? "true" : "false";
  out += ",\"dump_path\":";
  out += wp::JsonString(Utf8(report.dump_path));
  out += ",\"dump_error\":";
  out += wp::JsonString(report.dump_error);

  out += ",\"exception\":{";
  if (report.has_exception) {
    out += "\"code\":";
    out += std::to_string(report.exception_code);
    out += ",\"code_hex\":";
    out += wp::JsonString(wp::Hex(report.exception_code));
    out += ",\"name\":";
    out += wp::JsonString(ExceptionName(report.exception_code));
    out += ",\"address\":";
    out += wp::JsonString(wp::Hex(report.exception_address));
    out += ",\"flags\":";
    out += std::to_string(report.exception_flags);
    out += ",\"thread_id\":";
    out += std::to_string(report.thread_id);
    out += ",\"params\":[";
    for (DWORD index = 0; index < report.exception_param_count && index < 15; ++index) {
      if (index != 0) out += ",";
      out += wp::JsonString(wp::Hex(report.exception_params[index]));
    }
    out += "]";
  }
  out += "}";

  out += ",\"stack_quality\":";
  out += wp::JsonString(report.stack_quality);
  out += ",\"frames\":[";
  for (size_t index = 0; index < report.frames.size(); ++index) {
    AppendFrame(&out, report.frames[index], index + 1 == report.frames.size());
  }
  out += "]";

  out += ",\"modules\":[";
  for (size_t index = 0; index < report.modules.size(); ++index) {
    const ModuleRec& module = report.modules[index];
    out += "{\"base\":";
    out += wp::JsonString(wp::Hex(module.base));
    out += ",\"size\":";
    out += std::to_string(module.size);
    out += ",\"name\":";
    out += wp::JsonString(Utf8(module.name));
    out += ",\"path\":";
    out += wp::JsonString(Utf8(module.path));
    out += index + 1 == report.modules.size() ? "}" : "},";
  }
  out += "]";

  out += ",\"exit\":{";
  if (report.has_exit) {
    out += "\"code\":";
    out += std::to_string(report.exit_code);
    out += ",\"code_hex\":";
    out += wp::JsonString(wp::Hex(report.exit_code));
  }
  out += "}}";
  return out;
}

}  // namespace crash
