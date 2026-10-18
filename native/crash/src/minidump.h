// Minidump parsing: exception, modules, stack memory of the faulting thread, plus symbolication
// (a stack scan, not an unwind).
#pragma once

#include <windows.h>

#include <string>

#include "report.h"

namespace crash {

// Parse a .dmp; on failure report->error explains why.
void ParseDump(const std::wstring& path, const std::wstring& symbol_path, Report* report);

}  // namespace crash
