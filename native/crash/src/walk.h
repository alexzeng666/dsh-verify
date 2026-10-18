// Symbol resolution and live-process stack walking.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "report.h"

namespace crash {

// Initialise the dbghelp symbol handler (once per target process).
bool SymStart(HANDLE process, const std::wstring& symbol_path);
void SymStop(HANDLE process);

// Address -> module / symbol / source line (at minimum module + offset when symbols are missing).
void ResolveAddress(HANDLE process, uint64_t address, Frame* frame);

// Module attribution only (no symbol lookup).
void ModuleOfAddress(const std::vector<ModuleRec>& modules, uint64_t address, Frame* frame);

// Walk the real stack with StackWalk64 (usable on a live process / while attached as debugger).
void WalkLiveStack(HANDLE process, HANDLE thread, CONTEXT* context, bool is_wow64, std::vector<Frame>* frames,
                   int max_frames);

}  // namespace crash
