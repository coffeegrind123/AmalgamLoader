#pragma once

#include <Windows.h>

// Manual mapping injection function
// Returns 0 on success, -1 on failure
int ManualMapInject(const wchar_t* dllPath, const wchar_t* processName);