#pragma once

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#endif

#pragma warning(disable : 4995)

// Windows Header Files:
#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

// C RunTime Header Files
#include <stdlib.h>
#include <memory.h>
#include <strsafe.h>
#include <stdint.h>
#include <wchar.h>

// C++ RunTime Header Files
#include <vector>
#include <string>

