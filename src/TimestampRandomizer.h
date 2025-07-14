#pragma once

#include <Windows.h>
#include <string>
#include <random>
#include <ctime>

class TimestampRandomizer {
public:
    // Modify the PE timestamp of the specified executable
    static bool RandomizeTimestamp(const std::wstring& filePath);
    
    // Generate a random timestamp from 6 months to 2 years ago
    static DWORD GenerateRandomOldTimestamp();
    
    // Get last error message
    static std::wstring GetLastError();
    
private:
    static void SetLastError(const std::wstring& error);
    static thread_local std::wstring s_lastError;
};