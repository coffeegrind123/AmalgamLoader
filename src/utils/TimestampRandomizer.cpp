#include "TimestampRandomizer.h"
#include <fstream>
#include <vector>
#include <chrono>

thread_local std::wstring TimestampRandomizer::s_lastError;

bool TimestampRandomizer::RandomizeTimestamp(const std::wstring& filePath) {
    SetLastError(L"DEBUG: TimestampRandomizer started for: " + filePath);
    
    // Open the PE file for modification
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastError(L"Failed to open file: " + std::to_wstring(::GetLastError()));
        return false;
    }
    
    // Read DOS header
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr)) {
        SetLastError(L"Failed to read DOS header: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(L"Invalid DOS signature");
        CloseHandle(hFile);
        return false;
    }
    
    // Seek to NT headers
    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek to NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr)) {
        SetLastError(L"Failed to read NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(L"Invalid NT signature");
        CloseHandle(hFile);
        return false;
    }
    
    // Store original timestamp for logging
    DWORD originalTimestamp = ntHeaders.FileHeader.TimeDateStamp;
    
    // Generate a random old timestamp
    DWORD newTimestamp = GenerateRandomOldTimestamp();
    ntHeaders.FileHeader.TimeDateStamp = newTimestamp;
    
    SetLastError(L"DEBUG: Changing timestamp from " + std::to_wstring(originalTimestamp) + 
                L" to " + std::to_wstring(newTimestamp));
    
    // Seek back to NT headers position
    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek back to NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    // Write modified NT headers back
    DWORD bytesWritten;
    if (!WriteFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesWritten, nullptr)) {
        SetLastError(L"Failed to write modified NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    // Convert timestamps to readable dates for logging
    time_t originalTime = originalTimestamp;
    time_t newTime = newTimestamp;
    
    char originalDateStr[100], newDateStr[100];
    struct tm originalTm, newTm;
    localtime_s(&originalTm, &originalTime);
    localtime_s(&newTm, &newTime);
    
    strftime(originalDateStr, sizeof(originalDateStr), "%Y-%m-%d %H:%M:%S", &originalTm);
    strftime(newDateStr, sizeof(newDateStr), "%Y-%m-%d %H:%M:%S", &newTm);
    
    SetLastError(L"DEBUG: Timestamp successfully changed from " + 
                std::wstring(originalDateStr, originalDateStr + strlen(originalDateStr)) + 
                L" to " + std::wstring(newDateStr, newDateStr + strlen(newDateStr)));
    
    CloseHandle(hFile);
    return true;
}

DWORD TimestampRandomizer::GenerateRandomOldTimestamp() {
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::system_clock::to_time_t(now);
    
    // Generate random offset between 6 months (180 days) and 2 years (730 days) ago
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> daysDis(180, 730);
    std::uniform_int_distribution<> hoursDis(0, 23);
    std::uniform_int_distribution<> minutesDis(0, 59);
    
    int daysAgo = daysDis(gen);
    int hoursOffset = hoursDis(gen);
    int minutesOffset = minutesDis(gen);
    
    // Calculate the old timestamp
    time_t oldTime = currentTime - (daysAgo * 24 * 60 * 60) - (hoursOffset * 60 * 60) - (minutesOffset * 60);
    
    return static_cast<DWORD>(oldTime);
}

std::wstring TimestampRandomizer::GetLastError() {
    return s_lastError;
}

void TimestampRandomizer::SetLastError(const std::wstring& error) {
    s_lastError = error;
}