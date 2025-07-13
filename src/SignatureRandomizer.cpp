#include "SignatureRandomizer.h"
#include <random>
#include <chrono>
#include <fstream>
#include <shlobj.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

bool SignatureRandomizer::IsFirstRun() {
    // Check if we've already randomized signatures
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
        std::wstring markerPath = std::wstring(appDataPath) + L"\\AmalgamLoader\\.sig_processed";
        return GetFileAttributes(markerPath.c_str()) == INVALID_FILE_ATTRIBUTES;
    }
    return true;
}

bool SignatureRandomizer::RandomizeSignatures() {
    if (!IsFirstRun()) {
        return true; // Already processed
    }
    
    // Get current executable path
    wchar_t exePath[MAX_PATH];
    GetModuleFileName(nullptr, exePath, MAX_PATH);
    
    // Find DLL in same directory
    std::wstring exeDir = std::wstring(exePath);
    size_t lastSlash = exeDir.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        exeDir = exeDir.substr(0, lastSlash + 1);
    }
    
    // Look for Amalgam DLL (try common patterns)
    std::vector<std::wstring> dllPatterns = {
        L"Amalgamx64Release.dll",
        L"Amalgamx64Debug.dll", 
        L"AmalgamxRelease.dll",
        L"Amalgam.dll"
    };
    
    std::wstring dllPath;
    for (const auto& pattern : dllPatterns) {
        std::wstring testPath = exeDir + pattern;
        if (GetFileAttributes(testPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            dllPath = testPath;
            break;
        }
    }
    
    bool success = true;
    
    // Randomize the executable itself
    if (!RandomizeExecutable(exePath)) {
        success = false;
    }
    
    // Randomize the DLL if found
    if (!dllPath.empty() && !RandomizeDLL(dllPath)) {
        success = false;
    }
    
    if (success) {
        MarkAsProcessed();
    }
    
    return success;
}

bool SignatureRandomizer::RandomizeExecutable(const std::wstring& filePath) {
    if (IsAlreadyProcessed(filePath)) {
        return true;
    }
    
    // Generate random data based on system characteristics
    auto randomData = GenerateRandomData(RANDOM_DATA_SIZE);
    
    // Modify PE overlay (safest place to add data)
    if (!ModifyPEOverlay(filePath, randomData)) {
        return false;
    }
    
    // Modify resource section
    return ModifyResourceSection(filePath);
}

bool SignatureRandomizer::RandomizeDLL(const std::wstring& dllPath) {
    return RandomizeExecutable(dllPath); // Same process for DLL
}

std::vector<uint8_t> SignatureRandomizer::GenerateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    
    // Use system-specific seed
    std::string fingerprint = std::string(GetSystemFingerprint().begin(), GetSystemFingerprint().end());
    auto now = std::chrono::high_resolution_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
    
    std::mt19937 rng(static_cast<uint32_t>(timestamp ^ std::hash<std::string>{}(fingerprint)));
    
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(rng() % 256);
    }
    
    return data;
}

bool SignatureRandomizer::ModifyPEOverlay(const std::wstring& filePath, const std::vector<uint8_t>& randomData) {
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 
                             FILE_SHARE_READ, nullptr, OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Read PE header to find end of file
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }
    
    SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
    
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }
    
    // Find the end of the PE file (after last section)
    DWORD overlayOffset = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + 
                         (ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    
    // Find highest section end
    SetFilePointer(hFile, dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), nullptr, FILE_BEGIN);
    
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (ReadFile(hFile, &sectionHeader, sizeof(sectionHeader), &bytesRead, nullptr)) {
            DWORD sectionEnd = sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData;
            if (sectionEnd > overlayOffset) {
                overlayOffset = sectionEnd;
            }
        }
    }
    
    // Append random data as overlay
    SetFilePointer(hFile, overlayOffset, nullptr, FILE_BEGIN);
    
    // Write signature header
    const char* header = "AMLDR_SIG";
    DWORD bytesWritten;
    WriteFile(hFile, header, 9, &bytesWritten, nullptr);
    
    // Write random data
    WriteFile(hFile, randomData.data(), static_cast<DWORD>(randomData.size()), &bytesWritten, nullptr);
    
    CloseHandle(hFile);
    return true;
}

bool SignatureRandomizer::ModifyResourceSection(const std::wstring& filePath) {
    // Add dummy resources with random data
    // This is more complex - for now just return true
    // Full implementation would use UpdateResource API
    return true;
}

std::wstring SignatureRandomizer::GetSystemFingerprint() {
    std::wstring fingerprint;
    
    // Get computer name
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName) / sizeof(wchar_t);
    if (GetComputerName(computerName, &size)) {
        fingerprint += computerName;
    }
    
    // Get user name
    wchar_t userName[256];
    size = sizeof(userName) / sizeof(wchar_t);
    if (GetUserName(userName, &size)) {
        fingerprint += userName;
    }
    
    // Get system time (will be different per install)
    SYSTEMTIME st;
    GetSystemTime(&st);
    fingerprint += std::to_wstring(st.wYear) + std::to_wstring(st.wMonth) + 
                   std::to_wstring(st.wDay) + std::to_wstring(st.wHour);
    
    return fingerprint;
}

void SignatureRandomizer::MarkAsProcessed() {
    wchar_t appDataPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) {
        std::wstring dirPath = std::wstring(appDataPath) + L"\\AmalgamLoader";
        CreateDirectory(dirPath.c_str(), nullptr);
        
        std::wstring markerPath = dirPath + L"\\.sig_processed";
        HANDLE hFile = CreateFile(markerPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* marker = "PROCESSED";
            DWORD written;
            WriteFile(hFile, marker, 9, &written, nullptr);
            CloseHandle(hFile);
        }
    }
}

bool SignatureRandomizer::IsAlreadyProcessed(const std::wstring& filePath) {
    // Check if file already has our signature in overlay
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Simple check - look for our signature at end of file
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize > 1024) {
        SetFilePointer(hFile, fileSize - 1024, nullptr, FILE_BEGIN);
        
        char buffer[1024];
        DWORD bytesRead;
        if (ReadFile(hFile, buffer, 1024, &bytesRead, nullptr)) {
            // Look for our signature
            for (DWORD i = 0; i < bytesRead - 9; ++i) {
                if (memcmp(&buffer[i], "AMLDR_SIG", 9) == 0) {
                    CloseHandle(hFile);
                    return true;
                }
            }
        }
    }
    
    CloseHandle(hFile);
    return false;
}