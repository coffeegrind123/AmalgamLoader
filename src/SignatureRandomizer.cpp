#include "SignatureRandomizer.h"
#include <random>
#include <chrono>
#include <fstream>
#include <shlobj.h>
#include <wincrypt.h>
#include <vector>
#pragma comment(lib, "crypt32.lib")

// Static member definition
thread_local std::wstring SignatureRandomizer::s_lastError;

bool SignatureRandomizer::IsFirstRun() {
    // Get current executable path
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileName(nullptr, exePath, MAX_PATH) == 0) {
        SetLastError(L"Failed to get current executable path for first run check");
        return true; // Assume first run if we can't check
    }
    
    // Check if this executable has an embedded hash (indicating it's been processed)
    bool hasHash = HasEmbeddedHash(std::wstring(exePath));
    
    // Also check for fallback marker file
    bool hasMarker = false;
    std::wstring markerPath = std::wstring(exePath) + L".processed";
    if (GetFileAttributes(markerPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        hasMarker = true;
    }
    
    bool isFirstRun = !hasHash && !hasMarker;
    
    // Clean up any leftover backup files
    if (!isFirstRun) {
        std::wstring backupPath = std::wstring(exePath) + L".backup";
        if (GetFileAttributes(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (DeleteFile(backupPath.c_str())) {
                SetLastError(L"DEBUG: Cleaned up backup file: " + backupPath);
            } else {
                SetLastError(L"DEBUG: Failed to delete backup file: " + backupPath);
            }
        }
    }
    
    // Store debug info
    SetLastError(L"DEBUG IsFirstRun: exe=" + std::wstring(exePath) + L" hasHash=" + (hasHash ? L"true" : L"false") + L" hasMarker=" + (hasMarker ? L"true" : L"false") + L" firstrun=" + (isFirstRun ? L"true" : L"false"));
    
    return isFirstRun;
}

bool SignatureRandomizer::RandomizeSignatures() {
    SetLastError(L"DEBUG: RandomizeSignatures() started");
    
    if (!IsFirstRun()) {
        SetLastError(L"DEBUG: Not first run, returning true");
        return true; // Already processed
    }
    
    // Get current executable path
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileName(nullptr, exePath, MAX_PATH) == 0) {
        SetLastError(L"Failed to get current executable path: " + std::to_wstring(::GetLastError()));
        return false;
    }
    
    SetLastError(L"DEBUG: Current EXE: " + std::wstring(exePath));
    
    // Step 1: Calculate original hash before modification
    std::vector<uint8_t> originalHash = CalculateFileHash(std::wstring(exePath));
    if (originalHash.empty()) {
        SetLastError(L"Failed to calculate original file hash");
        return false;
    }
    SetLastError(L"DEBUG: Original hash calculated (" + std::to_wstring(originalHash.size()) + L" bytes)");
    
    // Step 2: Copy executable to temp location for modification
    std::wstring tempExePath;
    if (!CopyToTempLocation(std::wstring(exePath), tempExePath)) {
        std::wstring copyError = GetLastError();
        SetLastError(L"Failed to copy executable to temp location. Details: " + copyError);
        return false;
    }
    
    SetLastError(L"DEBUG: Copied to temp: " + tempExePath);
    
    // Step 2: Modify the temporary copy (safe since it's not running)
    bool success = true;
    if (!RandomizeExecutable(tempExePath)) {
        std::wstring detailedError = GetLastError();
        SetLastError(L"Failed to randomize temporary executable copy. Details: " + detailedError);
        success = false;
    }
    
    if (success) {
        // Step 3: Find and randomize DLL in same directory as original
        std::wstring exeDir = std::wstring(exePath);
        size_t lastSlash = exeDir.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            exeDir = exeDir.substr(0, lastSlash + 1);
        }
        
        std::vector<std::wstring> dllPatterns = {
            L"Amalgamx64Release.dll", L"Amalgamx64Debug.dll", 
            L"AmalgamxRelease.dll", L"Amalgam.dll"
        };
        
        for (const auto& pattern : dllPatterns) {
            std::wstring dllPath = exeDir + pattern;
            if (GetFileAttributes(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                SetLastError(L"DEBUG: Found DLL, randomizing: " + dllPath);
                if (!RandomizeDLL(dllPath)) {
                    SetLastError(L"Warning: Failed to randomize DLL: " + dllPath);
                    // Don't fail completely if DLL randomization fails
                }
                break;
            }
        }
    }
    
    if (success) {
        // Step 4: Embed original hash into the modified copy
        if (!EmbedOriginalHash(tempExePath, originalHash)) {
            std::wstring embedError = GetLastError();
            SetLastError(L"Failed to embed original hash into temp file. Details: " + embedError);
            
            // Fallback: Try to embed after file replacement instead
            SetLastError(L"DEBUG: Will try to embed hash after file replacement as fallback");
        } else {
            SetLastError(L"DEBUG: Original hash embedded successfully into temp file");
        }
    }
    
    if (success) {
        // Step 5: Replace original executable with modified copy
        if (!ReplaceOriginalFile(tempExePath, std::wstring(exePath))) {
            std::wstring replaceError = GetLastError();
            SetLastError(L"Failed to replace original executable. Details: " + replaceError);
            success = false;
        } else {
            SetLastError(L"DEBUG: Successfully replaced original executable");
            
            // If hash embedding failed earlier, try now on the final file
            if (success && GetLastError().find(L"Will try to embed hash after file replacement") != std::wstring::npos) {
                SetLastError(L"DEBUG: Attempting fallback hash embedding on final file");
                Sleep(1000); // Give AV time to finish scanning
                
                if (EmbedOriginalHash(std::wstring(exePath), originalHash)) {
                    SetLastError(L"DEBUG: Fallback hash embedding succeeded");
                } else {
                    SetLastError(L"WARNING: Both primary and fallback hash embedding failed - using marker file fallback");
                    // Final fallback: create a simple marker file
                    CreateFallbackMarker();
                }
            }
        }
    }
    
    if (success) {
        SetLastError(L"DEBUG: Signature randomization completed successfully");
    }
    
    return success;
}

bool SignatureRandomizer::RandomizeExecutable(const std::wstring& filePath) {
    SetLastError(L"DEBUG: RandomizeExecutable started for: " + filePath);
    
    if (IsAlreadyProcessed(filePath)) {
        SetLastError(L"DEBUG: File already processed, skipping");
        return true;
    }
    
    SetLastError(L"DEBUG: Generating random data");
    // Generate random data based on system characteristics
    auto randomData = GenerateRandomData(RANDOM_DATA_SIZE);
    
    SetLastError(L"DEBUG: Starting PE overlay modification");
    // Modify PE overlay (safest place to add data)
    if (!ModifyPEOverlay(filePath, randomData)) {
        std::wstring peError = GetLastError();
        SetLastError(L"PE overlay modification failed: " + peError);
        return false;
    }
    
    SetLastError(L"DEBUG: PE overlay modification completed, starting resource modification");
    // Modify resource section
    bool resourceResult = false;
    try {
        resourceResult = ModifyResourceSection(filePath);
        if (resourceResult) {
            SetLastError(L"DEBUG: Resource modification completed successfully");
        } else {
            SetLastError(L"DEBUG: Resource modification failed - " + GetLastError());
        }
    } catch (const std::exception& e) {
        // Convert exception message safely
        std::string msg = e.what();
        std::wstring wmsg(msg.begin(), msg.end());
        SetLastError(L"DEBUG: Exception in resource modification: " + wmsg);
        resourceResult = false;
    } catch (...) {
        SetLastError(L"DEBUG: Unknown exception in resource modification");
        resourceResult = false;
    }
    
    return resourceResult;
}

bool SignatureRandomizer::RandomizeDLL(const std::wstring& dllPath) {
    return RandomizeExecutable(dllPath); // Same process for DLL
}

std::vector<uint8_t> SignatureRandomizer::GenerateRandomData(size_t size) {
    std::vector<uint8_t> data(size);
    
    try {
        // Use system-specific seed with safer conversion
        std::wstring wFingerprint = GetSystemFingerprint();
        std::string fingerprint;
        
        // Convert wstring to string safely, limiting length to prevent issues
        if (wFingerprint.length() > 256) {
            wFingerprint = wFingerprint.substr(0, 256);
        }
        
        for (wchar_t wc : wFingerprint) {
            fingerprint += static_cast<char>(wc & 0xFF);
        }
        
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        
        std::mt19937 rng(static_cast<uint32_t>(timestamp ^ std::hash<std::string>{}(fingerprint)));
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(rng() % 256);
        }
    } catch (...) {
        // Fallback: use timestamp-only seed if fingerprint fails
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        std::mt19937 rng(static_cast<uint32_t>(timestamp));
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(rng() % 256);
        }
    }
    
    return data;
}

bool SignatureRandomizer::ModifyPEOverlay(const std::wstring& filePath, const std::vector<uint8_t>& randomData) {
    SetLastError(L"DEBUG: ModifyPEOverlay opening file: " + filePath);
    
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 
                             FILE_SHARE_READ, nullptr, OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to open file for overlay modification: " + std::to_wstring(error) + L" (file: " + filePath + L")");
        return false;
    }
    
    SetLastError(L"DEBUG: File opened successfully, reading DOS header");
    
    // Read PE header to find end of file
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr)) {
        SetLastError(L"Failed to read DOS header: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(L"Invalid DOS signature: " + std::to_wstring(dosHeader.e_magic));
        CloseHandle(hFile);
        return false;
    }
    
    SetLastError(L"DEBUG: DOS header valid, reading NT headers at offset " + std::to_wstring(dosHeader.e_lfanew));
    
    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek to NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    IMAGE_NT_HEADERS ntHeaders;
    if (!ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr)) {
        SetLastError(L"Failed to read NT headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(L"Invalid NT signature: " + std::to_wstring(ntHeaders.Signature));
        CloseHandle(hFile);
        return false;
    }
    
    SetLastError(L"DEBUG: NT headers valid, calculating overlay offset");
    
    // Find the end of the PE file (after last section)
    DWORD overlayOffset = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + 
                         (ntHeaders.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    
    SetLastError(L"DEBUG: Initial overlay offset: " + std::to_wstring(overlayOffset) + L", sections: " + std::to_wstring(ntHeaders.FileHeader.NumberOfSections));
    
    // Find highest section end
    if (SetFilePointer(hFile, dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS), nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek to section headers: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader;
        if (ReadFile(hFile, &sectionHeader, sizeof(sectionHeader), &bytesRead, nullptr)) {
            DWORD sectionEnd = sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData;
            if (sectionEnd > overlayOffset) {
                overlayOffset = sectionEnd;
            }
        } else {
            SetLastError(L"Failed to read section header " + std::to_wstring(i) + L": " + std::to_wstring(::GetLastError()));
            CloseHandle(hFile);
            return false;
        }
    }
    
    SetLastError(L"DEBUG: Final overlay offset: " + std::to_wstring(overlayOffset));
    
    // Append random data as overlay
    if (SetFilePointer(hFile, overlayOffset, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek to overlay position: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    SetLastError(L"DEBUG: Writing signature header");
    
    // Write signature header
    const char* header = "LDR_DATA_";
    DWORD bytesWritten;
    if (!WriteFile(hFile, header, 9, &bytesWritten, nullptr)) {
        SetLastError(L"Failed to write signature header: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    SetLastError(L"DEBUG: Writing random data (" + std::to_wstring(randomData.size()) + L" bytes)");
    
    // Write random data
    if (!WriteFile(hFile, randomData.data(), static_cast<DWORD>(randomData.size()), &bytesWritten, nullptr)) {
        SetLastError(L"Failed to write random data: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    SetLastError(L"DEBUG: PE overlay modification completed successfully");
    CloseHandle(hFile);
    return true;
}

bool SignatureRandomizer::ModifyResourceSection(const std::wstring& filePath) {
    SetLastError(L"DEBUG: ModifyResourceSection started for: " + filePath);
    
    // Generate random data for dummy resources
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> numRes(MIN_DUMMY_RESOURCES, MAX_DUMMY_RESOURCES);
    std::uniform_int_distribution<> resSize(64, 512);
    std::uniform_int_distribution<> resId(1000, 9999);
    
    int numResources = numRes(gen);
    bool success = true;
    
    SetLastError(L"DEBUG: About to begin resource update for " + std::to_wstring(numResources) + L" resources");
    
    // Begin resource update
    HANDLE hUpdate = BeginUpdateResource(filePath.c_str(), FALSE);
    if (hUpdate == nullptr) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to begin resource update: " + std::to_wstring(error) + L" (file: " + filePath + L")");
        return false;
    }
    
    SetLastError(L"DEBUG: Resource update handle obtained successfully");
    
    for (int i = 0; i < numResources; ++i) {
        // Generate random resource data
        size_t dataSize = resSize(gen);
        auto resourceData = GenerateRandomData(dataSize);
        
        // Generate unique resource ID
        WORD resourceId = static_cast<WORD>(resId(gen) + i);
        
        // Add custom resource type "DATA" with random data
        if (!UpdateResource(hUpdate, L"DATA", MAKEINTRESOURCE(resourceId), 
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                           resourceData.data(), static_cast<DWORD>(resourceData.size()))) {
            SetLastError(L"Failed to update resource " + std::to_wstring(resourceId) + L": " + std::to_wstring(::GetLastError()));
            success = false;
            break;
        }
    }
    
    // Add version info modification - add a custom string
    std::wstring fingerprint = GetSystemFingerprint();
    std::wstring fpSubstr = fingerprint.length() >= 8 ? fingerprint.substr(0, 8) : fingerprint;
    std::wstring customString = L"Build-" + fpSubstr;
    if (success) {
        if (!UpdateResource(hUpdate, RT_STRING, MAKEINTRESOURCE(1001),
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                           const_cast<LPVOID>(static_cast<LPCVOID>(customString.c_str())), 
                           static_cast<DWORD>(customString.length() * sizeof(wchar_t)))) {
            SetLastError(L"Failed to update string resource: " + std::to_wstring(::GetLastError()));
            success = false;
        }
    }
    
    // Commit changes
    if (!EndUpdateResource(hUpdate, !success)) {
        SetLastError(L"Failed to commit resource changes: " + std::to_wstring(::GetLastError()));
        return false;
    }
    
    return success;
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

// MarkAsProcessed function removed - now using embedded hash method

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
                if (memcmp(&buffer[i], "LDR_DATA_", 9) == 0) {
                    CloseHandle(hFile);
                    return true;
                }
            }
        }
    }
    
    CloseHandle(hFile);
    return false;
}

std::wstring SignatureRandomizer::GetLastError() {
    return s_lastError;
}

void SignatureRandomizer::SetLastError(const std::wstring& error) {
    s_lastError = error;
}

bool SignatureRandomizer::CopyToTempLocation(const std::wstring& sourcePath, std::wstring& tempPath) {
    SetLastError(L"DEBUG: CopyToTempLocation started - using Windows TEMP folder");
    
    // Use Windows TEMP folder (like real installers do)
    wchar_t tempFolderPath[MAX_PATH];
    DWORD tempPathLen = GetTempPath(MAX_PATH, tempFolderPath);
    if (tempPathLen == 0 || tempPathLen > MAX_PATH) {
        SetLastError(L"Failed to get Windows TEMP path: " + std::to_wstring(::GetLastError()));
        return false;
    }
    
    // Remove trailing backslash if present
    std::wstring tempDir = std::wstring(tempFolderPath);
    if (tempDir.back() == L'\\') {
        tempDir.pop_back();
    }
    
    SetLastError(L"DEBUG: Using TEMP path: " + tempDir);
    
    SetLastError(L"DEBUG: Generating installer-like temp filename");
    
    // Use GetTempFileName for proper Windows temp file naming (like installers)
    wchar_t tempFileName[MAX_PATH];
    if (GetTempFileName(tempDir.c_str(), L"AML", 0, tempFileName) == 0) {
        SetLastError(L"Failed to generate temp filename: " + std::to_wstring(::GetLastError()));
        return false;
    }
    
    // GetTempFileName creates a .tmp file, we need to rename it to .exe
    // Delete the .tmp file first, then use the name with .exe extension
    DeleteFile(tempFileName);
    
    std::wstring tempFileNameStr = std::wstring(tempFileName);
    size_t lastDot = tempFileNameStr.find_last_of(L".");
    if (lastDot != std::wstring::npos) {
        tempPath = tempFileNameStr.substr(0, lastDot) + L".exe";
    } else {
        tempPath = tempFileNameStr + L".exe";
    }
    
    SetLastError(L"DEBUG: Generated temp filename: " + tempPath);
    
    SetLastError(L"DEBUG: Temp file path: " + tempPath);
    SetLastError(L"DEBUG: Starting file copy from: " + sourcePath);
    
    // Copy the file
    if (!CopyFile(sourcePath.c_str(), tempPath.c_str(), FALSE)) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to copy file to temp location: " + std::to_wstring(error));
        return false;
    }
    
    SetLastError(L"DEBUG: File copy completed successfully");
    return true;
}

bool SignatureRandomizer::ReplaceOriginalFile(const std::wstring& modifiedPath, const std::wstring& originalPath) {
    // Create backup name
    std::wstring backupPath = originalPath + L".backup";
    
    // Move original to backup
    if (!MoveFile(originalPath.c_str(), backupPath.c_str())) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to backup original file: " + std::to_wstring(error));
        return false;
    }
    
    // Move modified file to original location
    if (!MoveFile(modifiedPath.c_str(), originalPath.c_str())) {
        DWORD error = ::GetLastError();
        // Try to restore backup
        MoveFile(backupPath.c_str(), originalPath.c_str());
        SetLastError(L"Failed to replace original file: " + std::to_wstring(error));
        return false;
    }
    
    // Delete backup if successful
    DeleteFile(backupPath.c_str());
    
    return true;
}

bool SignatureRandomizer::CleanupTempFiles(const std::wstring& tempDir) {
    // This function can be used to clean up old temp files if needed
    // For now, just return true
    return true;
}

std::vector<uint8_t> SignatureRandomizer::CalculateFileHash(const std::wstring& filePath) {
    std::vector<uint8_t> hash;
    
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastError(L"Failed to open file for hash calculation: " + std::to_wstring(::GetLastError()));
        return hash;
    }
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        SetLastError(L"Failed to acquire crypto context: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return hash;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        SetLastError(L"Failed to create hash: " + std::to_wstring(::GetLastError()));
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return hash;
    }
    
    const DWORD BUFFER_SIZE = 8192;
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead;
    
    while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, nullptr) && bytesRead > 0) {
        if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
            SetLastError(L"Failed to hash data: " + std::to_wstring(::GetLastError()));
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return hash;
        }
    }
    
    DWORD hashSize = 20; // SHA1 is 20 bytes
    hash.resize(hashSize);
    
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashSize, 0)) {
        SetLastError(L"Failed to get hash value: " + std::to_wstring(::GetLastError()));
        hash.clear();
    }
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    
    return hash;
}

bool SignatureRandomizer::EmbedOriginalHash(const std::wstring& filePath, const std::vector<uint8_t>& hash) {
    SetLastError(L"DEBUG: EmbedOriginalHash starting for: " + filePath);
    
    // Retry logic for file access (AV might be scanning)
    HANDLE hFile = INVALID_HANDLE_VALUE;
    int retries = 5;
    
    for (int i = 0; i < retries; i++) {
        hFile = CreateFile(filePath.c_str(), GENERIC_READ | GENERIC_WRITE, 
                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 
                          FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            SetLastError(L"DEBUG: File opened successfully on attempt " + std::to_wstring(i + 1));
            break;
        }
        
        DWORD error = ::GetLastError();
        SetLastError(L"DEBUG: File open attempt " + std::to_wstring(i + 1) + L" failed with error: " + std::to_wstring(error));
        
        if (i < retries - 1) {
            Sleep(500); // Wait 500ms before retry
        }
    }
    
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to open file for hash embedding after " + std::to_wstring(retries) + L" attempts. Error: " + std::to_wstring(error));
        return false;
    }
    
    // Go to end of file
    if (SetFilePointer(hFile, 0, nullptr, FILE_END) == INVALID_SET_FILE_POINTER) {
        SetLastError(L"Failed to seek to end of file: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    // Write hash marker
    const char* marker = "HASH_EMBED_";
    DWORD bytesWritten;
    if (!WriteFile(hFile, marker, 11, &bytesWritten, nullptr)) {
        SetLastError(L"Failed to write hash marker: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    // Write hash data
    if (!WriteFile(hFile, hash.data(), static_cast<DWORD>(hash.size()), &bytesWritten, nullptr)) {
        SetLastError(L"Failed to write hash data: " + std::to_wstring(::GetLastError()));
        CloseHandle(hFile);
        return false;
    }
    
    CloseHandle(hFile);
    return true;
}

std::vector<uint8_t> SignatureRandomizer::ExtractEmbeddedHash(const std::wstring& filePath) {
    std::vector<uint8_t> hash;
    
    HANDLE hFile = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return hash;
    }
    
    // Get file size
    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize < 31) { // 11 (marker) + 20 (SHA1 hash)
        CloseHandle(hFile);
        return hash;
    }
    
    // Read last 31 bytes
    if (SetFilePointer(hFile, fileSize - 31, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        CloseHandle(hFile);
        return hash;
    }
    
    char buffer[31];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, 31, &bytesRead, nullptr) || bytesRead != 31) {
        CloseHandle(hFile);
        return hash;
    }
    
    // Check for marker
    if (memcmp(buffer, "HASH_EMBED_", 11) == 0) {
        hash.assign(buffer + 11, buffer + 31);
    }
    
    CloseHandle(hFile);
    return hash;
}

bool SignatureRandomizer::HasEmbeddedHash(const std::wstring& filePath) {
    return !ExtractEmbeddedHash(filePath).empty();
}

void SignatureRandomizer::CreateFallbackMarker() {
    // Simple fallback: create a small marker file next to executable
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileName(nullptr, exePath, MAX_PATH) > 0) {
        std::wstring markerPath = std::wstring(exePath) + L".processed";
        HANDLE hFile = CreateFile(markerPath.c_str(), GENERIC_WRITE, 0, nullptr, 
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* marker = "1";
            DWORD written;
            WriteFile(hFile, marker, 1, &written, nullptr);
            CloseHandle(hFile);
            SetLastError(L"DEBUG: Created fallback marker file: " + markerPath);
        }
    }
}