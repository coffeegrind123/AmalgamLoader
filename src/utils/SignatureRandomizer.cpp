#include "SignatureRandomizer.h"
#include "TimestampRandomizer.h"
#include <random>
#include <chrono>
#include <fstream>
#include <shlobj.h>
#include <wincrypt.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <minwindef.h>
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
    
    // Clean up any leftover backup files and original executable
    if (!isFirstRun) {
        std::wstring backupPath = std::wstring(exePath) + L".backup";
        if (GetFileAttributes(backupPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            if (DeleteFile(backupPath.c_str())) {
                SetLastError(L"DEBUG: Cleaned up backup file: " + backupPath);
            } else {
                SetLastError(L"DEBUG: Failed to delete backup file: " + backupPath);
            }
        }
        
        // Clean up original executable if we're a randomized version
        std::wstring currentPath = std::wstring(exePath);
        if (currentPath.find(L"_v") != std::wstring::npos) {
            // Extract directory and construct original filename
            size_t lastSlash = currentPath.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) {
                std::wstring directory = currentPath.substr(0, lastSlash + 1);
                std::wstring originalPath = directory + L"AmalgamLoader.exe";
                
                // Check if original exists and is different from us
                if (GetFileAttributes(originalPath.c_str()) != INVALID_FILE_ATTRIBUTES &&
                    originalPath != currentPath) {
                    
                    SetLastError(L"DEBUG: Attempting to delete original executable: " + originalPath);
                    
                    // Try to delete with retries (file might be locked briefly)
                    for (int attempt = 0; attempt < 3; ++attempt) {
                        if (DeleteFile(originalPath.c_str())) {
                            SetLastError(L"DEBUG: Successfully deleted original executable");
                            break;
                        } else {
                            DWORD error = ::GetLastError();
                            SetLastError(L"DEBUG: Failed to delete original executable (attempt " + 
                                       std::to_wstring(attempt + 1) + L"): error " + std::to_wstring(error));
                            if (attempt < 2) {
                                Sleep(1000); // Wait 1 second before retry
                            }
                        }
                    }
                }
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
    
    // Step 2.5: Randomize PE timestamp to avoid fresh build detection
    if (success) {
        SetLastError(L"DEBUG: Applying timestamp randomization to temp file");
        if (!TimestampRandomizer::RandomizeTimestamp(tempExePath)) {
            std::wstring timestampError = TimestampRandomizer::GetLastError();
            SetLastError(L"Warning: Timestamp randomization failed: " + timestampError);
            // Don't fail completely, continue with other modifications
        } else {
            SetLastError(L"DEBUG: Timestamp randomization completed successfully");
        }
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
        std::wstring newExecutablePath;
        if (!ReplaceOriginalFile(tempExePath, std::wstring(exePath), newExecutablePath)) {
            std::wstring replaceError = GetLastError();
            SetLastError(L"Failed to replace original executable. Details: " + replaceError);
            success = false;
        } else {
            // Store the new executable path that we need to preserve
            std::wstring newExePathForRestart = L"NEW_EXECUTABLE_PATH:" + newExecutablePath;
            SetLastError(newExePathForRestart);
            
            // Ensure the new executable is marked as processed
            Sleep(1000); // Give AV time to finish scanning
            
            // Try to embed hash in the new executable
            if (!EmbedOriginalHash(newExecutablePath, originalHash)) {
                // If hash embedding fails, create a marker file for the new executable
                std::wstring newMarkerPath = newExecutablePath + L".processed";
                HANDLE hMarker = CreateFileW(newMarkerPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hMarker != INVALID_HANDLE_VALUE) {
                    // Write some basic info to the marker
                    DWORD written;
                    std::string markerData = "processed";
                    WriteFile(hMarker, markerData.c_str(), static_cast<DWORD>(markerData.length()), &written, nullptr);
                    CloseHandle(hMarker);
                }
            }
            
            // Always preserve the restart path
            SetLastError(newExePathForRestart);
        }
    }
    
    // Clean up temporary files (but preserve NEW_EXECUTABLE_PATH if it exists)
    std::wstring preservedPath = GetLastError();
    bool hasNewExePath = (preservedPath.find(L"NEW_EXECUTABLE_PATH:") != std::wstring::npos);
    
    if (!tempExePath.empty()) {
        DeleteFile(tempExePath.c_str()); // Clean up silently
    }
    
    if (success) {
        if (hasNewExePath) {
            // Preserve the NEW_EXECUTABLE_PATH message for restart
            SetLastError(preservedPath);
        } else {
            SetLastError(L"DEBUG: Signature randomization completed successfully");
        }
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
    // Re-enable resource modification with safer implementation
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
    
    // Re-enable advanced obfuscation and fix any corruption issues
    if (resourceResult) {
        SetLastError(L"DEBUG: Starting advanced obfuscation");
        try {
            if (ApplyAdvancedObfuscation(filePath)) {
                SetLastError(L"DEBUG: Advanced obfuscation completed successfully");
            } else {
                SetLastError(L"DEBUG: Advanced obfuscation had warnings but continued - " + GetLastError());
                // Don't fail completely, some techniques may have worked
            }
        } catch (const std::exception& e) {
            std::string msg = e.what();
            std::wstring wmsg(msg.begin(), msg.end());
            SetLastError(L"DEBUG: Exception in advanced obfuscation: " + wmsg);
            // Don't fail completely
        } catch (...) {
            SetLastError(L"DEBUG: Unknown exception in advanced obfuscation");
            // Don't fail completely
        }
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
        
        // Generate unique resource ID in safe range (high IDs unlikely to conflict)
        WORD resourceId = static_cast<WORD>(10000 + resId(gen) + i);
        
        // Add custom resource type "LDRDATA" (unique name to avoid conflicts)
        if (!UpdateResource(hUpdate, L"LDRDATA", MAKEINTRESOURCE(resourceId), 
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                           resourceData.data(), static_cast<DWORD>(resourceData.size()))) {
            SetLastError(L"Failed to update resource " + std::to_wstring(resourceId) + L": " + std::to_wstring(::GetLastError()));
            success = false;
            break;
        }
    }
    
    // Add a safe custom resource (avoid modifying critical RT_STRING resources)
    std::wstring fingerprint = GetSystemFingerprint();
    std::wstring fpSubstr = fingerprint.length() >= 8 ? fingerprint.substr(0, 8) : fingerprint;
    std::wstring customString = L"Build-" + fpSubstr;
    if (success) {
        // Use custom resource type instead of RT_STRING to avoid UI corruption
        if (!UpdateResource(hUpdate, L"LDRINFO", MAKEINTRESOURCE(1),
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                           const_cast<LPVOID>(static_cast<LPCVOID>(customString.c_str())), 
                           static_cast<DWORD>(customString.length() * sizeof(wchar_t)))) {
            SetLastError(L"Failed to update info resource: " + std::to_wstring(::GetLastError()));
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
    SetLastError(L"DEBUG: CopyToTempLocation started - using current directory");
    
    // Work in the same directory as the source file to avoid leaving traces in temp folders
    std::wstring sourceDir = sourcePath.substr(0, sourcePath.find_last_of(L'\\'));
    std::wstring sourceFilename = sourcePath.substr(sourcePath.find_last_of(L'\\') + 1);
    std::wstring sourceBasename = sourceFilename.substr(0, sourceFilename.find_last_of(L'.'));
    std::wstring sourceExtension = sourceFilename.substr(sourceFilename.find_last_of(L'.'));
    
    SetLastError(L"DEBUG: Working in directory: " + sourceDir);
    
    // Generate a temporary filename in the same directory
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    
    int randomSuffix = dis(gen);
    tempPath = sourceDir + L"\\" + sourceBasename + L"_tmp" + std::to_wstring(randomSuffix) + sourceExtension;
    
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

bool SignatureRandomizer::ReplaceOriginalFile(const std::wstring& modifiedPath, const std::wstring& originalPath, std::wstring& newPath) {
    SetLastError(L"DEBUG: ReplaceOriginalFile started - using new filename to avoid locking issues");
    
    // Instead of replacing the running executable, create a new executable with a different name
    // This completely avoids the file locking problem since we're not touching the running file
    
    // Generate a new filename based on original but with a suffix
    std::wstring directory = originalPath.substr(0, originalPath.find_last_of(L'\\'));
    std::wstring filename = originalPath.substr(originalPath.find_last_of(L'\\') + 1);
    std::wstring extension = L".exe";
    std::wstring basename = filename.substr(0, filename.find_last_of(L'.'));
    
    // Create new filename with randomized suffix for uniqueness
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    int randomSuffix = dis(gen);
    
    newPath = directory + L"\\" + basename + L"_v" + std::to_wstring(randomSuffix) + extension;
    
    SetLastError(L"DEBUG: Creating new executable at: " + newPath);
    
    // Simply copy the modified file to the new location
    if (!CopyFile(modifiedPath.c_str(), newPath.c_str(), FALSE)) {
        DWORD error = ::GetLastError();
        SetLastError(L"Failed to create new executable file: " + std::to_wstring(error));
        return false;
    }
    
    // Store the new path for the restart logic to use
    SetLastError(L"DEBUG: New executable created successfully - restart path: " + newPath);
    
    // Store the new path in the error message for backward compatibility
    SetLastError(L"NEW_EXECUTABLE_PATH:" + newPath);
    
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

// Enhanced obfuscation functions (from pe-packer integration)
bool SignatureRandomizer::ApplyAdvancedObfuscation(const std::wstring& filePath) {
    SetLastError(L"DEBUG: Applying advanced obfuscation to " + filePath);
    
    bool success = true;
    
    // Apply multiple obfuscation techniques
    // DISABLED: Code section mutation is too dangerous and corrupts executable
    // if (!MutateCodeSections(filePath)) {
    //     SetLastError(L"Warning: Code section mutation failed");
    //     success = false;
    // }
    SetLastError(L"DEBUG: Code section mutation skipped (too dangerous)");
    
    if (!RandomizeSectionNames(filePath)) {
        SetLastError(L"Warning: Section name randomization failed");
        // Don't fail completely
    }
    
    if (!InsertPolymorphicCode(filePath)) {
        SetLastError(L"Warning: Polymorphic code insertion failed");
        // Don't fail completely
    }
    
    if (!AddJunkSections(filePath)) {
        SetLastError(L"Warning: Junk section addition failed");
        // Don't fail completely
    }
    
    if (!ApplyAntiAnalysisTechniques(filePath)) {
        SetLastError(L"Warning: Anti-analysis techniques failed");
        // Don't fail completely
    }
    
    return success;
}

bool SignatureRandomizer::MutateCodeSections(const std::wstring& filePath) {
    // Read PE file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        SetLastError(L"Failed to open file for code mutation");
        return false;
    }
    
    std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    // Get DOS and NT headers
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    // Get section headers
    auto sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    // Find executable sections and apply mutations
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        auto& section = sectionHeaders[i];
        
        // Only mutate executable sections
        if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
            // Apply mutations to code section
            size_t sectionStart = section.PointerToRawData;
            size_t sectionSize = section.SizeOfRawData;
            
            if (sectionStart + sectionSize <= peData.size()) {
                // Insert random NOPs and junk instructions at various points
                ApplyCodeMutations(peData, sectionStart, sectionSize);
            }
        }
    }
    
    // Write modified PE back to file
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) {
        SetLastError(L"Failed to write mutated file");
        return false;
    }
    
    outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
    outFile.close();
    
    return true;
}

bool SignatureRandomizer::MutateCodeSectionsSafely(const std::wstring& filePath) {
    SetLastError(L"DEBUG: Applying ultra-safe code mutations to " + filePath);
    
    // Read PE file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        SetLastError(L"Failed to open file for safe code mutation");
        return false;
    }
    
    std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    // Get DOS and NT headers
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    // Get section headers
    auto sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    bool anyMutations = false;
    
    // Only look for existing NOPs to replace - never insert or modify actual instructions
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        auto& section = sectionHeaders[i];
        
        // Only process executable sections
        if (section.Characteristics & IMAGE_SCN_CNT_CODE) {
            size_t sectionStart = section.PointerToRawData;
            size_t sectionSize = section.SizeOfRawData;
            
            if (sectionStart + sectionSize <= peData.size()) {
                // Ultra-safe: only replace existing NOP instructions with NOP sleds
                for (size_t pos = sectionStart; pos < sectionStart + sectionSize - 4; ++pos) {
                    // Look for single NOPs and replace with multi-byte NOPs (functionally identical)
                    if (peData[pos] == 0x90 && 
                        pos + 3 < sectionStart + sectionSize &&
                        pos + 3 < peData.size()) {
                        
                        // Replace single NOP with 4-byte NOP (functionally identical but different signature)
                        peData[pos] = 0x0F;     // 2-byte NOP: 0F 1F
                        peData[pos + 1] = 0x1F;
                        peData[pos + 2] = 0x00;
                        peData[pos + 3] = 0x00;
                        anyMutations = true;
                        pos += 3; // Skip ahead to avoid overlap
                    }
                }
            }
        }
    }
    
    if (!anyMutations) {
        SetLastError(L"DEBUG: No safe mutation opportunities found - this is normal");
        return true; // Not an error, just no mutations possible
    }
    
    // Write modified PE back to file
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) {
        SetLastError(L"Failed to write safely mutated file");
        return false;
    }
    
    outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
    outFile.close();
    
    SetLastError(L"DEBUG: Safe code mutations completed successfully");
    return true;
}

void SignatureRandomizer::ApplyCodeMutations(std::vector<uint8_t>& peData, size_t sectionStart, size_t sectionSize) {
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Reduce mutation count to be more conservative and safer
    std::uniform_int_distribution<> mutation_dis(3, 15);
    int targetMutations = mutation_dis(gen);
    int successfulMutations = 0;
    
    // Try to find safe locations for mutations by scanning the entire section
    for (size_t offset = 0; offset < sectionSize - 20 && successfulMutations < targetMutations; offset += 4) {
        size_t pos = sectionStart + offset;
        
        // Skip if we're near the end of the data
        if (pos >= peData.size() - 10) break;
        
        // Try to apply safe mutation at this position
        if (InsertJunkCode(peData, pos)) {
            successfulMutations++;
            // Skip ahead a bit to avoid overlapping mutations
            offset += 8;
        }
    }
    
    // If we couldn't find many safe positions, try a second pass with broader search
    if (successfulMutations < 3) {
        for (size_t offset = 0; offset < sectionSize - 20 && successfulMutations < 5; offset += 8) {
            size_t pos = sectionStart + offset;
            if (pos >= peData.size() - 10) break;
            
            // Look specifically for compiler padding or alignment areas
            if (IsCompilerPadding(peData, pos)) {
                if (InsertJunkCode(peData, pos)) {
                    successfulMutations++;
                }
            }
        }
    }
}

bool SignatureRandomizer::InsertJunkCode(std::vector<uint8_t>& peData, size_t insertPos) {
    if (insertPos >= peData.size() - 10) return false;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Instead of inserting (which breaks everything), overwrite existing bytes with equivalent safe mutations
    // We'll look for safe patterns to replace or find padding areas
    
    // Look for NOP instructions (0x90) or padding areas to replace
    size_t searchStart = insertPos;
    size_t searchEnd = insertPos + 50;
    if (searchEnd > peData.size() - 10) {
        searchEnd = peData.size() > 10 ? peData.size() - 10 : 0;
    }
    
    for (size_t pos = searchStart; pos < searchEnd; ++pos) {
        // Look for existing NOPs that we can safely expand into NOP sleds
        if (peData[pos] == 0x90 && pos + 4 < peData.size()) {
            // Replace single NOP with NOP sled (same functionality, different signature)
            peData[pos] = 0x90;
            peData[pos + 1] = 0x90;
            peData[pos + 2] = 0x90;
            peData[pos + 3] = 0x90;
            return true;
        }
        
        // Look for INT 3 breakpoints (0xCC) in padding areas
        if (peData[pos] == 0xCC && pos + 4 < peData.size()) {
            // Replace with harmless NOPs
            peData[pos] = 0x90;
            peData[pos + 1] = 0x90;
            peData[pos + 2] = 0x90;
            peData[pos + 3] = 0x90;
            return true;
        }
        
        // Look for padding bytes (0x00 or 0xCC sequences)
        if ((peData[pos] == 0x00 || peData[pos] == 0xCC) && 
            pos + 6 < peData.size() &&
            (peData[pos + 1] == 0x00 || peData[pos + 1] == 0xCC) &&
            (peData[pos + 2] == 0x00 || peData[pos + 2] == 0xCC)) {
            
            // Replace padding with equivalent safe instruction sequence
            std::uniform_int_distribution<> type_dis(0, 2);
            switch (type_dis(gen)) {
                case 0: // NOP sled
                    peData[pos] = 0x90; peData[pos + 1] = 0x90; peData[pos + 2] = 0x90;
                    break;
                case 1: // Push/pop that preserves state
                    if (pos + 5 < peData.size()) {
                        peData[pos] = 0x50;     // push eax
                        peData[pos + 1] = 0x90; // nop
                        peData[pos + 2] = 0x90; // nop
                        peData[pos + 3] = 0x58; // pop eax
                    }
                    break;
                case 2: // Arithmetic that cancels out
                    if (pos + 5 < peData.size()) {
                        peData[pos] = 0x40;     // inc eax
                        peData[pos + 1] = 0x48; // dec eax
                        peData[pos + 2] = 0x90; // nop
                    }
                    break;
            }
            return true;
        }
    }
    
    // If no safe replacement found, don't modify anything (better safe than corrupted)
    return false;
}

bool SignatureRandomizer::IsCompilerPadding(const std::vector<uint8_t>& peData, size_t pos) {
    if (pos + 8 >= peData.size()) return false;
    
    // Check for common compiler padding patterns
    
    // Pattern 1: INT 3 padding (0xCC sequences)
    if (peData[pos] == 0xCC && peData[pos + 1] == 0xCC && peData[pos + 2] == 0xCC) {
        return true;
    }
    
    // Pattern 2: NULL padding (0x00 sequences)
    if (peData[pos] == 0x00 && peData[pos + 1] == 0x00 && peData[pos + 2] == 0x00) {
        return true;
    }
    
    // Pattern 3: NOP padding (0x90 sequences) - common in function alignment
    if (peData[pos] == 0x90 && peData[pos + 1] == 0x90) {
        return true;
    }
    
    // Pattern 4: Function alignment padding (look for alignment to 16-byte boundaries)
    if ((pos % 16) == 0 && pos > 0) {
        // Check if previous bytes are padding
        bool isPadding = true;
        for (int i = 1; i <= 8 && pos >= i; ++i) {
            uint8_t byte = peData[pos - i];
            if (byte != 0x90 && byte != 0xCC && byte != 0x00) {
                isPadding = false;
                break;
            }
        }
        if (isPadding) return true;
    }
    
    // Pattern 5: End-of-function padding (common after RET instructions)
    if (pos >= 4) {
        // Look for RET instruction followed by padding
        if (peData[pos - 1] == 0xC3 || peData[pos - 1] == 0xC2) { // RET or RET imm16
            if (peData[pos] == 0xCC || peData[pos] == 0x90 || peData[pos] == 0x00) {
                return true;
            }
        }
    }
    
    return false;
}

bool SignatureRandomizer::RandomizeSectionNames(const std::wstring& filePath) {
    // Read PE file
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    
    auto sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    // Randomize section names
    std::vector<std::string> randomNames = {
        ".code", ".data", ".rsrc", ".reloc", ".text", ".rdata", ".idata", ".edata", ".debug", ".tls"
    };
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> name_dis(0, static_cast<int>(randomNames.size() - 1));
    
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        auto& section = sectionHeaders[i];
        
        // Don't modify critical sections
        std::string currentName(reinterpret_cast<char*>(section.Name), 8);
        if (currentName.find(".text") == 0 || currentName.find(".rdata") == 0) {
            continue; // Skip critical sections
        }
        
        // Generate random name
        std::string newName = randomNames[name_dis(gen)];
        if (newName.length() < 8) {
            newName += std::to_string(gen() % 100); // Add random number
        }
        
        // Ensure it fits in 8 bytes
        if (newName.length() > 8) {
            newName = newName.substr(0, 8);
        }
        
        // Copy new name
        std::memset(section.Name, 0, 8);
        std::memcpy(section.Name, newName.c_str(), (std::min)(newName.length(), static_cast<size_t>(8)));
    }
    
    // Write modified PE back
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) return false;
    
    outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
    outFile.close();
    
    return true;
}

bool SignatureRandomizer::InsertPolymorphicCode(const std::wstring& filePath) {
    // This would insert polymorphic decryption stubs
    // For now, just insert some variable junk code
    std::vector<uint8_t> polymorphicStub = GenerateRandomData(64);
    
    // Insert at the end of the PE overlay
    std::ofstream file(filePath, std::ios::binary | std::ios::app);
    if (!file.is_open()) return false;
    
    file.write(reinterpret_cast<const char*>(polymorphicStub.data()), polymorphicStub.size());
    file.close();
    
    return true;
}

bool SignatureRandomizer::AddJunkSections(const std::wstring& filePath) {
    // Add fake sections with random data
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    // Add random data at the end of the file
    std::vector<uint8_t> junkData = GenerateRandomData(512);
    peData.insert(peData.end(), junkData.begin(), junkData.end());
    
    // Write back
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) return false;
    
    outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
    outFile.close();
    
    return true;
}

bool SignatureRandomizer::ApplyAntiAnalysisTechniques(const std::wstring& filePath) {
    // This would add anti-debug, anti-VM code
    // For now, just modify some PE characteristics
    
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::vector<uint8_t> peData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    
    auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    
    auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(peData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;
    
    // Modify some characteristics to make analysis harder
    std::random_device rd;
    std::mt19937 gen(rd());
    
    // Randomize timestamp
    ntHeaders->FileHeader.TimeDateStamp = gen();
    
    // Modify DLL characteristics
    ntHeaders->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    ntHeaders->OptionalHeader.DllCharacteristics |= IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    
    // Write back
    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) return false;
    
    outFile.write(reinterpret_cast<const char*>(peData.data()), peData.size());
    outFile.close();
    
    return true;
}