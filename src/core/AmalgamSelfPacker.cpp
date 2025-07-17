#include "../include/stdafx.h"
#include "../include/SelfPacker.h"
#include "../include/Log.h"
#include "../include/Obfuscation.h"

// Static member initialization
bool AmalgamSelfPacker::s_protectionInitialized = false;
bool AmalgamSelfPacker::s_runtimeProtectionApplied = false;

bool AmalgamSelfPacker::InitializeEarlyProtection() {
    if (s_protectionInitialized) {
        return true;
    }
    
    xlog::Normal("Initializing SelfPacker early protection...");
    
    try {
        // Initialize SelfPacker runtime protection
        if (!SelfPacker::InitializeRuntimeModifications()) {
            xlog::Error("SelfPacker runtime initialization failed - this will cause application crash");
            return false;
        }
        
        // Apply enhanced detection for injection tools
        if (DetectInjectionAnalysis()) {
            xlog::Warning("Injection analysis environment detected - exiting safely");
            ExitProcess(0);
        }
        
        s_protectionInitialized = true;
        xlog::Normal("SelfPacker early protection initialized successfully");
        return true;
    }
    catch (const std::exception& ex) {
        xlog::Error("Exception during SelfPacker early protection initialization: %s", ex.what());
        return false;
    } catch (...) {
        xlog::Error("Unknown exception during SelfPacker early protection initialization");
        return false;
    }
}

bool AmalgamSelfPacker::ApplyRuntimeProtection() {
    if (!s_protectionInitialized) {
        xlog::Warning("Attempting runtime protection without early initialization");
        if (!InitializeEarlyProtection()) {
            return false;
        }
    }
    
    if (s_runtimeProtectionApplied) {
        return true;
    }
    
    xlog::Normal("Applying SelfPacker runtime protection...");
    
    try {
        // Apply first-run modifications
        if (!SelfPacker::ApplyFirstRunModifications()) {
            xlog::Warning("SelfPacker first-run modifications failed");
            return false;
        }
        
        // Apply injection-specific protections
        if (!ApplyInjectionProtection()) {
            xlog::Warning("Injection protection failed");
            return false;
        }
        
        s_runtimeProtectionApplied = true;
        xlog::Normal("SelfPacker runtime protection applied successfully");
        return true;
    }
    catch (...) {
        xlog::Error("Exception during SelfPacker runtime protection");
        return false;
    }
}

bool AmalgamSelfPacker::PackExecutableForDistribution(const std::wstring& inputFile, const std::wstring& outputFile) {
    xlog::Normal("Packing executable: %ws -> %ws", inputFile.c_str(), outputFile.c_str());
    
    try {
        std::string inputA = WStringToString(inputFile);
        std::string outputA = WStringToString(outputFile);
        
        bool result = SelfPacker::PackExecutable(inputA, outputA);
        
        if (result) {
            xlog::Normal("Executable packing completed successfully");
        } else {
            xlog::Error("Executable packing failed");
        }
        
        return result;
    }
    catch (const std::exception& ex) {
        xlog::Error("Exception during executable packing: %s", ex.what());
        return false;
    }
}

bool AmalgamSelfPacker::ApplyInjectionProtection() {
    xlog::Normal("Applying injection-specific protection...");
    
    try {
        // Enhanced sandbox detection for injection analysis
        if (DetectSandboxEnvironment()) {
            xlog::Warning("Sandbox environment detected");
            return false;
        }
        
        // Dynamic analysis detection
        if (DetectDynamicAnalysis()) {
            xlog::Warning("Dynamic analysis detected");
            return false;
        }
        
        // Apply additional runtime modifications for injection scenarios
        SelfPacker::randomize_section_names();
        SelfPacker::obfuscate_string_constants();
        
        xlog::Normal("Injection protection applied successfully");
        return true;
    }
    catch (...) {
        xlog::Error("Exception during injection protection");
        return false;
    }
}

bool AmalgamSelfPacker::IsProtectedEnvironment() {
    return s_protectionInitialized && s_runtimeProtectionApplied;
}

bool AmalgamSelfPacker::MutateDLLForInjection(const std::wstring& dllPath) {
    xlog::Normal("Applying mutations to DLL: %ws", dllPath.c_str());
    
    try {
        std::string dllPathA = WStringToString(dllPath);
        
        // Read DLL data
        auto dllData = SelfPacker::read_file(dllPathA);
        if (dllData.empty()) {
            xlog::Error("Failed to read DLL for mutation");
            return false;
        }
        
        // Apply code mutations to DLL
        SelfPacker::apply_code_mutations(dllData);
        
        // Write mutated DLL back
        std::ofstream outFile(dllPathA, std::ios::binary);
        if (!outFile.is_open()) {
            xlog::Error("Failed to write mutated DLL");
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(dllData.data()), dllData.size());
        outFile.close();
        
        xlog::Normal("DLL mutation completed successfully");
        return true;
    }
    catch (const std::exception& ex) {
        xlog::Error("Exception during DLL mutation: %s", ex.what());
        return false;
    }
}

bool AmalgamSelfPacker::DetectInjectionAnalysis() {
    // Enhanced detection specifically for injection tool analysis
    
    // Check for common injection analysis tools
    HMODULE modules[] = {
        GetModuleHandleA("dbghelp.dll"),
        GetModuleHandleA("ntdll.dll"),
        GetModuleHandleA("kernel32.dll")
    };
    
    // Check for suspicious module patterns
    for (auto module : modules) {
        if (module) {
            // Check for hooked functions commonly used in analysis
            auto ntCreateThread = GetProcAddress(module, "NtCreateThreadEx");
            auto createRemoteThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateRemoteThread");
            
            if (ntCreateThread && createRemoteThread) {
                // Basic hook detection - compare first bytes
                BYTE ntBytes[8] = {0};
                BYTE crtBytes[8] = {0};
                
                if (ReadProcessMemory(GetCurrentProcess(), ntCreateThread, ntBytes, 8, nullptr) &&
                    ReadProcessMemory(GetCurrentProcess(), createRemoteThread, crtBytes, 8, nullptr)) {
                    
                    // Look for jump instructions (0xE9, 0xE8, 0xFF25) that indicate hooks
                    if (ntBytes[0] == 0xE9 || ntBytes[0] == 0xE8 || 
                        (ntBytes[0] == 0xFF && ntBytes[1] == 0x25)) {
                        return true;
                    }
                }
            }
        }
    }
    
    // Use standard SelfPacker checks
    return SelfPacker::check_debugger() || SelfPacker::check_vm_environment() || SelfPacker::check_sandbox();
}

bool AmalgamSelfPacker::DetectSandboxEnvironment() {
    // Enhanced sandbox detection for injection scenarios
    
    // Check for sandbox-specific registry keys
    HKEY hKey;
    const char* sandboxKeys[] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie",
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\CurrentControlSet\\Services\\VBoxService"
    };
    
    for (const char* key : sandboxKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    
    // Check process count (sandboxes often have fewer processes)
    DWORD processes[1024];
    DWORD cbNeeded;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        DWORD processCount = cbNeeded / sizeof(DWORD);
        if (processCount < 30) { // Typical system has more than 30 processes
            return true;
        }
    }
    
    return SelfPacker::check_sandbox();
}

bool AmalgamSelfPacker::DetectDynamicAnalysis() {
    // Detect dynamic analysis tools commonly used for injection analysis
    
    // Check for analysis tool processes
    const wchar_t* analysisTools[] = {
        L"procmon.exe",
        L"procexp.exe", 
        L"wireshark.exe",
        L"fiddler.exe",
        L"ida.exe",
        L"ida64.exe",
        L"x32dbg.exe",
        L"x64dbg.exe",
        L"ollydbg.exe",
        L"apimonitor.exe",
        L"regshot.exe"
    };
    
    for (const wchar_t* tool : analysisTools) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, tool) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    // Check for debugger presence using timing (safer approach)
    DWORD startTime = GetTickCount();
    
    // Use __try/__except to handle debugbreak safely
    __try {
        __debugbreak(); // This will be skipped if no debugger
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Exception means no debugger attached
    }
    
    DWORD endTime = GetTickCount();
    
    // If debugger was present, this would take longer
    return (endTime - startTime) > 10;
}

std::string AmalgamSelfPacker::WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

std::wstring AmalgamSelfPacker::StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), nullptr, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}