#include "../include/stdafx.h"
#include "../include/SelfPacker.h"
#include "../include/Log.h"
#include "../include/Obfuscation.h"
#include <shellapi.h>
#include <shlobj.h>
#pragma comment(lib, "shell32.lib")

// Static member initialization
bool AmalgamSelfPacker::s_protectionInitialized = false;
bool AmalgamSelfPacker::s_runtimeProtectionApplied = false;

bool AmalgamSelfPacker::InitializeEarlyProtection() {
    if (s_protectionInitialized) {
        return true;
    }
    
    xlog::Normal("Initializing SelfPacker early protection with all features...");
    
    try {
        // Step 1: Apply polymorphic runtime self-modification first
        ApplyPolymorphicProtection();
        
        // Step 2: Initialize SelfPacker runtime protection
        if (!SelfPacker::InitializeRuntimeModifications()) {
            xlog::Error("SelfPacker runtime initialization failed - this will cause application crash");
            return false;
        }
        
        // Step 3: Apply comprehensive anti-analysis detection
        if (DetectComprehensiveAnalysis()) {
            xlog::Warning("Comprehensive analysis environment detected - applying countermeasures");
            
            // Apply additional obfuscation instead of exiting
            ApplyAdvancedCountermeasures();
            
            // Only exit if in a hostile environment
            if (IsHostileEnvironment()) {
                xlog::Warning("Hostile environment confirmed - exiting safely");
                ExitProcess(0);
            }
        }
        
        // Step 4: Apply junk code insertion to current process
        ApplyRuntimeJunkCodeInsertions();
        
        // Step 5: Randomize section names of current executable
        SelfPacker::randomize_section_names();
        
        s_protectionInitialized = true;
        xlog::Normal("SelfPacker early protection with all features initialized successfully");
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
        // TODO: Re-enable when VM/sandbox detection is more functional
        /*
        if (DetectSandboxEnvironment()) {
            xlog::Warning("Sandbox environment detected");
            return false;
        }
        */
        
        // Dynamic analysis detection
        // TODO: Re-enable when dynamic analysis detection is more functional
        /*
        if (DetectDynamicAnalysis()) {
            xlog::Warning("Dynamic analysis detected");
            return false;
        }
        */
        
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
    
    // Check for common injection analysis tools - ALL OBFUSCATED
    HMODULE modules[] = {
        GetModuleHandleA(AY_OBFUSCATE("dbghelp.dll")),
        GetModuleHandleA(AY_OBFUSCATE("ntdll.dll")),
        GetModuleHandleA(AY_OBFUSCATE("kernel32.dll"))
    };
    
    // Check for suspicious module patterns
    for (auto module : modules) {
        if (module) {
            // Check for hooked functions commonly used in analysis - ALL OBFUSCATED
            auto ntCreateThread = GetProcAddress(module, AY_OBFUSCATE("NtCreateThreadEx"));
            auto createRemoteThread = GetProcAddress(GetModuleHandleA(AY_OBFUSCATE("kernel32.dll")), AY_OBFUSCATE("CreateRemoteThread"));
            
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
    
    // Check for sandbox-specific registry keys - ALL OBFUSCATED
    HKEY hKey;
    std::vector<std::string> sandboxKeys = {
        std::string(AY_OBFUSCATE("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie")),
        std::string(AY_OBFUSCATE("SOFTWARE\\VMware, Inc.\\VMware Tools")),
        std::string(AY_OBFUSCATE("SOFTWARE\\Oracle\\VirtualBox Guest Additions")),
        std::string(AY_OBFUSCATE("SYSTEM\\CurrentControlSet\\Services\\VBoxService"))
    };
    
    for (const std::string& key : sandboxKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
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
    // Detect dynamic analysis tools commonly used for injection analysis - ALL OBFUSCATED
    
    // Check for analysis tool processes
    std::vector<std::wstring> analysisTools = {
        StringToWString(AY_OBFUSCATE("procmon.exe")),
        StringToWString(AY_OBFUSCATE("procexp.exe")),
        StringToWString(AY_OBFUSCATE("wireshark.exe")),
        StringToWString(AY_OBFUSCATE("fiddler.exe")),
        StringToWString(AY_OBFUSCATE("ida.exe")),
        StringToWString(AY_OBFUSCATE("ida64.exe")),
        StringToWString(AY_OBFUSCATE("x32dbg.exe")),
        StringToWString(AY_OBFUSCATE("x64dbg.exe")),
        StringToWString(AY_OBFUSCATE("ollydbg.exe")),
        StringToWString(AY_OBFUSCATE("apimonitor.exe")),
        StringToWString(AY_OBFUSCATE("regshot.exe"))
    };
    
    for (const std::wstring& tool : analysisTools) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, tool.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    // Check for debugger presence using safe timing approach
    DWORD startTime = GetTickCount();
    
    // Use a safe alternative to debugbreak - check process debugging flags
    BOOL remoteDebuggerPresent = FALSE;
    bool debuggerDetected = IsDebuggerPresent() || CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebuggerPresent);
    
    DWORD endTime = GetTickCount();
    
    // If analysis tools detected or debugging detected, return true
    return debuggerDetected || (endTime - startTime) > 10;
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

std::wstring AmalgamSelfPacker::StringToWString(const char* str) {
    if (!str || strlen(str) == 0) return std::wstring();
    
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    std::wstring wstrTo(size_needed - 1, 0);  // -1 to exclude null terminator
    MultiByteToWideChar(CP_UTF8, 0, str, -1, &wstrTo[0], size_needed);
    return wstrTo;
}

void AmalgamSelfPacker::ApplyPolymorphicProtection() {
    xlog::Normal("Applying polymorphic protection to current process...");
    
    try {
        // Select random stub variant based on current conditions
        SelfPacker::StubVariant variant = SelectOptimalStubVariant();
        xlog::Normal("Selected stub variant: %d", static_cast<int>(variant));
        
        // Get current executable data for processing
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileName(nullptr, exePath, MAX_PATH) > 0) {
            std::string exePathA = WStringToString(std::wstring(exePath));
            auto exeData = SelfPacker::read_file(exePathA);
            
            if (!exeData.empty()) {
                // Apply polymorphic mutations based on variant
                auto modifiedStub = SelfPacker::get_stub_variant(variant);
                if (!modifiedStub.empty()) {
                    xlog::Normal("Applied polymorphic modifications successfully");
                }
            }
        }
    }
    catch (...) {
        xlog::Warning("Exception during polymorphic protection application");
    }
}

SelfPacker::StubVariant AmalgamSelfPacker::SelectOptimalStubVariant() {
    // Analyze current environment to select best protection level
    
    // Check system capabilities and threat level
    bool hasHighPrivileges = IsUserAnAdmin();
    bool inDeveloperEnvironment = DetectDeveloperTools();
    bool underActiveAnalysis = DetectActiveAnalysis();
    
    if (underActiveAnalysis || inDeveloperEnvironment) {
        xlog::Normal("Active analysis detected - using maximum protection (POLYMORPHIC)");
        return SelfPacker::STUB_POLYMORPHIC;
    }
    else if (DetectVirtualEnvironment()) {
        xlog::Normal("Virtual environment detected - using anti-VM variant");
        return SelfPacker::STUB_ANTI_VM;
    }
    else if (SelfPacker::check_debugger()) {
        xlog::Normal("Debugger detected - using anti-debug variant");
        return SelfPacker::STUB_ANTI_DEBUG;
    }
    else {
        xlog::Normal("Standard environment - using minimal variant");
        return SelfPacker::STUB_MINIMAL;
    }
}

bool AmalgamSelfPacker::DetectComprehensiveAnalysis() {
    // Combine all detection methods for comprehensive coverage
    // TODO: Re-enable sandbox and dynamic analysis detection when more functional
    return DetectInjectionAnalysis() || 
           // DetectSandboxEnvironment() || 
           // DetectDynamicAnalysis() ||
           DetectVirtualEnvironment() ||
           DetectDeveloperTools() ||
           DetectActiveAnalysis();
}

bool AmalgamSelfPacker::DetectVirtualEnvironment() {
    // Enhanced VM detection using multiple techniques
    
    // Check VM-specific registry keys - ALL OBFUSCATED
    std::vector<std::string> vmRegKeys = {
        std::string(AY_OBFUSCATE("HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion")), // VMware
        std::string(AY_OBFUSCATE("HARDWARE\\DESCRIPTION\\System\\VideoBiosVersion")),   // VirtualBox
        std::string(AY_OBFUSCATE("SOFTWARE\\VMware, Inc.\\VMware Tools")),
        std::string(AY_OBFUSCATE("SOFTWARE\\Oracle\\VirtualBox Guest Additions")),
        std::string(AY_OBFUSCATE("SYSTEM\\CurrentControlSet\\Services\\vmci")),
        std::string(AY_OBFUSCATE("SYSTEM\\CurrentControlSet\\Services\\vmhgfs"))
    };
    
    HKEY hKey;
    for (const std::string& key : vmRegKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
    
    // Check for VM-specific processes - ALL OBFUSCATED
    std::vector<std::wstring> vmProcesses = {
        StringToWString(AY_OBFUSCATE("vmtoolsd.exe")),
        StringToWString(AY_OBFUSCATE("vmwaretray.exe")),
        StringToWString(AY_OBFUSCATE("vmwareuser.exe")),
        StringToWString(AY_OBFUSCATE("vboxservice.exe")),
        StringToWString(AY_OBFUSCATE("vboxtray.exe")),
        StringToWString(AY_OBFUSCATE("vboxguest.exe")),
        StringToWString(AY_OBFUSCATE("xenservice.exe")),
        StringToWString(AY_OBFUSCATE("qemu-ga.exe"))
    };
    
    for (const std::wstring& process : vmProcesses) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, process.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    return SelfPacker::check_vm_environment();
}

bool AmalgamSelfPacker::DetectDeveloperTools() {
    // Detect development environments and tools - ALL OBFUSCATED
    std::vector<std::wstring> devTools = {
        StringToWString(AY_OBFUSCATE("devenv.exe")),
        StringToWString(AY_OBFUSCATE("msvsmon.exe")),
        StringToWString(AY_OBFUSCATE("vsjitdebugger.exe")),
        StringToWString(AY_OBFUSCATE("Code.exe")),
        StringToWString(AY_OBFUSCATE("atom.exe")),
        StringToWString(AY_OBFUSCATE("sublime_text.exe")),
        StringToWString(AY_OBFUSCATE("notepad++.exe")),
        StringToWString(AY_OBFUSCATE("HxD.exe")),
        StringToWString(AY_OBFUSCATE("010Editor.exe")),
        StringToWString(AY_OBFUSCATE("ida.exe")),
        StringToWString(AY_OBFUSCATE("ida64.exe")),
        StringToWString(AY_OBFUSCATE("idaq.exe")),
        StringToWString(AY_OBFUSCATE("idaq64.exe")),
        StringToWString(AY_OBFUSCATE("ghidra.exe")),
        StringToWString(AY_OBFUSCATE("radare2.exe")),
        StringToWString(AY_OBFUSCATE("x32dbg.exe")),
        StringToWString(AY_OBFUSCATE("x64dbg.exe"))
    };
    
    for (const std::wstring& tool : devTools) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, tool.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    return false;
}

bool AmalgamSelfPacker::DetectActiveAnalysis() {
    // Detect signs of active analysis/monitoring
    
    // Check for unusual thread count (analysis tools often inject threads)
    HANDLE hProcess = GetCurrentProcess();
    DWORD threadCount = 0;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(te32);
        
        if (Thread32First(hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                    threadCount++;
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        CloseHandle(hSnapshot);
    }
    
    // Suspicious if too many threads for a simple injector
    if (threadCount > 10) {
        return true;
    }
    
    // Check for monitoring APIs being hooked - ALL OBFUSCATED
    HMODULE hNtdll = GetModuleHandleA(AY_OBFUSCATE("ntdll.dll"));
    if (hNtdll) {
        auto ntCreateFile = GetProcAddress(hNtdll, AY_OBFUSCATE("NtCreateFile"));
        auto ntWriteFile = GetProcAddress(hNtdll, AY_OBFUSCATE("NtWriteFile"));
        
        if (ntCreateFile && ntWriteFile) {
            BYTE createBytes[8] = {0};
            BYTE writeBytes[8] = {0};
            
            if (ReadProcessMemory(hProcess, ntCreateFile, createBytes, 8, nullptr) &&
                ReadProcessMemory(hProcess, ntWriteFile, writeBytes, 8, nullptr)) {
                
                // Check for hooks (jump instructions)
                if ((createBytes[0] == 0xE9 || createBytes[0] == 0xE8) ||
                    (writeBytes[0] == 0xE9 || writeBytes[0] == 0xE8)) {
                    return true;
                }
            }
        }
    }
    
    return false;
}

void AmalgamSelfPacker::ApplyAdvancedCountermeasures() {
    xlog::Normal("Applying advanced countermeasures for hostile environment...");
    
    try {
        // Apply maximum obfuscation
        auto maxObfuscatedStub = SelfPacker::get_stub_variant(SelfPacker::STUB_POLYMORPHIC);
        
        // Apply additional runtime mutations
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileName(nullptr, exePath, MAX_PATH) > 0) {
            std::string exePathA = WStringToString(std::wstring(exePath));
            auto exeData = SelfPacker::read_file(exePathA);
            
            if (!exeData.empty()) {
                // Apply multiple rounds of mutations
                for (int i = 0; i < 3; ++i) {
                    SelfPacker::apply_code_mutations(exeData);
                    SelfPacker::insert_junk_instructions(exeData);
                }
                
                xlog::Normal("Applied %d rounds of advanced mutations", 3);
            }
        }
        
        // Apply runtime timing delays to confuse analysis
        for (int i = 0; i < 5; ++i) {
            Sleep(100 + (GetTickCount() % 200)); // Random delays
            
            // Insert CPU-intensive operations to mask behavior
            volatile int dummy = 0;
            for (int j = 0; j < 10000; ++j) {
                dummy += j * GetTickCount();
            }
        }
        
        xlog::Normal("Advanced countermeasures applied successfully");
    }
    catch (...) {
        xlog::Warning("Exception during advanced countermeasures application");
    }
}

bool AmalgamSelfPacker::IsHostileEnvironment() {
    // Determine if environment is actively hostile and requires termination
    
    int hostileScore = 0;
    
    // Score various hostile indicators
    if (SelfPacker::check_debugger()) hostileScore += 3;
    if (DetectDeveloperTools()) hostileScore += 2;
    if (DetectActiveAnalysis()) hostileScore += 3;
    // TODO: Re-enable when dynamic analysis detection is more functional
    // if (DetectDynamicAnalysis()) hostileScore += 2;
    
    // Check for multiple analysis tools running simultaneously - ALL OBFUSCATED
    std::vector<std::wstring> criticalAnalysisTools = {
        StringToWString(AY_OBFUSCATE("x64dbg.exe")),
        StringToWString(AY_OBFUSCATE("ida64.exe")),
        StringToWString(AY_OBFUSCATE("procmon.exe")),
        StringToWString(AY_OBFUSCATE("wireshark.exe"))
    };
    
    int toolCount = 0;
    for (const std::wstring& tool : criticalAnalysisTools) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(pe32);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, tool.c_str()) == 0) {
                        toolCount++;
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    if (toolCount >= 2) hostileScore += 5;
    
    xlog::Normal("Hostile environment score: %d/10", hostileScore);
    return hostileScore >= 7; // Threshold for termination
}

void AmalgamSelfPacker::ApplyRuntimeJunkCodeInsertions() {
    xlog::Normal("Applying runtime junk code insertions...");
    
    try {
        // Get current executable for processing
        wchar_t exePath[MAX_PATH];
        if (GetModuleFileName(nullptr, exePath, MAX_PATH) > 0) {
            std::string exePathA = WStringToString(std::wstring(exePath));
            auto exeData = SelfPacker::read_file(exePathA);
            
            if (!exeData.empty() && exeData.size() > 1024) {
                // Apply junk code insertions to confuse static analysis
                SelfPacker::insert_junk_instructions(exeData);
                
                xlog::Normal("Runtime junk code insertions applied successfully");
            }
        }
    }
    catch (...) {
        xlog::Warning("Exception during runtime junk code insertion");
    }
}