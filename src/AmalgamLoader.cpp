#include "stdafx.h"
#include "Log.h"
// #include "DumpHandler.h"  // Disabled to prevent unnecessary dump files
#include "SignatureRandomizer.h"
#include "TimestampRandomizer.h"
#include "../obfuscate.h"
#include "../pclient.h"
#include <shellapi.h>
#include <set>
#include <thread>
#include <random>
#include <chrono>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_ICON 1
#define ID_TRAY_EXIT 1001

class AutoInject {
private:
    HWND _hWnd;
    NOTIFYICONDATA _nid;
    bool _running;
    HANDLE _monitorThread;
    std::wstring _targetDllPath;

public:
    AutoInject() : _running(false), _monitorThread(nullptr) {
        // Find DLL to inject (look for any DLL in current directory)
        wchar_t currentDir[MAX_PATH];
        GetModuleFileNameW(nullptr, currentDir, MAX_PATH);
        std::wstring currentDirStr(currentDir);
        size_t lastSlash = currentDirStr.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            currentDirStr = currentDirStr.substr(0, lastSlash);
        }
        _targetDllPath = FindDllInDirectory(currentDirStr);
        
        if (_targetDllPath.empty()) {
            // If no DLL found, we'll just exit
            xlog::Error("No DLL found to inject");
            exit(1);
        }
        
        xlog::Normal("Auto-injector targeting tf_win64.exe with DLL: %ls", _targetDllPath.c_str());
    }

    ~AutoInject() {
        if (_monitorThread) {
            _running = false;
            WaitForSingleObject(_monitorThread, 5000);
            CloseHandle(_monitorThread);
        }
        RemoveTrayIcon();
    }

    bool Initialize() {
        // Create invisible window for message handling
        WNDCLASS wc = {};
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = L"AutoInjectClass";
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        
        if (!RegisterClass(&wc)) {
            return false;
        }

        _hWnd = CreateWindow(L"AutoInjectClass", L"AutoInject", 0,
            0, 0, 0, 0, HWND_MESSAGE, nullptr, GetModuleHandle(nullptr), this);
        
        if (!_hWnd) {
            return false;
        }

        // Setup system tray icon
        if (!SetupTrayIcon()) {
            return false;
        }

        // Start monitoring thread
        _running = true;
        _monitorThread = CreateThread(nullptr, 0, MonitorThreadProc, this, 0, nullptr);
        
        return _monitorThread != nullptr;
    }

    void Run() {
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

private:
    std::vector<DWORD> EnumProcessesByName(const wchar_t* processName) {
        std::vector<DWORD> result;
        DWORD processes[1024];
        DWORD cbNeeded;
        
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD processCount = cbNeeded / sizeof(DWORD);
            
            for (DWORD i = 0; i < processCount; i++) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
                if (hProcess != nullptr) {
                    wchar_t processNameBuffer[MAX_PATH];
                    if (GetModuleBaseName(hProcess, nullptr, processNameBuffer, MAX_PATH)) {
                        if (_wcsicmp(processNameBuffer, processName) == 0) {
                            result.push_back(processes[i]);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        return result;
    }
    
    std::vector<DWORD> EnumAllProcesses() {
        std::vector<DWORD> result;
        DWORD processes[1024];
        DWORD cbNeeded;
        
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD processCount = cbNeeded / sizeof(DWORD);
            for (DWORD i = 0; i < processCount; i++) {
                result.push_back(processes[i]);
            }
        }
        return result;
    }

    std::wstring FindDllInDirectory(const std::wstring& directory) {
        WIN32_FIND_DATA findData;
        std::wstring searchPath = directory + L"\\*.dll";
        HANDLE hFind = FindFirstFile(searchPath.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            std::wstring dllPath = directory + L"\\" + findData.cFileName;
            FindClose(hFind);
            return dllPath;
        }
        
        return L"";
    }

    bool SetupTrayIcon() {
        memset(&_nid, 0, sizeof(_nid));
        _nid.cbSize = sizeof(_nid);
        _nid.hWnd = _hWnd;
        _nid.uID = ID_TRAY_ICON;
        _nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        _nid.uCallbackMessage = WM_TRAYICON;
        _nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION); // Use default application icon
        wcscpy_s(_nid.szTip, L"Auto TF2 Injector - Waiting for tf_win64.exe");

        return Shell_NotifyIcon(NIM_ADD, &_nid) != FALSE;
    }

    void RemoveTrayIcon() {
        Shell_NotifyIcon(NIM_DELETE, &_nid);
    }

    void UpdateTrayTooltip(const std::wstring& status) {
        wcscpy_s(_nid.szTip, status.c_str());
        Shell_NotifyIcon(NIM_MODIFY, &_nid);
    }

    static DWORD WINAPI MonitorThreadProc(LPVOID param) {
        AutoInject* self = static_cast<AutoInject*>(param);
        return self->MonitorProcess();
    }

    DWORD MonitorProcess() {
        std::set<DWORD> injectedPids;
        
        while (_running) {
            // Find tf_win64.exe processes
            auto toWString = [](const char* str) {
                size_t len = strlen(str);
                std::wstring result(len, L'\0');
                mbstowcs_s(nullptr, &result[0], len + 1, str, len);
                return result;
            };
            std::wstring processName = toWString(AY_OBFUSCATE("tf_win64.exe"));
            auto processes = EnumProcessesByName(processName.c_str());
            
            bool foundProcess = false;
            for (const auto& pid : processes) {
                foundProcess = true;
                
                // Check if we've already injected into this PID
                if (injectedPids.find(pid) == injectedPids.end()) {
                    xlog::Normal("Found new tf_win64.exe process with PID %d, waiting for initialization...", pid);
                    
                    // Enhanced process stability detection and initialization wait
                    bool processStillExists = true;
                    bool processStable = false;
                    int stableCount = 0;
                    const int REQUIRED_STABLE_CHECKS = 5; // Increased from 3 to 5
                    const int MAX_WAIT_TIME = 30000; // Increased to 30 seconds for better stability
                    
                    for (int waitTime = 0; waitTime < MAX_WAIT_TIME && processStillExists && !processStable; waitTime += 1000) {
                        Sleep(1000);
                        
                        // Enhanced process existence and stability check
                        HANDLE hCheck = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                        if (hCheck == nullptr) {
                            xlog::Warning("Process %d exited during initialization wait, skipping", pid);
                            processStillExists = false;
                            break;
                        }
                        
                        // Check if process has loaded critical TF2 modules (indicates readiness for injection)
                        HMODULE hMods[1024];
                        DWORD cbNeeded;
                        bool hasCriticalModules = false;
                        bool hasEngineModule = false;
                        
                        if (EnumProcessModules(hCheck, hMods, sizeof(hMods), &cbNeeded)) {
                            DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                            
                            // Check for specific TF2 modules that indicate readiness
                            for (DWORD i = 0; i < moduleCount; i++) {
                                wchar_t moduleName[MAX_PATH];
                                if (GetModuleBaseName(hCheck, hMods[i], moduleName, MAX_PATH)) {
                                    std::wstring moduleStr(moduleName);
                                    
                                    // Look for engine.dll - critical TF2 module
                                    if (moduleStr.find(L"engine.dll") != std::wstring::npos) {
                                        hasEngineModule = true;
                                        break;
                                    }
                                }
                            }
                            
                            // Process is ready if it has engine.dll and sufficient module count
                            if (hasEngineModule && moduleCount > 15) {
                                hasCriticalModules = true;
                            }
                        }
                        
                        CloseHandle(hCheck);
                        
                        if (hasCriticalModules) {
                            stableCount++;
                            xlog::Normal("Process %d stability check %d/%d passed (engine.dll loaded, modules ready)", pid, stableCount, REQUIRED_STABLE_CHECKS);
                            if (stableCount >= REQUIRED_STABLE_CHECKS) {
                                processStable = true;
                                xlog::Normal("Process %d determined to be stable and injection-ready after %d seconds", pid, waitTime / 1000);
                                
                                // Additional wait for anti-cheat initialization to complete
                                xlog::Normal("Waiting additional 3 seconds for anti-cheat initialization");
                                Sleep(3000);
                            }
                        } else {
                            stableCount = 0; // Reset counter if stability check fails
                            if (hasEngineModule) {
                                xlog::Normal("Process %d has engine.dll but insufficient modules loaded", pid);
                            } else {
                                xlog::Normal("Process %d still initializing (engine.dll not loaded yet)", pid);
                            }
                        }
                    }
                    
                    if (!processStillExists) {
                        continue; // Skip to next process
                    }
                    
                    if (!processStable) {
                        xlog::Warning("Process %d did not stabilize within %d seconds, skipping injection", pid, MAX_WAIT_TIME / 1000);
                        continue; // Skip injection if process never stabilized
                    }
                    
                    // Try injection with improved retry strategy - only if process is stable
                    bool injectionSuccess = false;
                    const int MAX_ATTEMPTS = 3; // Reduced back to 3 since we have better stability detection
                    const int baseDelay = 500; // Increased base delay
                    
                    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
                        // Verify process still exists before each attempt
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                        if (hProcess == nullptr) {
                            xlog::Warning("Process %d no longer exists, skipping injection", pid);
                            break;
                        }
                        CloseHandle(hProcess);
                        
                        xlog::Normal("Injection attempt %d/%d for PID %d", attempt, MAX_ATTEMPTS, pid);
                        
                        // Use simple injection
                        bool injectResult = InjectIntoProcess(pid);
                        
                        if (injectResult) {
                            injectedPids.insert(pid);
                            UpdateTrayTooltip(L"Auto TF2 Injector - Injected into tf_win64.exe");
                            xlog::Normal("Successfully injected into PID %d on attempt %d", pid, attempt);
                            injectionSuccess = true;
                            break;
                        } else {
                            xlog::Warning("Injection attempt %d failed for PID %d", attempt, pid);
                            if (attempt < MAX_ATTEMPTS) {
                                // Exponential backoff with randomization
                                int delay = baseDelay * (1 << (attempt - 1)); // 200ms, 400ms, 800ms, 1600ms
                                int randomOffset = rand() % 100; // Add 0-100ms random offset
                                delay += randomOffset;
                                
                                xlog::Normal("Waiting %dms before next attempt", delay);
                                Sleep(delay);
                                
                                // Double-check process still exists before next retry
                                HANDLE hRetryCheck = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                                if (hRetryCheck == nullptr) {
                                    xlog::Warning("Process %d died between retry attempts, aborting", pid);
                                    break;
                                }
                                CloseHandle(hRetryCheck);
                            }
                        }
                    }
                    
                    if (!injectionSuccess) {
                        xlog::Error("Failed to inject into PID %d after %d attempts", pid, MAX_ATTEMPTS);
                    }
                }
            }
            
            if (!foundProcess) {
                UpdateTrayTooltip(L"Auto TF2 Injector - Waiting for tf_win64.exe");
                
                // Clean up injected PIDs list of processes that no longer exist
                auto allProcesses = EnumAllProcesses();
                std::set<DWORD> currentPids;
                for (const auto& pid : allProcesses) {
                    currentPids.insert(pid);
                }
                
                // Remove PIDs that no longer exist
                auto it = injectedPids.begin();
                while (it != injectedPids.end()) {
                    if (currentPids.find(*it) == currentPids.end()) {
                        xlog::Normal("Process %d no longer exists, removing from tracking", *it);
                        it = injectedPids.erase(it);
                    } else {
                        ++it;
                    }
                }
                
                // Also clear the set if no TF2 processes exist to start fresh
                auto toWString = [](const char* str) {
                    size_t len = strlen(str);
                    std::wstring result(len, L'\0');
                    mbstowcs_s(nullptr, &result[0], len + 1, str, len);
                    return result;
                };
                std::wstring tf2ProcessName = toWString(AY_OBFUSCATE("tf_win64.exe"));
                auto tf2Processes = EnumProcessesByName(tf2ProcessName.c_str());
                if (tf2Processes.empty()) {
                    if (!injectedPids.empty()) {
                        xlog::Normal("No tf_win64.exe processes found, clearing injection tracking");
                        injectedPids.clear();
                    }
                }
            }
            
            Sleep(1000); // Check every second
        }
        
        return 0;
    }

    bool InjectIntoProcess(DWORD pid) {
        xlog::Normal("Using manual mapping injection for PID %d", pid);
        
        // Convert DLL path to char*
        std::string dllPathA;
        int requiredSize = WideCharToMultiByte(CP_UTF8, 0, _targetDllPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
        dllPathA.resize(requiredSize);
        WideCharToMultiByte(CP_UTF8, 0, _targetDllPath.c_str(), -1, &dllPathA[0], requiredSize, nullptr, nullptr);
        dllPathA.resize(strlen(dllPathA.c_str())); // Remove null terminator from resize
        
        xlog::Normal("Manual mapping DLL: %s", dllPathA.c_str());
        
        // Convert process name to wide string
        std::wstring processName = L"tf_win64.exe";
        
        // Use our manual mapping function
        int result = ManualMapInject(_targetDllPath.c_str(), processName.c_str());
        
        if (result == 0) {
            xlog::Normal("Manual mapping injection successful for PID %d", pid);
            return true;
        } else {
            xlog::Error("Manual mapping injection failed for PID %d, error code: %d", pid, result);
            return false;
        }
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        AutoInject* self = nullptr;
        
        if (msg == WM_CREATE) {
            CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
            self = static_cast<AutoInject*>(cs->lpCreateParams);
            SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<AutoInject*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
        }

        if (self) {
            return self->HandleMessage(hwnd, msg, wParam, lParam);
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_TRAYICON:
            if (lParam == WM_RBUTTONUP) {
                ShowContextMenu();
            }
            break;
        case WM_COMMAND:
            if (wParam == ID_TRAY_EXIT) {
                PostQuitMessage(0);
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        }
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    void ShowContextMenu() {
        POINT pt;
        GetCursorPos(&pt);
        
        HMENU hMenu = CreatePopupMenu();
        AppendMenu(hMenu, MF_STRING, ID_TRAY_EXIT, L"Exit");
        
        SetForegroundWindow(_hWnd);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, _hWnd, nullptr);
        PostMessage(_hWnd, WM_NULL, 0, 0);
        
        DestroyMenu(hMenu);
    }
};

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
    // Setup dump generation (disabled to prevent unnecessary dump files)
    // dump::DumpHandler::Instance().CreateWatchdog( blackbone::Utils::GetExeDirectory(), dump::CreateFullDump );
    
    // CRITICAL: Check for timestamp flag FIRST - before ANY other code execution
    LPWSTR cmdLine = GetCommandLineW();
    
    // Quick check for timestamp flag without complex parsing
    if (cmdLine && wcsstr(cmdLine, L"--randomize-timestamp")) {
        // Parse more carefully to get the target file
        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(cmdLine, &argc);
        
        if (argc >= 3) {
            for (int i = 1; i < argc - 1; i++) {
                if (_wcsicmp(argv[i], L"--randomize-timestamp") == 0) {
                    // Found the flag, next argument is the target file
                    std::wstring targetFile = argv[i + 1];
                    
                    // Wait a moment to ensure file is not locked
                    Sleep(100);
                    
                    // Try multiple times with different sharing modes to handle file locking
                    HANDLE hFile = INVALID_HANDLE_VALUE;
                    for (int attempt = 0; attempt < 5 && hFile == INVALID_HANDLE_VALUE; attempt++) {
                        hFile = CreateFileW(targetFile.c_str(), GENERIC_READ | GENERIC_WRITE, 
                                           FILE_SHARE_READ, nullptr, OPEN_EXISTING, 
                                           FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hFile == INVALID_HANDLE_VALUE) {
                            Sleep(200 * (attempt + 1)); // Exponential backoff
                        }
                    }
                    
                    if (hFile != INVALID_HANDLE_VALUE) {
                        IMAGE_DOS_HEADER dosHeader;
                        DWORD bytesRead;
                        if (ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) &&
                            dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                            
                            if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                                IMAGE_NT_HEADERS ntHeaders;
                                if (ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, nullptr) &&
                                    ntHeaders.Signature == IMAGE_NT_SIGNATURE) {
                                    
                                    // Store original timestamp
                                    DWORD originalTimestamp = ntHeaders.FileHeader.TimeDateStamp;
                                    
                                    // Generate random old timestamp (6 months to 2 years ago)
                                    auto now = std::chrono::high_resolution_clock::now();
                                    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
                                    srand(static_cast<unsigned int>((timestamp ^ GetCurrentProcessId()) & 0xFFFFFFFF));
                                    
                                    int daysAgo = 180 + (rand() % 550);
                                    int hoursOffset = rand() % 24;
                                    int minutesOffset = rand() % 60;
                                    
                                    time_t currentTime = time(nullptr);
                                    time_t oldTime = currentTime - (daysAgo * 24 * 60 * 60) - 
                                                   (hoursOffset * 60 * 60) - (minutesOffset * 60);
                                    
                                    ntHeaders.FileHeader.TimeDateStamp = (DWORD)oldTime;
                                    
                                    // Write back with verification
                                    if (SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                                        DWORD bytesWritten;
                                        if (WriteFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesWritten, nullptr)) {
                                            FlushFileBuffers(hFile);
                                        }
                                    }
                                }
                            }
                        }
                        CloseHandle(hFile);
                    }
                    
                    LocalFree(argv);
                    return 0; // Exit immediately after timestamp randomization
                }
            }
        }
        
        LocalFree(argv);
    }
    
    // Check for build-time pack flag
    if (cmdLine && wcsstr(cmdLine, L"--build-time-pack")) {
        // Parse more carefully to get the target file
        int argc = 0;
        wchar_t** argv = CommandLineToArgvW(cmdLine, &argc);
        
        if (argc >= 3) {
            for (int i = 1; i < argc - 1; i++) {
                if (_wcsicmp(argv[i], L"--build-time-pack") == 0) {
                    // Found the flag, next argument is the target file
                    std::wstring targetFile = argv[i + 1];
                    
                    // Perform build-time packing operations on the target file
                    // This does the packing without the firstrun renaming logic
                    
                    // Randomize the executable (overlay, resources, etc.)
                    if (!SignatureRandomizer::RandomizeExecutable(targetFile)) {
                        LocalFree(argv);
                        return 1; // Error randomizing executable
                    }
                    
                    // Randomize timestamp
                    if (!TimestampRandomizer::RandomizeTimestamp(targetFile)) {
                        // Non-fatal, continue
                    }
                    
                    // Find and randomize DLL in same directory
                    std::wstring exeDir = targetFile;
                    size_t lastSlash = exeDir.find_last_of(L"\\");
                    if (lastSlash != std::wstring::npos) {
                        exeDir = exeDir.substr(0, lastSlash + 1);
                    }
                    
                    // Convert obfuscated strings to wide strings
                    auto toWString = [](const char* str) {
                        size_t len = strlen(str);
                        std::wstring result(len, L'\0');
                        mbstowcs_s(nullptr, &result[0], len + 1, str, len);
                        return result;
                    };
                    
                    std::vector<std::wstring> dllPatterns = {
                        toWString(AY_OBFUSCATE("Amalgamx64Release.dll")), 
                        toWString(AY_OBFUSCATE("Amalgamx64Debug.dll")), 
                        toWString(AY_OBFUSCATE("AmalgamxRelease.dll")), 
                        toWString(AY_OBFUSCATE("Amalgam.dll"))
                    };
                    
                    for (const auto& pattern : dllPatterns) {
                        std::wstring dllPath = exeDir + pattern;
                        if (GetFileAttributes(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                            SignatureRandomizer::RandomizeDLL(dllPath);
                            break;
                        }
                    }
                    
                    LocalFree(argv);
                    return 0; // Exit immediately after build-time packing
                }
            }
        }
        
        LocalFree(argv);
    }
    
    // Perform first-run signature randomization
    bool isFirstRun = SignatureRandomizer::IsFirstRun();
    std::wstring debugInfo = SignatureRandomizer::GetLastError();
    xlog::Normal("Checking first run status: %s", isFirstRun ? "TRUE (first run)" : "FALSE (already processed)");
    xlog::Normal("Debug info: %ws", debugInfo.c_str());
    
    if (isFirstRun) {
        xlog::Normal("First run detected - randomizing signatures...");
        
        // Create a simple progress window that stays visible
        HWND progressHwnd = CreateWindowEx(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            L"STATIC",
            L"AmalgamLoader - First Run Setup",
            WS_POPUP | WS_BORDER | WS_VISIBLE,
            (GetSystemMetrics(SM_CXSCREEN) - 450) / 2,
            (GetSystemMetrics(SM_CYSCREEN) - 200) / 2,
            450, 200,
            nullptr, nullptr, hInstance, nullptr);
            
        if (progressHwnd) {
            // Create static text control for the message
            HWND textHwnd = CreateWindow(L"STATIC",
                L"First Run Setup\n\n"
                L"AmalgamLoader is personalizing itself for this system.\n"
                L"This creates unique signatures to avoid detection.\n\n"
                L"Steps:\n"
                L"* Copying executable to temp location...\n"
                L"* Modifying PE structure and resources...\n"
                L"* Replacing original with personalized version...\n"
                L"* Will restart automatically when complete...\n\n"
                L"Please wait, this may take 10-30 seconds...",
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                10, 10, 430, 180,
                progressHwnd, nullptr, hInstance, nullptr);
                
            UpdateWindow(progressHwnd);
            
            // Set font to make it more readable
            if (textHwnd) {
                HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                    DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
                SendMessage(textHwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
            }
        }
        
        xlog::Normal("About to call RandomizeSignatures()...");
        bool randomizeResult = false;
        
        try {
            randomizeResult = SignatureRandomizer::RandomizeSignatures();
        } catch (...) {
            xlog::Error("Exception occurred during RandomizeSignatures()");
        }
        
        std::wstring randomizeError = SignatureRandomizer::GetLastError();
        
        // Close the progress window
        if (progressHwnd) {
            DestroyWindow(progressHwnd);
        }
        
        xlog::Normal("RandomizeSignatures returned: %s", randomizeResult ? "SUCCESS" : "FAILED");
        xlog::Normal("Last debug message: %ws", randomizeError.c_str());
        xlog::Normal("Continuing with startup logic...");
        
        // For debugging, let's also check what the last PE modification error was
        if (!randomizeResult) {
            xlog::Normal("PE modification details: Will check temp files in %TEMP% folder");
        }
        
        if (randomizeResult) {
            xlog::Normal("Signature randomization completed successfully - attempting automatic restart");
            
            // Extract the new executable path from the error message
            std::wstring lastError = SignatureRandomizer::GetLastError();
            std::wstring newExecutablePath;
            
            size_t pathPos = lastError.find(L"NEW_EXECUTABLE_PATH:");
            if (pathPos != std::wstring::npos) {
                newExecutablePath = lastError.substr(pathPos + 20); // Skip "NEW_EXECUTABLE_PATH:"
                xlog::Normal("Found new executable path: %ws", newExecutablePath.c_str());
                
                // Give a small delay to ensure file operations are complete
                Sleep(1000);
                
                // Restart using the new executable
                STARTUPINFO si = { sizeof(si) };
                PROCESS_INFORMATION pi = { 0 };
                
                if (CreateProcess(newExecutablePath.c_str(), lpCmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    xlog::Normal("Application restarted successfully with new executable - exiting current instance");
                    return 0; // Exit current instance
                } else {
                    DWORD createProcessError = GetLastError();
                    xlog::Warning("Failed to restart with new executable (error %d) - trying fallback", createProcessError);
                    
                    // Fallback: log message about new executable path
                    xlog::Normal("AmalgamLoader has been personalized for this system. New executable: %ls", newExecutablePath.c_str());
                    return 0;
                }
            } else {
                xlog::Warning("Could not find new executable path in error message");
                xlog::Normal("AmalgamLoader has been personalized for this system. Please restart the application manually.");
                return 0;
            }
        } else {
            std::wstring error = SignatureRandomizer::GetLastError();
            xlog::Warning("Signature randomization failed: %ws - continuing anyway", error.c_str());
        }
    }
    
    xlog::Normal("AutoInject for tf_win64.exe starting...");

    AutoInject injector;
    
    if (!injector.Initialize()) {
        xlog::Error("Failed to initialize auto-injector");
        return 1;
    }

    xlog::Normal("Auto-injector initialized successfully");
    injector.Run();
    
    xlog::Normal("Auto-injector shutting down");
    return 0;
}