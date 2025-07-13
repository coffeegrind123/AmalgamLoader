#include "stdafx.h"
#include "InjectionCore.h"
#include "Log.h"
// #include "DumpHandler.h"  // Disabled to prevent unnecessary dump files
#include "resource.h"
#include "SignatureRandomizer.h"
#include <shellapi.h>
#include <set>

#define WM_TRAYICON (WM_USER + 1)
#define ID_TRAY_ICON 1
#define ID_TRAY_EXIT 1001

class AutoInject {
private:
    HWND _hWnd;
    NOTIFYICONDATA _nid;
    InjectionCore _core;
    bool _running;
    HANDLE _monitorThread;
    std::wstring _targetDllPath;

public:
    AutoInject() : _core(_hWnd), _running(false), _monitorThread(nullptr) {
        // Find DLL to inject (look for any DLL in current directory)
        auto currentDir = blackbone::Utils::GetExeDirectory();
        _targetDllPath = FindDllInDirectory(currentDir);
        
        if (_targetDllPath.empty()) {
            // If no DLL found, we'll just exit
            xlog::Error("No DLL found to inject");
            MessageBox(nullptr, L"No DLL found in current directory for injection", L"Error", MB_OK | MB_ICONERROR);
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
            auto processes = blackbone::Process::EnumByName(L"tf_win64.exe");
            
            bool foundProcess = false;
            for (const auto& pid : processes) {
                foundProcess = true;
                
                // Check if we've already injected into this PID
                if (injectedPids.find(pid) == injectedPids.end()) {
                    xlog::Normal("Found new tf_win64.exe process with PID %d, waiting for initialization...", pid);
                    
                    // Wait for game to initialize before injection
                    Sleep(8000); // 8 second delay for better stability
                    
                    // Try injection with retries
                    bool injectionSuccess = false;
                    for (int attempt = 1; attempt <= 3; attempt++) {
                        // Verify process still exists before each attempt
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                        if (hProcess == nullptr) {
                            xlog::Warning("Process %d no longer exists, skipping injection", pid);
                            break;
                        }
                        CloseHandle(hProcess);
                        
                        xlog::Normal("Injection attempt %d/3 for PID %d", attempt, pid);
                        
                        if (InjectIntoProcess(pid)) {
                            injectedPids.insert(pid);
                            UpdateTrayTooltip(L"Auto TF2 Injector - Injected into tf_win64.exe");
                            xlog::Normal("Successfully injected into PID %d on attempt %d", pid, attempt);
                            injectionSuccess = true;
                            break;
                        } else {
                            xlog::Warning("Injection attempt %d failed for PID %d", attempt, pid);
                            if (attempt < 3) {
                                Sleep(2000); // Wait 2 seconds between retries
                            }
                        }
                    }
                    
                    if (!injectionSuccess) {
                        xlog::Error("Failed to inject into PID %d after 3 attempts", pid);
                    }
                }
            }
            
            if (!foundProcess) {
                UpdateTrayTooltip(L"Auto TF2 Injector - Waiting for tf_win64.exe");
                
                // Clean up injected PIDs list of processes that no longer exist
                auto allProcesses = blackbone::Process::EnumByName(L"");
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
                auto tf2Processes = blackbone::Process::EnumByName(L"tf_win64.exe");
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
        // Verify process is still running before attempting injection
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess == nullptr) {
            xlog::Warning("Cannot inject into PID %d - process no longer exists", pid);
            return false;
        }
        CloseHandle(hProcess);
        
        // Create injection context
        InjectContext context;
        context.pid = pid;
        context.cfg.processMode = Existing;
        context.cfg.initRoutine.clear();
        context.cfg.initArgs = L"";
        context.cfg.delay = 0;
        context.cfg.period = 0;
        context.cfg.skipProc = 0;
        context.cfg.hijack = false;
        context.cfg.unlink = false;
        context.cfg.erasePE = false;
        context.cfg.krnHandle = false;

        // Load the DLL image
        auto img = std::make_shared<blackbone::pe::PEImage>();
        if (!NT_SUCCESS(img->Load(_targetDllPath))) {
            xlog::Error("Failed to load DLL image: %ls", _targetDllPath.c_str());
            return false;
        }

        context.images.push_back(img);

        // Use normal injection for maximum compatibility with thread-creating DLLs
        context.cfg.injectMode = Normal;
        context.cfg.mmapFlags = 0;
        NTSTATUS status = _core.InjectMultiple(&context);
        
        if (NT_SUCCESS(status)) {
            xlog::Normal("Normal injection successful for PID %d", pid);
            return true;
        }
        
        xlog::Error("Normal injection failed for PID %d, status: 0x%X", pid, status);
        return false;
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
    
    // Perform first-run signature randomization
    if (SignatureRandomizer::IsFirstRun()) {
        xlog::Normal("First run detected - randomizing signatures...");
        if (SignatureRandomizer::RandomizeSignatures()) {
            xlog::Normal("Signature randomization completed successfully");
            MessageBox(nullptr, L"AmalgamLoader has been personalized for this system.\nPlease restart the application.", 
                      L"First Run Complete", MB_OK | MB_ICONINFORMATION);
            return 0; // Exit and let user restart
        } else {
            xlog::Warning("Signature randomization failed - continuing anyway");
        }
    }
    
    xlog::Normal("AutoInject for tf_win64.exe starting...");

    AutoInject injector;
    
    if (!injector.Initialize()) {
        MessageBox(nullptr, L"Failed to initialize auto-injector", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    xlog::Normal("Auto-injector initialized successfully");
    injector.Run();
    
    xlog::Normal("Auto-injector shutting down");
    return 0;
}