#include "stdafx.h"

#include "MainDlg.h"
#include "DumpHandler.h"
#include "DriverExtract.h"
#include "SignatureRandomizer.h"
#include "TimestampRandomizer.h"
#include "SelfPacker/SelfPacker.h"
#include "../obfuscate.h"

#include <shellapi.h>

/// <summary>
/// Crash dump notify callback
/// </summary>
/// <param name="path">Dump file path</param>
/// <param name="context">User context</param>
/// <param name="expt">Exception info</param>
/// <param name="success">if false - crash dump file was not saved</param>
/// <returns>status</returns>
int DumpNotifier( const wchar_t* path, void* context, EXCEPTION_POINTERS* expt, bool success )
{
    Message::ShowError( NULL, L"Program has crashed. Dump file saved at '" + std::wstring( path ) + L"'" );
    return 0;
}

/// <summary>
/// Associate profile file extension
/// </summary>
void AssociateExtension()
{
    wchar_t tmp[255] = { 0 };
    GetModuleFileNameW( NULL, tmp, sizeof( tmp ) );

#ifdef USE64
    std::wstring ext = L".xpr64";
    std::wstring alias = L"LoaderProfile64";
    std::wstring desc = L"Loader 64-bit injection profile";
#else
    std::wstring ext = L".xpr";
    std::wstring alias = L"LoaderProfile";
    std::wstring desc = L"Loader injection profile";
#endif 
    std::wstring editWith = std::wstring( tmp ) + L" --load %1";
    std::wstring runWith = std::wstring( tmp ) + L" --run %1";
    std::wstring icon = std::wstring( tmp ) + L",-" + std::to_wstring( IDI_ICON1 );

    auto AddKey = []( const std::wstring& subkey, const std::wstring& value, const wchar_t* regValue ) {
        SHSetValue( HKEY_CLASSES_ROOT, subkey.c_str(), regValue, REG_SZ, value.c_str(), (DWORD)(value.size() * sizeof( wchar_t )) );
    };

    SHDeleteKeyW( HKEY_CLASSES_ROOT, alias.c_str() );

    AddKey( ext, alias, nullptr );
    AddKey( ext, L"Application/xml", L"Content Type" );
    AddKey( alias, desc, nullptr );
    AddKey( alias + L"\\shell", L"Run", nullptr );
    AddKey( alias + L"\\shell\\Edit\\command", editWith, nullptr );
    AddKey( alias + L"\\shell\\Run\\command", runWith, nullptr );
    AddKey( alias + L"\\DefaultIcon", icon, nullptr );
}

/// <summary>
/// Log major OS information
/// </summary>
void LogOSInfo()
{
    SYSTEM_INFO info = { 0 };
    const char* osArch = "x64";

    auto pPeb = (blackbone::PEB_T*)NtCurrentTeb()->ProcessEnvironmentBlock;
    GetNativeSystemInfo( &info );

    if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        osArch = "x86";

    xlog::Normal(
        "Started on Windows %d.%d.%d.%d %s. Driver status: 0x%X",
        pPeb->OSMajorVersion,
        pPeb->OSMinorVersion,
        (pPeb->OSCSDVersion >> 8) & 0xFF,
        pPeb->OSBuildNumber,
        osArch,
        blackbone::Driver().status()
        );
}

/// <summary>
/// Parse command line string
/// </summary>
/// <param name="param">Resulting param</param>
/// <returns>Profile action</returns>
MainDlg::StartAction ParseCmdLine( std::wstring& param )
{
    int argc = 0;
    auto pCmdLine = GetCommandLineW();
    auto argv = CommandLineToArgvW( pCmdLine, &argc );

    for (int i = 1; i < argc; i++)
    {
        if (_wcsicmp( argv[i], L"--load" ) == 0 && i + 1 < argc)
        {
            param = argv[i + 1];
            return MainDlg::LoadProfile;
        }
        if (_wcsicmp( argv[i], L"--run" ) == 0 && i + 1 < argc)
        {
            param = argv[i + 1];
            return MainDlg::RunProfile;
        }
    }

    return MainDlg::Nothing;
}

int APIENTRY wWinMain( HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, LPWSTR lpCmdLine, int /*nCmdShow*/ )
{
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
                                    srand((unsigned int)(GetTickCount() ^ GetCurrentProcessId()));
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
                    
                    // IMMEDIATELY terminate - no ExitProcess, no cleanup, just terminate
                    TerminateProcess(GetCurrentProcess(), 0);
                }
            }
        }
        
        // If we get here, the flag was found but parsing failed - still exit
        TerminateProcess(GetCurrentProcess(), 1);
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
                        TerminateProcess(GetCurrentProcess(), 1);
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
                    TerminateProcess(GetCurrentProcess(), 0);
                }
            }
        }
        
        LocalFree(argv);
    }
    
    // Normal application execution starts here
    
    // Initialize anti-analysis and self-protection
    if (!SelfPacker::InitializeRuntimeModifications()) {
        // Silent exit if analysis environment detected
        ExitProcess(0);
    }
    
    // Clean up old executable versions if this is a newer version
    wchar_t currentExePath[MAX_PATH];
    if (GetModuleFileName(nullptr, currentExePath, MAX_PATH) > 0) {
        std::wstring currentPath(currentExePath);
        if (currentPath.find(L"_v") != std::wstring::npos) {
            // This is a versioned executable, try to clean up the original
            std::wstring directory = currentPath.substr(0, currentPath.find_last_of(L'\\'));
            auto toWString = [](const char* str) {
                size_t len = strlen(str);
                std::wstring result(len, L'\0');
                mbstowcs_s(nullptr, &result[0], len + 1, str, len);
                return result;
            };
            std::wstring originalName = toWString(AY_OBFUSCATE("AmalgamLoader.exe"));
            std::wstring originalPath = directory + L"\\" + originalName;
            
            // Try to delete the original (it should be unlocked now)
            if (DeleteFile(originalPath.c_str())) {
                // Also try to rename this version to the original name for future use
                std::wstring newOriginalPath = originalPath;
                if (MoveFile(currentPath.c_str(), newOriginalPath.c_str())) {
                    // Successfully replaced original, restart with original name
                    STARTUPINFO si = { sizeof(si) };
                    PROCESS_INFORMATION pi = { 0 };
                    if (CreateProcess(newOriginalPath.c_str(), lpCmdLine, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        ExitProcess(0); // Exit this temporary version
                    }
                }
            }
        }
    }
    
    // Apply first-run self-modifications for AV evasion
    if (SignatureRandomizer::IsFirstRun()) {
        // Only apply signature randomization during build (includes timestamp randomization)
        // Full personalization (SelfPacker) should only run at runtime, not during build
        if (!SignatureRandomizer::RandomizeSignatures()) {
            // If randomization fails, still continue but create fallback marker
            SignatureRandomizer::CreateFallbackMarker();
        }
    }
    
    // Setup dump generation
    dump::DumpHandler::Instance().CreateWatchdog( blackbone::Utils::GetExeDirectory(), dump::CreateFullDump, &DumpNotifier );
    AssociateExtension();

    std::wstring param;
    auto action = ParseCmdLine( param );
    MainDlg mainDlg( action, param );
    LogOSInfo();

    if (action != MainDlg::RunProfile)
        return (int)mainDlg.RunModeless( NULL, IDR_ACCELERATOR1 );
    else
        return mainDlg.LoadAndInject();
}