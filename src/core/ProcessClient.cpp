// AmalgamLoader Manual Mapping Implementation
// Following the JaRm Manual Mapping Tutorial (https://github.com/JaRm-/Manual-Mapping-Tutorial)
// 
// Manual Mapping Process (5 Steps):
// 1. Mapping the DLL Sections into Memory
// 2. Handling Relocations  
// 3. Handling Imports
// 4. Execute TLS Callbacks (Thread Local Storage)
// 5. Call DLL Main
//
// Steps 3-5 are carried out by injecting position-independent code into the remote process

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <cstring>
#include "../include/StringObfuscation.h"
#include "../include/Log.h"

// Function pointer types for LoadLibraryA and GetProcAddress
// These will be passed to the remote process since it can't directly call these functions
typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

// DLL entry point function signature
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Data structure passed to the remote process containing all necessary information
// for manual mapping. This is the "mp" parameter referenced in the tutorial.
typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;                        // Base address where DLL is mapped in target process
    PIMAGE_NT_HEADERS NtHeaders;           // Pointer to NT headers in target process
    PIMAGE_BASE_RELOCATION BaseRelocation; // Pointer to relocation table in target process
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory; // Pointer to import table in target process
    pLoadLibraryA fnLoadLibraryA;          // Function pointer to LoadLibraryA in target process
    pGetProcAddress fnGetProcAddress;      // Function pointer to GetProcAddress in target process
    HINSTANCE hMod;                        // Status reporting field for debugging (as per tutorial)
}MANUAL_INJECT, * PMANUAL_INJECT;

// Helper function for 64-bit module resolution
HMODULE ManualGetModuleHandle64(const char* moduleName) {
	return GetModuleHandleA(moduleName);
}

// ============================================================================
// POSITION-INDEPENDENT SHELLCODE FUNCTION
// ============================================================================
// This function is executed in the target process via CreateRemoteThread
// It performs steps 2-5 of the manual mapping process:
// - Handle relocations
// - Handle imports  
// - Execute TLS callbacks
// - Call DLL main
//
// CRITICAL: This function must be position-independent (no external calls)
// All needed functions are provided via the MANUAL_INJECT structure
// ============================================================================
DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD64 i, Function, count, delta;
	
	DWORD64* ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	// Validate input parameter - return FALSE if invalid
	if (!ManualInject) {
		return FALSE;
	}

	// ====================================================================
	// STEP 2: HANDLE RELOCATIONS
	// ====================================================================
	// Every PE file has a preferred ImageBase address it wants to be loaded at.
	// If we can't load it there, we need to fix up absolute addresses using
	// the base relocation table. This applies the "delta" (difference between
	// preferred and actual load address) to all absolute addresses.
	
	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD64)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

	// Only process relocations if they exist and delta is not zero
	if (pIBR && delta != 0)
	{
		// Each relocation block contains multiple relocation entries
		while (pIBR->VirtualAddress)
		{
			if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
			{
				// Calculate number of relocations in this block
				// Each relocation entry is 2 bytes (WORD), subtract the 8-byte block header
				count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				list = (PWORD)(pIBR + 1); // Point to first relocation entry after header

				// Process each relocation entry in this block
				for (i = 0; i < count; i++)
				{
					if (list[i])
					{
						// Extract relocation type (upper 4 bits) and offset (lower 12 bits)
						WORD type = (list[i] >> 12) & 0xF;
						WORD offset = list[i] & 0xFFF;
						
						// For 64-bit, we only handle IMAGE_REL_BASED_DIR64 relocations
						if (type == IMAGE_REL_BASED_DIR64)
						{
							// Apply delta to the 64-bit address at this location
							ptr = (DWORD64*)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + offset));
							*ptr += delta;
						}
						// Ignore other relocation types for 64-bit loader
					}
				}
			}

			// Move to next relocation block
			pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
		}
	}

	// ====================================================================
	// STEP 3: HANDLE IMPORTS
	// ====================================================================
	// The DLL needs to import functions from other DLLs (like kernel32.dll).
	// We need to:
	// 1. Load each required DLL using LoadLibraryA
	// 2. Get addresses of imported functions using GetProcAddress
	// 3. Update the Import Address Table (IAT) with these addresses
	//
	// OriginalFirstThunk = Import Name Table (function names/ordinals)
	// FirstThunk = Import Address Table (gets filled with actual addresses)
	
	pIID = ManualInject->ImportDirectory;

	// Process imports only if import directory exists
	if (pIID)
	{
		// Loop through each DLL that needs to be imported
		while (pIID->Name)
		{
			// Get pointers to the thunk tables (as shown in tutorial)
			DWORD64* pThunk = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
			DWORD64* pFunc = (DWORD64*)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

			// If OriginalFirstThunk not defined, use FirstThunk (as per tutorial)
			if (!pThunk) { pThunk = pFunc; }

			// Load the required DLL module
			char* importName = (char*)((LPBYTE)ManualInject->ImageBase + pIID->Name);
			hModule = ManualInject->fnLoadLibraryA(importName);

			if (!hModule)
			{
				ManualInject->hMod = (HINSTANCE)0x404; // Module loading failed
				return FALSE;
			}

			// Process each function import in this DLL (as per tutorial)
			for (; *pThunk; ++pThunk, ++pFunc)
			{
				if (*pThunk & IMAGE_ORDINAL_FLAG64)
				{
					// Import by ordinal (64-bit) - function imported by number
					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(*pThunk & 0xFFFF));
					if (!Function)
					{
						ManualInject->hMod = (HINSTANCE)0x405; // Ordinal import failed
						return FALSE;
					}
					*pFunc = Function; // Update IAT with function address
				}
				else
				{
					// Import by name (64-bit) - function imported by name
					pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + *pThunk);
					Function = (DWORD64)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
					if (!Function)
					{
						ManualInject->hMod = (HINSTANCE)0x406; // Name import failed
						return FALSE;
					}
					*pFunc = Function; // Update IAT with function address
				}
			}

			pIID++; // Move to next import descriptor
		}
	}

	// ====================================================================
	// STEP 4: EXECUTE TLS CALLBACKS
	// ====================================================================
	// Thread Local Storage (TLS) callbacks are executed before DLL main.
	// These are used for thread-specific initialization. Some malware uses
	// TLS callbacks to execute code before debuggers detect the main entry point.
	
	if (ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		PIMAGE_TLS_DIRECTORY64 pTLS = (PIMAGE_TLS_DIRECTORY64)((LPBYTE)ManualInject->ImageBase + 
			ManualInject->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		
		if (pTLS && pTLS->AddressOfCallBacks)
		{
			PIMAGE_TLS_CALLBACK* pCallback = (PIMAGE_TLS_CALLBACK*)pTLS->AddressOfCallBacks;
			// Execute each TLS callback with DLL_PROCESS_ATTACH
			for (; pCallback && *pCallback; ++pCallback)
			{
				(*pCallback)((LPVOID)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
			}
		}
	}

	// ====================================================================
	// STEP 5: CALL DLL MAIN
	// ====================================================================
	// Finally, call the DLL's entry point (DllMain) with DLL_PROCESS_ATTACH.
	// This is equivalent to what LoadLibrary does as the final step.
	
	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		// Get pointer to DLL entry point
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		
		// Call entry point with proper error handling
		__try
		{
			BOOL result = EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
			
			// Set status for debugging purposes
			ManualInject->hMod = result ? (HINSTANCE)ManualInject->ImageBase : (HINSTANCE)0x407;
			
			return result;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			// DLL entry point crashed
			ManualInject->hMod = (HINSTANCE)0x408;
			return FALSE;
		}
	}

	// If no entry point, still consider it successful
	ManualInject->hMod = (HINSTANCE)ManualInject->ImageBase;
	return TRUE;
}

// Marker function to calculate LoadDll function size
DWORD WINAPI LoadDllEnd()
{
	return 0;
}

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

// Validate that target process is 64-bit (this loader only supports 64-bit)
static bool isCorrectTargetArchitecture(HANDLE process)
{
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(process, &isWow64))
    {
        xlog::Error("Error checking target architecture: %d", GetLastError());
        return false;
    }
    
    // For strictly 64-bit loader, target must NOT be WOW64 (must be native 64-bit)
    if (isWow64)
    {
        xlog::Error("Target process is 32-bit, but this loader is strictly 64-bit only");
        return false;
    }
    
    return true; // Target is native 64-bit
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Get process ID by process name (as shown in tutorial)
DWORD GetPID(const wchar_t* processName) 
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	
	// Take snapshot of all processes
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			// Compare process name to the name we want
			if (wcscmp(entry.szExeFile, processName) == 0)
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}

// Success notification
void End() 
{
	Beep(300, 300);
	xlog::Normal("Successfully injected!");
}

// ============================================================================
// MAIN MANUAL MAPPING INJECTION FUNCTION
// ============================================================================
// This function implements the complete manual mapping process:
// 1. Setup: Get process handle and load DLL file
// 2. PE validation and architecture checking
// 3. Step 1: Map DLL sections into target process memory
// 4. Create and inject position-independent loader code
// 5. Execute loader via CreateRemoteThread (performs steps 2-5)
// ============================================================================
int ManualMapInject(const wchar_t* dllPath, const wchar_t* processName)
{

	HANDLE hProcess, hThread, hFile;
	PVOID mem1;
	DWORD ProcessId, FileSize, read, i;
	PVOID buffer, image;
	BOOLEAN bl;
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;

	THREADENTRY32 te32;
	CONTEXT ctx;

	MANUAL_INJECT ManualInject;

	te32.dwSize = sizeof(te32);
	ctx.ContextFlags = CONTEXT_FULL;

	xlog::Normal("Manual mapping injection initialized");
	
	// ====================================================================
	// SETUP: GET PROCESS ID AND HANDLE
	// ====================================================================
	// First, we need to find the target process and get a handle to it
	// with PROCESS_ALL_ACCESS permissions for memory operations
	
	xlog::Normal("Getting game PID...");
	DWORD PID = GetPID(processName);
	if (PID == 0) 
	{
		xlog::Error("Game is not running");
		Sleep(1000);
		return -1;
	}
	xlog::Normal("Found on PID %u", PID);
	xlog::Normal("Injecting...");
	//std::vector<std::uint8_t> bytes = KeyAuthApp.download("	858860");
	//if (!KeyAuthApp.data.success) // check whether file downloaded correctly
	//{
	//	system("cls");
	//	std::cout << skCrypt("\n\nStatus: ") << KeyAuthApp.data.message;
	//	Sleep(1500);
	//	exit(0);
	//}
	// ====================================================================
	// SETUP: LOAD DLL FILE INTO BUFFER
	// ====================================================================
	// As shown in tutorial: Load the DLL file into a buffer for processing
	// std::ifstream infile(dllPath, std::ios::binary);
	// std::vector<BYTE> buffer((std::istreambuf_iterator<char>(infile)), std::istreambuf_iterator<char>());
	
	hFile = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		xlog::Error("Unable to open the DLL (%d)", GetLastError());
		Sleep(100);
		return -1;
	}

	FileSize = GetFileSize(hFile, NULL);
	buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!buffer)
	{
		xlog::Error("Unable to allocate memory for DLL data (%d)", GetLastError());

		CloseHandle(hFile);
		Sleep(100);
		return -1;
	}

	// Read the DLL file into memory buffer
	if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
	{
		xlog::Error("Unable to read the DLL (%d)", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hFile);
		Sleep(100);
		return -1;
	}

	CloseHandle(hFile);

	// ====================================================================
	// PE VALIDATION AND PARSING
	// ====================================================================
	// Parse PE headers and validate the DLL is compatible
	// As shown in tutorial: Get DOS header and NT headers using e_lfanew
	
	pIDH = (PIMAGE_DOS_HEADER)buffer;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		xlog::Error("Invalid executable image");

		VirtualFree(buffer, 0, MEM_RELEASE);
		Sleep(100);
		return -1;
	}

	// Get NT headers using e_lfanew offset (as per tutorial)
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		xlog::Error("Invalid PE header");

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		xlog::Error("The image is not a DLL");
		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	// Validate 64-bit architecture (this loader only supports 64-bit)
	if (pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		xlog::Error("Invalid DLL architecture: Expected x64, got 0x%x", pINH->FileHeader.Machine);
		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	// Enable debug privileges for memory operations
	RtlAdjustPrivilege(20, TRUE, FALSE, &bl);

	ProcessId = PID;
	// Open process handle with full access (as per tutorial)
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (!hProcess)
	{
		xlog::Error("Unable to open target process handle (%d)", GetLastError());
		return -1;
	}

	// Validate architecture compatibility
	if (!isCorrectTargetArchitecture(hProcess))
	{
		xlog::Error("Target process architecture doesn't match current process");
		CloseHandle(hProcess);
		return -1;
	}

	// ====================================================================
	// STEP 1: ALLOCATE MEMORY AND MAP SECTIONS
	// ====================================================================
	// Allocate memory in target process for the DLL
	// Size needed is found in OptionalHeader.SizeOfImage (as per tutorial)
	
	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!image)
	{
		xlog::Error("Unable to allocate memory for the DLL (%d)", GetLastError());

		VirtualFree(buffer, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		return -1;
	}

	// Copy PE header to target process (first 0x1000 bytes as per tutorial)
	// Tutorial: WriteProcessMemory(hProc, pAlloc, buffer.data(), 0x1000, 0);
	if (!WriteProcessMemory(hProcess, image, buffer, 0x1000, NULL))
	{
		xlog::Error("Unable to copy headers to target process (%d)", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	// Get first section header using IMAGE_FIRST_SECTION macro (as per tutorial)
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pINH);

	// Copy each section to its virtual address (as per tutorial)
	// Tutorial: WriteProcessMemory(hProc, pAlloc + pSectionHeader->VirtualAddress, 
	//           buffer.data() + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, 0);
	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		if (pSectionHeader->PointerToRawData) // Only copy sections that have raw data
		{
			if (!WriteProcessMemory(hProcess, 
				(PVOID)((LPBYTE)image + pSectionHeader->VirtualAddress), 
				(PVOID)((LPBYTE)buffer + pSectionHeader->PointerToRawData), 
				pSectionHeader->SizeOfRawData, NULL))
			{
				xlog::Error("Unable to copy section %d to target process (%d)", i, GetLastError());
			}
		}
		pSectionHeader++; // Move to next section header
	}

	// Calculate required memory for loader code with safety checks
	DWORD64 loadDllAddr = (DWORD64)LoadDll;
	DWORD64 loadDllEndAddr = (DWORD64)LoadDllEnd;
	DWORD64 loadDllSize;
	
	// Safety check for function size calculation
	if (loadDllEndAddr > loadDllAddr) {
		loadDllSize = loadDllEndAddr - loadDllAddr;
	} else {
		// Fallback: use a reasonable size estimate
		loadDllSize = 2048; // Should be enough for most LoadDll functions
		xlog::Warning("LoadDll function size calculation failed, using fallback size: %llu", loadDllSize);
	}
	
	// Additional safety check
	if (loadDllSize > 0x10000) { // 64KB max reasonable size
		loadDllSize = 2048;
		xlog::Warning("LoadDll function size too large, using fallback size: %llu", loadDllSize);
	}
	
	DWORD totalLoaderSize = (DWORD)(sizeof(MANUAL_INJECT) + loadDllSize + 512); // Add 512 bytes buffer
	
	mem1 = VirtualAllocEx(hProcess, NULL, totalLoaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	if (!mem1)
	{
		xlog::Error("Unable to allocate memory for the loader code (%d)", GetLastError());

		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return -1;
	}

	xlog::Normal("Loader code allocated at 0x%p", mem1);
	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;
	
	xlog::Normal("Manual inject structure initialized - ImageBase: 0x%p", image);


	if (!WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
	{
		xlog::Error("Memory write error (%d)", GetLastError());
		return -1;
	}
	//std::cout << "LoadDllSize " << std::dec << (DWORD64)LoadDllEnd - (DWORD64)LoadDll << std::endl;

	// Write LoadDll function using pre-calculated size
	PVOID functionAddress = (PVOID)((PMANUAL_INJECT)mem1 + 1);
	xlog::Normal("Writing LoadDll function to address: 0x%p (size: %llu bytes)", functionAddress, loadDllSize);
	
	if (!WriteProcessMemory(hProcess, functionAddress, LoadDll, loadDllSize, NULL))
	{
		xlog::Error("Memory write error (%d)", GetLastError());
		return -1;
	}
	xlog::Normal("LoadDll function written successfully");
	//std::cout << "LoadDllAddress " << std::hex << (PVOID)((PMANUAL_INJECT)mem1 + 1) << std::endl;

	// Use CreateRemoteThread instead of thread hijacking (as per tutorial)
	xlog::Normal("Creating remote thread to execute LoadDll function...");
	
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)functionAddress, mem1, 0, NULL);
	
	if (!hThread)
	{
		xlog::Error("Unable to create remote thread (%d)", GetLastError());
		VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}
	
	xlog::Normal("Remote thread created successfully");
	
	// Wait for the remote thread to complete (as per tutorial)
	xlog::Normal("Waiting for remote thread to complete...");
	
	DWORD waitResult = WaitForSingleObject(hThread, 10000); // 10 second timeout
	
	if (waitResult == WAIT_TIMEOUT)
	{
		xlog::Error("Remote thread timed out after 10 seconds");
		TerminateThread(hThread, 0);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}
	else if (waitResult == WAIT_FAILED)
	{
		xlog::Error("Wait for remote thread failed (%d)", GetLastError());
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return -1;
	}
	
	// Get thread exit code
	DWORD threadExitCode;
	GetExitCodeThread(hThread, &threadExitCode);
	
	xlog::Normal("Remote thread completed with exit code: %d", threadExitCode);
	
	// Check for debugging status (as per tutorial)
	MANUAL_INJECT statusCheck;
	if (ReadProcessMemory(hProcess, mem1, &statusCheck, sizeof(statusCheck), NULL))
	{
		if (statusCheck.hMod == (HINSTANCE)0x404)
		{
			xlog::Error("LoadDll function failed - module loading failed");
		}
		else if (statusCheck.hMod == (HINSTANCE)0x405)
		{
			xlog::Error("LoadDll function failed - ordinal import failed");
		}
		else if (statusCheck.hMod == (HINSTANCE)0x406)
		{
			xlog::Error("LoadDll function failed - name import failed");
		}
		else if (statusCheck.hMod == (HINSTANCE)0x407)
		{
			xlog::Error("LoadDll function failed - DLL entry point returned FALSE");
		}
		else if (statusCheck.hMod == (HINSTANCE)0x408)
		{
			xlog::Error("LoadDll function failed - DLL entry point crashed");
		}
		else if (statusCheck.hMod == statusCheck.ImageBase)
		{
			xlog::Normal("LoadDll function completed successfully");
		}
		else
		{
			xlog::Warning("LoadDll function status unknown (hMod: 0x%p)", statusCheck.hMod);
		}
	}
	
	CloseHandle(hThread);
	
	// Give the DLL time to initialize properly before cleaning up
	Sleep(2000);
	
	// Only cleanup the loader memory, keep the DLL image in target process
	VirtualFreeEx(hProcess, mem1, 0, MEM_RELEASE);
	// Note: We don't free the image memory as the DLL needs it to stay loaded
	
	CloseHandle(hProcess);

	xlog::Normal("Manual mapping injection completed successfully");

	End();
	return 0;
}
