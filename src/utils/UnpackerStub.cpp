#include <windows.h>
#include <winnt.h>
#include <stdio.h>
#include <stdlib.h>

// Converted from pe-packer-x64/unpacker.c to C++
// This is the unpacker stub that loads and executes the embedded PE

void debug_log(const char* message) {
    FILE* log_file = fopen("unpacker_debug.log", "a");
    if (log_file) {
        fprintf(log_file, "[%lu] %s\n", GetTickCount(), message);
        fflush(log_file);
        fclose(log_file);
    }
}

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

void* load_pe(PBYTE pe_data, PBYTE* base_address, DWORD64* original_imagebase);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    debug_log("=== Unpacker stub starting ===");
    
    // Hide the console window since we're loading a GUI application
    HWND consoleWindow = GetConsoleWindow();
    if (consoleWindow) {
        ShowWindow(consoleWindow, SW_HIDE);
        debug_log("Console window hidden");
    }
    
    PVOID start_address = NULL;
    
    PBYTE current_va = (PBYTE)GetModuleHandle(NULL);
    debug_log("Got current module handle");
    
    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)current_va;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);

    char log_msg[256];
    sprintf(log_msg, "Found %d sections", p_NT_HDR->FileHeader.NumberOfSections);
    debug_log(log_msg);

    // Find the .rsrc section (where packed data is stored)
    IMAGE_SECTION_HEADER* rsrc_section = nullptr;
    for (WORD i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; i++) {
        sprintf(log_msg, "Section %d name: %.8s", i, sections[i].Name);
        debug_log(log_msg);
        
        if (strncmp((char*)sections[i].Name, ".rsrc", 5) == 0) {
            rsrc_section = &sections[i];
            debug_log("Found .rsrc section with packed data");
            break;
        }
    }
    
    if (!rsrc_section) {
        debug_log("ERROR: .rsrc section not found!");
        return -1;
    }
    
    sprintf(log_msg, "Packed section VirtualAddress: 0x%x, VirtualSize: 0x%x", 
            rsrc_section->VirtualAddress, rsrc_section->Misc.VirtualSize);
    debug_log(log_msg);
    
    PBYTE section_packed = current_va + rsrc_section->VirtualAddress;
    debug_log("Located packed section");

    // Log the first few bytes of the packed section for debugging
    sprintf(log_msg, "First 16 bytes of packed section: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", 
            section_packed[0], section_packed[1], section_packed[2], section_packed[3],
            section_packed[4], section_packed[5], section_packed[6], section_packed[7],
            section_packed[8], section_packed[9], section_packed[10], section_packed[11],
            section_packed[12], section_packed[13], section_packed[14], section_packed[15]);
    debug_log(log_msg);
    
    // Try different offsets to see if the PE data is stored elsewhere in the section
    for (int offset = 0; offset < 1024; offset += 16) {
        PBYTE test_data = section_packed + offset;
        if (test_data[0] == 0x4D && test_data[1] == 0x5A) {
            sprintf(log_msg, "Found MZ signature at offset %d in packed section", offset);
            debug_log(log_msg);
            section_packed = test_data;
            break;
        }
    }

    PBYTE loaded_base = nullptr;
    DWORD64 original_imagebase = 0;
    start_address = load_pe(section_packed, &loaded_base, &original_imagebase);

    // [ Entrypoint call ]

    if (start_address != NULL) {
        sprintf(log_msg, "Entry point loaded at address: 0x%p", start_address);
        debug_log(log_msg);
        
        debug_log("Calling entry point...");
        
        // Add more debugging information
        sprintf(log_msg, "Entry point address: 0x%p", start_address);
        debug_log(log_msg);
        sprintf(log_msg, "Parameters - hInstance: 0x%p, hPrevInstance: 0x%p, lpCmdLine: %s, nCmdShow: %d", 
                hInstance, hPrevInstance, lpCmdLine ? lpCmdLine : "NULL", nCmdShow);
        debug_log(log_msg);
        
        // Call the entry point directly - AmalgamLoader uses wWinMain (wide character version)
        __try {
            // First try to verify the memory is executable
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(start_address, &mbi, sizeof(mbi))) {
                sprintf(log_msg, "Memory info: BaseAddress=0x%p, AllocationBase=0x%p, Protect=0x%x, State=0x%x", 
                        mbi.BaseAddress, mbi.AllocationBase, mbi.Protect, mbi.State);
                debug_log(log_msg);
            }
            
            typedef int (WINAPI *wWinMainFunc)(HINSTANCE, HINSTANCE, LPWSTR, int);
            wWinMainFunc wWinMain = (wWinMainFunc)start_address;
            
            // Convert command line to wide character
            LPWSTR lpCmdLineW = GetCommandLineW();
            
            debug_log("About to call wWinMain function...");
            debug_log("Flushing log before wWinMain call...");
            fflush(stdout);
            
            // Add a small delay to ensure logging is flushed
            Sleep(10);
            
            // Try a simple test first - read the first few bytes of the entry point
            __try {
                BYTE testBytes[16];
                memcpy(testBytes, start_address, 16);
                sprintf(log_msg, "Entry point bytes: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X", 
                        testBytes[0], testBytes[1], testBytes[2], testBytes[3], testBytes[4], testBytes[5], testBytes[6], testBytes[7],
                        testBytes[8], testBytes[9], testBytes[10], testBytes[11], testBytes[12], testBytes[13], testBytes[14], testBytes[15]);
                debug_log(log_msg);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                debug_log("ERROR: Cannot read entry point memory!");
                return -1;
            }
            
            debug_log("Entry point validation passed");
            
            debug_log("Attempting to call entry point...");
            
            // Try a more direct approach - use inline assembly to call the entry point
            // This might give us better crash information
            __try {
                // Try different calling conventions - in x64, calling convention is less important
                debug_log("Trying default calling convention...");
                typedef int (*DefaultEntryFunc)(HINSTANCE, HINSTANCE, LPWSTR, int);
                DefaultEntryFunc defaultFunc = (DefaultEntryFunc)start_address;
                
                debug_log("Calling entry point with default convention...");
                
                // Try using the loaded base address as hInstance since TLS callbacks are failing
                HINSTANCE peInstance = (HINSTANCE)loaded_base;
                sprintf(log_msg, "Using loaded base as hInstance: 0x%p (original ImageBase: 0x%p, unpacker: 0x%p)", 
                        peInstance, (void*)original_imagebase, hInstance);
                debug_log(log_msg);
                
                debug_log("About to make the actual call...");
                
                // Flush all logs and ensure everything is written
                fflush(stdout);
                fflush(stderr);
                Sleep(50);
                
                // Try calling in a separate thread to avoid stack issues
                debug_log("Attempting direct call first...");
                
                // Try the original pe-packer approach - call as void function with no parameters
                debug_log("Trying original pe-packer approach - void function call...");
                __try {
                    typedef void (*VoidEntryFunc)(void);
                    VoidEntryFunc voidFunc = (VoidEntryFunc)start_address;
                    
                    // Let's try to verify the function is actually callable
                    debug_log("Attempting to call void function...");
                    
                    // Final check - let's see if there's an issue with the DYNAMIC_BASE flag
                    // The original pe-packer handles this differently
                    debug_log("Checking if we should use different memory allocation approach...");
                    debug_log("About to call - this is the critical moment...");
                    
                    // Try to check if the function address is within our loaded memory
                    ULONG_PTR func_addr = (ULONG_PTR)voidFunc;
                    ULONG_PTR loaded_start = (ULONG_PTR)loaded_base;
                    ULONG_PTR loaded_end = loaded_start + 0x79000; // Use the SizeOfImage we saw in logs
                    
                    sprintf(log_msg, "Function address: 0x%p, Loaded range: 0x%p - 0x%p", 
                            (void*)func_addr, (void*)loaded_start, (void*)loaded_end);
                    debug_log(log_msg);
                    
                    if (func_addr >= loaded_start && func_addr < loaded_end) {
                        debug_log("Function address is within loaded PE range - trying void call...");
                        
                        // Try calling as void function first
                        __try {
                            voidFunc();
                            debug_log("Void function call returned successfully!");
                            return 0; // Success!
                        } __except(EXCEPTION_EXECUTE_HANDLER) {
                            DWORD voidExceptionCode = GetExceptionCode();
                            sprintf(log_msg, "Void call failed with exception 0x%08X, trying WinMain call...", voidExceptionCode);
                            debug_log(log_msg);
                        }
                        
                        // If void call failed, try calling as WinMain
                        debug_log("Attempting to call as WinMain function...");
                        typedef int (WINAPI *WinMainFunc)(HINSTANCE, HINSTANCE, LPWSTR, int);
                        WinMainFunc winMainFunc = (WinMainFunc)voidFunc;
                        
                        // Get wide command line
                        LPWSTR lpCmdLineW = GetCommandLineW();
                        HINSTANCE peInstance = (HINSTANCE)loaded_base;
                        
                        int result = winMainFunc(peInstance, NULL, lpCmdLineW, 1);
                        sprintf(log_msg, "WinMain call returned with code: %d", result);
                        debug_log(log_msg);
                        return 0; // Success!
                    } else {
                        debug_log("ERROR: Function address is outside loaded PE range!");
                    }
                    debug_log("Void function call completed successfully");
                    return 0; // Success, exit early
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    DWORD exceptionCode = GetExceptionCode();
                    sprintf(log_msg, "ERROR: Void function call crashed with exception: 0x%08X", exceptionCode);
                    debug_log(log_msg);
                    
                    // Log common exception codes
                    if (exceptionCode == 0xC0000005) {
                        debug_log("Void call exception: Access Violation - Invalid memory access");
                    } else if (exceptionCode == 0xC000001D) {
                        debug_log("Void call exception: Illegal Instruction - Invalid CPU instruction");
                    } else if (exceptionCode == 0xC00000FD) {
                        debug_log("Void call exception: Stack Overflow - Stack space exhausted");
                    }
                    
                    debug_log("Falling back to WinMain approach...");
                }
                
                // Structure to pass parameters to thread
                struct ThreadParams {
                    DefaultEntryFunc func;
                    HINSTANCE hInst;
                    HINSTANCE hPrevInst;
                    LPWSTR cmdLine;
                    int showCmd;
                    int result;
                    bool completed;
                };
                
                ThreadParams params = {
                    defaultFunc,
                    peInstance,
                    hPrevInstance,
                    lpCmdLineW,
                    nCmdShow,
                    -1,
                    false
                };
                
                // Create thread to call entry point
                HANDLE hThread = CreateThread(NULL, 0, [](LPVOID lpParam) -> DWORD {
                    ThreadParams* p = (ThreadParams*)lpParam;
                    __try {
                        p->result = p->func(p->hInst, p->hPrevInst, p->cmdLine, p->showCmd);
                        p->completed = true;
                        return 0;
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                        p->completed = false;
                        return 1;
                    }
                }, &params, 0, NULL);
                
                int result = -1;
                
                if (hThread) {
                    debug_log("Entry point thread created, waiting for completion...");
                    DWORD waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
                    
                    if (waitResult == WAIT_OBJECT_0) {
                        if (params.completed) {
                            debug_log("Entry point thread completed successfully");
                            result = params.result;
                        } else {
                            debug_log("Entry point thread failed");
                            CloseHandle(hThread);
                            return -1;
                        }
                    } else {
                        debug_log("Entry point thread timed out or failed");
                        TerminateThread(hThread, 1);
                        CloseHandle(hThread);
                        return -1;
                    }
                    
                    CloseHandle(hThread);
                } else {
                    debug_log("Failed to create entry point thread, trying direct call...");
                    result = defaultFunc(peInstance, hPrevInstance, lpCmdLineW, nCmdShow);
                }
                debug_log("Entry point call completed successfully");
                sprintf(log_msg, "Entry point returned with code: %d", result);
                debug_log(log_msg);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                DWORD exceptionCode = GetExceptionCode();
                sprintf(log_msg, "ERROR: Entry point crashed during call with exception: 0x%08X", exceptionCode);
                debug_log(log_msg);
                
                // Log common exception codes
                if (exceptionCode == 0xC0000005) {
                    debug_log("Exception type: Access Violation - Invalid memory access");
                } else if (exceptionCode == 0xC000001D) {
                    debug_log("Exception type: Illegal Instruction - Invalid CPU instruction");
                } else if (exceptionCode == 0xC0000094) {
                    debug_log("Exception type: Integer Divide by Zero");
                } else if (exceptionCode == 0xC00000FD) {
                    debug_log("Exception type: Stack Overflow - Stack space exhausted");
                } else if (exceptionCode == 0xC0000096) {
                    debug_log("Exception type: Privileged Instruction - Attempted to execute privileged instruction");
                } else {
                    debug_log("Exception type: Unknown exception");
                }
                
                // Flush logs immediately after exception
                fflush(stdout);
                fflush(stderr);
                
                return -1;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            sprintf(log_msg, "ERROR: Entry point crashed with exception code: 0x%08X", GetExceptionCode());
            debug_log(log_msg);
            return -1;
        }
        
        return 0;
    } else {
        debug_log("ERROR: Failed to load entry point");
        return -1;
    }

    return 0;
}

void* load_pe(PBYTE pe_data, PBYTE* base_address, DWORD64* original_imagebase) {
    if (base_address) *base_address = nullptr;
    if (original_imagebase) *original_imagebase = 0;
    debug_log("load_pe: Starting PE parsing");
    
    // [ PE Parsing ]
    
    if (!pe_data) {
        debug_log("load_pe: ERROR - pe_data is NULL");
        return NULL;
    }

    IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)pe_data;
    debug_log("load_pe: Got DOS header");
    
    // Validate DOS header
    if (p_DOS_HDR->e_magic != IMAGE_DOS_SIGNATURE) {
        debug_log("load_pe: ERROR - Invalid DOS signature");
        return NULL;
    }
    
    debug_log("load_pe: DOS header valid");
    
    IMAGE_NT_HEADERS64* p_NT_HDR = (IMAGE_NT_HEADERS64*)(((PBYTE)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    debug_log("load_pe: Got NT header");
    
    // Validate NT header
    if (p_NT_HDR->Signature != IMAGE_NT_SIGNATURE) {
        debug_log("load_pe: ERROR - Invalid NT signature");
        return NULL;
    }
    
    debug_log("load_pe: NT header valid");

    char log_msg[256];
    sprintf(log_msg, "load_pe: PE ImageBase=0x%llx, SizeOfImage=0x%x", 
            p_NT_HDR->OptionalHeader.ImageBase, p_NT_HDR->OptionalHeader.SizeOfImage);
    debug_log(log_msg);
    
    // Store original ImageBase for caller
    if (original_imagebase) *original_imagebase = p_NT_HDR->OptionalHeader.ImageBase;

    IMAGE_DATA_DIRECTORY import_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY reloc_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // [ Allocate memory ]

    PBYTE addrp = NULL;

    // Use the original pe-packer-x64 memory allocation approach, but always allocate new memory
    // because we can't overwrite the unpacker's own memory
    debug_log("load_pe: Checking DYNAMIC_BASE flag for memory allocation");
    
    if (p_NT_HDR->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        debug_log("load_pe: DYNAMIC_BASE set, allocating new memory");
        addrp = (PBYTE)VirtualAlloc(NULL, p_NT_HDR->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    } else {
        debug_log("load_pe: DYNAMIC_BASE not set, but allocating new memory anyway (unpacker cannot overwrite itself)");
        addrp = (PBYTE)VirtualAlloc(NULL, p_NT_HDR->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    if (addrp == NULL) {
        debug_log("load_pe: ERROR - Failed to allocate memory");
        return NULL;
    }
    
    sprintf(log_msg, "load_pe: Allocated memory at 0x%p", addrp);
    debug_log(log_msg);

    // [ Mapping PE sections ]

    debug_log("load_pe: Starting section mapping");
    
    sprintf(log_msg, "load_pe: Copying headers - src: 0x%p, dest: 0x%p, size: %d", 
            pe_data, addrp, p_NT_HDR->OptionalHeader.SizeOfHeaders);
    debug_log(log_msg);
    
    // Try to access the first few bytes of pe_data to check if it's readable
    __try {
        BYTE first_byte = pe_data[0];
        sprintf(log_msg, "load_pe: PE data first byte: 0x%02X", first_byte);
        debug_log(log_msg);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        debug_log("load_pe: ERROR - Cannot read PE data!");
        return NULL;
    }
    
    // Try the memcpy operation with exception handling
    __try {
        memcpy(addrp, pe_data, p_NT_HDR->OptionalHeader.SizeOfHeaders);
        debug_log("load_pe: Header copy successful");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        debug_log("load_pe: ERROR - Header copy failed!");
        return NULL;
    }
    
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);

    debug_log("load_pe: Mapping sections");
    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; i++) {
        sprintf(log_msg, "load_pe: Processing section %d", i);
        debug_log(log_msg);
        
        PBYTE dest = addrp + sections[i].VirtualAddress;

        __try {
            if (sections[i].SizeOfRawData > 0) {
                DWORD oldProtect;
                VirtualProtect(dest, sections[i].SizeOfRawData, PAGE_READWRITE, &oldProtect);
                memcpy(dest, pe_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
            } else {
                DWORD oldProtect;
                VirtualProtect(dest, sections[i].Misc.VirtualSize, PAGE_READWRITE, &oldProtect);
                memset(dest, 0, sections[i].Misc.VirtualSize);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            sprintf(log_msg, "load_pe: ERROR - Section %d mapping failed!", i);
            debug_log(log_msg);
            return NULL;
        }
    }

    debug_log("load_pe: Section mapping completed");

    // [ Fix imports ]

    debug_log("load_pe: Starting import resolution");
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(addrp + import_dir.VirtualAddress);

    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; i++) {
        PVOID module_name = addrp + import_descriptors[i].Name;
        sprintf(log_msg, "load_pe: Loading module: %s", (char*)module_name);
        debug_log(log_msg);
        
        HMODULE import_module = LoadLibraryA((LPCSTR)module_name);

        if (import_module == NULL) {
            sprintf(log_msg, "load_pe: ERROR - Failed to load module: %s", (char*)module_name);
            debug_log(log_msg);
            return NULL;
        }
        
        sprintf(log_msg, "load_pe: Module loaded successfully: %s", (char*)module_name);
        debug_log(log_msg);

        IMAGE_THUNK_DATA64* lookup_table = (IMAGE_THUNK_DATA64*)(addrp + import_descriptors[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA64* address_table = (IMAGE_THUNK_DATA64*)(addrp + import_descriptors[i].FirstThunk);

        sprintf(log_msg, "load_pe: Import table pointers - lookup: 0x%p, address: 0x%p", lookup_table, address_table);
        debug_log(log_msg);

        debug_log("load_pe: Resolving function imports");
        
        // Check if the import table is accessible
        __try {
            DWORD64 first_entry = lookup_table[0].u1.AddressOfData;
            sprintf(log_msg, "load_pe: First import entry: 0x%I64x", first_entry);
            debug_log(log_msg);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            debug_log("load_pe: ERROR - Cannot access import table!");
            return NULL;
        }
        
        for (int j = 0; lookup_table[j].u1.AddressOfData != 0; j++) {
            sprintf(log_msg, "load_pe: Processing import entry %d", j);
            debug_log(log_msg);
            void* function_handle = NULL;

            DWORD64 lookup_addr = lookup_table[j].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG64) == 0) {
                IMAGE_IMPORT_BY_NAME* image_import = NULL;
                char* funct_name = NULL;
                
                __try {
                    image_import = (IMAGE_IMPORT_BY_NAME*)(addrp + lookup_addr);
                    funct_name = (char*)&(image_import->Name);
                    
                    sprintf(log_msg, "load_pe: Resolving function: %s", funct_name);
                    debug_log(log_msg);
                    
                    function_handle = (PVOID)GetProcAddress(import_module, funct_name);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    sprintf(log_msg, "load_pe: ERROR - Invalid function name pointer at address: 0x%I64x", lookup_addr);
                    debug_log(log_msg);
                    return NULL;
                }
                
                if (function_handle == NULL) {
                    sprintf(log_msg, "load_pe: ERROR - Failed to resolve function: %s", funct_name ? funct_name : "UNKNOWN");
                    debug_log(log_msg);
                    return NULL;
                }
            } else {
                // This is an ordinal import
                DWORD ordinal = lookup_addr & 0xFFFF;  // Get the lower 16 bits
                sprintf(log_msg, "load_pe: Resolving function by ordinal: %d", ordinal);
                debug_log(log_msg);
                
                function_handle = (PVOID)GetProcAddress(import_module, MAKEINTRESOURCEA(ordinal));
                
                if (function_handle == NULL) {
                    sprintf(log_msg, "load_pe: ERROR - Failed to resolve function by ordinal: %d", ordinal);
                    debug_log(log_msg);
                    return NULL;
                }
                
                sprintf(log_msg, "load_pe: Ordinal function resolved successfully: %d", ordinal);
                debug_log(log_msg);
            }

            address_table[j].u1.Function = (DWORD64)function_handle;
        }
    }

    debug_log("load_pe: Import resolution completed");

    // [ Fix relocations ]

    debug_log("load_pe: Starting relocation fixes");
    
    // Use original pe-packer-x64 relocation approach - process relocations if directory exists
    if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0) {
        debug_log("load_pe: Processing relocations");
    
    sprintf(log_msg, "load_pe: Relocation directory - VA: 0x%x, Size: %d", reloc_dir.VirtualAddress, reloc_dir.Size);
    debug_log(log_msg);
    
    PIMAGE_BASE_RELOCATION p_reloc = (PIMAGE_BASE_RELOCATION)(addrp + reloc_dir.VirtualAddress);
    ULONG_PTR delta_VA_reloc = ((ULONG_PTR)addrp) - p_NT_HDR->OptionalHeader.ImageBase;
    PBASE_RELOCATION_ENTRY reloc = NULL;

    sprintf(log_msg, "load_pe: Relocation delta: 0x%I64x", delta_VA_reloc);
    debug_log(log_msg);
    
    int reloc_block_count = 0;
    while (p_reloc->VirtualAddress != 0) {
        sprintf(log_msg, "load_pe: Processing relocation block %d at VA 0x%x", reloc_block_count++, p_reloc->VirtualAddress);
        debug_log(log_msg);
        reloc = (PBASE_RELOCATION_ENTRY)(p_reloc + 1);

        __try {
            while ((PBYTE)reloc != (PBYTE)p_reloc + p_reloc->SizeOfBlock) {
                switch (reloc->Type) {
                    case IMAGE_REL_BASED_DIR64:
                        *((ULONG_PTR*)((ULONG_PTR)addrp + p_reloc->VirtualAddress + reloc->Offset)) += delta_VA_reloc;
                        break;
                    case IMAGE_REL_BASED_HIGHLOW:
                        *((DWORD*)((ULONG_PTR)addrp + p_reloc->VirtualAddress + reloc->Offset)) += (DWORD)delta_VA_reloc;
                        break;
                    case IMAGE_REL_BASED_HIGH:
                        *((WORD*)((ULONG_PTR)addrp + p_reloc->VirtualAddress + reloc->Offset)) += HIWORD(delta_VA_reloc);
                        break;
                    case IMAGE_REL_BASED_LOW:
                        *((WORD*)((ULONG_PTR)addrp + p_reloc->VirtualAddress + reloc->Offset)) += LOWORD(delta_VA_reloc);
                        break;
                    case IMAGE_REL_BASED_ABSOLUTE:
                        break;
                    default:
                        break;
                }
                reloc++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            sprintf(log_msg, "load_pe: ERROR - Relocation failed at block %d", reloc_block_count - 1);
            debug_log(log_msg);
            return NULL;
        }
        
        p_reloc = (PIMAGE_BASE_RELOCATION)reloc;
    }

        debug_log("load_pe: Relocation fixes completed");
    } else {
        debug_log("load_pe: No relocations to process");
    }
    // [ Fix permissions ]

    debug_log("load_pe: Setting section permissions");
    for (int i = 0; i < p_NT_HDR->FileHeader.NumberOfSections; ++i) {
        PBYTE dest = addrp + sections[i].VirtualAddress;
        DWORD64 s_perm = sections[i].Characteristics;
        DWORD64 v_perm = 0;
        if (s_perm & IMAGE_SCN_MEM_EXECUTE) {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else {
            v_perm = (s_perm & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
        }
        DWORD oldProtect;
        VirtualProtect(dest, sections[i].Misc.VirtualSize, v_perm, &oldProtect);
    }

    debug_log("load_pe: Section permissions set");
    
    // Check for TLS callbacks and execute them
    IMAGE_DATA_DIRECTORY tls_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir.VirtualAddress != 0 && tls_dir.Size != 0) {
        debug_log("load_pe: Found TLS directory, processing callbacks...");
        IMAGE_TLS_DIRECTORY64* tls_data = (IMAGE_TLS_DIRECTORY64*)(addrp + tls_dir.VirtualAddress);
        
        if (tls_data->AddressOfCallBacks != 0) {
            // Calculate the delta for relocation
            ULONG_PTR delta_VA = ((ULONG_PTR)addrp) - p_NT_HDR->OptionalHeader.ImageBase;
            
            PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)(addrp + (tls_data->AddressOfCallBacks - p_NT_HDR->OptionalHeader.ImageBase));
            
            for (int i = 0; callbacks[i] != nullptr; i++) {
                // Apply relocation to callback address
                PIMAGE_TLS_CALLBACK relocated_callback = (PIMAGE_TLS_CALLBACK)((ULONG_PTR)callbacks[i] + delta_VA);
                
                sprintf(log_msg, "load_pe: Calling TLS callback %d at 0x%p (relocated from 0x%p)", i, relocated_callback, callbacks[i]);
                debug_log(log_msg);
                __try {
                    relocated_callback(addrp, DLL_PROCESS_ATTACH, nullptr);
                    sprintf(log_msg, "load_pe: TLS callback %d completed successfully", i);
                    debug_log(log_msg);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    DWORD exceptionCode = GetExceptionCode();
                    sprintf(log_msg, "load_pe: TLS callback %d failed with exception 0x%08X, continuing...", i, exceptionCode);
                    debug_log(log_msg);
                }
            }
        }
        debug_log("load_pe: TLS callbacks completed");
    } else {
        debug_log("load_pe: No TLS directory found");
    }

    PVOID entry_point = (PVOID)(addrp + p_NT_HDR->OptionalHeader.AddressOfEntryPoint);
    
    // Set the base address for the caller
    if (base_address) *base_address = addrp;
    
    sprintf(log_msg, "load_pe: Completed successfully, entry point at 0x%p", entry_point);
    debug_log(log_msg);
    
    return entry_point;
}

