#include <windows.h>
#include <winnt.h>

#include <stdio.h>
#include <stdlib.h>

/*
    SPECIAL THANKS TO
        * https://0xrick.github.io/win-internals/pe1/
        * https://wirediver.com/tutorial-writing-a-pe-packer-intro/
*/

// https://github.com/NUL0x4C/AtomPePacker/blob/000982bb625bed6c9c1e135289c8e0f4738b8602/PP64Stub/Structs.h#L37

void* load_pe(PBYTE pe_load);

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main(int argc, char *argv[]) {
    PVOID start_address = NULL;
    
    PBYTE current_va = (PBYTE) GetModuleHandle(NULL);
    
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) current_va;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    PBYTE section_packed = current_va + sections[p_NT_HDR->FileHeader.NumberOfSections - 1].VirtualAddress;

    start_address = load_pe(section_packed);

    // [ Entrypoint call ]

    if (start_address != NULL) {
        ((void (*)(void)) start_address)();
    } else {
        return -1;
    }

    return 0;
}

void* load_pe(PBYTE pe_data) {
    // [ PE Parsing ]

    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) pe_data;
    IMAGE_NT_HEADERS64* p_NT_HDR = (IMAGE_NT_HEADERS64*) (((PBYTE) p_DOS_HDR) + p_DOS_HDR->e_lfanew);

    IMAGE_DATA_DIRECTORY import_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY reloc_dir = p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    // [ Allocate memory ]

    PBYTE addrp = NULL;

    if (p_NT_HDR->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
        addrp = (PBYTE) VirtualAlloc(NULL, p_NT_HDR->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    } else {
        addrp = (PBYTE) GetModuleHandle(NULL);
    }

    if (addrp == NULL) {
        return NULL;
    }

    // [ Mapping PE sections ]

    memcpy(addrp, pe_data, p_NT_HDR->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*) (p_NT_HDR + 1);

    for (int i=0; i<p_NT_HDR->FileHeader.NumberOfSections; i++) {
        PBYTE dest = addrp + sections[i].VirtualAddress;

        if (sections[i].SizeOfRawData > 0) {
            DWORD oldProtect;
            VirtualProtect(dest, sections[i].SizeOfRawData, PAGE_READWRITE, &oldProtect);
            memcpy(dest, pe_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        } else {
            DWORD oldProtect;
            VirtualProtect(dest, sections[i].Misc.VirtualSize, PAGE_READWRITE, &oldProtect);
            memset(dest, 0, sections[i].Misc.VirtualSize);
        }
    }

    // [ Fix imports ]

    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) (addrp + import_dir.VirtualAddress);

    for (int i = 0; import_descriptors[i].OriginalFirstThunk != 0; i++) {
        PVOID module_name = addrp + import_descriptors[i].Name;
        HMODULE import_module = LoadLibraryA((LPCSTR) module_name);

        if (import_module == NULL) {
            return NULL;
        }

        IMAGE_THUNK_DATA64* lookup_table = (IMAGE_THUNK_DATA64*) (addrp + import_descriptors[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA64* address_table = (IMAGE_THUNK_DATA64*) (addrp + import_descriptors[i].FirstThunk);

        for (int j = 0; lookup_table[j].u1.AddressOfData != 0; j++) {
            void* function_handle = NULL;

            DWORD64 lookup_addr = lookup_table[j].u1.AddressOfData;

            if ((lookup_addr & IMAGE_ORDINAL_FLAG64) == 0) {
                IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) (addrp + lookup_addr);
                char* funct_name = (char*) &(image_import->Name);
                function_handle = (PVOID) GetProcAddress(import_module, funct_name);
            } else {
                function_handle = (PVOID) GetProcAddress(import_module, (LPSTR) lookup_addr);
            }

            if (function_handle == NULL) {
                return NULL;
            }

            address_table[j].u1.Function = (DWORD64) function_handle;
        }
    }

    // [ Fix relocations ]

    PIMAGE_BASE_RELOCATION p_reloc = (PIMAGE_BASE_RELOCATION) (addrp + reloc_dir.VirtualAddress);
    ULONG_PTR delta_VA_reloc = ((ULONG_PTR) addrp) - p_NT_HDR->OptionalHeader.ImageBase;
    PBASE_RELOCATION_ENTRY reloc = NULL;

    while (p_reloc->VirtualAddress != 0) {
        reloc = (PBASE_RELOCATION_ENTRY) (p_reloc + 1);

        while ((PBYTE) reloc != (PBYTE) p_reloc + p_reloc->SizeOfBlock) {
            switch (reloc->Type) {
                case IMAGE_REL_BASED_DIR64:
                    *((ULONG_PTR*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += delta_VA_reloc;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *((DWORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += (DWORD) delta_VA_reloc;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *((WORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += HIWORD(delta_VA_reloc);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *((WORD*)((ULONG_PTR) addrp + p_reloc->VirtualAddress + reloc->Offset)) += LOWORD(delta_VA_reloc);
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }
            reloc++;
        }
        p_reloc = (PIMAGE_BASE_RELOCATION) reloc;
    }

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

    return (PVOID) (addrp + p_NT_HDR->OptionalHeader.AddressOfEntryPoint);
}

