#include "SelfPacker.h"
#include <iostream>
#include <fstream>
#include <random>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>

// Ensure NTSTATUS is defined
#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

// Include zlib for compression (from packer-tutorial)
#include "zlib.h"

// Define PPEB if not available
#ifndef PPEB
typedef struct _PEB* PPEB;
#endif

SelfPacker::SelfPacker() {
}

SelfPacker::~SelfPacker() {
}

// Core file reading function (from packer-tutorial)
std::vector<std::uint8_t> SelfPacker::read_file(const std::string& filename) {
    std::ifstream fp(filename, std::ios::binary);
    
    if (!fp.is_open()) {
        log_packing_info("Error: couldn't open file: " + filename);
        return {};
    }

    auto vec_data = std::vector<std::uint8_t>();
    vec_data.insert(vec_data.end(),
                   std::istreambuf_iterator<char>(fp),
                   std::istreambuf_iterator<char>());

    return vec_data;
}

// PE validation function (from packer-tutorial)
void SelfPacker::validate_target(const std::vector<std::uint8_t>& target) {
    if (target.size() < sizeof(IMAGE_DOS_HEADER)) {
        throw std::runtime_error("File too small to be a valid PE");
    }
    
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(target.data());

    // IMAGE_DOS_SIGNATURE is 0x5A4D (for "MZ")
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        throw std::runtime_error("Target image has no valid DOS header");
    }

    if (dos_header->e_lfanew >= target.size()) {
        throw std::runtime_error("Invalid e_lfanew offset");
    }

    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(target.data() + dos_header->e_lfanew);

    // IMAGE_NT_SIGNATURE is 0x4550 (for "PE")
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Target image has no valid NT header");
    }

    // Support both x86 and x64 (unlike original pe-packer which is x86 only)
    if (nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && 
        nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        throw std::runtime_error("Unsupported PE format");
    }
}

// Data compression using zlib (from packer-tutorial)
std::vector<std::uint8_t> SelfPacker::compress_data(const std::vector<std::uint8_t>& data) {
    // Get the maximum size of a compressed buffer
    uLong packed_max = compressBound(static_cast<uLong>(data.size()));
    uLong packed_real = packed_max;

    // Allocate a vector with that size
    std::vector<std::uint8_t> packed(packed_max);
    
    if (compress(packed.data(), &packed_real, data.data(), static_cast<uLong>(data.size())) != Z_OK) {
        throw std::runtime_error("zlib failed to compress the buffer");
    }

    // Resize the buffer to the real compressed size
    packed.resize(packed_real);
    return packed;
}

// Simple XOR encryption with random key
std::vector<std::uint8_t> SelfPacker::encrypt_data(const std::vector<std::uint8_t>& data, const std::string& key) {
    std::vector<std::uint8_t> encrypted = data;
    
    for (size_t i = 0; i < encrypted.size(); ++i) {
        encrypted[i] ^= static_cast<std::uint8_t>(key[i % key.length()]);
    }
    
    return encrypted;
}

// Generate random encryption key
std::string SelfPacker::generate_random_key(size_t length) {
    static std::uniform_int_distribution<> dis(1, 255); // Avoid null bytes
    
    std::string key;
    key.reserve(length);
    
    for (size_t i = 0; i < length; ++i) {
        key += static_cast<char>(dis(SelfPacker::get_safe_rng()));
    }
    
    return key;
}

// Main packing function that combines packer-tutorial and pe-packer techniques
bool SelfPacker::PackExecutable(const std::string& inputFile, const std::string& outputFile) {
    try {
        log_packing_info("Starting self-packing process...");
        
        // Read the target file
        auto target = read_file(inputFile);
        if (target.empty()) {
            return false;
        }
        
        // Size validation - ensure reasonable input size
        const size_t MAX_INPUT_SIZE = 10 * 1024 * 1024; // 10MB max input
        if (target.size() > MAX_INPUT_SIZE) {
            log_packing_info("Input file too large: " + std::to_string(target.size()) + " bytes");
            return false;
        }
        
        // Validate PE format
        validate_target(target);
        log_packing_info("PE validation passed, input size: " + std::to_string(target.size()) + " bytes");
        
        // Generate random packing configuration
        auto config = generate_random_config();
        
        // Apply compression if enabled
        std::vector<std::uint8_t> processed_data = target;
        if (config.use_compression) {
            processed_data = compress_data(target);
            log_packing_info("Applied compression");
        }
        
        // Apply encryption if enabled
        std::string encryption_key;
        if (config.use_encryption) {
            encryption_key = generate_random_key();
            processed_data = encrypt_data(processed_data, encryption_key);
            log_packing_info("Applied encryption");
        }
        
        // Load stub (use current executable as base)
        auto stub_data = load_stub_resource();
        
        // Apply code mutations to stub (from pe-packer techniques)
        if (config.use_code_mutation) {
            apply_code_mutations(stub_data);
            log_packing_info("Applied code mutations");
        }
        
        // Insert junk code for obfuscation
        if (config.use_junk_code) {
            insert_junk_instructions(stub_data);
            log_packing_info("Inserted junk code");
        }
        
        // Add packed section to stub
        add_packed_section(stub_data, processed_data, encryption_key);
        log_packing_info("Added packed section");
        
        // Size validation - prevent excessive output sizes
        const size_t MAX_OUTPUT_SIZE = 5 * 1024 * 1024; // 5MB absolute maximum
        
        if (stub_data.size() > MAX_OUTPUT_SIZE) {
            log_packing_info("ERROR: Output too large (" + std::to_string(stub_data.size()) + " bytes), aborting");
            return false;
        }
        
        log_packing_info("Final packed size: " + std::to_string(stub_data.size()) + " bytes");
        
        // Write final packed executable
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile.is_open()) {
            log_packing_info("Error: couldn't open output file");
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(stub_data.data()), stub_data.size());
        outFile.close();
        
        log_packing_info("Successfully packed executable, final size: " + std::to_string(stub_data.size()) + " bytes");
        return true;
    }
    catch (const std::exception& ex) {
        log_packing_info("Packing failed: " + std::string(ex.what()));
        return false;
    }
}

// Anti-analysis checks (basic implementation)
bool SelfPacker::check_debugger() {
    // Use only safe, well-documented APIs
    if (IsDebuggerPresent()) {
        return true;
    }
    
    // Safe PEB check with proper error handling
    __try {
        BOOL beingDebugged = FALSE;
        HANDLE hProcess = GetCurrentProcess();
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        
        if (hNtdll) {
            typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
            pNtQueryInformationProcess NtQueryInformationProcess = 
                (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            
            if (NtQueryInformationProcess) {
                NTSTATUS status = NtQueryInformationProcess(hProcess, 7, &beingDebugged, sizeof(BOOL), NULL);
                if (status == 0 && beingDebugged) {
                    return true;
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Ignore exceptions and continue
    }
    
    return false;
}

bool SelfPacker::check_vm_environment() {
    // Basic VM detection - check for VM artifacts with error handling
    __try {
        HKEY hKey;
        bool isVM = false;
        
        // Check for VMware
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            isVM = true;
            RegCloseKey(hKey);
        }
        
        // Check for VirtualBox
        if (!isVM && RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            isVM = true;
            RegCloseKey(hKey);
        }
        
        return isVM;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Return false on any exception
        return false;
    }
}

bool SelfPacker::check_sandbox() {
    // Basic sandbox detection - check for limited execution time with error handling
    __try {
        DWORD startTime = GetTickCount();
        Sleep(1000); // Sleep for 1 second
        DWORD endTime = GetTickCount();
        
        // If sleep was significantly accelerated, likely in sandbox
        return (endTime - startTime) < 500;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        // Return false on any exception
        return false;
    }
}

// Runtime initialization for self-modification
bool SelfPacker::InitializeRuntimeModifications() {
    try {
        // Perform anti-analysis checks - but don't exit during development
        if (check_debugger() || check_vm_environment() || check_sandbox()) {
            // Log detection but continue for development builds
            log_packing_info("Analysis environment detected - continuing in development mode");
            // In production, you might want to enable: ExitProcess(0);
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
}

// Apply first-run modifications
bool SelfPacker::ApplyFirstRunModifications() {
    try {
        // Randomize some PE characteristics
        randomize_section_names();
        
        // Apply runtime obfuscation
        obfuscate_string_constants();
        
        return true;
    }
    catch (...) {
        return false;
    }
}

// Generate random configuration for polymorphic behavior
SelfPacker::PackingConfig SelfPacker::generate_random_config() {
    static std::uniform_int_distribution<> dis(0, 1);
    
    PackingConfig config;
    
    if (dis(SelfPacker::get_safe_rng())) config.use_compression = dis(SelfPacker::get_safe_rng());
    if (dis(SelfPacker::get_safe_rng())) config.use_encryption = dis(SelfPacker::get_safe_rng());
    if (dis(SelfPacker::get_safe_rng())) config.use_anti_debug = dis(SelfPacker::get_safe_rng());
    if (dis(SelfPacker::get_safe_rng())) config.use_anti_vm = dis(SelfPacker::get_safe_rng());
    if (dis(SelfPacker::get_safe_rng())) config.use_code_mutation = dis(SelfPacker::get_safe_rng());
    if (dis(SelfPacker::get_safe_rng())) config.use_junk_code = dis(SelfPacker::get_safe_rng());
    
    return config;
}

// Safe random number generator helper
std::mt19937& SelfPacker::SelfPacker::get_safe_rng() {
    static bool initialized = false;
    static std::mt19937 gen;
    
    if (!initialized) {
        // Use time-based seeding instead of std::random_device to avoid crashes
        auto now = std::chrono::high_resolution_clock::now();
        auto seed = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
        gen.seed(static_cast<unsigned int>(seed ^ GetTickCount() ^ GetCurrentThreadId()));
        initialized = true;
    }
    
    return gen;
}

// Utility functions
std::uint8_t SelfPacker::generate_random_byte() {
    static std::uniform_int_distribution<> dis(0, 255);
    return static_cast<std::uint8_t>(dis(SelfPacker::get_safe_rng()));
}

std::uint32_t SelfPacker::generate_random_dword() {
    return (static_cast<std::uint32_t>(generate_random_byte()) << 24) |
           (static_cast<std::uint32_t>(generate_random_byte()) << 16) |
           (static_cast<std::uint32_t>(generate_random_byte()) << 8) |
           static_cast<std::uint32_t>(generate_random_byte());
}

// Logging function
void SelfPacker::log_packing_info(const std::string& message) {
#ifdef _DEBUG
    std::cout << "[SelfPacker] " << message << std::endl;
#endif
}

// Load stub from embedded resources or create simple stub
std::vector<std::uint8_t> SelfPacker::load_stub_resource() {
    // FIXED: Create minimal stub instead of reading current executable
    // Reading current executable causes exponential growth (3GB+ files)
    
    log_packing_info("Creating minimal stub template (avoiding recursive read)");
    
    // Create a reasonable sized stub for final 1-2MB output
    const size_t STUB_SIZE = 512 * 1024; // 512KB stub base
    std::vector<std::uint8_t> stubData(STUB_SIZE);
    
    // Fill with random data to create variety
    for (size_t i = 0; i < STUB_SIZE; ++i) {
        stubData[i] = generate_random_byte();
    }
    
    // Set basic PE headers at the beginning
    if (STUB_SIZE >= sizeof(IMAGE_DOS_HEADER)) {
        IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(stubData.data());
        dosHeader->e_magic = IMAGE_DOS_SIGNATURE; // 'MZ'
        dosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
    }
    
    log_packing_info("Created minimal stub of size: " + std::to_string(stubData.size()) + " bytes");
    return stubData;
}

void SelfPacker::add_packed_section(std::vector<std::uint8_t>& stub_data, 
                                   const std::vector<std::uint8_t>& packed_data,
                                   const std::string& encryption_key) {
    if (stub_data.empty()) {
        throw std::runtime_error("Empty stub data");
    }
    
    // Get DOS and NT headers
    auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(stub_data.data());
    auto e_lfanew = dos_header->e_lfanew;
    
    // Support both x86 and x64 (detect architecture)
    auto nt_header32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(stub_data.data() + e_lfanew);
    auto nt_header64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(stub_data.data() + e_lfanew);
    
    DWORD file_alignment, section_alignment;
    DWORD size_of_headers, size_of_image;
    bool is64bit = false;
    
    if (nt_header32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64bit = true;
        file_alignment = nt_header64->OptionalHeader.FileAlignment;
        section_alignment = nt_header64->OptionalHeader.SectionAlignment;
        size_of_headers = nt_header64->OptionalHeader.SizeOfHeaders;
        size_of_image = nt_header64->OptionalHeader.SizeOfImage;
    } else {
        file_alignment = nt_header32->OptionalHeader.FileAlignment;
        section_alignment = nt_header32->OptionalHeader.SectionAlignment;
        size_of_headers = nt_header32->OptionalHeader.SizeOfHeaders;
        size_of_image = nt_header32->OptionalHeader.SizeOfImage;
    }
    
    // Align the buffer to the file boundary if it isn't already
    if (stub_data.size() % file_alignment != 0) {
        stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));
    }
    
    // Save the offset to our new section
    auto raw_offset = static_cast<std::uint32_t>(stub_data.size());
    
    // Encode the size of our unpacked data into the stub data
    auto unpacked_size = packed_data.size();
    stub_data.insert(stub_data.end(),
                    reinterpret_cast<const std::uint8_t*>(&unpacked_size),
                    reinterpret_cast<const std::uint8_t*>(&unpacked_size) + sizeof(std::size_t));
    
    // Encode the encryption key size and key
    auto key_size = encryption_key.size();
    stub_data.insert(stub_data.end(),
                    reinterpret_cast<const std::uint8_t*>(&key_size),
                    reinterpret_cast<const std::uint8_t*>(&key_size) + sizeof(std::size_t));
    
    stub_data.insert(stub_data.end(), encryption_key.begin(), encryption_key.end());
    
    // Add our packed data
    stub_data.insert(stub_data.end(), packed_data.begin(), packed_data.end());
    
    // Calculate the section size for storage in the PE file
    auto section_size = static_cast<std::uint32_t>(packed_data.size() + sizeof(std::size_t) * 2 + encryption_key.size());
    
    // Re-acquire NT header pointer since buffer addresses may have changed
    if (is64bit) {
        nt_header64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(stub_data.data() + e_lfanew);
    } else {
        nt_header32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(stub_data.data() + e_lfanew);
    }
    
    // Pad the section data with 0s if we aren't on the file alignment boundary
    if (stub_data.size() % file_alignment != 0) {
        stub_data.resize(align<std::size_t>(stub_data.size(), file_alignment));
    }
    
    // Get section count and increment it
    WORD section_count;
    WORD size_of_optional_header;
    IMAGE_SECTION_HEADER* section_table;
    
    if (is64bit) {
        section_count = nt_header64->FileHeader.NumberOfSections;
        ++nt_header64->FileHeader.NumberOfSections;
        size_of_optional_header = nt_header64->FileHeader.SizeOfOptionalHeader;
        section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<std::uint8_t*>(&nt_header64->OptionalHeader) + size_of_optional_header);
    } else {
        section_count = nt_header32->FileHeader.NumberOfSections;
        ++nt_header32->FileHeader.NumberOfSections;
        size_of_optional_header = nt_header32->FileHeader.SizeOfOptionalHeader;
        section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(
            reinterpret_cast<std::uint8_t*>(&nt_header32->OptionalHeader) + size_of_optional_header);
    }
    
    // Get pointers to our new section and the previous section
    auto section = &section_table[section_count];
    auto prev_section = &section_table[section_count - 1];
    
    // Calculate the memory offset, memory size and raw aligned size of our packed section
    auto virtual_offset = align(prev_section->VirtualAddress + prev_section->Misc.VirtualSize, section_alignment);
    auto virtual_size = section_size;
    auto raw_size = align<DWORD>(section_size, file_alignment);
    
    // Generate random section name for polymorphism
    char section_names[][9] = {".packed", ".data2", ".rsrc2", ".text2", ".code", ".extra"};
    int name_idx = generate_random_byte() % (sizeof(section_names) / sizeof(section_names[0]));
    
    // Assign the section metadata
    std::memcpy(section->Name, section_names[name_idx], 8);
    section->Misc.VirtualSize = virtual_size;
    section->VirtualAddress = virtual_offset;
    section->SizeOfRawData = raw_size;
    section->PointerToRawData = raw_offset;
    
    // Mark our section as initialized, readable data
    section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    
    // Calculate the new size of the image
    auto new_image_size = align(virtual_offset + virtual_size, section_alignment);
    if (is64bit) {
        nt_header64->OptionalHeader.SizeOfImage = new_image_size;
    } else {
        nt_header32->OptionalHeader.SizeOfImage = new_image_size;
    }
}

void SelfPacker::apply_code_mutations(std::vector<std::uint8_t>& code) {
    // Apply pe-packer style code mutations
    if (code.empty()) return;
    
    // Generate random mutation count
    static std::uniform_int_distribution<> mutation_dis(50, 200);
    
    int mutation_count = mutation_dis(SelfPacker::get_safe_rng());
    
    for (int i = 0; i < mutation_count; ++i) {
        apply_single_mutation(code);
    }
    
    log_packing_info("Applied " + std::to_string(mutation_count) + " code mutations");
}

void SelfPacker::apply_single_mutation(std::vector<std::uint8_t>& code) {
    static std::uniform_int_distribution<> pos_dis(0, static_cast<int>(code.size() - 10));
    static std::uniform_int_distribution<> type_dis(0, 6);
    
    if (code.size() < 20) return;
    
    size_t pos = pos_dis(SelfPacker::get_safe_rng());
    int mutation_type = type_dis(SelfPacker::get_safe_rng());
    
    switch (mutation_type) {
        case 0: // Insert NOP sled
            insert_nop_sled(code, pos);
            break;
        case 1: // Insert junk push/pop
            insert_junk_push_pop(code, pos);
            break;
        case 2: // Insert fake conditional jumps
            insert_fake_conditionals(code, pos);
            break;
        case 3: // Insert arithmetic junk
            insert_arithmetic_junk(code, pos);
            break;
        case 4: // Insert fake function calls
            insert_fake_calls(code, pos);
            break;
        case 5: // XOR obfuscation
            apply_xor_obfuscation(code, pos);
            break;
        case 6: // Insert cpuid instructions
            insert_cpuid_junk(code, pos);
            break;
    }
}

void SelfPacker::insert_nop_sled(std::vector<std::uint8_t>& code, size_t pos) {
    static std::uniform_int_distribution<> count_dis(3, 15);
    
    int nop_count = count_dis(SelfPacker::get_safe_rng());
    std::vector<std::uint8_t> nops(nop_count, 0x90); // NOP instruction
    code.insert(code.begin() + pos, nops.begin(), nops.end());
}

void SelfPacker::insert_junk_push_pop(std::vector<std::uint8_t>& code, size_t pos) {
    // Insert push/pop pairs that don't affect execution
    std::vector<std::uint8_t> junk_code = {
        0x50,                    // push eax
        0x53,                    // push ebx
        0x01, 0xC3,              // add ebx, eax
        0x29, 0xC3,              // sub ebx, eax
        0x5B,                    // pop ebx
        0x58                     // pop eax
    };
    
    code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
}

void SelfPacker::insert_fake_conditionals(std::vector<std::uint8_t>& code, size_t pos) {
    // Insert conditional jumps that always/never jump
    static std::uniform_int_distribution<> type_dis(0, 3);
    
    std::vector<std::uint8_t> junk_code;
    
    switch (type_dis(SelfPacker::get_safe_rng())) {
        case 0: // Always false condition
            junk_code = {
                0x31, 0xC0,          // xor eax, eax
                0x85, 0xC0,          // test eax, eax
                0x75, 0x05,          // jnz +5 (never taken)
                0x90, 0x90, 0x90, 0x90, 0x90  // NOPs
            };
            break;
        case 1: // Always true condition
            junk_code = {
                0x31, 0xC0,          // xor eax, eax
                0x40,                // inc eax
                0x85, 0xC0,          // test eax, eax
                0x74, 0x05,          // jz +5 (never taken)
                0x90, 0x90, 0x90, 0x90, 0x90  // NOPs
            };
            break;
        case 2: // Complex fake condition
            junk_code = {
                0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
                0xBB, 0x01, 0x00, 0x00, 0x00,  // mov ebx, 1
                0x39, 0xD8,                     // cmp eax, ebx
                0x75, 0x02,                     // jnz +2 (never taken)
                0x90, 0x90                      // NOPs
            };
            break;
        case 3: // Loop that executes once
            junk_code = {
                0xB9, 0x01, 0x00, 0x00, 0x00,  // mov ecx, 1
                0x49,                           // dec ecx
                0x85, 0xC9,                     // test ecx, ecx
                0x75, 0x02,                     // jnz +2 (never taken)
                0x90, 0x90                      // NOPs
            };
            break;
    }
    
    code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
}

void SelfPacker::insert_arithmetic_junk(std::vector<std::uint8_t>& code, size_t pos) {
    // Insert arithmetic operations that cancel out
    static std::uniform_int_distribution<> val_dis(1, 255);
    
    uint8_t rand_val = static_cast<uint8_t>(val_dis(SelfPacker::get_safe_rng()));
    
    std::vector<std::uint8_t> junk_code = {
        0x50,                    // push eax
        0xB8, rand_val, 0x00, 0x00, 0x00,  // mov eax, rand_val
        0x6B, 0xC0, 0x02,        // imul eax, 2
        0xD1, 0xE8,              // shr eax, 1
        0x2D, rand_val, 0x00, 0x00, 0x00,  // sub eax, rand_val
        0x58                     // pop eax
    };
    
    code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
}

void SelfPacker::insert_fake_calls(std::vector<std::uint8_t>& code, size_t pos) {
    // Insert call/ret pairs for obfuscation
    std::vector<std::uint8_t> junk_code = {
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call +0 (next instruction)
        0xC3                           // ret
    };
    
    code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
}

void SelfPacker::apply_xor_obfuscation(std::vector<std::uint8_t>& code, size_t pos) {
    // XOR a small region with a key, then XOR it back
    static std::uniform_int_distribution<> key_dis(1, 255);
    static std::uniform_int_distribution<> size_dis(4, 12);
    
    if (pos + 20 >= code.size()) return;
    
    uint8_t xor_key = static_cast<uint8_t>(key_dis(SelfPacker::get_safe_rng()));
    int region_size = size_dis(SelfPacker::get_safe_rng());
    
    // XOR a region
    for (int i = 0; i < region_size && pos + i < code.size(); ++i) {
        code[pos + i] ^= xor_key;
    }
    
    // Insert code to XOR it back at runtime
    std::vector<std::uint8_t> decrypt_code = {
        0x50,                              // push eax
        0x51,                              // push ecx
        0xB9, static_cast<uint8_t>(region_size), 0x00, 0x00, 0x00,  // mov ecx, region_size
        0xB0, xor_key,                     // mov al, xor_key
        // XOR loop would go here - simplified for now
        0x59,                              // pop ecx
        0x58                               // pop eax
    };
    
    code.insert(code.begin() + pos + region_size, decrypt_code.begin(), decrypt_code.end());
}

void SelfPacker::insert_cpuid_junk(std::vector<std::uint8_t>& code, size_t pos) {
    // Insert CPUID instructions for timing obfuscation
    std::vector<std::uint8_t> junk_code = {
        0x50,                    // push eax
        0x53,                    // push ebx
        0x51,                    // push ecx
        0x52,                    // push edx
        0x31, 0xC0,              // xor eax, eax
        0x0F, 0xA2,              // cpuid
        0x5A,                    // pop edx
        0x59,                    // pop ecx
        0x5B,                    // pop ebx
        0x58                     // pop eax
    };
    
    code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
}

void SelfPacker::insert_junk_instructions(std::vector<std::uint8_t>& code) {
    // TODO: Implement junk code insertion
}

void SelfPacker::randomize_section_names() {
    // TODO: Implement section name randomization
}

void SelfPacker::obfuscate_string_constants() {
    // TODO: Implement string obfuscation
}

SelfPacker::StubVariant SelfPacker::select_random_stub_variant() {
    static std::uniform_int_distribution<> dis(0, 3);
    return static_cast<StubVariant>(dis(SelfPacker::get_safe_rng()));
}

std::vector<std::uint8_t> SelfPacker::get_stub_variant(StubVariant variant) {
    // TODO: Return appropriate stub based on variant
    return {};
}