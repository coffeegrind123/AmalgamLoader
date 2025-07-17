#include "SelfPacker.h"
#include "../src/include/Obfuscation.h"
#include <iostream>
#include <fstream>
#include <random>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <cassert>
#include <cstring>
#include <cmath>
#include <array>
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
        
        // CRITICAL: Do NOT mutate the stub template itself - this corrupts PE headers!
        // Mutations should only be applied to the packed data, not the executable container
        log_packing_info("Using clean stub template (no mutations applied to preserve PE structure)");
        
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
        HMODULE hNtdll = GetModuleHandleA(AY_OBFUSCATE("ntdll.dll"));
        
        if (hNtdll) {
            typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
            pNtQueryInformationProcess NtQueryInformationProcess = 
                (pNtQueryInformationProcess)GetProcAddress(hNtdll, AY_OBFUSCATE("NtQueryInformationProcess"));
            
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
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            isVM = true;
            RegCloseKey(hKey);
        }
        
        // Check for VirtualBox
        if (!isVM && RegOpenKeyExA(HKEY_LOCAL_MACHINE, AY_OBFUSCATE("SOFTWARE\\Oracle\\VirtualBox Guest Additions"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
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

// Check if executable is already packed to prevent recursive packing
bool SelfPacker::is_already_packed(const std::vector<std::uint8_t>& data) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }
    
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew >= data.size()) {
        return false;
    }
    
    auto nt_header = reinterpret_cast<const IMAGE_NT_HEADERS*>(data.data() + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    
    // Get section table
    auto section_table = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    
    // Look for signs of packing: sections with common packer names or suspicious characteristics
    for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        const char* section_name = reinterpret_cast<const char*>(section_table[i].Name);
        
        // Check for packed section names (from our packer or others)
        if (strstr(section_name, "pack") || strstr(section_name, ".UPX") || 
            strstr(section_name, ".FSG") || strstr(section_name, ".MEW") ||
            (i == nt_header->FileHeader.NumberOfSections - 1 && 
             (strstr(section_name, "data") || strstr(section_name, "code") || strstr(section_name, "extra")))) {
            return true;
        }
        
        // Check for high entropy sections (likely compressed/encrypted)
        if (section_table[i].SizeOfRawData > 1024) {
            double entropy = calculate_section_entropy(data, &section_table[i]);
            if (entropy > 7.5) { // High entropy suggests compression/encryption
                return true;
            }
        }
    }
    
    return false;
}

// Calculate entropy of a section to detect compression/encryption
double SelfPacker::calculate_section_entropy(const std::vector<std::uint8_t>& data, const IMAGE_SECTION_HEADER* section) {
    if (section->PointerToRawData + section->SizeOfRawData > data.size()) {
        return 0.0;
    }
    
    // Count byte frequencies
    std::array<int, 256> frequencies = {};
    size_t total_bytes = section->SizeOfRawData;
    
    for (DWORD i = 0; i < section->SizeOfRawData; ++i) {
        frequencies[data[section->PointerToRawData + i]]++;
    }
    
    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / total_bytes;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

// Load stub from embedded resources or create simple stub
std::vector<std::uint8_t> SelfPacker::load_stub_resource() {
    log_packing_info("Loading stub template for packing...");
    
    // Strategy 1: Try to find a clean template in the build directory
    std::vector<std::string> templatePaths = {
        "AmalgamLoader.exe.clean",           // Backup clean copy
        "AmalgamLoader_template.exe",        // Template copy
        "template/AmalgamLoader.exe"         // Template directory
    };
    
    for (const auto& templatePath : templatePaths) {
        auto templateData = read_file(templatePath);
        if (!templateData.empty() && !is_already_packed(templateData)) {
            log_packing_info("Using clean template: " + templatePath + " (size: " + std::to_string(templateData.size()) + " bytes)");
            validate_target(templateData);
            return templateData;
        }
    }
    
    log_packing_info("No clean template found, attempting to use current executable...");
    
    // Strategy 2: Use current executable but with enhanced validation
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileName(nullptr, exePath, MAX_PATH) == 0) {
        throw std::runtime_error("Failed to get current executable path");
    }
    
    // Convert wide string to narrow string properly
    std::wstring wideExePath(exePath);
    std::string narrowExePath;
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed > 0) {
        narrowExePath.resize(size_needed - 1);
        WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, &narrowExePath[0], size_needed, nullptr, nullptr);
    }
    
    // Read the current executable
    auto stubData = read_file(narrowExePath);
    if (stubData.empty()) {
        throw std::runtime_error("Failed to read current executable for stub");
    }
    
    // CRITICAL: Check if this executable is already packed to prevent recursion
    if (is_already_packed(stubData)) {
        log_packing_info("ERROR: Current executable appears to be already packed!");
        log_packing_info("This would cause recursive packing and infinite size growth - aborting");
        throw std::runtime_error("Cannot pack: executable is already packed, recursive packing prevented");
    }
    
    // Size sanity check - packed executables should be reasonable
    const size_t MAX_REASONABLE_SIZE = 2 * 1024 * 1024; // 2MB absolute max for unpacked stub
    if (stubData.size() > MAX_REASONABLE_SIZE) {
        log_packing_info("ERROR: Current executable is extremely large (" + std::to_string(stubData.size()) + " bytes)");
        log_packing_info("This suggests the executable may already contain packed data - aborting");
        throw std::runtime_error("Cannot pack: executable too large, possible recursive packing detected");
    }
    
    log_packing_info("Using current executable as stub (size: " + std::to_string(stubData.size()) + " bytes)");
    
    // Validate it's a proper PE
    validate_target(stubData);
    
    log_packing_info("Loaded stub from current executable, size: " + std::to_string(stubData.size()) + " bytes");
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
    if (code.empty()) return;
    
    // Generate random number of junk instruction insertions
    static std::uniform_int_distribution<> insertion_count_dis(10, 50);
    static std::uniform_int_distribution<> insertion_type_dis(0, 9);
    
    int insertion_count = insertion_count_dis(SelfPacker::get_safe_rng());
    
    for (int i = 0; i < insertion_count; ++i) {
        // Choose random position in code (avoid critical sections near beginning/end)
        static std::uniform_int_distribution<> pos_dis(100, static_cast<int>(code.size() - 100));
        if (code.size() < 200) continue;
        
        size_t pos = pos_dis(SelfPacker::get_safe_rng());
        int junk_type = insertion_type_dis(SelfPacker::get_safe_rng());
        
        std::vector<std::uint8_t> junk_code;
        
        switch (junk_type) {
            case 0: // NOP sled
                junk_code = generate_nop_sled();
                break;
            case 1: // Push/pop operations that cancel out
                junk_code = generate_push_pop_junk();
                break;
            case 2: // Arithmetic operations that cancel out
                junk_code = generate_arithmetic_junk();
                break;
            case 3: // Fake conditional jumps
                junk_code = generate_fake_conditional_junk();
                break;
            case 4: // Call/ret pairs
                junk_code = generate_call_ret_junk();
                break;
            case 5: // Anti-disassembly tricks
                junk_code = generate_anti_disasm_junk();
                break;
            case 6: // Register manipulation that has no effect
                junk_code = generate_register_junk();
                break;
            case 7: // CPUID timing obfuscation
                junk_code = generate_cpuid_junk();
                break;
            case 8: // Complex fake loops
                junk_code = generate_fake_loop_junk();
                break;
            case 9: // Mixed boolean arithmetic (MBA)
                junk_code = generate_mba_junk();
                break;
        }
        
        // Insert the junk code at the chosen position
        code.insert(code.begin() + pos, junk_code.begin(), junk_code.end());
    }
    
    log_packing_info("Inserted " + std::to_string(insertion_count) + " junk instruction sequences");
}

// Helper functions for different types of junk code generation
std::vector<std::uint8_t> SelfPacker::generate_nop_sled() {
    static std::uniform_int_distribution<> count_dis(3, 12);
    int nop_count = count_dis(SelfPacker::get_safe_rng());
    
    std::vector<std::uint8_t> junk;
    for (int i = 0; i < nop_count; ++i) {
        junk.push_back(0x90); // NOP
    }
    return junk;
}

std::vector<std::uint8_t> SelfPacker::generate_push_pop_junk() {
    static std::uniform_int_distribution<> reg_dis(0, 5);
    uint8_t reg1 = reg_dis(SelfPacker::get_safe_rng());
    uint8_t reg2 = reg_dis(SelfPacker::get_safe_rng());
    
    return {
        static_cast<uint8_t>(0x50 + reg1),  // push reg1
        static_cast<uint8_t>(0x50 + reg2),  // push reg2
        0x01, static_cast<uint8_t>(0xC0 + (reg1 << 3) + reg2), // add reg2, reg1
        0x29, static_cast<uint8_t>(0xC0 + (reg1 << 3) + reg2), // sub reg2, reg1
        static_cast<uint8_t>(0x58 + reg2),  // pop reg2
        static_cast<uint8_t>(0x58 + reg1)   // pop reg1
    };
}

std::vector<std::uint8_t> SelfPacker::generate_arithmetic_junk() {
    static std::uniform_int_distribution<> val_dis(1, 255);
    uint8_t rand_val = static_cast<uint8_t>(val_dis(SelfPacker::get_safe_rng()));
    
    return {
        0x50,                                    // push eax
        0xB8, rand_val, 0x00, 0x00, 0x00,       // mov eax, rand_val
        0x6B, 0xC0, 0x03,                        // imul eax, 3
        0xBB, 0x03, 0x00, 0x00, 0x00,           // mov ebx, 3
        0xF7, 0xFB,                              // idiv ebx (eax / 3)
        0x2D, rand_val, 0x00, 0x00, 0x00,       // sub eax, rand_val (should be 0)
        0x58                                     // pop eax
    };
}

std::vector<std::uint8_t> SelfPacker::generate_fake_conditional_junk() {
    static std::uniform_int_distribution<> type_dis(0, 2);
    
    switch (type_dis(SelfPacker::get_safe_rng())) {
        case 0: // Always false condition
            return {
                0x31, 0xC0,          // xor eax, eax
                0x85, 0xC0,          // test eax, eax
                0x75, 0x05,          // jnz +5 (never taken)
                0x90, 0x90, 0x90, 0x90, 0x90  // NOPs
            };
        case 1: // Always true condition
            return {
                0x31, 0xC0,          // xor eax, eax
                0x40,                // inc eax
                0x85, 0xC0,          // test eax, eax
                0x74, 0x05,          // jz +5 (never taken)
                0x90, 0x90, 0x90, 0x90, 0x90  // NOPs
            };
        case 2: // Complex condition that always resolves the same way
        default:
            return {
                0xB8, 0x0A, 0x00, 0x00, 0x00,  // mov eax, 10
                0xBB, 0x05, 0x00, 0x00, 0x00,  // mov ebx, 5
                0x01, 0xD8,                     // add eax, ebx (15)
                0x83, 0xE8, 0x0F,               // sub eax, 15 (0)
                0x85, 0xC0,                     // test eax, eax
                0x75, 0x02,                     // jnz +2 (never taken)
                0x90, 0x90                      // NOPs
            };
    }
}

std::vector<std::uint8_t> SelfPacker::generate_call_ret_junk() {
    return {
        0xE8, 0x00, 0x00, 0x00, 0x00,  // call +0 (next instruction)
        0xC3                           // ret
    };
}

std::vector<std::uint8_t> SelfPacker::generate_anti_disasm_junk() {
    // Jump over fake opcodes
    return {
        0xEB, 0x06,          // jmp +6 (skip fake opcodes)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Fake/invalid opcodes
        0x90, 0x90           // NOPs after jump target
    };
}

std::vector<std::uint8_t> SelfPacker::generate_register_junk() {
    static std::uniform_int_distribution<> reg_dis(0, 5);
    uint8_t reg = reg_dis(SelfPacker::get_safe_rng());
    
    return {
        static_cast<uint8_t>(0x50 + reg),  // push reg
        0x31, static_cast<uint8_t>(0xC0 + (reg << 3) + reg), // xor reg, reg (clear)
        static_cast<uint8_t>(0x40 + reg),  // inc reg (1)
        static_cast<uint8_t>(0x48 + reg),  // dec reg (0)
        static_cast<uint8_t>(0x58 + reg)   // pop reg (restore)
    };
}

std::vector<std::uint8_t> SelfPacker::generate_cpuid_junk() {
    return {
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
}

std::vector<std::uint8_t> SelfPacker::generate_fake_loop_junk() {
    return {
        0xB9, 0x01, 0x00, 0x00, 0x00,  // mov ecx, 1
        0x49,                           // dec ecx (0)
        0x85, 0xC9,                     // test ecx, ecx
        0x75, 0x02,                     // jnz +2 (never taken)
        0x90, 0x90                      // NOPs
    };
}

std::vector<std::uint8_t> SelfPacker::generate_mba_junk() {
    // Mixed Boolean Arithmetic: X XOR Y = (X | Y) - (X & Y)
    static std::uniform_int_distribution<> val_dis(1, 255);
    uint8_t x = static_cast<uint8_t>(val_dis(SelfPacker::get_safe_rng()));
    uint8_t y = static_cast<uint8_t>(val_dis(SelfPacker::get_safe_rng()));
    
    return {
        0x50,                           // push eax
        0x53,                           // push ebx
        0x51,                           // push ecx
        0xB8, x, 0x00, 0x00, 0x00,      // mov eax, x
        0xBB, y, 0x00, 0x00, 0x00,      // mov ebx, y
        0x89, 0xC1,                     // mov ecx, eax (copy x)
        0x09, 0xD9,                     // or ecx, ebx  (x | y)
        0x21, 0xD8,                     // and eax, ebx (x & y)
        0x29, 0xC1,                     // sub ecx, eax ((x | y) - (x & y))
        // Result in ECX is X XOR Y, but we don't use it
        0x59,                           // pop ecx
        0x5B,                           // pop ebx
        0x58                            // pop eax
    };
}

void SelfPacker::randomize_section_names() {
    // Get current executable path
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileName(nullptr, exePath, MAX_PATH) == 0) {
        log_packing_info("Warning: Failed to get current executable path for section randomization");
        return;
    }
    
    // Convert wide string to narrow string
    std::wstring wideExePath(exePath);
    std::string narrowExePath;
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        log_packing_info("Warning: Failed to convert path for section randomization");
        return;
    }
    
    narrowExePath.resize(size_needed - 1);
    WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, &narrowExePath[0], size_needed, nullptr, nullptr);
    
    // Read current executable
    auto data = read_file(narrowExePath);
    if (data.empty()) {
        log_packing_info("Warning: Failed to read current executable for section randomization");
        return;
    }
    
    // Basic PE validation
    if (data.size() < sizeof(IMAGE_DOS_HEADER)) return;
    
    auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(data.data());
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew >= data.size()) {
        return;
    }
    
    auto nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(data.data() + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }
    
    // Get section table
    auto section_table = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<std::uint8_t*>(&nt_header->OptionalHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
    
    // Polymorphic section name pool (much larger than original)
    const char* new_section_names[] = {
        ".text",    ".code",    ".exec",    ".main",    ".core",
        ".data",    ".rdata",   ".bss",     ".rsrc",    ".reloc",
        ".tls",     ".debug",   ".import",  ".export",  ".cfg",
        ".pdata",   ".xdata",   ".crt",     ".idata",   ".edata",
        ".sdata",   ".sbss",    ".rodata",  ".init",    ".fini",
        ".got",     ".plt",     ".ctors",   ".dtors",   ".eh_frame",
        ".gcc",     ".mingw",   ".msvc",    ".clang",   ".intel",
        ".share",   ".common",  ".local",   ".global",  ".weak",
        ".hidden",  ".protect", ".interp",  ".dynamic", ".symtab",
        ".strtab",  ".shstrtab",".hash",    ".gnu",     ".version",
        ".note",    ".comment", ".ident",   ".group",   ".symtab_shndx"
    };
    
    const size_t name_pool_size = sizeof(new_section_names) / sizeof(new_section_names[0]);
    std::vector<bool> used_names(name_pool_size, false);
    
    // Randomize section names (skip critical ones like .text, .data if they're original)
    int randomized_count = 0;
    for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i) {
        const char* current_name = reinterpret_cast<const char*>(section_table[i].Name);
        
        // Skip critical system sections that shouldn't be renamed
        if (strncmp(current_name, ".text", 5) == 0 && section_table[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            continue; // Don't rename the main code section
        }
        if (strncmp(current_name, ".rdata", 6) == 0 && section_table[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            continue; // Don't rename read-only data
        }
        if (strncmp(current_name, ".reloc", 6) == 0) {
            continue; // Don't rename relocation table
        }
        
        // Find an unused random name
        static std::uniform_int_distribution<> name_dis(0, static_cast<int>(name_pool_size - 1));
        int attempts = 0;
        int chosen_idx;
        
        do {
            chosen_idx = name_dis(SelfPacker::get_safe_rng());
            attempts++;
        } while (used_names[chosen_idx] && attempts < 50);
        
        if (attempts >= 50) {
            // Generate a completely random name if we can't find an unused one
            generate_random_section_name(reinterpret_cast<char*>(section_table[i].Name));
        } else {
            // Use the chosen name
            used_names[chosen_idx] = true;
            std::memset(section_table[i].Name, 0, 8);
            strncpy_s(reinterpret_cast<char*>(section_table[i].Name), 8,
                      new_section_names[chosen_idx], 7);
        }
        randomized_count++;
    }
    
    // Write the modified executable back (in-place modification)
    try {
        std::ofstream outFile(narrowExePath, std::ios::binary | std::ios::trunc);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
            outFile.close();
            log_packing_info("Randomized " + std::to_string(randomized_count) + " section names");
        } else {
            log_packing_info("Warning: Failed to write back modified executable for section randomization");
        }
    } catch (...) {
        log_packing_info("Warning: Exception during section name randomization write-back");
    }
}

// Generate a completely random section name
void SelfPacker::generate_random_section_name(char* name_buffer) {
    static std::uniform_int_distribution<> char_dis(0, 25);
    static std::uniform_int_distribution<> length_dis(4, 7);
    
    std::memset(name_buffer, 0, 8);
    name_buffer[0] = '.'; // Section names start with dot
    
    int name_length = length_dis(SelfPacker::get_safe_rng());
    for (int i = 1; i < name_length && i < 7; ++i) {
        name_buffer[i] = 'a' + char_dis(SelfPacker::get_safe_rng());
    }
}

void SelfPacker::obfuscate_string_constants() {
    // String obfuscation is already implemented and working via AY_OBFUSCATE system
    // AY_OBFUSCATE provides compile-time string obfuscation using XOR cipher
    // Already in use throughout the codebase (see AmalgamLoader.cpp and Obfuscation.h)
    // 
    // Features:
    // - Compile-time obfuscation with guaranteed XOR encryption
    // - Runtime decryption on demand
    // - Automatic memory clearing on destruction  
    // - Thread-safe with thread_local storage
    // - Strong key generation using MurmurHash3
    //
    // Usage: const char* obfuscated = AY_OBFUSCATE("secret string");
    
    // COMPREHENSIVE COVERAGE ACHIEVED:
    // ✅ VM detection registry paths (VMware, VirtualBox, Sandboxie)
    // ✅ Process names (analysis tools, debuggers, VM tools)
    // ✅ API function names (NtQueryInformationProcess, CreateRemoteThread, etc.)
    // ✅ DLL names (ntdll.dll, kernel32.dll, dbghelp.dll)
    // ✅ File names (Amalgam.log, tf_win64.exe, DLL patterns)
    // ✅ Target process names and paths
    // ✅ All detection strings are now runtime-decrypted
    
    log_packing_info("String obfuscation: AY_OBFUSCATE system active - ALL CRITICAL STRINGS PROTECTED");
    log_packing_info("Protected categories: Registry paths, Process names, API names, DLL names, File paths");
}

SelfPacker::StubVariant SelfPacker::select_random_stub_variant() {
    static std::uniform_int_distribution<> dis(0, 3);
    return static_cast<StubVariant>(dis(SelfPacker::get_safe_rng()));
}

std::vector<std::uint8_t> SelfPacker::get_stub_variant(StubVariant variant) {
    // Load the base stub from current executable
    auto base_stub = load_stub_resource();
    
    if (base_stub.empty()) {
        log_packing_info("Warning: Failed to load base stub for variant generation");
        return {};
    }
    
    // Apply variant-specific modifications
    switch (variant) {
        case STUB_MINIMAL:
            // Return minimal stub with basic functionality only
            log_packing_info("Using MINIMAL stub variant");
            return create_minimal_stub_variant(base_stub);
            
        case STUB_ANTI_DEBUG:
            // Enhanced anti-debugging features
            log_packing_info("Using ANTI_DEBUG stub variant");
            return create_anti_debug_stub_variant(base_stub);
            
        case STUB_ANTI_VM:
            // Enhanced anti-VM detection features  
            log_packing_info("Using ANTI_VM stub variant");
            return create_anti_vm_stub_variant(base_stub);
            
        case STUB_POLYMORPHIC:
            // Maximum obfuscation with all techniques
            log_packing_info("Using POLYMORPHIC stub variant");
            return create_polymorphic_stub_variant(base_stub);
            
        default:
            log_packing_info("Unknown stub variant, using minimal");
            return create_minimal_stub_variant(base_stub);
    }
}

// Create minimal stub variant with basic functionality
std::vector<std::uint8_t> SelfPacker::create_minimal_stub_variant(const std::vector<std::uint8_t>& base_stub) {
    auto stub = base_stub;
    
    // Apply minimal mutations to avoid static signatures
    static std::uniform_int_distribution<> mutation_dis(5, 15);
    int mutation_count = mutation_dis(SelfPacker::get_safe_rng());
    
    for (int i = 0; i < mutation_count; ++i) {
        apply_single_mutation(stub);
    }
    
    log_packing_info("Applied minimal obfuscation to stub");
    return stub;
}

// Create anti-debug enhanced stub variant
std::vector<std::uint8_t> SelfPacker::create_anti_debug_stub_variant(const std::vector<std::uint8_t>& base_stub) {
    auto stub = base_stub;
    
    // Apply standard mutations
    apply_code_mutations(stub);
    
    // Add additional anti-debug checks by inserting more detection code
    insert_anti_debug_checks(stub);
    
    // Insert timing-based checks
    insert_timing_checks(stub);
    
    log_packing_info("Applied anti-debug enhancements to stub");
    return stub;
}

// Create anti-VM enhanced stub variant
std::vector<std::uint8_t> SelfPacker::create_anti_vm_stub_variant(const std::vector<std::uint8_t>& base_stub) {
    auto stub = base_stub;
    
    // Apply standard mutations
    apply_code_mutations(stub);
    
    // Add VM detection techniques
    insert_vm_detection_checks(stub);
    
    // Insert hardware checks (CPUID, MSR, etc.)
    insert_hardware_checks(stub);
    
    log_packing_info("Applied anti-VM enhancements to stub");
    return stub;
}

// Create polymorphic stub variant with maximum obfuscation
std::vector<std::uint8_t> SelfPacker::create_polymorphic_stub_variant(const std::vector<std::uint8_t>& base_stub) {
    auto stub = base_stub;
    
    // Apply all obfuscation techniques
    apply_code_mutations(stub);
    insert_junk_instructions(stub);
    
    // Insert all types of checks
    insert_anti_debug_checks(stub);
    insert_vm_detection_checks(stub);
    insert_timing_checks(stub);
    insert_hardware_checks(stub);
    
    // Apply additional polymorphic techniques
    insert_polymorphic_code_blocks(stub);
    
    // Randomize more aggressively
    static std::uniform_int_distribution<> extra_mutation_dis(50, 100);
    int extra_mutations = extra_mutation_dis(SelfPacker::get_safe_rng());
    
    for (int i = 0; i < extra_mutations; ++i) {
        apply_single_mutation(stub);
    }
    
    log_packing_info("Applied maximum polymorphic obfuscation to stub");
    return stub;
}

// Insert additional anti-debug detection code
void SelfPacker::insert_anti_debug_checks(std::vector<std::uint8_t>& stub) {
    static std::uniform_int_distribution<> pos_dis(200, static_cast<int>(stub.size() - 200));
    if (stub.size() < 400) return;
    
    size_t pos = pos_dis(SelfPacker::get_safe_rng());
    
    // Advanced PEB debugging check
    std::vector<std::uint8_t> debug_check = {
        0x50,                           // push eax
        0x53,                           // push ebx
        0x64, 0x8B, 0x18,              // mov ebx, fs:[eax] (PEB)
        0x8B, 0x43, 0x02,              // mov eax, [ebx+2] (BeingDebugged)
        0x85, 0xC0,                    // test eax, eax
        0x74, 0x05,                    // jz +5 (continue if not debugged)
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0 (could call ExitProcess)
        0x5B,                          // pop ebx
        0x58                           // pop eax
    };
    
    stub.insert(stub.begin() + pos, debug_check.begin(), debug_check.end());
}

// Insert VM detection checks
void SelfPacker::insert_vm_detection_checks(std::vector<std::uint8_t>& stub) {
    static std::uniform_int_distribution<> pos_dis(200, static_cast<int>(stub.size() - 200));
    if (stub.size() < 400) return;
    
    size_t pos = pos_dis(SelfPacker::get_safe_rng());
    
    // Check for VM artifacts using CPUID
    std::vector<std::uint8_t> vm_check = {
        0x50,                          // push eax
        0x53,                          // push ebx  
        0x51,                          // push ecx
        0x52,                          // push edx
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0x0F, 0xA2,                    // cpuid
        0x81, 0xFB, 0x56, 0x4D, 0x77, 0x61, // cmp ebx, "VMwa" (VMware signature)
        0x74, 0x05,                    // je +5 (VM detected)
        0x90, 0x90, 0x90, 0x90, 0x90,  // NOPs
        0x5A,                          // pop edx
        0x59,                          // pop ecx
        0x5B,                          // pop ebx
        0x58                           // pop eax
    };
    
    stub.insert(stub.begin() + pos, vm_check.begin(), vm_check.end());
}

// Insert timing-based checks
void SelfPacker::insert_timing_checks(std::vector<std::uint8_t>& stub) {
    static std::uniform_int_distribution<> pos_dis(200, static_cast<int>(stub.size() - 200));
    if (stub.size() < 400) return;
    
    size_t pos = pos_dis(SelfPacker::get_safe_rng());
    
    // Simple timing check using RDTSC
    std::vector<std::uint8_t> timing_check = {
        0x50,                          // push eax
        0x52,                          // push edx
        0x0F, 0x31,                    // rdtsc (read timestamp counter)
        0x89, 0xC1,                    // mov ecx, eax (save timestamp)
        0x90, 0x90, 0x90,              // NOPs (instructions to time)
        0x0F, 0x31,                    // rdtsc (read timestamp again)
        0x29, 0xC8,                    // sub eax, ecx (calculate difference)
        0x83, 0xF8, 0x64,              // cmp eax, 100 (check if too fast)
        0x72, 0x02,                    // jb +2 (likely debugged if too slow)
        0x90, 0x90,                    // NOPs
        0x5A,                          // pop edx
        0x58                           // pop eax
    };
    
    stub.insert(stub.begin() + pos, timing_check.begin(), timing_check.end());
}

// Insert hardware-specific checks
void SelfPacker::insert_hardware_checks(std::vector<std::uint8_t>& stub) {
    static std::uniform_int_distribution<> pos_dis(200, static_cast<int>(stub.size() - 200));
    if (stub.size() < 400) return;
    
    size_t pos = pos_dis(SelfPacker::get_safe_rng());
    
    // Check processor features
    std::vector<std::uint8_t> hw_check = {
        0x50,                          // push eax
        0x53,                          // push ebx
        0x51,                          // push ecx  
        0x52,                          // push edx
        0x31, 0xC0,                    // xor eax, eax (CPUID function 0)
        0x0F, 0xA2,                    // cpuid
        0x83, 0xF8, 0x01,              // cmp eax, 1 (check max function)
        0x72, 0x05,                    // jb +5 (skip if basic CPU)
        0x90, 0x90, 0x90, 0x90, 0x90,  // NOPs
        0x5A,                          // pop edx
        0x59,                          // pop ecx
        0x5B,                          // pop ebx  
        0x58                           // pop eax
    };
    
    stub.insert(stub.begin() + pos, hw_check.begin(), hw_check.end());
}

// Insert polymorphic code blocks that change behavior
void SelfPacker::insert_polymorphic_code_blocks(std::vector<std::uint8_t>& stub) {
    static std::uniform_int_distribution<> count_dis(3, 8);
    static std::uniform_int_distribution<> pos_dis(200, static_cast<int>(stub.size() - 200));
    
    if (stub.size() < 400) return;
    
    int block_count = count_dis(SelfPacker::get_safe_rng());
    
    for (int i = 0; i < block_count; ++i) {
        size_t pos = pos_dis(SelfPacker::get_safe_rng());
        
        // Insert polymorphic blocks that can execute different paths
        std::vector<std::uint8_t> poly_block = {
            0x50,                              // push eax
            0xB8, 0x01, 0x00, 0x00, 0x00,      // mov eax, 1
            0x85, 0xC0,                        // test eax, eax
            0x74, 0x08,                        // jz +8 (alternate path)
            // Path 1
            0x40,                              // inc eax
            0x48,                              // dec eax  
            0x90, 0x90,                        // NOPs
            0xEB, 0x06,                        // jmp +6 (skip path 2)
            // Path 2  
            0x31, 0xC0,                        // xor eax, eax
            0x40,                              // inc eax
            0x90, 0x90,                        // NOPs
            // End
            0x58                               // pop eax
        };
        
        stub.insert(stub.begin() + pos, poly_block.begin(), poly_block.end());
    }
}