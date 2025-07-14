#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <memory>

class SelfPacker {
public:
    SelfPacker();
    ~SelfPacker();
    
    // Main self-packing function for build-time use
    static bool PackExecutable(const std::string& inputFile, const std::string& outputFile);
    
    // Runtime modification functions
    static bool InitializeRuntimeModifications();
    static bool ApplyFirstRunModifications();
    
private:
    // Core functions from packer-tutorial
    static std::vector<std::uint8_t> read_file(const std::string& filename);
    static void validate_target(const std::vector<std::uint8_t>& target);
    static std::vector<std::uint8_t> load_stub_resource();
    
    template <typename T>
    static T align(T value, T alignment) {
        return value + ((value % alignment == 0) ? 0 : alignment - (value % alignment));
    }
    
    // Compression and encryption (from packer-tutorial)
    static std::vector<std::uint8_t> compress_data(const std::vector<std::uint8_t>& data);
    static std::vector<std::uint8_t> encrypt_data(const std::vector<std::uint8_t>& data, const std::string& key);
    static std::string generate_random_key(size_t length = 32);
    
    // PE manipulation (from packer-tutorial)
    static void add_packed_section(std::vector<std::uint8_t>& stub_data, 
                                 const std::vector<std::uint8_t>& packed_data,
                                 const std::string& encryption_key);
    
    // Anti-analysis techniques
    static bool check_debugger();
    static bool check_vm_environment();
    static bool check_sandbox();
    static void apply_anti_analysis_patches();
    
    // Code obfuscation (adapted from pe-packer for x64)
    static void apply_code_mutations(std::vector<std::uint8_t>& code);
    static void apply_single_mutation(std::vector<std::uint8_t>& code);
    static void insert_junk_instructions(std::vector<std::uint8_t>& code);
    static void randomize_instruction_order(std::vector<std::uint8_t>& code);
    static void obfuscate_string_constants();
    
    // Specific mutation techniques (from pe-packer)
    static void insert_nop_sled(std::vector<std::uint8_t>& code, size_t pos);
    static void insert_junk_push_pop(std::vector<std::uint8_t>& code, size_t pos);
    static void insert_fake_conditionals(std::vector<std::uint8_t>& code, size_t pos);
    static void insert_arithmetic_junk(std::vector<std::uint8_t>& code, size_t pos);
    static void insert_fake_calls(std::vector<std::uint8_t>& code, size_t pos);
    static void apply_xor_obfuscation(std::vector<std::uint8_t>& code, size_t pos);
    static void insert_cpuid_junk(std::vector<std::uint8_t>& code, size_t pos);
    
    // Runtime self-modification
    static void modify_pe_headers();
    static void randomize_section_names();
    static void patch_import_table();
    static void apply_runtime_encryption();
    
    // Utility functions
    static std::uint8_t generate_random_byte();
    static std::uint32_t generate_random_dword();
    static void xor_memory_region(void* address, size_t size, std::uint8_t key);
    
    // Stub variants for polymorphism
    enum StubVariant {
        STUB_MINIMAL,
        STUB_ANTI_DEBUG,
        STUB_ANTI_VM,
        STUB_POLYMORPHIC
    };
    
    static StubVariant select_random_stub_variant();
    static std::vector<std::uint8_t> get_stub_variant(StubVariant variant);
    
    // Configuration flags
    struct PackingConfig {
        bool use_compression = true;
        bool use_encryption = true;
        bool use_anti_debug = true;
        bool use_anti_vm = true;
        bool use_code_mutation = true;
        bool use_junk_code = true;
        bool randomize_techniques = true;
    };
    
    static PackingConfig generate_random_config();
    static void log_packing_info(const std::string& message);
};