#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <random>

class SelfPacker {
public:
    SelfPacker();
    ~SelfPacker();
    
    // Main self-packing function for build-time use
    static bool PackExecutable(const std::string& inputFile, const std::string& outputFile);
    
    // Runtime modification functions
    static bool InitializeRuntimeModifications();
    static bool ApplyFirstRunModifications();
    
    // Public access to anti-analysis and mutation functions for integration
    static bool check_debugger();
    static bool check_vm_environment();
    static bool check_sandbox();
    static void apply_code_mutations(std::vector<std::uint8_t>& code);
    static void randomize_section_names();
    static void obfuscate_string_constants();
    static std::vector<std::uint8_t> read_file(const std::string& filename);
    
private:
    // Core functions from packer-tutorial
    static void validate_target(const std::vector<std::uint8_t>& target);
    static std::vector<std::uint8_t> load_stub_resource();
    static bool is_already_packed(const std::vector<std::uint8_t>& data);
    static double calculate_section_entropy(const std::vector<std::uint8_t>& data, const IMAGE_SECTION_HEADER* section);
    
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
    static void apply_anti_analysis_patches();
    
    // Code obfuscation (adapted from pe-packer for x64)
    static void apply_single_mutation(std::vector<std::uint8_t>& code);
    static void randomize_instruction_order(std::vector<std::uint8_t>& code);
    
    // Junk code generation helpers
    static std::vector<std::uint8_t> generate_nop_sled();
    static std::vector<std::uint8_t> generate_push_pop_junk();
    static std::vector<std::uint8_t> generate_arithmetic_junk();
    static std::vector<std::uint8_t> generate_fake_conditional_junk();
    static std::vector<std::uint8_t> generate_call_ret_junk();
    static std::vector<std::uint8_t> generate_anti_disasm_junk();
    static std::vector<std::uint8_t> generate_register_junk();
    static std::vector<std::uint8_t> generate_cpuid_junk();
    static std::vector<std::uint8_t> generate_fake_loop_junk();
    static std::vector<std::uint8_t> generate_mba_junk();
    static void generate_random_section_name(char* name_buffer);
    
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
    static void patch_import_table();
    static void apply_runtime_encryption();
    
    // Utility functions
    static std::uint8_t generate_random_byte();
    static std::uint32_t generate_random_dword();
    static std::mt19937& get_safe_rng();
    static void xor_memory_region(void* address, size_t size, std::uint8_t key);
    
public:
    // Stub variants for polymorphism
    enum StubVariant {
        STUB_MINIMAL,
        STUB_ANTI_DEBUG,
        STUB_ANTI_VM,
        STUB_POLYMORPHIC
    };
    
    static StubVariant select_random_stub_variant();
    static std::vector<std::uint8_t> get_stub_variant(StubVariant variant);
    static void insert_junk_instructions(std::vector<std::uint8_t>& code);

private:
    
    // Stub variant creation helpers
    static std::vector<std::uint8_t> create_minimal_stub_variant(const std::vector<std::uint8_t>& base_stub);
    static std::vector<std::uint8_t> create_anti_debug_stub_variant(const std::vector<std::uint8_t>& base_stub);
    static std::vector<std::uint8_t> create_anti_vm_stub_variant(const std::vector<std::uint8_t>& base_stub);
    static std::vector<std::uint8_t> create_polymorphic_stub_variant(const std::vector<std::uint8_t>& base_stub);
    
    // Advanced anti-analysis insertion helpers
    static void insert_anti_debug_checks(std::vector<std::uint8_t>& stub);
    static void insert_vm_detection_checks(std::vector<std::uint8_t>& stub);
    static void insert_timing_checks(std::vector<std::uint8_t>& stub);
    static void insert_hardware_checks(std::vector<std::uint8_t>& stub);
    static void insert_polymorphic_code_blocks(std::vector<std::uint8_t>& stub);
    
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