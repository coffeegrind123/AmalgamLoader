#pragma once

#include <Windows.h>
#include <string>
#include <vector>

class SignatureRandomizer {
public:
    static bool IsFirstRun();
    static bool RandomizeSignatures();
    static bool RandomizeExecutable(const std::wstring& filePath);
    static bool RandomizeDLL(const std::wstring& dllPath);
    static std::wstring GetLastError();
    
private:
    static std::vector<uint8_t> GenerateRandomData(size_t size);
    static bool ModifyPEOverlay(const std::wstring& filePath, const std::vector<uint8_t>& randomData);
    static bool ModifyResourceSection(const std::wstring& filePath);
    static std::wstring GetSystemFingerprint();
    static void MarkAsProcessed();
    static bool IsAlreadyProcessed(const std::wstring& filePath);
    static void SetLastError(const std::wstring& error);
    
    // Hash-based checking functions
    static std::vector<uint8_t> CalculateFileHash(const std::wstring& filePath);
    static bool EmbedOriginalHash(const std::wstring& filePath, const std::vector<uint8_t>& hash);
    static std::vector<uint8_t> ExtractEmbeddedHash(const std::wstring& filePath);
    static bool HasEmbeddedHash(const std::wstring& filePath);
    static void CreateFallbackMarker();
    
    // New copy-modify-replace functions
    static bool CopyToTempLocation(const std::wstring& sourcePath, std::wstring& tempPath);
    static bool ReplaceOriginalFile(const std::wstring& modifiedPath, const std::wstring& originalPath, std::wstring& newPath);
    static bool CleanupTempFiles(const std::wstring& tempDir);
    
    // Enhanced obfuscation functions (from pe-packer)
    static bool ApplyAdvancedObfuscation(const std::wstring& filePath);
    static bool MutateCodeSections(const std::wstring& filePath);
    static bool MutateCodeSectionsSafely(const std::wstring& filePath);
    static bool InsertPolymorphicCode(const std::wstring& filePath);
    static bool RandomizeSectionNames(const std::wstring& filePath);
    static bool AddJunkSections(const std::wstring& filePath);
    static bool ApplyAntiAnalysisTechniques(const std::wstring& filePath);
    
    // PE manipulation helpers
    static bool InsertJunkCode(std::vector<uint8_t>& peData, size_t insertPos);
    static bool IsCompilerPadding(const std::vector<uint8_t>& peData, size_t pos);
    static void ApplyCodeMutations(std::vector<uint8_t>& peData, size_t sectionStart, size_t sectionSize);
    
    // Constants for modification
    static constexpr size_t RANDOM_DATA_SIZE = 1024;
    static constexpr size_t MIN_DUMMY_RESOURCES = 5;
    static constexpr size_t MAX_DUMMY_RESOURCES = 15;
    
    // Error tracking
    static thread_local std::wstring s_lastError;
};