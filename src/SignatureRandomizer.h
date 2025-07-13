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
    static bool AddDummyResources(const std::wstring& filePath);
    static std::wstring GetSystemFingerprint();
    static void MarkAsProcessed();
    static bool IsAlreadyProcessed(const std::wstring& filePath);
    static void SetLastError(const std::wstring& error);
    
    // Constants for modification
    static constexpr size_t RANDOM_DATA_SIZE = 1024;
    static constexpr size_t MIN_DUMMY_RESOURCES = 5;
    static constexpr size_t MAX_DUMMY_RESOURCES = 15;
    
    // Error tracking
    static thread_local std::wstring s_lastError;
};