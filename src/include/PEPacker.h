#pragma once

#include <windows.h>
#include <winnt.h>
#include <vector>
#include <string>
#include <memory>

class PEPacker {
public:
    // Pack a PE executable by embedding it in the unpacker stub
    static bool PackExecutable(const std::string& inputFile, const std::string& outputFile);
    
    // Get the embedded unpacker stub
    static std::vector<uint8_t> GetUnpackerStub();
    
    // Align data to specified alignment
    static std::vector<uint8_t> PadData(const std::vector<uint8_t>& data, DWORD alignment);
    
    // Add a new section to PE file
    static bool AddSection(std::vector<uint8_t>& peData, const std::string& sectionName, 
                          const std::vector<uint8_t>& sectionData, DWORD characteristics);
    
    // Validate PE file
    static bool ValidatePE(const std::vector<uint8_t>& peData);
    
    // Read file into vector
    static std::vector<uint8_t> ReadFile(const std::string& filename);
    
    // Write vector to file
    static bool WriteFile(const std::string& filename, const std::vector<uint8_t>& data);
    
    // Calculate aligned size
    static DWORD Align(DWORD value, DWORD alignment);
    
    // Get last error message
    static std::string GetLastError();
    
    // Get all accumulated debug messages
    static std::string GetAllMessages();
    
private:
    static void SetLastError(const std::string& error);
    static void AddDebugMessage(const std::string& message);
    static thread_local std::string s_lastError;
    static thread_local std::string s_allMessages;
    
    // Update PE headers after adding section
    static bool UpdatePEHeaders(std::vector<uint8_t>& peData, DWORD newSectionRVA, DWORD newSectionSize);
};