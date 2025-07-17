#include "../include/PEPacker.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

thread_local std::string PEPacker::s_lastError;
thread_local std::string PEPacker::s_allMessages;

std::vector<uint8_t> PEPacker::ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        SetLastError("Failed to open file: " + filename);
        return {};
    }
    
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    
    if (!file.good()) {
        SetLastError("Failed to read file: " + filename);
        return {};
    }
    
    return data;
}

bool PEPacker::WriteFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        SetLastError("Failed to create output file: " + filename);
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    
    if (!file.good()) {
        SetLastError("Failed to write to file: " + filename);
        return false;
    }
    
    return true;
}

DWORD PEPacker::Align(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

std::vector<uint8_t> PEPacker::PadData(const std::vector<uint8_t>& data, DWORD alignment) {
    if (alignment == 0) return data;
    
    DWORD alignedSize = Align(static_cast<DWORD>(data.size()), alignment);
    std::vector<uint8_t> paddedData = data;
    paddedData.resize(alignedSize, 0);
    
    return paddedData;
}

bool PEPacker::ValidatePE(const std::vector<uint8_t>& peData) {
    if (peData.size() < sizeof(IMAGE_DOS_HEADER)) {
        SetLastError("File too small to be a valid PE");
        return false;
    }
    
    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(peData.data());
    
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError("Invalid DOS signature");
        return false;
    }
    
    if (dosHeader->e_lfanew >= peData.size()) {
        SetLastError("Invalid e_lfanew offset");
        return false;
    }
    
    const IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        peData.data() + dosHeader->e_lfanew);
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError("Invalid NT signature");
        return false;
    }
    
    if (ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        SetLastError("Only x64 PE files are supported");
        return false;
    }
    
    return true;
}

std::vector<uint8_t> PEPacker::GetUnpackerStub() {
    // Load the built unpacker stub from the same directory as the current executable
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) == 0) {
        SetLastError("Failed to get current executable path");
        return {};
    }
    
    // Get directory of current executable
    std::wstring wideExePath(exePath);
    size_t lastSlash = wideExePath.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        wideExePath = wideExePath.substr(0, lastSlash + 1);
    }
    
    // Convert to narrow string and append UnpackerStub.exe
    std::string stubPath;
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed > 0) {
        stubPath.resize(size_needed - 1);
        WideCharToMultiByte(CP_UTF8, 0, wideExePath.c_str(), -1, &stubPath[0], size_needed, nullptr, nullptr);
    }
    stubPath += "UnpackerStub.exe";
    
    std::vector<uint8_t> stubData = ReadFile(stubPath);
    if (stubData.empty()) {
        SetLastError("Could not load unpacker stub from: " + stubPath);
        return {};
    }
    
    if (!ValidatePE(stubData)) {
        SetLastError("Unpacker stub is not a valid PE file");
        return {};
    }
    
    SetLastError("Loaded unpacker stub from: " + stubPath);
    return stubData;
}

bool PEPacker::UpdatePEHeaders(std::vector<uint8_t>& peData, DWORD newSectionRVA, DWORD newSectionSize) {
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + dosHeader->e_lfanew);
    
    // Update SizeOfImage to include the new section
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    DWORD alignedSectionSize = Align(newSectionSize, sectionAlignment);
    ntHeaders->OptionalHeader.SizeOfImage = newSectionRVA + alignedSectionSize;
    
    return true;
}

bool PEPacker::AddSection(std::vector<uint8_t>& peData, const std::string& sectionName, 
                         const std::vector<uint8_t>& sectionData, DWORD characteristics) {
    
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + dosHeader->e_lfanew);
    
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    DWORD sectionAlignment = ntHeaders->OptionalHeader.SectionAlignment;
    WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;
    
    AddDebugMessage("AddSection: Current number of sections: " + std::to_string(numberOfSections));
    AddDebugMessage("AddSection: Section name to add: " + sectionName);
    AddDebugMessage("AddSection: Section data size: " + std::to_string(sectionData.size()));
    
    // Get pointer to section table
    IMAGE_SECTION_HEADER* sectionTable = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    // Check if there's space for a new section in the section table
    // The section table must fit between the NT headers and the first section's raw data
    DWORD sectionTableSize = (numberOfSections + 1) * sizeof(IMAGE_SECTION_HEADER);
    DWORD headersSize = ntHeaders->OptionalHeader.SizeOfHeaders;
    DWORD sectionTableOffset = static_cast<DWORD>(reinterpret_cast<uint8_t*>(sectionTable) - peData.data());
    
    AddDebugMessage("AddSection: Section table offset: " + std::to_string(sectionTableOffset));
    AddDebugMessage("AddSection: Headers size: " + std::to_string(headersSize));
    AddDebugMessage("AddSection: Section table size needed: " + std::to_string(sectionTableSize));
    
    if (sectionTableOffset + sectionTableSize > headersSize) {
        AddDebugMessage("AddSection: ERROR - Not enough space in section table!");
        return false;
    }
    
    // Find the last section to calculate new section's RVA and file offset
    DWORD newSectionRVA = 0;
    DWORD newSectionFileOffset = 0;
    
    if (numberOfSections > 0) {
        const IMAGE_SECTION_HEADER* lastSection = &sectionTable[numberOfSections - 1];
        newSectionRVA = Align(lastSection->VirtualAddress + lastSection->Misc.VirtualSize, sectionAlignment);
        newSectionFileOffset = Align(lastSection->PointerToRawData + lastSection->SizeOfRawData, fileAlignment);
    } else {
        newSectionRVA = Align(ntHeaders->OptionalHeader.SizeOfHeaders, sectionAlignment);
        newSectionFileOffset = Align(ntHeaders->OptionalHeader.SizeOfHeaders, fileAlignment);
    }
    
    // Pad section data to file alignment
    std::vector<uint8_t> paddedSectionData = PadData(sectionData, fileAlignment);
    
    // Resize PE data to accommodate new section
    peData.resize(newSectionFileOffset + paddedSectionData.size());
    
    // IMPORTANT: Recalculate pointers after resize as they may have been invalidated
    dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(peData.data());
    ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(peData.data() + dosHeader->e_lfanew);
    sectionTable = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&ntHeaders->OptionalHeader) + ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    // Copy section data to the end of the file
    std::copy(paddedSectionData.begin(), paddedSectionData.end(), 
              peData.begin() + newSectionFileOffset);
    
    // Update section headers
    IMAGE_SECTION_HEADER* newSection = &sectionTable[numberOfSections];
    
    AddDebugMessage("AddSection: Adding section at index " + std::to_string(numberOfSections));
    AddDebugMessage("AddSection: New section RVA: " + std::to_string(newSectionRVA));
    AddDebugMessage("AddSection: New section file offset: " + std::to_string(newSectionFileOffset));
    
    // Clear section header
    memset(newSection, 0, sizeof(IMAGE_SECTION_HEADER));
    
    // Set section name (truncate to 8 characters)
    strncpy_s(reinterpret_cast<char*>(newSection->Name), 8, sectionName.c_str(), 7);
    
    // Set section properties
    newSection->VirtualAddress = newSectionRVA;
    newSection->Misc.VirtualSize = static_cast<DWORD>(sectionData.size());
    newSection->PointerToRawData = newSectionFileOffset;
    newSection->SizeOfRawData = static_cast<DWORD>(paddedSectionData.size());
    newSection->Characteristics = characteristics;
    
    // Increment number of sections
    ntHeaders->FileHeader.NumberOfSections++;
    
    AddDebugMessage("AddSection: Updated NumberOfSections to " + std::to_string(ntHeaders->FileHeader.NumberOfSections));
    
    // Update PE headers
    bool success = UpdatePEHeaders(peData, newSectionRVA, static_cast<DWORD>(sectionData.size()));
    AddDebugMessage("AddSection: UpdatePEHeaders returned " + std::string(success ? "true" : "false"));
    
    return success;
}

bool PEPacker::PackExecutable(const std::string& inputFile, const std::string& outputFile) {
    s_allMessages.clear(); // Clear previous messages
    AddDebugMessage("Starting PE packing process");
    
    // Read the target executable to be packed
    std::vector<uint8_t> targetData = ReadFile(inputFile);
    if (targetData.empty()) {
        return false;
    }
    
    // Check if the file has a hash marker appended by SignatureRandomizer
    // The marker is "HASH_EMBED_" (11 bytes) + 20 bytes SHA1 hash = 31 bytes total
    // We need to work with the PE data without the hash marker, but preserve it in the final file
    std::vector<uint8_t> hashMarker;
    bool hasHashMarker = false;
    
    if (targetData.size() >= 31) {
        // Check for hash marker at the end
        std::string marker(targetData.end() - 31, targetData.end() - 20);
        if (marker == "HASH_EMBED_") {
            SetLastError("Found hash marker, separating it from PE data");
            hasHashMarker = true;
            // Save the hash marker
            hashMarker.assign(targetData.end() - 31, targetData.end());
            // Work with PE data without the hash marker
            targetData.resize(targetData.size() - 31);
        }
    }
    
    // Validate target PE
    if (!ValidatePE(targetData)) {
        SetLastError("Target file is not a valid PE executable");
        return false;
    }
    
    // Get the unpacker stub
    std::vector<uint8_t> stubData = GetUnpackerStub();
    if (stubData.empty()) {
        return false;
    }
    
    // Get file alignment from stub
    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(stubData.data());
    const IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        stubData.data() + dosHeader->e_lfanew);
    
    DWORD fileAlignment = ntHeaders->OptionalHeader.FileAlignment;
    
    // Pad target data to file alignment
    std::vector<uint8_t> paddedTargetData = PadData(targetData, fileAlignment);
    
    // Validate the first few bytes of the target data before packing
    std::string originalBytes = "Original target data first 16 bytes: ";
    for (int i = 0; i < 16 && i < targetData.size(); i++) {
        char hex[8];
        sprintf_s(hex, 8, "%02X ", targetData[i]);
        originalBytes += hex;
    }
    SetLastError(originalBytes);
    
    // Add the target executable as a new section in the stub
    // Use .rsrc section name to mimic the Python implementation  
    // Store the original targetData directly, not the padded version
    SetLastError("Adding packed section of size: " + std::to_string(targetData.size()));
    
    // First, let's see what sections exist in the stub before adding
    const IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(stubData.data());
    const IMAGE_NT_HEADERS64* ntHdr = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        stubData.data() + dosHdr->e_lfanew);
    const IMAGE_SECTION_HEADER* sectHdr = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const uint8_t*>(&ntHdr->OptionalHeader) + ntHdr->FileHeader.SizeOfOptionalHeader);
    
    std::string sectionList = "Stub sections before adding: ";
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = {0};
        strncpy_s(sectionName, 9, (char*)sectHdr[i].Name, 8);
        sectionList += sectionName;
        sectionList += " ";
    }
    AddDebugMessage(sectionList);
    
    if (!AddSection(stubData, ".rsrc", targetData, 
                   IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA)) {
        AddDebugMessage("Failed to add packed section to stub");
        return false;
    }
    
    AddDebugMessage("AddSection call completed successfully");
    
    // Now let's see what sections exist after adding
    // IMPORTANT: Recalculate pointers because stubData may have been reallocated during AddSection
    const IMAGE_DOS_HEADER* dosHdrAfter = reinterpret_cast<const IMAGE_DOS_HEADER*>(stubData.data());
    const IMAGE_NT_HEADERS64* ntHdrAfter = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        stubData.data() + dosHdrAfter->e_lfanew);
    const IMAGE_SECTION_HEADER* sectHdrAfter = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const uint8_t*>(&ntHdrAfter->OptionalHeader) + ntHdrAfter->FileHeader.SizeOfOptionalHeader);
    
    sectionList = "Stub sections after adding: ";
    AddDebugMessage("Section enumeration: NumberOfSections = " + std::to_string(ntHdrAfter->FileHeader.NumberOfSections));
    for (WORD i = 0; i < ntHdrAfter->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = {0};
        strncpy_s(sectionName, 9, (char*)sectHdrAfter[i].Name, 8);
        sectionList += sectionName;
        sectionList += " ";
        AddDebugMessage("Section " + std::to_string(i) + ": " + std::string(sectionName));
    }
    AddDebugMessage(sectionList);
    
    // If we had a hash marker, append it to the packed executable
    if (hasHashMarker) {
        stubData.insert(stubData.end(), hashMarker.begin(), hashMarker.end());
        SetLastError("Re-appended hash marker to packed executable");
    }
    
    // Write the packed executable
    if (!WriteFile(outputFile, stubData)) {
        return false;
    }
    
    SetLastError("PE packing completed successfully");
    return true;
}

std::string PEPacker::GetLastError() {
    return s_lastError;
}

std::string PEPacker::GetAllMessages() {
    return s_allMessages;
}

void PEPacker::SetLastError(const std::string& error) {
    s_lastError = error;
}

void PEPacker::AddDebugMessage(const std::string& message) {
    s_allMessages += message + "\n";
    s_lastError = message;
}