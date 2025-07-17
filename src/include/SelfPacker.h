#pragma once

// Forward declaration to include SelfPacker
#include "../SelfPacker/SelfPacker.h"

// Integration wrapper class for tight coupling with AmalgamLoader
class AmalgamSelfPacker {
public:
    // Initialize runtime protection early in startup
    static bool InitializeEarlyProtection();
    
    // Apply runtime self-modification after first-run checks
    static bool ApplyRuntimeProtection();
    
    // Pack executable during build-time (called from post-build events)
    static bool PackExecutableForDistribution(const std::wstring& inputFile, const std::wstring& outputFile);
    
    // Enhanced protection specifically for injection scenarios
    static bool ApplyInjectionProtection();
    
    // Check if we're running in a protected environment
    static bool IsProtectedEnvironment();
    
    // Apply mutations to loaded DLL before injection
    static bool MutateDLLForInjection(const std::wstring& dllPath);
    
private:
    static bool s_protectionInitialized;
    static bool s_runtimeProtectionApplied;
    
    // Enhanced anti-analysis specifically for injection tools
    static bool DetectInjectionAnalysis();
    static bool DetectSandboxEnvironment();
    static bool DetectDynamicAnalysis();
    
    // Convert between string types for SelfPacker compatibility
    static std::string WStringToString(const std::wstring& wstr);
    static std::wstring StringToWString(const std::string& str);
};