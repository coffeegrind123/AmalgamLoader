# AmalgamLoader

A sophisticated Windows DLL injection tool with advanced stealth and evasion capabilities. Built on the BlackBone library with extensive enhancements for anti-detection and runtime polymorphism.

## Core Features

### Advanced Injection Methods
- **x86 and x64 process support** - Full cross-architecture injection capabilities
- **Kernel-mode injection** - Driver-level injection for maximum stealth (driver required)
- **Manual driver mapping** - Load kernel drivers without Windows driver signing (driver required)
- **Pure managed image injection** - Inject .NET assemblies without proxy DLLs
- **Cross-session injection** - Windows 7+ support for cross-session and cross-desktop injection
- **Native process injection** - Inject into processes with only ntdll loaded
- **Thread hijacking** - Stealth injection using existing threads
- **WOW64 injection** - Inject x64 images into 32-bit WOW64 processes

### Manual Mapping Capabilities
- **Complete relocation handling** - Import, delayed import, and bound import resolution
- **Memory hiding** - Hide allocated image memory from detection (driver required)
- **TLS support** - Static TLS and TLS callback execution
- **Security features** - Security cookie and DEP exception support
- **Manifest processing** - Image manifests and Side-by-Side (SxS) support
- **API visibility** - Make modules visible to GetModuleHandle, GetProcAddress, etc.
- **C++/CLI support** - Full support for managed C++ images

### Stealth & Anti-Detection

#### Runtime Signature Randomization
- **Per-machine polymorphism** - Unique file signatures for each installation
- **System fingerprinting** - Uses computer name, username, and timestamp for unique seeds
- **PE overlay modification** - Safe binary modification that preserves functionality
- **Resource section randomization** - Adds dummy resources with random data
- **Hash-based verification** - Embedded original hash for integrity checking
- **One-time processing** - Automatic detection with restart notification

#### Build-Time Obfuscation
- **Multi-layer protection** - Hyperion + UPX chained obfuscation
- **Generic naming** - No identifying strings in the executable
- **Icon removal** - Minimal visual footprint
- **Self-contained state** - All processing state contained within executable

### Configuration & Profiles
- **Injection profiles** - Save and load injection configurations
- **Profile file association** - .xpr/.xpr64 file extensions
- **Custom initialization** - Call custom routines after injection
- **Module unlinking** - Remove module traces after injection
- **Comprehensive logging** - Detailed operation logging and error reporting

## Recent Enhancements

### v2024 Updates
- **Complete signature randomization system** - Runtime polymorphism for anti-detection
- **Enhanced error handling** - Comprehensive error reporting throughout injection pipeline
- **Build system integration** - Automated obfuscation and signing in CI/CD
- **Project restructuring** - Renamed from Xenos to AmalgamLoader with updated branding
- **Dump handling removal** - Eliminated unnecessary dump file creation for stealth
- **BlackBone integration** - Updated to latest BlackBone library with custom modifications

### Technical Improvements
- **Resource modification API** - Proper UpdateResource() implementation for signature changes
- **System fingerprinting** - Machine-specific randomization seeds
- **Copy-modify-replace workflow** - Safe file modification without corruption risk
- **AppData marker system** - First-run detection and processing state tracking
- **Fallback mechanisms** - Robust error recovery and cleanup procedures

## System Requirements

- **Operating System**: Windows 7 - Windows 11 (x64)
- **Privileges**: Administrator rights for kernel-mode features
- **Dependencies**: Visual Studio 2019+ runtime, BlackBone library
- **Optional**: Kernel driver for advanced injection modes

## Build Configuration

AmalgamLoader supports multiple build configurations:
- **Release** - Standard optimized build
- **ReleaseAVX2** - AVX2-optimized build for modern processors
- **ReleaseFreetype** - Build with FreeType font rendering
- **ReleaseFreetypeAVX2** - Combined FreeType and AVX2 optimizations

## Security Notice

This tool is designed for legitimate software development, security research, and penetration testing purposes. The advanced evasion capabilities are intended to test defensive systems and should only be used in authorized environments.

## License

AmalgamLoader is licensed under the MIT License. Dependencies are under their respective licenses.

## Attribution

Based on the BlackBone library by DarthTon - https://github.com/DarthTon/Blackbone
Enhanced and maintained by the Amalgam project team.