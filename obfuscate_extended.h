#pragma once

// Include the original string obfuscation
#include "obfuscate.h"

// Include the new polymorphic type obfuscation
#include "cmut.hxx"

// Extended obfuscation macros for easier usage
#define OBF_STRING(str) AY_OBFUSCATE(str)
#define OBF_INT(val) cmut<int>(val)
#define OBF_UINT(val) cmut<unsigned int>(val)
#define OBF_FLOAT(val) cmut<float>(val)
#define OBF_DOUBLE(val) cmut<double>(val)
#define OBF_BOOL(val) cmut<bool>(val)
#define OBF_CHAR(val) cmut<char>(val)
#define OBF_UCHAR(val) cmut<unsigned char>(val)
#define OBF_SHORT(val) cmut<short>(val)
#define OBF_USHORT(val) cmut<unsigned short>(val)
#define OBF_LONG(val) cmut<long>(val)
#define OBF_ULONG(val) cmut<unsigned long>(val)
#define OBF_LONGLONG(val) cmut<long long>(val)
#define OBF_ULONGLONG(val) cmut<unsigned long long>(val)

// Convenience macros for common types
#define OBF_SIZE_T(val) cmut<size_t>(val)
#define OBF_PTRDIFF_T(val) cmut<ptrdiff_t>(val)
#define OBF_INTPTR_T(val) cmut<intptr_t>(val)
#define OBF_UINTPTR_T(val) cmut<uintptr_t>(val)

// Template function for automatic type deduction
template<typename T>
inline auto obfuscate_value(const T& value) {
    return cmut<T>(value);
}

// Macro for automatic type deduction
#define OBF_AUTO(val) obfuscate_value(val)

// Combined obfuscation namespace
namespace obf {
    
    // String obfuscation
    template<typename... Args>
    inline auto string(Args&&... args) {
        return AY_OBFUSCATE(std::forward<Args>(args)...);
    }
    
    // Value obfuscation
    template<typename T>
    inline auto value(const T& val) {
        return cmut<T>(val);
    }
    
    // Utility functions
    template<typename T>
    inline T get_value(const cmut<T>& obf_val) {
        return obf_val.get();
    }
    
    template<typename T>
    inline void set_value(cmut<T>& obf_val, const T& new_val) {
        obf_val.set(new_val);
    }
}

// Usage examples in comments:
/*
Example usage:

// String obfuscation
const char* obf_str = OBF_STRING("Hello World");
auto obf_str2 = obf::string("Another string");

// Value obfuscation
auto obf_int = OBF_INT(42);
auto obf_float = OBF_FLOAT(3.14f);
auto obf_bool = OBF_BOOL(true);

// Automatic type deduction
auto obf_auto = OBF_AUTO(123);

// Using namespace functions
auto obf_val = obf::value(456);
int plain_val = obf::get_value(obf_val);

// Arithmetic operations
obf_int += 10;
obf_float *= 2.0f;
auto result = obf_int + obf_float;

// Implicit conversion
int plain_int = obf_int;
float plain_float = obf_float;
*/