// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/simd/base.h

enum macro_simd_flags {
/*line: 26*/    SIMD_COMPILER_HAS_REQUIRED_FEATURES = 0x1,  // 1
/*line: 35*/    SIMD_CURRENT_LIBRARY_VERSION = 0x6,  // 6
/*line: 55*/    SIMD_LIBRARY_VERSION = 0x6,  // 6
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 103
// #define SIMD_INLINE __attribute__((__always_inline__))

// Line: 109
// #define SIMD_CONST __attribute__((__const__))

// Line: 115
// #define SIMD_NODEBUG __attribute__((__nodebug__))

// Line: 126
// #define SIMD_OVERLOAD __attribute__((__overloadable__))

// Line: 127
// #define SIMD_CPPFUNC SIMD_INLINE SIMD_CONST SIMD_NODEBUG

// Line: 128
// #define SIMD_CFUNC SIMD_CPPFUNC SIMD_OVERLOAD

// Line: 129
// #define SIMD_NOINLINE SIMD_CONST SIMD_NODEBUG SIMD_OVERLOAD

// Line: 130
// #define SIMD_NONCONST SIMD_INLINE SIMD_NODEBUG SIMD_OVERLOAD

// Line: 131
// #define __SIMD_INLINE__ SIMD_CPPFUNC

// Line: 132
// #define __SIMD_ATTRIBUTES__ SIMD_CFUNC

// Line: 133
// #define __SIMD_OVERLOAD__ SIMD_OVERLOAD

