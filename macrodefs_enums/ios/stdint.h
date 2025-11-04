// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/stdint.h

enum macro_wordsize {
/*line: 10*/    __WORDSIZE = 0x40,  // 64
};

enum macro_int_limits {
/* 7.18.2.1 Limits of exact-width integer types */
/*line: 91*/    INT8_MAX = 0x7f,  // 127
/*line: 92*/    INT16_MAX = 0x7fff,  // 32767
/*line: 93*/    INT32_MAX = 0x7fffffff,  // 2147483647
/*line: 94*/    INT64_MAX = 0x7fffffffffffffff,  // 9223372036854775807LL
/*line: 96*/    INT8_MIN = -0x80,  // -128
/*line: 97*/    INT16_MIN = -0x8000,  // -32768
/*
      Note:  the literal "most negative int" cannot be written in C --
      the rules in the standard (section 6.4.4.1 in C99) will give it
      an unsigned type, so INT32_MIN (and the most negative member of
      any larger signed type) must be written via a constant expression.
   */
/*line: 104*/   INT32_MIN = -0x80000000,  // (-INT32_MAX-1)
/*line: 105*/   INT64_MIN = -0x8000000000000000,  // (-INT64_MAX-1)
};

enum macro_uint_limits {
/*line: 107*/   UINT8_MAX = 0xff,  // 255
/*line: 108*/   UINT16_MAX = 0xffff,  // 65535
/*line: 109*/   UINT32_MAX = 0xffffffff,  // 4294967295U
/*line: 110*/   UINT64_MAX = 0xffffffffffffffff,  // 18446744073709551615ULL
};

// Depends on identifiers
enum macro_int_least_limits {
/* 7.18.2.2 Limits of minimum-width integer types */
/*line: 113*/   INT_LEAST8_MIN = -0x80,  // INT8_MIN
/*line: 114*/   INT_LEAST16_MIN = -0x8000,  // INT16_MIN
/*line: 115*/   INT_LEAST32_MIN = -0x80000000,  // INT32_MIN
/*line: 116*/   INT_LEAST64_MIN = -0x8000000000000000,  // INT64_MIN
/*line: 118*/   INT_LEAST8_MAX = 0x7f,  // INT8_MAX
/*line: 119*/   INT_LEAST16_MAX = 0x7fff,  // INT16_MAX
/*line: 120*/   INT_LEAST32_MAX = 0x7fffffff,  // INT32_MAX
/*line: 121*/   INT_LEAST64_MAX = 0x7fffffffffffffff,  // INT64_MAX
};

// Depends on identifiers
enum macro_uint_least_limits {
/*line: 123*/   UINT_LEAST8_MAX = 0xff,  // UINT8_MAX
/*line: 124*/   UINT_LEAST16_MAX = 0xffff,  // UINT16_MAX
/*line: 125*/   UINT_LEAST32_MAX = 0xffffffff,  // UINT32_MAX
/*line: 126*/   UINT_LEAST64_MAX = 0xffffffffffffffff,  // UINT64_MAX
};

// Depends on identifiers
enum macro_int_fast_limits {
/* 7.18.2.3 Limits of fastest minimum-width integer types */
/*line: 129*/   INT_FAST8_MIN = -0x80,  // INT8_MIN
/*line: 130*/   INT_FAST16_MIN = -0x8000,  // INT16_MIN
/*line: 131*/   INT_FAST32_MIN = -0x80000000,  // INT32_MIN
/*line: 132*/   INT_FAST64_MIN = -0x8000000000000000,  // INT64_MIN
/*line: 134*/   INT_FAST8_MAX = 0x7f,  // INT8_MAX
/*line: 135*/   INT_FAST16_MAX = 0x7fff,  // INT16_MAX
/*line: 136*/   INT_FAST32_MAX = 0x7fffffff,  // INT32_MAX
/*line: 137*/   INT_FAST64_MAX = 0x7fffffffffffffff,  // INT64_MAX
};

// Depends on identifiers
enum macro_uint_fast_limits {
/*line: 139*/   UINT_FAST8_MAX = 0xff,  // UINT8_MAX
/*line: 140*/   UINT_FAST16_MAX = 0xffff,  // UINT16_MAX
/*line: 141*/   UINT_FAST32_MAX = 0xffffffff,  // UINT32_MAX
/*line: 142*/   UINT_FAST64_MAX = 0xffffffffffffffff,  // UINT64_MAX
};

// Depends on identifiers
enum macro_intptr_limits {
/*line: 147*/   INTPTR_MAX = 0x7fffffffffffffff,  // 9223372036854775807L
/*line: 151*/   INTPTR_MIN = -0x8000000000000000,  // (-INTPTR_MAX-1)
};

enum macro_uintptr_limits {
/*line: 154*/   UINTPTR_MAX = 0xffffffffffffffff,  // 18446744073709551615UL
};

// Depends on identifiers
enum macro_intmax_limits {
/* 7.18.2.5 Limits of greatest-width integer types */
/*line: 160*/   INTMAX_MAX = 0x7fffffffffffffff,  // INTMAX_C(9223372036854775807)
/*line: 161*/   UINTMAX_MAX = 0xffffffffffffffff,  // UINTMAX_C(18446744073709551615)
/*line: 162*/   INTMAX_MIN = -0x8000000000000000,  // (-INTMAX_MAX-1)
};

// Depends on identifiers
enum macro_ptr_diff_limits {
/*line: 166*/   PTRDIFF_MIN = -0x8000000000000000,  // INTMAX_MIN
/*line: 167*/   PTRDIFF_MAX = 0x7fffffffffffffff,  // INTMAX_MAX
};

// Depends on identifiers
enum macro_size_limits {
/*line: 173*/   SIZE_MAX = 0xffffffffffffffff,  // UINTPTR_MAX
};

// Depends on identifiers
enum macro_wchar_limits {
/*line: 181*/   WCHAR_MAX = 0x7fffffff,  // __WCHAR_MAX__
/*line: 195*/   WCHAR_MIN = -0x80000000,  // (-WCHAR_MAX-1)
};

// Depends on identifiers
enum macro_wint_limits {
/*line: 199*/   WINT_MIN = -0x80000000,  // INT32_MIN
/*line: 200*/   WINT_MAX = 0x7fffffff,  // INT32_MAX
};

// Depends on identifiers
enum macro_sigatomic_limits {
/*line: 202*/   SIG_ATOMIC_MIN = -0x80000000,  // INT32_MIN
/*line: 203*/   SIG_ATOMIC_MAX = 0x7fffffff,  // INT32_MAX
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 176
// #define RSIZE_MAX (SIZE_MAX >> 1)

