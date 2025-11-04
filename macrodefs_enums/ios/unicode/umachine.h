// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/umachine.h

// Depends on identifiers
enum macro_int64_limits {
/** The smallest value a 64 bit signed integer can hold @stable ICU 2.8 */
/*line: 223*/   U_INT64_MIN = -0x8000000000000000,  // ((int64_t)(INT64_C(-9223372036854775807)-1))
/** The largest value a 64 bit signed integer can hold @stable ICU 2.8 */
/*line: 227*/   U_INT64_MAX = 0x7fffffffffffffff,  // ((int64_t)(INT64_C(9223372036854775807)))
/** The largest value a 64 bit unsigned integer can hold @stable ICU 2.8 */
/*line: 231*/   U_UINT64_MAX = 0xffffffffffffffff,  // ((uint64_t)(UINT64_C(18446744073709551615)))
};

enum macro_bool {
// Apple changes this from 0 to 1 for compatibility, rdar://73713881
/*line: 274*/   U_DEFINE_FALSE_AND_TRUE = 0x1,  // 1
};

enum macro_ubool {
/**
 * The TRUE value of a UBool.
 *
 * @deprecated ICU 68 Use standard "true" instead.
 */
/*line: 295*/   TRUE = 0x1,  // 1
/**
 * The FALSE value of a UBool.
 *
 * @deprecated ICU 68 Use standard "false" instead.
 */
/*line: 303*/   FALSE = 0x0,  // 0
};

enum macro_uchar_size {
/** Number of bytes in a UChar (always 2). @stable ICU 2.0 */
/*line: 350*/   U_SIZEOF_UCHAR = 0x2,  // 2
};

enum macro_is_typedef {
/*line: 362*/   U_CHAR16_IS_TYPEDEF = 0x0,  // 0
};

enum macro_u_sentinel {
/**
 * This value is intended for sentinel values for APIs that
 * (take or) return single code points (UChar32).
 * It is outside of the Unicode code point range 0..0x10ffff.
 * 
 * For example, a "done" or "error" value in a new API
 * could be indicated with U_SENTINEL.
 *
 * ICU APIs designed before ICU 2.4 usually define service-specific "done"
 * values, mostly 0xffff.
 * Those may need to be distinguished from
 * actual U+ffff text contents by calling functions like
 * CharacterIterator::hasNext() or UnicodeString::length().
 *
 * @return -1
 * @see UChar32
 * @stable ICU 2.4
 */
/*line: 487*/   U_SENTINEL = -0x1,  // (-1)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 84
// #define U_CFUNC extern

// Line: 96
// #define U_ATTRIBUTE_DEPRECATED __attribute__(((deprecated))

// Line: 110
// #define U_CAPI U_CFUNCUU_EXPORT

// Line: 112
// #define U_STABLE U_CAPI

// Line: 114
// #define U_DRAFT U_CAPI

// Line: 116
// #define U_DEPRECATED U_CAPIUU_ATTRIBUTE_DEPRECATED

// Line: 118
// #define U_OBSOLETE U_CAPI

// Line: 120
// #define U_INTERNAL U_CAPI

// Line: 147
// #define UPRV_BLOCK_MACRO_BEGIN do

// Line: 156
// #define UPRV_BLOCK_MACRO_END while((false)

// Line: 397
// #define UCHAR_TYPE uint16_t

