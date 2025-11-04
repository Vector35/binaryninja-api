// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/arm/limits.h

enum macro_arm_type_limits {
/*line: 54*/    MB_LEN_MAX = 0x6, /* Allow 31 bit UTF2 */ // 6
/*line: 57*/    CLK_TCK = 0x64, /* ticks per second */ // __DARWIN_CLK_TCK
/*line: 70*/    CHAR_BIT = 0x8, /* number of bits in a char */ // 8
/*
 * According to ANSI (section 2.2.4.2), the values below must be usable by
 * #if preprocessing directives.  Additionally, the expression must have the
 * same type as would an expression that is an object of the corresponding
 * type converted according to the integral promotions.  The subtraction for
 * INT_MIN and LONG_MIN is so the value is not unsigned; 2147483648 is an
 * unsigned int for 32-bit two's complement ANSI compilers (section 3.1.3.2).
 * These numbers work for pcc as well.  The UINT_MAX and ULONG_MAX values
 * are written as hex so that GCC will be quiet about large integer constants.
 */
/*line: 82*/    SCHAR_MAX = 0x7f, /* min value for a signed char */ // 127
/*line: 83*/    SCHAR_MIN = -0x80, /* max value for a signed char */ // (-128)
/*line: 85*/    UCHAR_MAX = 0xff, /* max value for an unsigned char */ // 255
/*line: 86*/    CHAR_MAX = 0x7f, /* max value for a char */ // 127
/*line: 87*/    CHAR_MIN = -0x80, /* min value for a char */ // (-128)
/*line: 89*/    USHRT_MAX = 0xffff, /* max value for an unsigned short */ // 65535
/*line: 90*/    SHRT_MAX = 0x7fff, /* max value for a short */ // 32767
/*line: 91*/    SHRT_MIN = -0x8000, /* min value for a short */ // (-32768)
/*line: 93*/    UINT_MAX = 0xffffffff, /* max value for an unsigned int */ // 0xffffffff
/*line: 94*/    INT_MAX = 0x7fffffff, /* max value for an int */ // 2147483647
/*line: 95*/    INT_MIN = -0x80000000, /* min value for an int */ // (-2147483647-1)
/*line: 98*/    ULONG_MAX = 0xffffffffffffffff, /* max unsigned long */ // 0xffffffffffffffffUL
/*line: 99*/    LONG_MAX = 0x7fffffffffffffff, /* max signed long */ // 0x7fffffffffffffffL
/*line: 100*/   LONG_MIN = -0x8000000000000000, /* min signed long */ // (-0x7fffffffffffffffL-1)
/*line: 107*/   ULLONG_MAX = 0xffffffffffffffff, /* max unsigned long long */ // 0xffffffffffffffffULL
/*line: 108*/   LLONG_MAX = 0x7fffffffffffffff, /* max signed long long */ // 0x7fffffffffffffffLL
/*line: 109*/   LLONG_MIN = -0x8000000000000000, /* min signed long long */ // (-0x7fffffffffffffffLL-1)
/*line: 115*/   LONG_BIT = 0x40,  // 64
/*line: 119*/   SSIZE_MAX = 0x7fffffffffffffff, /* max value for a ssize_t */ // LONG_MAX
/*line: 120*/   WORD_BIT = 0x20,  // 32
/*line: 123*/   SIZE_T_MAX = 0xffffffffffffffff, /* max value for a size_t */ // ULONG_MAX
/*line: 125*/   UQUAD_MAX = 0xffffffffffffffff,  // ULLONG_MAX
/*line: 126*/   QUAD_MAX = 0x7fffffffffffffff,  // LLONG_MAX
/*line: 127*/   QUAD_MIN = -0x8000000000000000,  // LLONG_MIN
};

