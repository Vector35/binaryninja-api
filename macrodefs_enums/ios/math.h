// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/math.h

enum macro_fp_taxonomy {
/******************************************************************************
 *      Taxonomy of floating point data types                                 *
 ******************************************************************************/
/*line: 80*/    FP_NAN = 0x1,  // 1
/*line: 81*/    FP_INFINITE = 0x2,  // 2
/*line: 82*/    FP_ZERO = 0x3,  // 3
/*line: 83*/    FP_NORMAL = 0x4,  // 4
/*line: 84*/    FP_SUBNORMAL = 0x5,  // 5
/*line: 85*/    FP_SUPERNORMAL = 0x6, /* legacy PowerPC support; this is otherwise unused */ // 6
};

enum macro_fma_support {
/*  On these architectures, fma(), fmaf( ), and fmal( ) are generally about as
    fast as (or faster than) separate multiply and add of the same operands.  */
/*line: 90*/    FP_FAST_FMA = 0x1,  // 1
/*line: 91*/    FP_FAST_FMAF = 0x1,  // 1
/*line: 92*/    FP_FAST_FMAL = 0x1,  // 1
};

enum macro_ilogb_constants {
/* The values returned by `ilogb' for 0 and NaN respectively. */
/*line: 109*/   FP_ILOGB0 = -0x80000000,  // (-2147483647-1)
/*line: 110*/   FP_ILOGBNAN = -0x80000000,  // (-2147483647-1)
};

enum macro_math_errhandling {
/* Bitmasks for the math_errhandling macro.  */
/*line: 113*/   MATH_ERRNO = 0x1, /* errno set by math functions.  */ // 1
/*line: 114*/   MATH_ERREXCEPT = 0x2, /* Exceptions raised by math functions.  */ // 2
};

// Depends on identifiers
enum macro_fp_flags {
/*line: 751*/   FP_SNAN = 0x1,  // FP_NAN
/*line: 752*/   FP_QNAN = 0x1,  // FP_NAN
/*line: 755*/   DOMAIN = 0x1,  // 1
/*line: 756*/   SING = 0x2,  // 2
/*line: 757*/   OVERFLOW = 0x3,  // 3
/*line: 758*/   UNDERFLOW = 0x4,  // 4
/*line: 759*/   TLOSS = 0x5,  // 5
/*line: 760*/   PLOSS = 0x6,  // 6
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 63
// #define HUGE_VAL __builtin_huge_val()

// Line: 64
// #define HUGE_VALF __builtin_huge_valf()

// Line: 65
// #define HUGE_VALL __builtin_huge_vall()

// Line: 74
// #define INFINITY HUGE_VALF

// Line: 116
// #define math_errhandling (__math_errhandling())

// Line: 710
// #define M_E 2.71828182845904523536028747135266250

// Line: 711
// #define M_LOG2E 1.44269504088896340735992468100189214

// Line: 712
// #define M_LOG10E 0.434294481903251827651128918916605082

// Line: 713
// #define M_LN2 0.693147180559945309417232121458176568

// Line: 714
// #define M_LN10 2.30258509299404568401799145468436421

// Line: 715
// #define M_PI 3.14159265358979323846264338327950288

// Line: 716
// #define M_PI_2 1.57079632679489661923132169163975144

// Line: 717
// #define M_PI_4 0.785398163397448309615660845819875721

// Line: 718
// #define M_1_PI 0.318309886183790671537767526745028724

// Line: 719
// #define M_2_PI 0.636619772367581343075535053490057448

// Line: 720
// #define M_2_SQRTPI 1.12837916709551257389615890312154517

// Line: 721
// #define M_SQRT2 1.41421356237309504880168872420969808

// Line: 722
// #define M_SQRT1_2 0.707106781186547524400844362104849039

// Line: 724
// #define MAXFLOAT 0x1.fffffep+127f

// Line: 753
// #define HUGE MAXFLOAT

// Line: 754
// #define X_TLOSS 1.41484755040568800000e+16

