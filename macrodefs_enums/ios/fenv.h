// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/fenv.h

enum macro_floating_point_exceptions {
/*line: 136*/   FE_INEXACT = 0x10,  // 0x0010
/*line: 137*/   FE_UNDERFLOW = 0x8,  // 0x0008
/*line: 138*/   FE_OVERFLOW = 0x4,  // 0x0004
/*line: 139*/   FE_DIVBYZERO = 0x2,  // 0x0002
/*line: 140*/   FE_INVALID = 0x1,  // 0x0001
/*  FE_FLUSHTOZERO
    An ARM-specific flag that is raised when a denormal is flushed to zero.
    This is also called the "input denormal exception"                        */
/*line: 144*/   FE_FLUSHTOZERO = 0x80,  // 0x0080
/*line: 145*/   FE_ALL_EXCEPT = 0x9f,  // 0x009f
};

enum macro_rounding_mode {
/*line: 147*/   FE_TONEAREST = 0x0,  // 0x00000000
/*line: 148*/   FE_UPWARD = 0x400000,  // 0x00400000
/*line: 149*/   FE_DOWNWARD = 0x800000,  // 0x00800000
/*line: 150*/   FE_TOWARDZERO = 0xc00000,  // 0x00C00000
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 168
// #define FE_DFL_ENV &_FE_DFL_ENV

// Line: 185
// #define FE_DFL_DISABLE_DENORMS_ENV &_FE_DFL_DISABLE_DENORMS_ENV

