// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/printf.h

enum macro_printfmaxarg {
/*
 * The API defined by GLIBC allows a renderer to take multiple arguments
 * This is obviously usable for things like (ptr+len) pairs etc.
 * The current limit is to deal with up to __PRINTFMAXARG arguments (any
 * above this limit are ignored).
 */
/*line: 65*/    __PRINTFMAXARG = 0x2,  // 2
};

// Depends on identifiers
enum macro_printf_flags {
/*line: 127*/   PA_FLAG_MASK = 0xff0000,  // 0xff0000
/*line: 128*/   PA_FLAG_LONG_LONG = 0x10000,  // (1<<16)
/*line: 129*/   PA_FLAG_LONG = 0x20000,  // (1<<17)
/*line: 130*/   PA_FLAG_SHORT = 0x40000,  // (1<<18)
/*line: 131*/   PA_FLAG_PTR = 0x80000,  // (1<<19)
/*line: 132*/   PA_FLAG_QUAD = 0x100000,  // (1<<20)
/*line: 133*/   PA_FLAG_INTMAX = 0x200000,  // (1<<21)
/*line: 134*/   PA_FLAG_SIZE = 0x400000,  // (1<<22)
/*line: 135*/   PA_FLAG_PTRDIFF = 0x800000,  // (1<<23)
/*line: 136*/   PA_FLAG_LONG_DOUBLE = 0x10000,  // PA_FLAG_LONG_LONG
};

