// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/arm/_param.h

// Depends on identifiers
enum macro_arm_darwin_alignbytes {
/*
 * Round p (pointer or byte index) up to a correctly-aligned value for all
 * data types (int, long, ...).   The result is unsigned int and must be
 * cast to any desired pointer type.
 */
/*line: 17*/    __DARWIN_ALIGNBYTES = -0x1,  // (sizeof(__darwin_size_t)-1)
/*line: 20*/    __DARWIN_ALIGNBYTES32 = -0x1,  // (sizeof(__uint32_t)-1)
};

