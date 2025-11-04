// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/_types.h

// Depends on identifiers
enum macro_wchar_max {
/*line: 52*/    __DARWIN_WCHAR_MAX = 0x7fffffff,  // __WCHAR_MAX__
};

// Depends on identifiers
enum macro_darwin_wchar {
/*line: 58*/    __DARWIN_WCHAR_MIN = -0x80000000,  // (-0x7fffffff-1)
/*line: 62*/    __DARWIN_WEOF = -0x1,  // ((__darwin_wint_t)-1)
};

enum macro_fortify_source {
/*line: 68*/    _FORTIFY_SOURCE = 0x2, /* on by default */ // 2
};

