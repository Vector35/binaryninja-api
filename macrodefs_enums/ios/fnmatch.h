// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/fnmatch.h

enum macro_fnm_ret {
/*line: 66*/    FNM_NOMATCH = 0x1, /* Match failed. */ // 1
};

enum macro_fnmatch_flags {
/*line: 68*/    FNM_NOESCAPE = 0x1, /* Disable backslash escaping. */ // 0x01
/*line: 69*/    FNM_PATHNAME = 0x2, /* Slash must be matched by slash. */ // 0x02
/*line: 70*/    FNM_PERIOD = 0x4, /* Period must be matched by period. */ // 0x04
/*line: 72*/    FNM_NOSYS = -0x1, /* Reserved. */ // (-1)
/*line: 75*/    FNM_LEADING_DIR = 0x8, /* Ignore /<tail> after Imatch. */ // 0x08
/*line: 76*/    FNM_CASEFOLD = 0x10, /* Case insensitive search. */ // 0x10
/*line: 77*/    FNM_IGNORECASE = 0x10,  // FNM_CASEFOLD
/*line: 78*/    FNM_FILE_NAME = 0x2,  // FNM_PATHNAME
};

