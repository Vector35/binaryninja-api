// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/glob.h

enum macro_glob_flags {
/* Believed to have been introduced in 1003.2-1992 */
/*line: 89*/    GLOB_APPEND = 0x1, /* Append to output from previous call. */ // 0x0001
/*line: 90*/    GLOB_DOOFFS = 0x2, /* Use gl_offs. */ // 0x0002
/*line: 91*/    GLOB_ERR = 0x4, /* Return on error. */ // 0x0004
/*line: 92*/    GLOB_MARK = 0x8, /* Append / to matching directories. */ // 0x0008
/*line: 93*/    GLOB_NOCHECK = 0x10, /* Return pattern itself if nothing matches. */ // 0x0010
/*line: 94*/    GLOB_NOSORT = 0x20, /* Don't sort. */ // 0x0020
/*line: 95*/    GLOB_NOESCAPE = 0x2000, /* Disable backslash escaping. */ // 0x2000
};

enum macro_glob_error {
/* Error values returned by glob(3) */
/*line: 98*/    GLOB_NOSPACE = -0x1, /* Malloc call failed. */ // (-1)
/*line: 99*/    GLOB_ABORTED = -0x2, /* Unignored error. */ // (-2)
/*line: 100*/   GLOB_NOMATCH = -0x3, /* No match and GLOB_NOCHECK was not set. */ // (-3)
/*line: 101*/   GLOB_NOSYS = -0x4, /* Obsolete: source comptability only. */ // (-4)
/*line: 103*/   GLOB_ALTDIRFUNC = 0x40, /* Use alternately specified directory funcs. */ // 0x0040
/*line: 104*/   GLOB_BRACE = 0x80, /* Expand braces ala csh. */ // 0x0080
/*line: 105*/   GLOB_MAGCHAR = 0x100, /* Pattern had globbing characters. */ // 0x0100
/*line: 106*/   GLOB_NOMAGIC = 0x200, /* GLOB_NOCHECK without magic chars (csh). */ // 0x0200
/*line: 107*/   GLOB_QUOTE = 0x400, /* Quote special chars with \. */ // 0x0400
/*line: 108*/   GLOB_TILDE = 0x800, /* Expand tilde names from the passwd file. */ // 0x0800
/*line: 109*/   GLOB_LIMIT = 0x1000, /* limit number of returned paths */ // 0x1000
/*line: 111*/   _GLOB_ERR_BLOCK = 0x80000000, /* (internal) error callback is a block */ // 0x80000000
/* source compatibility, these are the old names */
/*line: 115*/   GLOB_MAXPATH = 0x1000,  // GLOB_LIMIT
/*line: 116*/   GLOB_ABEND = -0x2,  // GLOB_ABORTED
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 123
// #define __glob_noescape __attribute__((__noescape__))

