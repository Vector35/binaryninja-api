// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/vis.h

// Depends on identifiers
enum macro_vis_encoding {
/*
 * to select alternate encoding format
 */
/*line: 67*/    VIS_OCTAL = 0x1, /* use octal \ddd format */ // 0x0001
/*line: 68*/    VIS_CSTYLE = 0x2, /* use \[nrft0..] where appropiate */ // 0x0002
/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
/*line: 74*/    VIS_SP = 0x4, /* also encode space */ // 0x0004
/*line: 75*/    VIS_TAB = 0x8, /* also encode tab */ // 0x0008
/*line: 76*/    VIS_NL = 0x10, /* also encode newline */ // 0x0010
/*line: 77*/    VIS_WHITE = 0x1c,  // (VIS_SP|VIS_TAB|VIS_NL)
/*line: 78*/    VIS_SAFE = 0x20, /* only encode "unsafe" characters */ // 0x0020
/*line: 79*/    VIS_DQ = 0x8000, /* also encode double quotes */ // 0x8000
};

// Depends on identifiers
enum macro_vis_flags {
/*
 * other
 */
/*line: 84*/    VIS_NOSLASH = 0x40, /* inhibit printing '\' */ // 0x0040
/*line: 85*/    VIS_HTTP1808 = 0x80, /* http-style escape % hex hex */ // 0x0080
/*line: 86*/    VIS_HTTPSTYLE = 0x80, /* http-style escape % hex hex */ // 0x0080
/*line: 87*/    VIS_GLOB = 0x100, /* encode glob(3) magic characters */ // 0x0100
/*line: 88*/    VIS_MIMESTYLE = 0x200, /* mime-style escape = HEX HEX */ // 0x0200
/*line: 89*/    VIS_HTTP1866 = 0x400, /* http-style &#num; or &string; */ // 0x0400
/*line: 90*/    VIS_NOESCAPE = 0x800, /* don't decode `\' */ // 0x0800
/*line: 91*/    _VIS_END = 0x1000, /* for unvis */ // 0x1000
/*line: 92*/    VIS_SHELL = 0x2000, /* encode shell special characters [not glob] */ // 0x2000
/*line: 93*/    VIS_META = 0x211c,  // (VIS_WHITE|VIS_GLOB|VIS_SHELL)
/*line: 94*/    VIS_NOLOCALE = 0x4000, /* encode using the C locale */ // 0x4000
};

enum macro_unvis_status {
/*
 * unvis return codes
 */
/*line: 99*/    UNVIS_VALID = 0x1, /* character valid */ // 1
/*line: 100*/   UNVIS_VALIDPUSH = 0x2, /* character valid, push back passed char */ // 2
/*line: 101*/   UNVIS_NOCHAR = 0x3, /* valid sequence, no character produced */ // 3
/*line: 102*/   UNVIS_SYNBAD = -0x1, /* unrecognized escape sequence */ // -1
/*line: 103*/   UNVIS_ERROR = -0x2, /* decoder in unknown state (unrecoverable) */ // -2
};

// Depends on identifiers
enum macro_unvis_end {
/*
 * unvis flags
 */
/*line: 108*/   UNVIS_END = 0x1000, /* no more characters */ // _VIS_END
};

