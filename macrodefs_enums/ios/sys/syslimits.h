// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/syslimits.h

enum macro_syslimits {
/*line: 76*/    ARG_MAX = 0x40000,  // (256*1024)
/*line: 85*/    CHILD_MAX = 0x10a, /* max simultaneous processes */ // 266
/*line: 86*/    GID_MAX = 0x7fffffff, /* max value for a gid_t (2^31-2) */ // 2147483647U
/*line: 88*/    LINK_MAX = 0x7fff, /* max file link count */ // 32767
/*line: 89*/    MAX_CANON = 0x400, /* max bytes in term canon input line */ // 1024
/*line: 90*/    MAX_INPUT = 0x400, /* max bytes in terminal input */ // 1024
/*
 * NOTE: Many filesystems (including HFS & APFS) may support names longer than `NAME_MAX` bytes.
 * See manpage for `getdirentries` and `readdir` for details.
 */
/*line: 95*/    NAME_MAX = 0xff, /* max bytes in a file name */ // 255
/*line: 96*/    NGROUPS_MAX = 0x10, /* max supplemental group id's */ // 16
/*line: 98*/    UID_MAX = 0x7fffffff, /* max value for a uid_t (2^31-2) */ // 2147483647U
/*line: 100*/   OPEN_MAX = 0x2800, /* max open files per process - todo, make a config option? */ // 10240
/*line: 103*/   PATH_MAX = 0x400, /* max bytes in pathname */ // 1024
/*line: 104*/   PIPE_BUF = 0x200, /* max bytes for atomic pipe writes */ // 512
/*line: 106*/   BC_BASE_MAX = 0x63, /* max ibase/obase values in bc(1) */ // 99
/*line: 107*/   BC_DIM_MAX = 0x800, /* max array elements in bc(1) */ // 2048
/*line: 108*/   BC_SCALE_MAX = 0x63, /* max scale value in bc(1) */ // 99
/*line: 109*/   BC_STRING_MAX = 0x3e8, /* max const string length in bc(1) */ // 1000
/*line: 110*/   CHARCLASS_NAME_MAX = 0xe, /* max character class name size */ // 14
/*line: 111*/   COLL_WEIGHTS_MAX = 0x2, /* max weights for order keyword */ // 2
/*line: 112*/   EQUIV_CLASS_MAX = 0x2,  // 2
/*line: 113*/   EXPR_NEST_MAX = 0x20, /* max expressions nested in expr(1) */ // 32
/*line: 114*/   LINE_MAX = 0x800, /* max bytes in an input line */ // 2048
/*line: 115*/   RE_DUP_MAX = 0xff, /* max RE's in interval notation */ // 255
/*line: 118*/   NZERO = 0x14, /* default priority [XSI] */ // 20
};

