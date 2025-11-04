// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dirent.h

enum macro_dirblksiz {
/* definitions for library routines operating on directories. */
/*line: 92*/    DIRBLKSIZ = 0x400,  // 1024
};

enum macro_directory_flags {
/* flags for opendir2 */
/*line: 95*/    DTF_HIDEW = 0x1, /* hide whiteout entries */ // 0x0001
/*line: 96*/    DTF_NODUP = 0x2, /* don't return duplicate names */ // 0x0002
/*line: 97*/    DTF_REWIND = 0x4, /* rewind after reading union stack */ // 0x0004
/*line: 98*/    __DTF_READALL = 0x8, /* everything has been read */ // 0x0008
/*line: 99*/    __DTF_SKIPREAD = 0x10, /* assume internal buffer is populated */ // 0x0010
/*line: 100*/   __DTF_ATEND = 0x20, /* there's nothing more to read in the kernel */ // 0x0020
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 156
// #define __scandir_noescape __attribute__((__noescape__))

