// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/dirent.h

// Depends on identifiers
enum macro_dirent_types {
/*line: 84*/    __DARWIN_MAXNAMLEN = 0xff,  // 255
/*line: 100*/   __DARWIN_MAXPATHLEN = 0x400,  // 1024
/*line: 119*/   MAXNAMLEN = 0xff,  // __DARWIN_MAXNAMLEN
/*
 * File types
 */
/*line: 123*/   DT_UNKNOWN = 0x0,  // 0
/*line: 124*/   DT_FIFO = 0x1,  // 1
/*line: 125*/   DT_CHR = 0x2,  // 2
/*line: 126*/   DT_DIR = 0x4,  // 4
/*line: 127*/   DT_BLK = 0x6,  // 6
/*line: 128*/   DT_REG = 0x8,  // 8
/*line: 129*/   DT_LNK = 0xa,  // 10
/*line: 130*/   DT_SOCK = 0xc,  // 12
/*line: 131*/   DT_WHT = 0xe,  // 14
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 102
// #define __DARWIN_STRUCT_DIRENTRY { \
// 	__uint64_t  d_ino;      /* file number of entry */ \
// 	__uint64_t  d_seekoff;  /* seek offset (optional, used by servers) */ \
// 	__uint16_t  d_reclen;   /* length of this record */ \
// 	__uint16_t  d_namlen;   /* length of string in d_name */ \
// 	__uint8_t   d_type;     /* file type, see below */ \
// 	char      d_name[__DARWIN_MAXPATHLEN]; /* entry name (up to MAXPATHLEN bytes) */ \
// }

// Line: 118
// #define d_fileno d_ino

