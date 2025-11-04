// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/unistd.h

enum macro_posix_version {
/*line: 79*/    _POSIX_VERSION = 0x30db0,  // 200112L
/*line: 80*/    _POSIX2_VERSION = 0x30db0,  // 200112L
};

enum macro_posix_thread_keys_max {
/*line: 86*/    _POSIX_THREAD_KEYS_MAX = 0x80,  // 128
};

enum macro_access_flags {
/* access function */
/*line: 89*/    F_OK = 0x0, /* test for existence of file */ // 0
/*line: 90*/    X_OK = 0x1, /* test for execute or search permission */ // (1<<0)
/*line: 91*/    W_OK = 0x2, /* test for write permission */ // (1<<1)
/*line: 92*/    R_OK = 0x4, /* test for read permission */ // (1<<2)
};

enum macro_extended_access_flags {
/*
 * Extended access functions.
 * Note that we depend on these matching the definitions in sys/kauth.h,
 * but with the bits shifted left by 8.
 */
/*line: 100*/   _READ_OK = 0x200, /* read file data / read directory */ // (1<<9)
/*line: 101*/   _WRITE_OK = 0x400, /* write file data / add file to directory */ // (1<<10)
/*line: 102*/   _EXECUTE_OK = 0x800, /* execute file / search in directory*/ // (1<<11)
/*line: 103*/   _DELETE_OK = 0x1000, /* delete file / delete directory */ // (1<<12)
/*line: 104*/   _APPEND_OK = 0x2000, /* append to file / add subdirectory to directory */ // (1<<13)
/*line: 105*/   _RMFILE_OK = 0x4000, /* - / remove file from directory */ // (1<<14)
/*line: 106*/   _RATTR_OK = 0x8000, /* read basic attributes */ // (1<<15)
/*line: 107*/   _WATTR_OK = 0x10000, /* write basic attributes */ // (1<<16)
/*line: 108*/   _REXT_OK = 0x20000, /* read extended attributes */ // (1<<17)
/*line: 109*/   _WEXT_OK = 0x40000, /* write extended attributes */ // (1<<18)
/*line: 110*/   _RPERM_OK = 0x80000, /* read permissions */ // (1<<19)
/*line: 111*/   _WPERM_OK = 0x100000, /* write permissions */ // (1<<20)
/*line: 112*/   _CHOWN_OK = 0x200000, /* change ownership */ // (1<<21)
/*line: 114*/   _ACCESS_EXTENDED_MASK = 0x3ffe00,  // (_READ_OK|_WRITE_OK|_EXECUTE_OK|_DELETE_OK|_APPEND_OK|_RMFILE_OK|_REXT_OK|_WEXT_OK|_RATTR_OK|_WATTR_OK|_RPERM_OK|_WPERM_OK|_CHOWN_OK)
};

// Depends on identifiers
enum macro_lseek_whence {
/* whence values for lseek(2); renamed by POSIX 1003.1 */
/*line: 126*/   L_SET = 0x0,  // SEEK_SET
/*line: 127*/   L_INCR = 0x1,  // SEEK_CUR
/*line: 128*/   L_XTND = 0x2,  // SEEK_END
};

enum macro_accessx_limits {
/*line: 137*/   ACCESSX_MAX_DESCRIPTORS = 0x64,  // 100
/*line: 138*/   ACCESSX_MAX_TABLESIZE = 0x4000,  // (16*1024)
};

enum macro_pathconf_options {
/* configurable pathname variables */
/*line: 142*/   _PC_LINK_MAX = 0x1,  // 1
/*line: 143*/   _PC_MAX_CANON = 0x2,  // 2
/*line: 144*/   _PC_MAX_INPUT = 0x3,  // 3
/*line: 145*/   _PC_NAME_MAX = 0x4,  // 4
/*line: 146*/   _PC_PATH_MAX = 0x5,  // 5
/*line: 147*/   _PC_PIPE_BUF = 0x6,  // 6
/*line: 148*/   _PC_CHOWN_RESTRICTED = 0x7,  // 7
/*line: 149*/   _PC_NO_TRUNC = 0x8,  // 8
/*line: 150*/   _PC_VDISABLE = 0x9,  // 9
/*line: 153*/   _PC_NAME_CHARS_MAX = 0xa,  // 10
/*line: 154*/   _PC_CASE_SENSITIVE = 0xb,  // 11
/*line: 155*/   _PC_CASE_PRESERVING = 0xc,  // 12
/*line: 156*/   _PC_EXTENDED_SECURITY_NP = 0xd,  // 13
/*line: 157*/   _PC_AUTH_OPAQUE_NP = 0xe,  // 14
/*line: 160*/   _PC_2_SYMLINKS = 0xf, /* Symlink supported in directory */ // 15
/*line: 161*/   _PC_ALLOC_SIZE_MIN = 0x10, /* Minimum storage actually allocated */ // 16
/*line: 162*/   _PC_ASYNC_IO = 0x11, /* Async I/O [AIO] supported? */ // 17
/*line: 163*/   _PC_FILESIZEBITS = 0x12, /* # of bits to represent file size */ // 18
/*line: 164*/   _PC_PRIO_IO = 0x13, /* Priority I/O [PIO] supported? */ // 19
/*line: 165*/   _PC_REC_INCR_XFER_SIZE = 0x14, /* Recommended increment for next two */ // 20
/*line: 166*/   _PC_REC_MAX_XFER_SIZE = 0x15, /* Recommended max file transfer size */ // 21
/*line: 167*/   _PC_REC_MIN_XFER_SIZE = 0x16, /* Recommended min file transfer size */ // 22
/*line: 168*/   _PC_REC_XFER_ALIGN = 0x17, /* Recommended buffer alignment */ // 23
/*line: 169*/   _PC_SYMLINK_MAX = 0x18, /* Max # of bytes in symlink name */ // 24
/*line: 170*/   _PC_SYNC_IO = 0x19, /* Sync I/O [SIO] supported? */ // 25
/*line: 171*/   _PC_XATTR_SIZE_BITS = 0x1a, /* # of bits to represent maximum xattr size */ // 26
/*line: 172*/   _PC_MIN_HOLE_SIZE = 0x1b, /* Recommended minimum hole size for sparse files */ // 27
};

enum macro_path_config {
/* configurable system strings */
/*line: 175*/   _CS_PATH = 0x1,  // 1
};

