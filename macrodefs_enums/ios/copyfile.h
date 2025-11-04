// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/copyfile.h

enum macro_copyfile_states {
/*line: 68*/    COPYFILE_STATE_SRC_FD = 0x1,  // 1
/*line: 69*/    COPYFILE_STATE_SRC_FILENAME = 0x2,  // 2
/*line: 70*/    COPYFILE_STATE_DST_FD = 0x3,  // 3
/*line: 71*/    COPYFILE_STATE_DST_FILENAME = 0x4,  // 4
/*line: 72*/    COPYFILE_STATE_QUARANTINE = 0x5,  // 5
/*line: 73*/    COPYFILE_STATE_STATUS_CB = 0x6,  // 6
/*line: 74*/    COPYFILE_STATE_STATUS_CTX = 0x7,  // 7
/*line: 75*/    COPYFILE_STATE_COPIED = 0x8,  // 8
/*line: 76*/    COPYFILE_STATE_XATTRNAME = 0x9,  // 9
/*line: 77*/    COPYFILE_STATE_WAS_CLONED = 0xa,  // 10
/*line: 78*/    COPYFILE_STATE_SRC_BSIZE = 0xb,  // 11
/*line: 79*/    COPYFILE_STATE_DST_BSIZE = 0xc,  // 12
/*line: 80*/    COPYFILE_STATE_BSIZE = 0xd,  // 13
/*line: 81*/    COPYFILE_STATE_FORBID_CROSS_MOUNT = 0xe,  // 14
/*line: 82*/    COPYFILE_STATE_NOCPROTECT = 0xf,  // 15
/*line: 83*/    COPYFILE_STATE_PRESERVE_SUID = 0x10,  // 16
/*line: 84*/    COPYFILE_STATE_RECURSIVE_SRC_FTSENT = 0x11,  // 17
/*line: 85*/    COPYFILE_STATE_FORBID_DST_EXISTING_SYMLINKS = 0x12,  // 18
};

enum macro_copyfile_flags {
/* flags for copyfile */
/*line: 92*/    COPYFILE_ACL = 0x1,  // (1<<0)
/*line: 93*/    COPYFILE_STAT = 0x2,  // (1<<1)
/*line: 94*/    COPYFILE_XATTR = 0x4,  // (1<<2)
/*line: 95*/    COPYFILE_DATA = 0x8,  // (1<<3)
/*line: 97*/    COPYFILE_SECURITY = 0x3,  // (COPYFILE_STAT|COPYFILE_ACL)
/*line: 98*/    COPYFILE_METADATA = 0x7,  // (COPYFILE_SECURITY|COPYFILE_XATTR)
/*line: 99*/    COPYFILE_ALL = 0xf,  // (COPYFILE_METADATA|COPYFILE_DATA)
/*line: 101*/   COPYFILE_RECURSIVE = 0x8000, /* Descend into hierarchies */ // (1<<15)
/*line: 102*/   COPYFILE_CHECK = 0x10000, /* return flags for xattr or acls if set */ // (1<<16)
/*line: 103*/   COPYFILE_EXCL = 0x20000, /* fail if destination exists */ // (1<<17)
/*line: 104*/   COPYFILE_NOFOLLOW_SRC = 0x40000, /* don't follow if source is a symlink */ // (1<<18)
/*line: 105*/   COPYFILE_NOFOLLOW_DST = 0x80000, /* don't follow if dst is a symlink */ // (1<<19)
/*line: 106*/   COPYFILE_MOVE = 0x100000, /* unlink src after copy */ // (1<<20)
/*line: 107*/   COPYFILE_UNLINK = 0x200000, /* unlink dst before copy */ // (1<<21)
/*line: 108*/   COPYFILE_NOFOLLOW = 0xc0000,  // (COPYFILE_NOFOLLOW_SRC|COPYFILE_NOFOLLOW_DST)
/*line: 110*/   COPYFILE_PACK = 0x400000,  // (1<<22)
/*line: 111*/   COPYFILE_UNPACK = 0x800000,  // (1<<23)
/*line: 113*/   COPYFILE_CLONE = 0x1000000,  // (1<<24)
/*line: 114*/   COPYFILE_CLONE_FORCE = 0x2000000,  // (1<<25)
/*line: 116*/   COPYFILE_RUN_IN_PLACE = 0x4000000,  // (1<<26)
/*line: 118*/   COPYFILE_DATA_SPARSE = 0x8000000,  // (1<<27)
/*line: 120*/   COPYFILE_PRESERVE_DST_TRACKED = 0x10000000,  // (1<<28)
/*line: 122*/   COPYFILE_VERBOSE = 0x40000000,  // (1<<30)
};

enum macro_copyfile_recurse_options {
/*line: 124*/   COPYFILE_RECURSE_ERROR = 0x0,  // 0
/*line: 125*/   COPYFILE_RECURSE_FILE = 0x1,  // 1
/*line: 126*/   COPYFILE_RECURSE_DIR = 0x2,  // 2
/*line: 127*/   COPYFILE_RECURSE_DIR_CLEANUP = 0x3,  // 3
/*line: 128*/   COPYFILE_COPY_DATA = 0x4,  // 4
/*line: 129*/   COPYFILE_COPY_XATTR = 0x5,  // 5
};

enum macro_copyfile_event {
/*line: 131*/   COPYFILE_START = 0x1,  // 1
/*line: 132*/   COPYFILE_FINISH = 0x2,  // 2
/*line: 133*/   COPYFILE_ERR = 0x3,  // 3
/*line: 134*/   COPYFILE_PROGRESS = 0x4,  // 4
};

enum macro_copyfile_callback_command {
/*line: 136*/   COPYFILE_CONTINUE = 0x0,  // 0
/*line: 137*/   COPYFILE_SKIP = 0x1,  // 1
/*line: 138*/   COPYFILE_QUIT = 0x2,  // 2
};

