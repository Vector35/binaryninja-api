// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/fts.h

enum macro_fts_options {
/*line: 92*/    FTS_COMFOLLOW = 0x1, /* follow command line symlinks */ // 0x001
/*line: 93*/    FTS_LOGICAL = 0x2, /* logical walk */ // 0x002
/*line: 94*/    FTS_NOCHDIR = 0x4, /* don't change directories */ // 0x004
/*line: 95*/    FTS_NOSTAT = 0x8, /* don't get stat info */ // 0x008
/*line: 96*/    FTS_PHYSICAL = 0x10, /* physical walk */ // 0x010
/*line: 97*/    FTS_SEEDOT = 0x20, /* return dot and dot-dot */ // 0x020
/*line: 98*/    FTS_XDEV = 0x40, /* don't cross devices */ // 0x040
/*line: 99*/    FTS_WHITEOUT = 0x80, /* (no longer supported) return whiteout information */ // 0x080
/*line: 100*/   FTS_COMFOLLOWDIR = 0x400, /* (non-std) follow command line symlinks for directories only */ // 0x400
/*line: 104*/   FTS_NOSTAT_TYPE = 0x800, /* (non-std) no stat, but use d_type in struct dirent when available */ // 0x800
/*line: 105*/   FTS_OPTIONMASK = 0xcff, /* valid user option mask */ // 0xcff
/*line: 108*/   FTS_NAMEONLY = 0x100, /* (private) child names only */ // 0x100
/*line: 109*/   FTS_STOP = 0x200, /* (private) unrecoverable error */ // 0x200
/*line: 110*/   FTS_THREAD_FCHDIR = 0x400, /* (private) use pthread_fchdir_np */ // 0x400
/*line: 112*/   FTS_BLOCK_COMPAR = 0x80000000, /* fts_compar is a block */ // 0x80000000
};

enum macro_fts_level {
/*line: 134*/   FTS_ROOTPARENTLEVEL = -0x1,  // -1
/*line: 135*/   FTS_ROOTLEVEL = 0x0,  // 0
/*line: 136*/   FTS_MAXLEVEL = 0x7fffffff,  // 0x7fffffff
};

enum macro_fts_info {
/*line: 139*/   FTS_D = 0x1, /* preorder directory */ // 1
/*line: 140*/   FTS_DC = 0x2, /* directory that causes cycles */ // 2
/*line: 141*/   FTS_DEFAULT = 0x3, /* none of the above */ // 3
/*line: 142*/   FTS_DNR = 0x4, /* unreadable directory */ // 4
/*line: 143*/   FTS_DOT = 0x5, /* dot or dot-dot */ // 5
/*line: 144*/   FTS_DP = 0x6, /* postorder directory */ // 6
/*line: 145*/   FTS_ERR = 0x7, /* error; errno is set */ // 7
/*line: 146*/   FTS_F = 0x8, /* regular file */ // 8
/*line: 147*/   FTS_INIT = 0x9, /* initialized only */ // 9
/*line: 148*/   FTS_NS = 0xa, /* stat(2) failed */ // 10
/*line: 149*/   FTS_NSOK = 0xb, /* no stat(2) requested */ // 11
/*line: 150*/   FTS_SL = 0xc, /* symbolic link */ // 12
/*line: 151*/   FTS_SLNONE = 0xd, /* symbolic link without target */ // 13
/*line: 152*/   FTS_W = 0xe, /* whiteout object */ // 14
};

enum macro_fts_flags {
/*line: 155*/   FTS_DONTCHDIR = 0x1, /* don't chdir .. to the parent */ // 0x01
/*line: 156*/   FTS_SYMFOLLOW = 0x2, /* followed a symlink to get here */ // 0x02
/*line: 157*/   FTS_ISW = 0x4, /* this is a whiteout object */ // 0x04
/*line: 158*/   FTS_CHDIRFD = 0x8, /* indicates the fts_symfd field was set for chdir */ // 0x08
};

enum macro_fts_instruction {
/*line: 161*/   FTS_AGAIN = 0x1, /* read node again */ // 1
/*line: 162*/   FTS_FOLLOW = 0x2, /* follow symbolic link */ // 2
/*line: 163*/   FTS_NOINSTR = 0x3, /* no instructions */ // 3
/*line: 164*/   FTS_SKIP = 0x4, /* discard node */ // 4
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 181
// #define __fts_noescape __attribute__((__noescape__))

