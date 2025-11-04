// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/ftw.h

enum macro_ftw_flags {
/*
 * Valid flags for the 3rd argument to the function that is passed as the
 * second argument to ftw(3) and nftw(3).  Say it three times fast!
 */
/*line: 35*/    FTW_F = 0x0, /* File.  */ // 0
/*line: 36*/    FTW_D = 0x1, /* Directory.  */ // 1
/*line: 37*/    FTW_DNR = 0x2, /* Directory without read permission.  */ // 2
/*line: 38*/    FTW_DP = 0x3, /* Directory with subdirectories visited.  */ // 3
/*line: 39*/    FTW_NS = 0x4, /* Unknown type; stat() failed.  */ // 4
/*line: 40*/    FTW_SL = 0x5, /* Symbolic link.  */ // 5
/*line: 41*/    FTW_SLN = 0x6, /* Sym link that names a nonexistent file.  */ // 6
};

enum macro_nftw_flags {
/*
 * Flags for use as the 4th argument to nftw(3).  These may be ORed together.
 */
/*line: 46*/    FTW_PHYS = 0x1, /* Physical walk, don't follow sym links.  */ // 0x01
/*line: 47*/    FTW_MOUNT = 0x2, /* The walk does not cross a mount point.  */ // 0x02
/*line: 48*/    FTW_DEPTH = 0x4, /* Subdirs visited before the dir itself. */ // 0x04
/*line: 49*/    FTW_CHDIR = 0x8, /* Change to a directory before reading it. */ // 0x08
};

