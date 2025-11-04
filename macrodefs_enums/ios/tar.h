// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/tar.h

enum macro_tar_header_length {
/*line: 43*/    TMAGLEN = 0x6,  // 6
/*line: 45*/    TVERSLEN = 0x2,  // 2
};

enum macro_file_type {
/* Values used in typeflag field */
/*line: 48*/    REGTYPE = 0x30, /* Regular file */ // '0'
/*line: 49*/    AREGTYPE = 0x0, /* Regular file */ // '\0'
/*line: 50*/    LNKTYPE = 0x31, /* Link */ // '1'
/*line: 51*/    SYMTYPE = 0x32, /* Reserved */ // '2'
/*line: 52*/    CHRTYPE = 0x33, /* Character special */ // '3'
/*line: 53*/    BLKTYPE = 0x34, /* Block special */ // '4'
/*line: 54*/    DIRTYPE = 0x35, /* Directory */ // '5'
/*line: 55*/    FIFOTYPE = 0x36, /* FIFO special */ // '6'
/*line: 56*/    CONTTYPE = 0x37, /* Reserved */ // '7'
};

enum macro_tar_mode_bits {
/* Bits used in the mode field - values in octal */
/*line: 59*/    TSUID = 0x800, /* Set UID on execution */ // 04000
/*line: 60*/    TSGID = 0x400, /* Set GID on execution */ // 02000
/*line: 61*/    TSVTX = 0x200, /* Reserved */ // 01000
/* File permissions */
/*line: 63*/    TUREAD = 0x100, /* Read by owner */ // 00400
/*line: 64*/    TUWRITE = 0x80, /* Write by owner */ // 00200
/*line: 65*/    TUEXEC = 0x40, /* Execute/Search by owner */ // 00100
/*line: 66*/    TGREAD = 0x20, /* Read by group */ // 00040
/*line: 67*/    TGWRITE = 0x10, /* Write by group */ // 00020
/*line: 68*/    TGEXEC = 0x8, /* Execute/Search by group */ // 00010
/*line: 69*/    TOREAD = 0x4, /* Read by other */ // 00004
/*line: 70*/    TOWRITE = 0x2, /* Write by other */ // 00002
/*line: 71*/    TOEXEC = 0x1, /* Execute/Search by other */ // 00001
};

