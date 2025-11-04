// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/_types/_s_ifmt.h

enum macro_file_type {
/* File type */
/*line: 35*/    S_IFMT = 0xf000, /* [XSI] type of file mask */ // 0170000
/*line: 36*/    S_IFIFO = 0x1000, /* [XSI] named pipe (fifo) */ // 0010000
/*line: 37*/    S_IFCHR = 0x2000, /* [XSI] character special */ // 0020000
/*line: 38*/    S_IFDIR = 0x4000, /* [XSI] directory */ // 0040000
/*line: 39*/    S_IFBLK = 0x6000, /* [XSI] block special */ // 0060000
/*line: 40*/    S_IFREG = 0x8000, /* [XSI] regular */ // 0100000
/*line: 41*/    S_IFLNK = 0xa000, /* [XSI] symbolic link */ // 0120000
/*line: 42*/    S_IFSOCK = 0xc000, /* [XSI] socket */ // 0140000
/*line: 44*/    S_IFWHT = 0xe000, /* OBSOLETE: whiteout */ // 0160000
};

enum macro_file_permissions {
/* Read, write, execute/search by owner */
/*line: 49*/    S_IRWXU = 0x1c0, /* [XSI] RWX mask for owner */ // 0000700
/*line: 50*/    S_IRUSR = 0x100, /* [XSI] R for owner */ // 0000400
/*line: 51*/    S_IWUSR = 0x80, /* [XSI] W for owner */ // 0000200
/*line: 52*/    S_IXUSR = 0x40, /* [XSI] X for owner */ // 0000100
/* Read, write, execute/search by group */
/*line: 54*/    S_IRWXG = 0x38, /* [XSI] RWX mask for group */ // 0000070
/*line: 55*/    S_IRGRP = 0x20, /* [XSI] R for group */ // 0000040
/*line: 56*/    S_IWGRP = 0x10, /* [XSI] W for group */ // 0000020
/*line: 57*/    S_IXGRP = 0x8, /* [XSI] X for group */ // 0000010
/* Read, write, execute/search by others */
/*line: 59*/    S_IRWXO = 0x7, /* [XSI] RWX mask for other */ // 0000007
/*line: 60*/    S_IROTH = 0x4, /* [XSI] R for other */ // 0000004
/*line: 61*/    S_IWOTH = 0x2, /* [XSI] W for other */ // 0000002
/*line: 62*/    S_IXOTH = 0x1, /* [XSI] X for other */ // 0000001
/*line: 64*/    S_ISUID = 0x800, /* [XSI] set user id on execution */ // 0004000
/*line: 65*/    S_ISGID = 0x400, /* [XSI] set group id on execution */ // 0002000
/*line: 66*/    S_ISVTX = 0x200, /* [XSI] directory restrcted delete */ // 0001000
/*line: 69*/    S_ISTXT = 0x200, /* sticky bit: not supported */ // S_ISVTX
/*line: 70*/    S_IREAD = 0x100, /* backward compatability */ // S_IRUSR
/*line: 71*/    S_IWRITE = 0x80, /* backward compatability */ // S_IWUSR
/*line: 72*/    S_IEXEC = 0x40, /* backward compatability */ // S_IXUSR
};

