// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/xattr.h

enum macro_xattr_options {
/* Options for pathname based xattr calls */
/*line: 35*/    XATTR_NOFOLLOW = 0x1, /* Don't follow symbolic links */ // 0x0001
/* Options for setxattr calls */
/*line: 38*/    XATTR_CREATE = 0x2, /* set the value, fail if attr already exists */ // 0x0002
/*line: 39*/    XATTR_REPLACE = 0x4, /* set the value, fail if attr does not exist */ // 0x0004
/* Set this to bypass authorization checking (eg. if doing auth-related work) */
/*line: 42*/    XATTR_NOSECURITY = 0x8,  // 0x0008
/* Set this to bypass the default extended attribute file (dot-underscore file) */
/*line: 45*/    XATTR_NODEFAULT = 0x10,  // 0x0010
/* option for f/getxattr() and f/listxattr() to expose the HFS Compression extended attributes */
/*line: 48*/    XATTR_SHOWCOMPRESSION = 0x20,  // 0x0020
/* Options for pathname based xattr calls */
/*line: 51*/    XATTR_NOFOLLOW_ANY = 0x40, /* Don't follow any symbolic links in the path */ // 0x0040
};

enum macro_xattr_maxnamelen {
/*line: 53*/    XATTR_MAXNAMELEN = 0x7f,  // 127
};

