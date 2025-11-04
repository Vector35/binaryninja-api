// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/doubleagent_types.h

enum macro_xattr_maxnamelen {
/*line: 32*/    DA_XATTR_MAXNAMELEN = 0x7f, // Must match the 'XATTR_MAXNAMELEN' in <sys/xattr.h>. // 127
};

enum macro_max_num_of_xattrs {
/*line: 36*/    MAX_NUM_OF_XATTRS = 0x100,  // 256
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 37
// #define LISTXATTR_RESULT_MAX_NAMES_LEN (sizeof(DA_XATTR_RESOURCEFORK_NAME) + sizeof(DA_XATTR_FINDERINFO_NAME) + (MAX_NUM_OF_XATTRS * ((DA_XATTR_MAXNAMELEN + 1))))

// Line: 38
// #define LISTXATTR_RESULT_MAX_HINTS_LEN (MAX_NUM_OF_XATTRS * 2 * sizeof(uint32_t))

// Line: 39
// #define LISTXATTR_RESULT_MAX_SIZE (LISTXATTR_RESULT_MAX_NAMES_LEN + LISTXATTR_RESULT_MAX_HINTS_LEN)

