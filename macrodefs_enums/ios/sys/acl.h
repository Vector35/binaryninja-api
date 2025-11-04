// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/acl.h

// Depends on identifiers
enum macro_darwin_acl_permissions {
/*line: 33*/    __DARWIN_ACL_READ_DATA = 0x2,  // (1<<1)
/*line: 34*/    __DARWIN_ACL_LIST_DIRECTORY = 0x2,  // __DARWIN_ACL_READ_DATA
/*line: 35*/    __DARWIN_ACL_WRITE_DATA = 0x4,  // (1<<2)
/*line: 36*/    __DARWIN_ACL_ADD_FILE = 0x4,  // __DARWIN_ACL_WRITE_DATA
/*line: 37*/    __DARWIN_ACL_EXECUTE = 0x8,  // (1<<3)
/*line: 38*/    __DARWIN_ACL_SEARCH = 0x8,  // __DARWIN_ACL_EXECUTE
/*line: 39*/    __DARWIN_ACL_DELETE = 0x10,  // (1<<4)
/*line: 40*/    __DARWIN_ACL_APPEND_DATA = 0x20,  // (1<<5)
/*line: 41*/    __DARWIN_ACL_ADD_SUBDIRECTORY = 0x20,  // __DARWIN_ACL_APPEND_DATA
/*line: 42*/    __DARWIN_ACL_DELETE_CHILD = 0x40,  // (1<<6)
/*line: 43*/    __DARWIN_ACL_READ_ATTRIBUTES = 0x80,  // (1<<7)
/*line: 44*/    __DARWIN_ACL_WRITE_ATTRIBUTES = 0x100,  // (1<<8)
/*line: 45*/    __DARWIN_ACL_READ_EXTATTRIBUTES = 0x200,  // (1<<9)
/*line: 46*/    __DARWIN_ACL_WRITE_EXTATTRIBUTES = 0x400,  // (1<<10)
/*line: 47*/    __DARWIN_ACL_READ_SECURITY = 0x800,  // (1<<11)
/*line: 48*/    __DARWIN_ACL_WRITE_SECURITY = 0x1000,  // (1<<12)
/*line: 49*/    __DARWIN_ACL_CHANGE_OWNER = 0x2000,  // (1<<13)
/*line: 50*/    __DARWIN_ACL_SYNCHRONIZE = 0x100000,  // (1<<20)
};

enum macro_acl_flags {
/*line: 52*/    __DARWIN_ACL_EXTENDED_ALLOW = 0x1,  // 1
/*line: 53*/    __DARWIN_ACL_EXTENDED_DENY = 0x2,  // 2
/*line: 55*/    __DARWIN_ACL_ENTRY_INHERITED = 0x10,  // (1<<4)
/*line: 56*/    __DARWIN_ACL_ENTRY_FILE_INHERIT = 0x20,  // (1<<5)
/*line: 57*/    __DARWIN_ACL_ENTRY_DIRECTORY_INHERIT = 0x40,  // (1<<6)
/*line: 58*/    __DARWIN_ACL_ENTRY_LIMIT_INHERIT = 0x80,  // (1<<7)
/*line: 59*/    __DARWIN_ACL_ENTRY_ONLY_INHERIT = 0x100,  // (1<<8)
/*line: 60*/    __DARWIN_ACL_FLAG_NO_INHERIT = 0x20000,  // (1<<17)
};

enum macro_acl_max_entries {
/*
 * Implementation constants.
 *
 * The ACL_TYPE_EXTENDED binary format permits 169 entries plus
 * the ACL header in a page.  Give ourselves some room to grow;
 * this limit is arbitrary.
 */
/*line: 69*/    ACL_MAX_ENTRIES = 0x80,  // 128
};

// Depends on identifiers
enum macro_acl_undefined_id {
/* 23.2.7 ACL qualifier constants */
/*line: 115*/   ACL_UNDEFINED_ID = 0x0, /* XXX ? */ // NULL
};

