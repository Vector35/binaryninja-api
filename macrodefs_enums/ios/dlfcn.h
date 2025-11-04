// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dlfcn.h

enum macro_dlfcn_flags {
/*line: 83*/    RTLD_LAZY = 0x1,  // 0x1
/*line: 84*/    RTLD_NOW = 0x2,  // 0x2
/*line: 85*/    RTLD_LOCAL = 0x4,  // 0x4
/*line: 86*/    RTLD_GLOBAL = 0x8,  // 0x8
/*line: 89*/    RTLD_NOLOAD = 0x10,  // 0x10
/*line: 90*/    RTLD_NODELETE = 0x80,  // 0x80
/*line: 91*/    RTLD_FIRST = 0x100, /* Mac OS X 10.5 and later */ // 0x100
};

enum macro_dlopen_flags {
/*
 * Special handle arguments for dlsym().
 */
/*line: 96*/    RTLD_NEXT = -0x1, /* Search subsequent objects. */ // ((void*)-1)
/*line: 97*/    RTLD_DEFAULT = -0x2, /* Use default search algorithm. */ // ((void*)-2)
/*line: 98*/    RTLD_SELF = -0x3, /* Search this and subsequent objects (Mac OS X 10.5 and later) */ // ((void*)-3)
/*line: 99*/    RTLD_MAIN_ONLY = -0x5, /* Search main executable only (Mac OS X 10.5 and later) */ // ((void*)-5)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 39
// #define __DYLDDL_UNAVAILABLE __API_UNAVAILABLE(driverkit)

// Line: 41
// #define __DYLDDL_DLSYM_UNAVAILABLE __API_UNAVAILABLE(driverkit)

