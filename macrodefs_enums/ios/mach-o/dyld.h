// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/dyld.h

enum macro_nslinkmodule_options {
/*line: 188*/   NSLINKMODULE_OPTION_NONE = 0x0,  // 0x0
/*line: 189*/   NSLINKMODULE_OPTION_BINDNOW = 0x1,  // 0x1
/*line: 190*/   NSLINKMODULE_OPTION_PRIVATE = 0x2,  // 0x2
/*line: 191*/   NSLINKMODULE_OPTION_RETURN_ON_ERROR = 0x4,  // 0x4
/*line: 192*/   NSLINKMODULE_OPTION_DONT_CALL_MOD_INIT_ROUTINES = 0x8,  // 0x8
/*line: 193*/   NSLINKMODULE_OPTION_TRAILING_PHYS_NAME = 0x10,  // 0x10
};

enum macro_nsunlink_module_options {
/*line: 196*/   NSUNLINKMODULE_OPTION_NONE = 0x0,  // 0x0
/*line: 197*/   NSUNLINKMODULE_OPTION_KEEP_MEMORY_MAPPED = 0x1,  // 0x1
/*line: 198*/   NSUNLINKMODULE_OPTION_RESET_LAZY_REFERENCES = 0x2,  // 0x2
};

enum macro_lookup_options {
/*line: 209*/   NSLOOKUPSYMBOLINIMAGE_OPTION_BIND = 0x0,  // 0x0
/*line: 210*/   NSLOOKUPSYMBOLINIMAGE_OPTION_BIND_NOW = 0x1,  // 0x1
/*line: 211*/   NSLOOKUPSYMBOLINIMAGE_OPTION_BIND_FULLY = 0x2,  // 0x2
/*line: 212*/   NSLOOKUPSYMBOLINIMAGE_OPTION_RETURN_ON_ERROR = 0x4,  // 0x4
};

enum macro_nsaddimage_options {
/*line: 257*/   NSADDIMAGE_OPTION_NONE = 0x0,  // 0x0
/*line: 258*/   NSADDIMAGE_OPTION_RETURN_ON_ERROR = 0x1,  // 0x1
/*line: 259*/   NSADDIMAGE_OPTION_WITH_SEARCHING = 0x2,  // 0x2
/*line: 260*/   NSADDIMAGE_OPTION_RETURN_ONLY_IF_LOADED = 0x4,  // 0x4
/*line: 261*/   NSADDIMAGE_OPTION_MATCH_FILENAME_BY_INSTALLNAME = 0x8,  // 0x8
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 39
// #define DYLD_DRIVERKIT_UNAVAILABLE __API_UNAVAILABLE(driverkit)

