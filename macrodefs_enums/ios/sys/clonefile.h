// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/clonefile.h

enum macro_clonefile_options {
/* Options for clonefile calls */
/*line: 33*/    CLONE_NOFOLLOW = 0x1, /* Don't follow symbolic links */ // 0x0001
/*line: 34*/    CLONE_NOOWNERCOPY = 0x2, /* Don't copy ownership information from source */ // 0x0002
/*line: 35*/    CLONE_ACL = 0x4, /* Copy access control lists from source */ // 0x0004
/*line: 36*/    CLONE_NOFOLLOW_ANY = 0x8, /* Don't follow any symbolic links in the path */ // 0x0008
};

