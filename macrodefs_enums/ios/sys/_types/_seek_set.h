// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/_types/_seek_set.h

enum macro_seek_mode {
/*line: 36*/    SEEK_SET = 0x0, /* set file offset to offset */ // 0
/*line: 37*/    SEEK_CUR = 0x1, /* set file offset to current plus offset */ // 1
/*line: 38*/    SEEK_END = 0x2, /* set file offset to EOF plus offset */ // 2
/*line: 43*/    SEEK_HOLE = 0x3, /* set file offset to the start of the next hole greater than or equal to the supplied offset */ // 3
/*line: 47*/    SEEK_DATA = 0x4, /* set file offset to the start of the next non-hole file region greater than or equal to the supplied offset */ // 4
};

