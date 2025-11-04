// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/_locale.h

// Depends on identifiers
enum macro_locale_masks {
/*line: 75*/    LC_ALL_MASK = 0x3f,  // (LC_COLLATE_MASK|LC_CTYPE_MASK|LC_MESSAGES_MASK|LC_MONETARY_MASK|LC_NUMERIC_MASK|LC_TIME_MASK)
/*line: 81*/    LC_COLLATE_MASK = 0x1,  // (1<<0)
/*line: 82*/    LC_CTYPE_MASK = 0x2,  // (1<<1)
/*line: 83*/    LC_MESSAGES_MASK = 0x4,  // (1<<2)
/*line: 84*/    LC_MONETARY_MASK = 0x8,  // (1<<3)
/*line: 85*/    LC_NUMERIC_MASK = 0x10,  // (1<<4)
/*line: 86*/    LC_TIME_MASK = 0x20,  // (1<<5)
};

// Depends on identifiers
enum macro_locale_mask {
/*line: 88*/    _LC_NUM_MASK = 0x6,  // 6
/*line: 89*/    _LC_LAST_MASK = 0x20,  // (1<<(_LC_NUM_MASK-1))
};

// Depends on identifiers
enum macro_locale_constant {
/*line: 91*/    LC_GLOBAL_LOCALE = -0x1,  // ((locale_t)-1)
/*line: 92*/    LC_C_LOCALE = 0x0,  // ((locale_t)NULL)
};

