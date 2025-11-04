// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/pwd.h

enum macro_password_storage {
/*line: 66*/    _PW_KEYBYNAME = 0x31, /* stored by name */ // '1'
/*line: 67*/    _PW_KEYBYNUM = 0x32, /* stored by entry in the "file" */ // '2'
/*line: 68*/    _PW_KEYBYUID = 0x33, /* stored by uid */ // '3'
/*line: 70*/    _PASSWORD_EFMT1 = 0x5f, /* extended encryption format */ // '_'
/*line: 72*/    _PASSWORD_LEN = 0x80, /* max length, not counting NULL */ // 128
};

enum macro_password_flags {
/*line: 74*/    _PASSWORD_NOUID = 0x1, /* flag for no specified uid. */ // 0x01
/*line: 75*/    _PASSWORD_NOGID = 0x2, /* flag for no specified gid. */ // 0x02
/*line: 76*/    _PASSWORD_NOCHG = 0x4, /* flag for no specified change. */ // 0x04
/*line: 77*/    _PASSWORD_NOEXP = 0x8, /* flag for no specified expire. */ // 0x08
/*line: 79*/    _PASSWORD_WARNDAYS = 0xe, /* days to warn about expiry */ // 14
/*line: 80*/    _PASSWORD_CHGNOW = -0x1, /* special day to force password
					 * change at next login */ // -1
};

