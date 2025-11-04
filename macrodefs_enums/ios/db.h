// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/db.h

enum macro_return_code {
/*line: 45*/    RET_ERROR = -0x1, /* Return values. */ // -1
/*line: 46*/    RET_SUCCESS = 0x0,  // 0
/*line: 47*/    RET_SPECIAL = 0x1,  // 1
};

enum macro_db_limits {
/*line: 49*/    MAX_PAGE_NUMBER = 0xffffffff, /* >= # of pages in a file */ // 0xffffffff
/*line: 51*/    MAX_PAGE_OFFSET = 0xffff, /* >= # of bytes in a page */ // 65535
/*line: 53*/    MAX_REC_NUMBER = 0xffffffff, /* >= # of records in a tree */ // 0xffffffff
};

enum macro_routine_flags {
/* Routine flags. */
/*line: 63*/    R_CURSOR = 0x1, /* del, put, seq */ // 1
/*line: 64*/    __R_UNUSED = 0x2, /* UNUSED */ // 2
/*line: 65*/    R_FIRST = 0x3, /* seq */ // 3
/*line: 66*/    R_IAFTER = 0x4, /* put (RECNO) */ // 4
/*line: 67*/    R_IBEFORE = 0x5, /* put (RECNO) */ // 5
/*line: 68*/    R_LAST = 0x6, /* seq (BTREE, RECNO) */ // 6
/*line: 69*/    R_NEXT = 0x7, /* seq */ // 7
/*line: 70*/    R_NOOVERWRITE = 0x8, /* put */ // 8
/*line: 71*/    R_PREV = 0x9, /* seq (BTREE, RECNO) */ // 9
/*line: 72*/    R_SETCURSOR = 0xa, /* put (RECNO) */ // 10
/*line: 73*/    R_RECNOSYNC = 0xb, /* sync (RECNO) */ // 11
};

enum macro_db_flags {
/*line: 91*/    DB_LOCK = 0x20000000, /* Do locking. */ // 0x20000000
/*line: 92*/    DB_SHMEM = 0x40000000, /* Use shared memory. */ // 0x40000000
/*line: 93*/    DB_TXN = 0x80000000, /* Do transactions. */ // 0x80000000
};

enum macro_btree_constants {
/*line: 113*/   BTREEMAGIC = 0x53162,  // 0x053162
/*line: 114*/   BTREEVERSION = 0x3,  // 3
};

enum macro_duplicate_keys {
/*line: 118*/   R_DUP = 0x1, /* duplicate keys */ // 0x01
};

enum macro_hash_constants {
/*line: 131*/   HASHMAGIC = 0x61561,  // 0x061561
/*line: 132*/   HASHVERSION = 0x2,  // 2
};

enum macro_record_flags {
/*line: 147*/   R_FIXEDLEN = 0x1, /* fixed-length records */ // 0x01
/*line: 148*/   R_NOKEY = 0x2, /* key not required */ // 0x02
/*line: 149*/   R_SNAPSHOT = 0x4, /* snapshot the input */ // 0x04
};

