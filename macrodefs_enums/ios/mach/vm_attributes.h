// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_attributes.h

enum macro_vm_attributes {
/*line: 78*/    MATTR_CACHE = 0x1, /* cachability */ // 1
/*line: 79*/    MATTR_MIGRATE = 0x2, /* migrability */ // 2
/*line: 80*/    MATTR_REPLICATE = 0x4, /* replicability */ // 4
};

enum macro_vm_attribute {
/*line: 87*/    MATTR_VAL_OFF = 0x0, /* (generic) turn attribute off */ // 0
/*line: 88*/    MATTR_VAL_ON = 0x1, /* (generic) turn attribute on */ // 1
/*line: 89*/    MATTR_VAL_GET = 0x2, /* (generic) return current value */ // 2
/*line: 91*/    MATTR_VAL_CACHE_FLUSH = 0x6, /* flush from all caches */ // 6
/*line: 92*/    MATTR_VAL_DCACHE_FLUSH = 0x7, /* flush from data caches */ // 7
/*line: 93*/    MATTR_VAL_ICACHE_FLUSH = 0x8, /* flush from instruction caches */ // 8
/*line: 94*/    MATTR_VAL_CACHE_SYNC = 0x9, /* sync I+D caches */ // 9
/*line: 95*/    MATTR_VAL_CACHE_SYNC = 0x9, /* sync I+D caches */ // 9
};

enum macro_page_info {
/*line: 97*/    MATTR_VAL_GET_INFO = 0xa, /* get page info (stats) */ // 10
};

