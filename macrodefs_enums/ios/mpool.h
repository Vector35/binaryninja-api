// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mpool.h

enum macro_hash_size {
/*
 * The memory pool scheme is a simple one.  Each in-memory page is referenced
 * by a bucket which is threaded in up to two of three ways.  All active pages
 * are threaded on a hash chain (hashed by page number) and an lru chain.
 * Inactive pages are threaded on a free chain.  Each reference to a memory
 * pool is handed an opaque MPOOL cookie which stores all of this information.
 */
/*line: 49*/    HASHSIZE = 0x80,  // 128
};

enum macro_mpool_flags {
/*line: 59*/    MPOOL_DIRTY = 0x1, /* page needs to be written */ // 0x01
/*line: 60*/    MPOOL_PINNED = 0x2, /* page is pinned into memory */ // 0x02
};

