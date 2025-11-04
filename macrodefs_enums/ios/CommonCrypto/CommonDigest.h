// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/CommonCrypto/CommonDigest.h

enum macro_md2_constants {
/*** MD2 ***/
/*line: 68*/    CC_MD2_DIGEST_LENGTH = 0x10, /* digest length in bytes */ // 16
/*line: 69*/    CC_MD2_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_md4_constants {
/*** MD4 ***/
/*line: 94*/    CC_MD4_DIGEST_LENGTH = 0x10, /* digest length in bytes */ // 16
/*line: 95*/    CC_MD4_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_md5_constants {
/*** MD5 ***/
/*line: 121*/   CC_MD5_DIGEST_LENGTH = 0x10, /* digest length in bytes */ // 16
/*line: 122*/   CC_MD5_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_sha1_constants {
/*** SHA1 ***/
/*line: 147*/   CC_SHA1_DIGEST_LENGTH = 0x14, /* digest length in bytes */ // 20
/*line: 148*/   CC_SHA1_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_sha224_constants {
/*** SHA224 ***/
/*line: 168*/   CC_SHA224_DIGEST_LENGTH = 0x1c, /* digest length in bytes */ // 28
/*line: 169*/   CC_SHA224_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_sha256_constants {
/*** SHA256 ***/
/*line: 193*/   CC_SHA256_DIGEST_LENGTH = 0x20, /* digest length in bytes */ // 32
/*line: 194*/   CC_SHA256_BLOCK_BYTES = 0x40, /* block size in bytes */ // 64
};

enum macro_sha384_constants {
/*** SHA384 ***/
/*line: 211*/   CC_SHA384_DIGEST_LENGTH = 0x30, /* digest length in bytes */ // 48
/*line: 212*/   CC_SHA384_BLOCK_BYTES = 0x80, /* block size in bytes */ // 128
};

enum macro_sha512_constants {
/*** SHA512 ***/
/*line: 236*/   CC_SHA512_DIGEST_LENGTH = 0x40, /* digest length in bytes */ // 64
/*line: 237*/   CC_SHA512_BLOCK_BYTES = 0x80, /* block size in bytes */ // 128
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 70
// #define CC_MD2_BLOCK_LONG (CC_MD2_BLOCK_BYTES / sizeof(CC_LONG))

// Line: 96
// #define CC_MD4_BLOCK_LONG (CC_MD4_BLOCK_BYTES / sizeof(CC_LONG))

// Line: 123
// #define CC_MD5_BLOCK_LONG (CC_MD5_BLOCK_BYTES / sizeof(CC_LONG))

// Line: 149
// #define CC_SHA1_BLOCK_LONG (CC_SHA1_BLOCK_BYTES / sizeof(CC_LONG))

