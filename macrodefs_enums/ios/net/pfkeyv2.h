// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/pfkeyv2.h

enum macro_pfkey_flags {
/*line: 77*/    __PFKEY_V2_H = 0x1,  // 1
/*line: 79*/    PF_KEY_V2 = 0x2,  // 2
/*line: 80*/    PFKEYV2_REVISION = 0x30c7e,  // 199806L
};

enum macro_sadb_commands {
/*line: 82*/    SADB_RESERVED = 0x0,  // 0
/*line: 83*/    SADB_GETSPI = 0x1,  // 1
/*line: 84*/    SADB_UPDATE = 0x2,  // 2
/*line: 85*/    SADB_ADD = 0x3,  // 3
/*line: 86*/    SADB_DELETE = 0x4,  // 4
/*line: 87*/    SADB_GET = 0x5,  // 5
/*line: 88*/    SADB_ACQUIRE = 0x6,  // 6
/*line: 89*/    SADB_REGISTER = 0x7,  // 7
/*line: 90*/    SADB_EXPIRE = 0x8,  // 8
/*line: 91*/    SADB_FLUSH = 0x9,  // 9
/*line: 92*/    SADB_DUMP = 0xa,  // 10
/*line: 93*/    SADB_X_PROMISC = 0xb,  // 11
/*line: 94*/    SADB_X_PCHANGE = 0xc,  // 12
/*line: 96*/    SADB_X_SPDUPDATE = 0xd,  // 13
/*line: 97*/    SADB_X_SPDADD = 0xe,  // 14
/*line: 98*/    SADB_X_SPDDELETE = 0xf, /* by policy index */ // 15
/*line: 99*/    SADB_X_SPDGET = 0x10,  // 16
/*line: 100*/   SADB_X_SPDACQUIRE = 0x11,  // 17
/*line: 101*/   SADB_X_SPDDUMP = 0x12,  // 18
/*line: 102*/   SADB_X_SPDFLUSH = 0x13,  // 19
/*line: 103*/   SADB_X_SPDSETIDX = 0x14,  // 20
/*line: 104*/   SADB_X_SPDEXPIRE = 0x15,  // 21
/*line: 105*/   SADB_X_SPDDELETE2 = 0x16, /* by policy id */ // 22
/*line: 106*/   SADB_GETSASTAT = 0x17,  // 23
/*line: 107*/   SADB_X_SPDENABLE = 0x18, /* by policy id */ // 24
/*line: 108*/   SADB_X_SPDDISABLE = 0x19, /* by policy id */ // 25
/*line: 109*/   SADB_MIGRATE = 0x1a,  // 26
/*line: 110*/   SADB_MAX = 0x1a,  // 26
};

enum macro_sadb_extension_type {
/*line: 320*/   SADB_EXT_RESERVED = 0x0,  // 0
/*line: 321*/   SADB_EXT_SA = 0x1,  // 1
/*line: 322*/   SADB_EXT_LIFETIME_CURRENT = 0x2,  // 2
/*line: 323*/   SADB_EXT_LIFETIME_HARD = 0x3,  // 3
/*line: 324*/   SADB_EXT_LIFETIME_SOFT = 0x4,  // 4
/*line: 325*/   SADB_EXT_ADDRESS_SRC = 0x5,  // 5
/*line: 326*/   SADB_EXT_ADDRESS_DST = 0x6,  // 6
/*line: 327*/   SADB_EXT_ADDRESS_PROXY = 0x7,  // 7
/*line: 328*/   SADB_EXT_KEY_AUTH = 0x8,  // 8
/*line: 329*/   SADB_EXT_KEY_ENCRYPT = 0x9,  // 9
/*line: 330*/   SADB_EXT_IDENTITY_SRC = 0xa,  // 10
/*line: 331*/   SADB_EXT_IDENTITY_DST = 0xb,  // 11
/*line: 332*/   SADB_EXT_SENSITIVITY = 0xc,  // 12
/*line: 333*/   SADB_EXT_PROPOSAL = 0xd,  // 13
/*line: 334*/   SADB_EXT_SUPPORTED_AUTH = 0xe,  // 14
/*line: 335*/   SADB_EXT_SUPPORTED_ENCRYPT = 0xf,  // 15
/*line: 336*/   SADB_EXT_SPIRANGE = 0x10,  // 16
/*line: 337*/   SADB_X_EXT_KMPRIVATE = 0x11,  // 17
/*line: 338*/   SADB_X_EXT_POLICY = 0x12,  // 18
/*line: 339*/   SADB_X_EXT_SA2 = 0x13,  // 19
/*line: 340*/   SADB_EXT_SESSION_ID = 0x14,  // 20
/*line: 341*/   SADB_EXT_SASTAT = 0x15,  // 21
/*line: 342*/   SADB_X_EXT_IPSECIF = 0x16,  // 22
/*line: 343*/   SADB_X_EXT_ADDR_RANGE_SRC_START = 0x17,  // 23
/*line: 344*/   SADB_X_EXT_ADDR_RANGE_SRC_END = 0x18,  // 24
/*line: 345*/   SADB_X_EXT_ADDR_RANGE_DST_START = 0x19,  // 25
/*line: 346*/   SADB_X_EXT_ADDR_RANGE_DST_END = 0x1a,  // 26
/*line: 347*/   SADB_EXT_MIGRATE_ADDRESS_SRC = 0x1b,  // 27
/*line: 348*/   SADB_EXT_MIGRATE_ADDRESS_DST = 0x1c,  // 28
/*line: 349*/   SADB_X_EXT_MIGRATE_IPSECIF = 0x1d,  // 29
/*line: 350*/   SADB_EXT_MAX = 0x1d,  // 29
};

enum macro_sadb_satype {
/*line: 352*/   SADB_SATYPE_UNSPEC = 0x0,  // 0
/*line: 353*/   SADB_SATYPE_AH = 0x2,  // 2
/*line: 354*/   SADB_SATYPE_ESP = 0x3,  // 3
/*line: 355*/   SADB_SATYPE_RSVP = 0x5,  // 5
/*line: 356*/   SADB_SATYPE_OSPFV2 = 0x6,  // 6
/*line: 357*/   SADB_SATYPE_RIPV2 = 0x7,  // 7
/*line: 358*/   SADB_SATYPE_MIP = 0x8,  // 8
/*line: 359*/   SADB_X_SATYPE_IPCOMP = 0x9,  // 9
/*line: 360*/   SADB_X_SATYPE_POLICY = 0xa,  // 10
/*line: 361*/   SADB_SATYPE_MAX = 0xb,  // 11
};

enum macro_sa_state {
/*line: 363*/   SADB_SASTATE_LARVAL = 0x0,  // 0
/*line: 364*/   SADB_SASTATE_MATURE = 0x1,  // 1
/*line: 365*/   SADB_SASTATE_DYING = 0x2,  // 2
/*line: 366*/   SADB_SASTATE_DEAD = 0x3,  // 3
/*line: 367*/   SADB_SASTATE_MAX = 0x3,  // 3
};

enum macro_sadb_saflags_pfs {
/*line: 369*/   SADB_SAFLAGS_PFS = 0x1,  // 1
};

enum macro_authentication_algorithm {
/* RFC2367 numbers - meets RFC2407 */
/*line: 372*/   SADB_AALG_NONE = 0x0,  // 0
/*line: 373*/   SADB_AALG_MD5HMAC = 0x1, /*2*/ // 1
/*line: 374*/   SADB_AALG_SHA1HMAC = 0x2, /*3*/ // 2
/*line: 375*/   SADB_AALG_MAX = 0x8,  // 8
/* private allocations - based on RFC2407/IANA assignment */
/*line: 377*/   SADB_X_AALG_SHA2_256 = 0x6, /*5*/ // 6
/*line: 378*/   SADB_X_AALG_SHA2_384 = 0x7, /*6*/ // 7
/*line: 379*/   SADB_X_AALG_SHA2_512 = 0x8, /*7*/ // 8
/* private allocations should use 249-255 (RFC2407) */
/*line: 381*/   SADB_X_AALG_MD5 = 0x3, /*249*/ // 3
/*line: 382*/   SADB_X_AALG_SHA = 0x4, /*250*/ // 4
/*line: 383*/   SADB_X_AALG_NULL = 0x5, /*251*/ // 5
};

enum macro_encryption_algorithm {
/* RFC2367 numbers - meets RFC2407 */
/*line: 386*/   SADB_EALG_NONE = 0x0,  // 0
/*line: 387*/   SADB_EALG_DESCBC = 0x1, /*2*/ // 1
/*line: 388*/   SADB_EALG_3DESCBC = 0x2, /*3*/ // 2
/*line: 389*/   SADB_EALG_NULL = 0x3, /*11*/ // 3
/*line: 390*/   SADB_EALG_MAX = 0xc,  // 12
/* private allocations - based on RFC2407/IANA assignment */
/*line: 392*/   SADB_X_EALG_CAST128CBC = 0x5, /*6*/ // 5
/*line: 393*/   SADB_X_EALG_BLOWFISHCBC = 0x4, /*7*/ // 4
/*line: 394*/   SADB_X_EALG_RIJNDAELCBC = 0xc,  // 12
/*line: 395*/   SADB_X_EALG_AESCBC = 0xc,  // 12
/*line: 396*/   SADB_X_EALG_AES = 0xc,  // 12
/*line: 397*/   SADB_X_EALG_AES_GCM = 0xd,  // 13
/*line: 398*/   SADB_X_EALG_CHACHA20POLY1305 = 0xe,  // 14
/*line: 399*/   SADB_X_EALG_AES_GMAC = 0xf,  // 15
};

enum macro_sadb_x_calg {
/*line: 403*/   SADB_X_CALG_NONE = 0x0,  // 0
/*line: 404*/   SADB_X_CALG_OUI = 0x1,  // 1
/*line: 405*/   SADB_X_CALG_DEFLATE = 0x2,  // 2
/*line: 406*/   SADB_X_CALG_LZS = 0x3,  // 3
/*line: 407*/   SADB_X_CALG_MAX = 0x4,  // 4
};

enum macro_sadb_identtype {
/*line: 410*/   SADB_IDENTTYPE_RESERVED = 0x0,  // 0
/*line: 411*/   SADB_IDENTTYPE_PREFIX = 0x1,  // 1
/*line: 412*/   SADB_IDENTTYPE_FQDN = 0x2,  // 2
/*line: 413*/   SADB_IDENTTYPE_USERFQDN = 0x3,  // 3
/*line: 414*/   SADB_X_IDENTTYPE_ADDR = 0x4,  // 4
/*line: 415*/   SADB_IDENTTYPE_MAX = 0x4,  // 4
};

enum macro_sadb_x_ext {
/* `flags' in sadb_sa structure holds followings */
/*line: 418*/   SADB_X_EXT_NONE = 0x0, /* i.e. new format. */ // 0x0000
/*line: 419*/   SADB_X_EXT_OLD = 0x1, /* old format. */ // 0x0001
/*line: 421*/   SADB_X_EXT_IV4B = 0x10, /* IV length of 4 bytes in use */ // 0x0010
/*line: 422*/   SADB_X_EXT_DERIV = 0x20, /* DES derived */ // 0x0020
/*line: 423*/   SADB_X_EXT_CYCSEQ = 0x40, /* allowing to cyclic sequence. */ // 0x0040
};

enum macro_esp_padding {
/* three of followings are exclusive flags each them */
/*line: 426*/   SADB_X_EXT_PSEQ = 0x0, /* sequencial padding for ESP */ // 0x0000
/*line: 427*/   SADB_X_EXT_PRAND = 0x100, /* random padding for ESP */ // 0x0100
/*line: 428*/   SADB_X_EXT_PZERO = 0x200, /* zero padding for ESP */ // 0x0200
/*line: 429*/   SADB_X_EXT_PMASK = 0x300, /* mask for padding flag */ // 0x0300
};

enum macro_sadb_x_ext_iiv {
/*line: 431*/   SADB_X_EXT_IIV = 0x400, /* Implicit IV */ // 0x0400
};

enum macro_sadb_x_ext_rawcpi {
/*line: 436*/   SADB_X_EXT_RAWCPI = 0x80, /* use well known CPI (IPComp) */ // 0x0080
};

enum macro_sadb_key_flags_max {
/*line: 439*/   SADB_KEY_FLAGS_MAX = 0x7fff,  // 0x7fff
};

enum macro_lifetime_type {
/* Identifier for menber of lifetime structure */
/*line: 446*/   SADB_X_LIFETIME_ALLOCATIONS = 0x0,  // 0
/*line: 447*/   SADB_X_LIFETIME_BYTES = 0x1,  // 1
/*line: 448*/   SADB_X_LIFETIME_ADDTIME = 0x2,  // 2
/*line: 449*/   SADB_X_LIFETIME_USETIME = 0x3,  // 3
};

enum macro_lifetime_rate {
/* The rate for SOFT lifetime against HARD one. */
/*line: 452*/   PFKEY_SOFT_LIFETIME_RATE = 0x50,  // 80
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 443
// #define PFKEY_SPI_SIZE sizeof(u_int32_t)

