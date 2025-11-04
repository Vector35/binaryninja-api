// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/nameser.h

enum macro_nameser_constants {
/*%
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__NAMESER > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your libbind.a
 * contains a new enough lib/nameser/ to support the feature you need.
 */
/*line: 75*/    __NAMESER = 0x1328dbe, /*%< New interface version stamp. */ // 20090302
/*
 * Define constants based on RFC0883, RFC1034, RFC 1035
 */
/*line: 79*/    NS_PACKETSZ = 0x200, /*%< default UDP packet size */ // 512
/*line: 80*/    NS_MAXDNAME = 0x401, /*%< maximum domain name (presentation format)*/ // 1025
/*line: 81*/    NS_MAXMSG = 0xffff, /*%< maximum message size */ // 65535
/*line: 82*/    NS_MAXCDNAME = 0xff, /*%< maximum compressed domain name */ // 255
/*line: 83*/    NS_MAXLABEL = 0x3f, /*%< maximum length of domain label */ // 63
/*line: 84*/    NS_MAXLABELS = 0x80, /*%< theoretical max #/labels per domain name */ // 128
/*line: 85*/    NS_MAXNNAME = 0x100, /*%< maximum uncompressed (binary) domain name*/ // 256
/*line: 87*/    NS_HFIXEDSZ = 0xc, /*%< #/bytes of fixed data in header */ // 12
/*line: 88*/    NS_QFIXEDSZ = 0x4, /*%< #/bytes of fixed data in query */ // 4
/*line: 89*/    NS_RRFIXEDSZ = 0xa, /*%< #/bytes of fixed data in r record */ // 10
/*line: 90*/    NS_INT32SZ = 0x4, /*%< #/bytes of data in a u_int32_t */ // 4
/*line: 91*/    NS_INT16SZ = 0x2, /*%< #/bytes of data in a u_int16_t */ // 2
/*line: 92*/    NS_INT8SZ = 0x1, /*%< #/bytes of data in a u_int8_t */ // 1
/*line: 93*/    NS_INADDRSZ = 0x4, /*%< IPv4 T_A */ // 4
/*line: 94*/    NS_IN6ADDRSZ = 0x10, /*%< IPv6 T_AAAA */ // 16
/*line: 95*/    NS_CMPRSFLGS = 0xc0, /*%< Flag bits indicating name compression. */ // 0xc0
/*line: 96*/    NS_DEFAULTPORT = 0x35, /*%< For both TCP and UDP. */ // 53
};

enum macro_tsig_flags {
/*line: 314*/   NS_TSIG_FUDGE = 0x12c,  // 300
/*line: 315*/   NS_TSIG_TCP_COUNT = 0x64,  // 100
};

enum macro_tsig_errors {
/*line: 318*/   NS_TSIG_ERROR_NO_TSIG = -0xa,  // -10
/*line: 319*/   NS_TSIG_ERROR_NO_SPACE = -0xb,  // -11
/*line: 320*/   NS_TSIG_ERROR_FORMERR = -0xc,  // -12
};

// Depends on identifiers
enum macro_dns_key_flags {
/* Flags field of the KEY RR rdata. */
/*line: 445*/   NS_KEY_TYPEMASK = 0xc000, /*%< Mask for "type" bits */ // 0xC000
/*line: 446*/   NS_KEY_TYPE_AUTH_CONF = 0x0, /*%< Key usable for both */ // 0x0000
/*line: 447*/   NS_KEY_TYPE_CONF_ONLY = 0x8000, /*%< Key usable for confidentiality */ // 0x8000
/*line: 448*/   NS_KEY_TYPE_AUTH_ONLY = 0x4000, /*%< Key usable for authentication */ // 0x4000
/*line: 449*/   NS_KEY_TYPE_NO_KEY = 0xc000, /*%< No key usable for either; no key */ // 0xC000
/* The type bits can also be interpreted independently, as single bits: */
/*line: 451*/   NS_KEY_NO_AUTH = 0x8000, /*%< Key unusable for authentication */ // 0x8000
/*line: 452*/   NS_KEY_NO_CONF = 0x4000, /*%< Key unusable for confidentiality */ // 0x4000
/*line: 453*/   NS_KEY_RESERVED2 = 0x2000, /* Security is *mandatory* if bit=0 */ // 0x2000
/*line: 454*/   NS_KEY_EXTENDED_FLAGS = 0x1000, /*%< reserved - must be zero */ // 0x1000
/*line: 455*/   NS_KEY_RESERVED4 = 0x800, /*%< reserved - must be zero */ // 0x0800
/*line: 456*/   NS_KEY_RESERVED5 = 0x400, /*%< reserved - must be zero */ // 0x0400
/*line: 457*/   NS_KEY_NAME_TYPE = 0x300, /*%< these bits determine the type */ // 0x0300
/*line: 458*/   NS_KEY_NAME_USER = 0x0, /*%< key is assoc. with user */ // 0x0000
/*line: 459*/   NS_KEY_NAME_ENTITY = 0x200, /*%< key is assoc. with entity eg host */ // 0x0200
/*line: 460*/   NS_KEY_NAME_ZONE = 0x100, /*%< key is zone key */ // 0x0100
/*line: 461*/   NS_KEY_NAME_RESERVED = 0x300, /*%< reserved meaning */ // 0x0300
/*line: 462*/   NS_KEY_RESERVED8 = 0x80, /*%< reserved - must be zero */ // 0x0080
/*line: 463*/   NS_KEY_RESERVED9 = 0x40, /*%< reserved - must be zero */ // 0x0040
/*line: 464*/   NS_KEY_RESERVED10 = 0x20, /*%< reserved - must be zero */ // 0x0020
/*line: 465*/   NS_KEY_RESERVED11 = 0x10, /*%< reserved - must be zero */ // 0x0010
/*line: 466*/   NS_KEY_SIGNATORYMASK = 0xf, /*%< key can sign RR's of same name */ // 0x000F
/*line: 467*/   NS_KEY_RESERVED_BITMASK = 0x2cf0,  // (NS_KEY_RESERVED2|NS_KEY_RESERVED4|NS_KEY_RESERVED5|NS_KEY_RESERVED8|NS_KEY_RESERVED9|NS_KEY_RESERVED10|NS_KEY_RESERVED11)
/*line: 474*/   NS_KEY_RESERVED_BITMASK2 = 0xffff, /*%< no bits defined here */ // 0xFFFF
/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
/*line: 476*/   NS_ALG_MD5RSA = 0x1, /*%< MD5 with RSA */ // 1
/*line: 477*/   NS_ALG_DH = 0x2, /*%< Diffie Hellman KEY */ // 2
/*line: 478*/   NS_ALG_DSA = 0x3, /*%< DSA KEY */ // 3
/*line: 479*/   NS_ALG_DSS = 0x3,  // NS_ALG_DSA
/*line: 480*/   NS_ALG_EXPIRE_ONLY = 0xfd, /*%< No alg, no security */ // 253
/*line: 481*/   NS_ALG_PRIVATE_OID = 0xfe, /*%< Key begins with OID giving alg */ // 254
/* value 0 is reserved */
/*line: 484*/   NS_KEY_PROT_TLS = 0x1,  // 1
/*line: 485*/   NS_KEY_PROT_EMAIL = 0x2,  // 2
/*line: 486*/   NS_KEY_PROT_DNSSEC = 0x3,  // 3
/*line: 487*/   NS_KEY_PROT_IPSEC = 0x4,  // 4
/*line: 488*/   NS_KEY_PROT_ANY = 0xff,  // 255
};

enum macro_md5rsa_bits {
/* Signatures */
/*line: 491*/   NS_MD5RSA_MIN_BITS = 0x200, /*%< Size of a mod or exp in bits */ // 512
/*line: 492*/   NS_MD5RSA_MAX_BITS = 0x1000,  // 4096
};

enum macro_dsa_sizes {
/*line: 500*/   NS_DSA_SIG_SIZE = 0x29,  // 41
/*line: 501*/   NS_DSA_MIN_SIZE = 0xd5,  // 213
/*line: 502*/   NS_DSA_MAX_BYTES = 0x195,  // 405
};

enum macro_ns_sig_offsets {
/* Offsets into SIG record rdata to find various values */
/*line: 505*/   NS_SIG_TYPE = 0x0, /*%< Type flags */ // 0
/*line: 506*/   NS_SIG_ALG = 0x2, /*%< Algorithm */ // 2
/*line: 507*/   NS_SIG_LABELS = 0x3, /*%< How many labels in name */ // 3
/*line: 508*/   NS_SIG_OTTL = 0x4, /*%< Original TTL */ // 4
/*line: 509*/   NS_SIG_EXPIR = 0x8, /*%< Expiration time */ // 8
/*line: 510*/   NS_SIG_SIGNED = 0xc, /*%< Signature time */ // 12
/*line: 511*/   NS_SIG_FOOT = 0x10, /*%< Key footprint */ // 16
/*line: 512*/   NS_SIG_SIGNER = 0x12, /*%< Domain name of who signed it */ // 18
/* How RR types are represented as bit-flags in NXT records */
/*line: 514*/   NS_NXT_BITS = 0x8,  // 8
/*line: 518*/   NS_NXT_MAX = 0x7f,  // 127
};

enum macro_edns_flags {
/*%
 * EDNS0 extended flags and option codes, host order.
 */
/*line: 523*/   NS_OPT_DNSSEC_OK = 0x8000,  // 0x8000U
/*line: 524*/   NS_OPT_NSID = 0x3,  // 3
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 102
// #define ns_sect res_9_ns_sect

// Line: 133
// #define ns_msg res_9_ns_msg

// Line: 159
// #define _ns_flagdata _res_9_ns_flagdata

// Line: 176
// #define ns_rr res_9_ns_rr

// Line: 216
// #define ns_flag res_9_ns_flag

// Line: 236
// #define ns_opcode res_9_ns_opcode

// Line: 252
// #define ns_rcode res_9_ns_rcode

// Line: 278
// #define ns_update_operation res_9_ns_update_operation

// Line: 290
// #define ns_tsig_key res_9_ns_tsig_key

// Line: 303
// #define ns_tcp_tsig_state res_9_ns_tcp_tsig_state

// Line: 407
// #define ns_class res_9_ns_class

// Line: 424
// #define ns_key_types res_9_ns_key_types

// Line: 434
// #define ns_cert_types res_9_ns_cert_types

// Line: 494
// #define NS_MD5RSA_MAX_BYTES ((NS_MD5RSA_MAX_BITS+7/8)*2+3)

// Line: 496
// #define NS_MD5RSA_MAX_BASE64 (((NS_MD5RSA_MAX_BYTES+2)/3)*4)

// Line: 497
// #define NS_MD5RSA_MIN_SIZE ((NS_MD5RSA_MIN_BITS+7)/8)

// Line: 498
// #define NS_MD5RSA_MAX_SIZE ((NS_MD5RSA_MAX_BITS+7)/8)

// Line: 570
// #define ns_msg_getflag res_9_ns_msg_getflag

// Line: 571
// #define ns_get16 res_9_ns_get16

// Line: 572
// #define ns_get32 res_9_ns_get32

// Line: 573
// #define ns_put16 res_9_ns_put16

// Line: 574
// #define ns_put32 res_9_ns_put32

// Line: 575
// #define ns_initparse res_9_ns_initparse

// Line: 576
// #define ns_skiprr res_9_ns_skiprr

// Line: 577
// #define ns_parserr res_9_ns_parserr

// Line: 578
// #define ns_parserr2 res_9_ns_parserr2

// Line: 579
// #define ns_sprintrr res_9_ns_sprintrr

// Line: 580
// #define ns_sprintrrf res_9_ns_sprintrrf

// Line: 581
// #define ns_format_ttl res_9_ns_format_ttl

// Line: 582
// #define ns_parse_ttl res_9_ns_parse_ttl

// Line: 583
// #define ns_datetosecs res_9_ns_datetosecs

// Line: 584
// #define ns_name_ntol res_9_ns_name_ntol

// Line: 585
// #define ns_name_ntop res_9_ns_name_ntop

// Line: 586
// #define ns_name_pton res_9_ns_name_pton

// Line: 587
// #define ns_name_pton2 res_9_ns_name_pton2

// Line: 588
// #define ns_name_unpack res_9_ns_name_unpack

// Line: 589
// #define ns_name_unpack2 res_9_ns_name_unpack2

// Line: 590
// #define ns_name_pack res_9_ns_name_pack

// Line: 591
// #define ns_name_compress res_9_ns_name_compress

// Line: 592
// #define ns_name_uncompress res_9_ns_name_uncompress

// Line: 593
// #define ns_name_skip res_9_ns_name_skip

// Line: 594
// #define ns_name_rollback res_9_ns_name_rollback

// Line: 595
// #define ns_sign res_9_ns_sign

// Line: 596
// #define ns_sign2 res_9_ns_sign2

// Line: 597
// #define ns_sign_tcp res_9_ns_sign_tcp

// Line: 598
// #define ns_sign_tcp2 res_9_ns_sign_tcp2

// Line: 599
// #define ns_sign_tcp_init res_9_ns_sign_tcp_init

// Line: 600
// #define ns_find_tsig res_9_ns_find_tsig

// Line: 601
// #define ns_verify res_9_ns_verify

// Line: 602
// #define ns_verify_tcp res_9_ns_verify_tcp

// Line: 603
// #define ns_verify_tcp_init res_9_ns_verify_tcp_init

// Line: 604
// #define ns_samedomain res_9_ns_samedomain

// Line: 605
// #define ns_subdomain res_9_ns_subdomain

// Line: 606
// #define ns_makecanon res_9_ns_makecanon

// Line: 607
// #define ns_samename res_9_ns_samename

// Line: 608
// #define ns_rdata_unpack res_9_ns_rdata_unpack

// Line: 609
// #define ns_rdata_equal res_9_ns_rdata_equal

// Line: 610
// #define ns_rdata_refers res_9_ns_rdata_refers

