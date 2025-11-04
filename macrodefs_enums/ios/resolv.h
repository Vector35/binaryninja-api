// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/resolv.h

enum macro_resolver_version {
/*%
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__RES > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your resolver
 * is new enough to contain a certain feature.
 */
/*line: 88*/    __RES = 0x1328dbe,  // 20090302
};

enum macro_resolver_limits {
/*%
 * Global defines and variables for resolver stub.
 */
/*line: 166*/   MAXNS = 0x3, /*%< max # name servers we'll track */ // 3
/*line: 167*/   MAXDFLSRCH = 0x3, /*%< # default domain levels to try */ // 3
/*line: 168*/   MAXDNSRCH = 0x6, /*%< max # domains in search path */ // 6
/*line: 169*/   LOCALDOMAINPARTS = 0x2, /*%< min levels in name that is "local" */ // 2
/*line: 170*/   RES_TIMEOUT = 0x5, /*%< min. seconds between retries */ // 5
/*line: 171*/   MAXRESOLVSORT = 0xa, /*%< number of net to sort on */ // 10
/*line: 172*/   RES_MAXNDOTS = 0xf, /*%< should reflect bit field size */ // 15
/*line: 173*/   RES_MAXRETRANS = 0x1e, /*%< only for resolv.conf/RES_OPTIONS */ // 30
/*line: 174*/   RES_MAXRETRY = 0x5, /*%< only for resolv.conf/RES_OPTIONS */ // 5
/*line: 175*/   RES_DFLRETRY = 0x2, /*%< Default #/tries. */ // 2
/*line: 176*/   RES_MAXTIME = 0xffff, /*%< Infinity, in milliseconds. */ // 65535
};

enum macro_resolver_flags {
/*%
 * Resolver flags (used to be discrete per-module statics ints).
 */
/*line: 258*/   RES_F_VC = 0x1, /*%< socket is TCP */ // 0x00000001
/*line: 259*/   RES_F_CONN = 0x2, /*%< socket is connected */ // 0x00000002
/*line: 260*/   RES_F_EDNS0ERR = 0x4, /*%< EDNS0 caused errors */ // 0x00000004
/*line: 261*/   RES_F__UNUSED = 0x8, /*%< (unused) */ // 0x00000008
/*line: 262*/   RES_F_LASTMASK = 0xf0, /*%< ordinal server of last res_nsend */ // 0x000000F0
/*line: 263*/   RES_F_LASTSHIFT = 0x4, /*%< bit position of LASTMASK "flag" */ // 4
};

enum macro_resolve_options {
/* res_findzonecut2() options */
/*line: 267*/   RES_EXHAUSTIVE = 0x1, /*%< always do all queries */ // 0x00000001
/*line: 268*/   RES_IPV4ONLY = 0x2, /*%< IPv4 only */ // 0x00000002
/*line: 269*/   RES_IPV6ONLY = 0x4, /*%< IPv6 only */ // 0x00000004
};

enum macro_resolver_options {
/*%
 * Resolver options (keep these in synch with res_debug.c, please)
 */
/*line: 274*/   RES_INIT = 0x1, /*%< address initialized */ // 0x00000001
/*line: 275*/   RES_DEBUG = 0x2, /*%< print debug messages */ // 0x00000002
/*line: 276*/   RES_AAONLY = 0x4, /*%< authoritative answers only (!IMPL)*/ // 0x00000004
/*line: 277*/   RES_USEVC = 0x8, /*%< use virtual circuit */ // 0x00000008
/*line: 278*/   RES_PRIMARY = 0x10, /*%< query primary server only (!IMPL) */ // 0x00000010
/*line: 279*/   RES_IGNTC = 0x20, /*%< ignore truncation errors */ // 0x00000020
/*line: 280*/   RES_RECURSE = 0x40, /*%< recursion desired */ // 0x00000040
/*line: 281*/   RES_DEFNAMES = 0x80, /*%< use default domain name */ // 0x00000080
/*line: 282*/   RES_STAYOPEN = 0x100, /*%< Keep TCP socket open */ // 0x00000100
/*line: 283*/   RES_DNSRCH = 0x200, /*%< search up local domain tree */ // 0x00000200
/*line: 284*/   RES_INSECURE1 = 0x400, /*%< type 1 security disabled */ // 0x00000400
/*line: 285*/   RES_INSECURE2 = 0x800, /*%< type 2 security disabled */ // 0x00000800
/*line: 286*/   RES_NOALIASES = 0x1000, /*%< shuts off HOSTALIASES feature */ // 0x00001000
/*line: 287*/   RES_USE_INET6 = 0x2000, /*%< use/map IPv6 in gethostbyname() */ // 0x00002000
/*line: 288*/   RES_ROTATE = 0x4000, /*%< rotate ns list after each query */ // 0x00004000
/*line: 289*/   RES_NOCHECKNAME = 0x8000, /*%< do not check names for sanity. */ // 0x00008000
/*line: 290*/   RES_KEEPTSIG = 0x10000, /*%< do not strip TSIG records */ // 0x00010000
/*line: 291*/   RES_BLAST = 0x20000, /*%< blast all recursive servers */ // 0x00020000
/* Keep names for compatibility, these are not used by libresolv */
/*line: 296*/   RES_NO_NIBBLE = 0x40000, /* disable IPv6 nibble mode reverse */ // 0x00040000
/*line: 297*/   RES_NO_BITSTRING = 0x80000, /* disable IPv6 bitstring mode reverse */ // 0x00080000
/*line: 299*/   RES_NOTLDQUERY = 0x100000, /*%< don't unqualified name as a tld */ // 0x00100000
/*line: 300*/   RES_USE_DNSSEC = 0x200000, /*%< use DNSSEC using OK bit in OPT */ // 0x00200000
/*line: 303*/   RES_NSID = 0x800000, /*%< request name server ID */ // 0x00800000
/* KAME extensions: use higher bit to avoid conflict with ISC use */
/*line: 306*/   RES_USE_DNAME = 0x10000000, /*%< use DNAME */ // 0x10000000
/*line: 308*/   RES_USE_A6 = 0x20000000, /* use A6 */ // 0x20000000
/*line: 310*/   RES_USE_EDNS0 = 0x40000000, /*%< use EDNS0 if configured */ // 0x40000000
/*line: 311*/   RES_NO_NIBBLE2 = 0x80000000, /*%< disable alternate nibble lookup */ // 0x80000000
};

// Depends on identifiers
enum macro_resolve_flags {
/*line: 313*/   RES_DEFAULT = 0x800002c0,  // (RES_RECURSE|RES_DEFNAMES|RES_DNSRCH|RES_NO_NIBBLE2)
};

enum macro_resolver_pfcode {
/*%
 * Resolver "pfcode" values.  Used by dig.
 */
/*line: 319*/   RES_PRF_STATS = 0x1,  // 0x00000001
/*line: 320*/   RES_PRF_UPDATE = 0x2,  // 0x00000002
/*line: 321*/   RES_PRF_CLASS = 0x4,  // 0x00000004
/*line: 322*/   RES_PRF_CMD = 0x8,  // 0x00000008
/*line: 323*/   RES_PRF_QUES = 0x10,  // 0x00000010
/*line: 324*/   RES_PRF_ANS = 0x20,  // 0x00000020
/*line: 325*/   RES_PRF_AUTH = 0x40,  // 0x00000040
/*line: 326*/   RES_PRF_ADD = 0x80,  // 0x00000080
/*line: 327*/   RES_PRF_HEAD1 = 0x100,  // 0x00000100
/*line: 328*/   RES_PRF_HEAD2 = 0x200,  // 0x00000200
/*line: 329*/   RES_PRF_TTLID = 0x400,  // 0x00000400
/*line: 330*/   RES_PRF_HEADX = 0x800,  // 0x00000800
/*line: 331*/   RES_PRF_QUERY = 0x1000,  // 0x00001000
/*line: 332*/   RES_PRF_REPLY = 0x2000,  // 0x00002000
/*line: 333*/   RES_PRF_INIT = 0x4000,  // 0x00004000
/*line: 334*/   RES_PRF_TRUNC = 0x8000,  // 0x00008000
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 110
// #define __h_errno_set _res_9_h_errno_set

// Line: 111
// #define __res_state __res_9_state

// Line: 136
// #define res_goahead res_9_goahead

// Line: 137
// #define res_nextns res_9_nextns

// Line: 138
// #define res_modified res_9_modified

// Line: 139
// #define res_done res_9_done

// Line: 140
// #define res_error res_9_error

// Line: 141
// #define res_sendhookact res_9_sendhookact

// Line: 155
// #define res_sym res_9_sym

// Line: 178
// #define __res_state_ext __res_9_state_ext

// Line: 199
// #define nsaddr nsaddr_list[0]

// Line: 235
// #define res_state res_9_state

// Line: 240
// #define res_sockaddr_union res_9_sockaddr_union

// Line: 370
// #define fp_nquery res_9_fp_nquery

// Line: 371
// #define fp_query res_9_fp_query

// Line: 372
// #define hostalias res_9_hostalias_1

// Line: 373
// #define p_query res_9_p_query

// Line: 374
// #define res_close res_9_close

// Line: 375
// #define res_init res_9_init

// Line: 376
// #define res_isourserver res_9_isourserver

// Line: 377
// #define res_mkquery res_9_mkquery

// Line: 378
// #define res_query res_9_query

// Line: 379
// #define res_querydomain res_9_querydomain

// Line: 380
// #define res_search res_9_search

// Line: 381
// #define res_send res_9_send

// Line: 382
// #define res_sendsigned res_9_sendsigned

// Line: 432
// #define __p_key_syms __res_9_p_key_syms

// Line: 433
// #define __p_cert_syms __res_9_p_cert_syms

// Line: 434
// #define __p_class_syms __res_9_p_class_syms

// Line: 435
// #define __p_type_syms __res_9_p_type_syms

// Line: 436
// #define __p_rcode_syms __res_9_p_rcode_syms

// Line: 447
// #define b64_ntop res_9_b64_ntop

// Line: 448
// #define b64_pton res_9_b64_pton

// Line: 449
// #define dn_comp res_9_dn_comp

// Line: 450
// #define dn_count_labels res_9_dn_count_labels

// Line: 451
// #define dn_expand res_9_dn_expand

// Line: 452
// #define dn_skipname res_9_dn_skipname

// Line: 453
// #define fp_resstat res_9_fp_resstat

// Line: 454
// #define loc_aton res_9_loc_aton

// Line: 455
// #define loc_ntoa res_9_loc_ntoa

// Line: 456
// #define p_cdname res_9_p_cdname

// Line: 457
// #define p_cdnname res_9_p_cdnname

// Line: 458
// #define p_class res_9_p_class

// Line: 459
// #define p_fqname res_9_p_fqname

// Line: 460
// #define p_fqnname res_9_p_fqnname

// Line: 461
// #define p_option res_9_p_option

// Line: 462
// #define p_secstodate res_9_p_secstodate

// Line: 463
// #define p_section res_9_p_section

// Line: 464
// #define p_time res_9_p_time

// Line: 465
// #define p_type res_9_p_type

// Line: 466
// #define p_rcode res_9_p_rcode

// Line: 467
// #define putlong res_9_putlong

// Line: 468
// #define putshort res_9_putshort

// Line: 469
// #define res_dnok res_9_dnok

// Line: 470
// #define res_findzonecut res_9_findzonecut

// Line: 471
// #define res_findzonecut2 res_9_findzonecut2

// Line: 472
// #define res_hnok res_9_hnok

// Line: 473
// #define res_hostalias res_9_hostalias_2

// Line: 474
// #define res_mailok res_9_mailok

// Line: 475
// #define res_nameinquery res_9_nameinquery

// Line: 476
// #define res_nclose res_9_nclose

// Line: 477
// #define res_ninit res_9_ninit

// Line: 478
// #define res_nmkquery res_9_nmkquery

// Line: 479
// #define res_pquery res_9_pquery

// Line: 480
// #define res_nquery res_9_nquery

// Line: 481
// #define res_nquerydomain res_9_nquerydomain

// Line: 482
// #define res_nsearch res_9_nsearch

// Line: 483
// #define res_nsend res_9_nsend

// Line: 484
// #define res_nsendsigned res_9_nsendsigned

// Line: 485
// #define res_nisourserver res_9_nisourserver

// Line: 486
// #define res_ownok res_9_ownok

// Line: 487
// #define res_queriesmatch res_9_queriesmatch

// Line: 488
// #define res_randomid res_9_randomid

// Line: 489
// #define res_nrandomid res_9_nrandomid

// Line: 490
// #define sym_ntop res_9_sym_ntop

// Line: 491
// #define sym_ntos res_9_sym_ntos

// Line: 492
// #define sym_ston res_9_sym_ston

// Line: 493
// #define res_nopt res_9_nopt

// Line: 494
// #define res_nopt_rdata res_9_nopt_rdata

// Line: 495
// #define res_ndestroy res_9_ndestroy

// Line: 496
// #define res_nametoclass res_9_nametoclass

// Line: 497
// #define res_nametotype res_9_nametotype

// Line: 498
// #define res_setservers res_9_setservers

// Line: 499
// #define res_getservers res_9_getservers

// Line: 502
// #define getlong res_9_getlong

// Line: 503
// #define getshort res_9_getshort

// Line: 504
// #define __res_vinit res_9_vinit

