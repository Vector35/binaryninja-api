// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/in_pcb.h

enum macro_inp_flags {
/*
 * These defines are for use with the inpcb.
 */
/*line: 266*/   INP_IPV4 = 0x1,  // 0x1
/*line: 267*/   INP_IPV6 = 0x2,  // 0x2
/*line: 268*/   INP_V4MAPPEDV6 = 0x4,  // 0x4
/*
 * Flags for inp_flags.
 *
 * Some of these are publicly defined for legacy reasons, as they are
 * (unfortunately) used by certain applications to determine, at compile
 * time, whether or not the OS supports certain features.
 */
/*line: 283*/   INP_ANONPORT = 0x40, /* port chosen for user */ // 0x00000040
/*line: 286*/   IN6P_IPV6_V6ONLY = 0x8000, /* restrict AF_INET6 socket for v6 */ // 0x00008000
/*line: 289*/   IN6P_BINDV6ONLY = 0x1000000, /* do not grab IPv4 traffic */ // 0x01000000
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 269
// #define inp_faddr inp_dependfaddr.inp46_foreign.ia46_addr4

// Line: 270
// #define inp_laddr inp_dependladdr.inp46_local.ia46_addr4

// Line: 271
// #define in6p_faddr inp_dependfaddr.inp6_foreign

// Line: 272
// #define in6p_laddr inp_dependladdr.inp6_local

