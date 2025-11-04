// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/ip6.h

enum macro_ipv6_constants {
/*line: 126*/   IPV6_VERSION = 0x60,  // 0x60
/*line: 127*/   IPV6_VERSION_MASK = 0xf0,  // 0xf0
/*line: 135*/   IPV6_FLOWINFO_MASK = 0xffffff0f, /* flow info (28 bits) */ // 0xffffff0f
/*line: 136*/   IPV6_FLOWLABEL_MASK = 0xffff0f00, /* flow label (20 bits) */ // 0xffff0f00
/*line: 137*/   IPV6_FLOW_ECN_MASK = 0x3000, /* the 2 ECN bits */ // 0x00003000
/* ECN bits proposed by Sally Floyd */
/*line: 142*/   IP6TOS_CE = 0x1, /* congestion experienced */ // 0x01
/*line: 143*/   IP6TOS_ECT = 0x2, /* ECN-capable transport */ // 0x02
};

enum macro_ip6_flow_dscp {
/*
 * To access the 6 bits of the DSCP value in the 32 bits ip6_flow field
 */
/*line: 149*/   IP6FLOW_DSCP_MASK = 0xfc00000,  // 0x0fc00000
/*line: 150*/   IP6FLOW_DSCP_SHIFT = 0x16,  // 22
};

enum macro_ip6_option {
/* Option types and related macros */
/*line: 178*/   IP6OPT_PAD1 = 0x0, /* 00 0 00000 */ // 0x00
/*line: 179*/   IP6OPT_PADN = 0x1, /* 00 0 00001 */ // 0x01
/*line: 180*/   IP6OPT_JUMBO = 0xc2, /* 11 0 00010 = 194 */ // 0xC2
/*line: 181*/   IP6OPT_NSAP_ADDR = 0xc3, /* 11 0 00011 */ // 0xC3
/*line: 182*/   IP6OPT_TUNNEL_LIMIT = 0x4, /* 00 0 00100 */ // 0x04
/*line: 183*/   IP6OPT_RTALERT = 0x5, /* 00 0 00101 (KAME definition) */ // 0x05
/*line: 184*/   IP6OPT_ROUTER_ALERT = 0x5, /* 00 0 00101 (RFC3542, recommended) */ // 0x05
};

enum macro_ip6_options {
/*line: 186*/   IP6OPT_RTALERT_LEN = 0x4,  // 4
/*line: 187*/   IP6OPT_RTALERT_MLD = 0x0, /* Datagram contains an MLD message */ // 0
/*line: 188*/   IP6OPT_RTALERT_RSVP = 0x1, /* Datagram contains an RSVP message */ // 1
/*line: 189*/   IP6OPT_RTALERT_ACTNET = 0x2, /* contains an Active Networks msg */ // 2
/*line: 190*/   IP6OPT_MINLEN = 0x2,  // 2
};

enum macro_ip6opt_eid {
/*line: 192*/   IP6OPT_EID = 0x8a, /* 10 0 01010 */ // 0x8a
};

enum macro_ip6_option_type {
/*line: 195*/   IP6OPT_TYPE_SKIP = 0x0,  // 0x00
/*line: 196*/   IP6OPT_TYPE_DISCARD = 0x40,  // 0x40
/*line: 197*/   IP6OPT_TYPE_FORCEICMP = 0x80,  // 0x80
/*line: 198*/   IP6OPT_TYPE_ICMP = 0xc0,  // 0xC0
};

enum macro_ip6_mutable {
/*line: 200*/   IP6OPT_MUTABLE = 0x20,  // 0x20
};

enum macro_ip6_jumbo_len {
/*line: 214*/   IP6OPT_JUMBO_LEN = 0x6,  // 6
};

enum macro_ip6_alert {
/*line: 246*/   IP6_ALERT_MLD = 0x0,  // 0x0000
/*line: 247*/   IP6_ALERT_RSVP = 0x100,  // 0x0100
/*line: 248*/   IP6_ALERT_AN = 0x200,  // 0x0200
};

enum macro_ip6_flags {
/*line: 284*/   IP6F_OFF_MASK = 0xf8ff, /* mask out offset from _offlg */ // 0xf8ff
/*line: 285*/   IP6F_RESERVED_MASK = 0x600, /* reserved bits in ip6f_offlg */ // 0x0600
/*line: 286*/   IP6F_MORE_FRAG = 0x100, /* more-fragments flag */ // 0x0100
};

enum macro_ipv6_parameters {
/*
 * Internet implementation parameters.
 */
/*line: 292*/   IPV6_MAXHLIM = 0xff, /* maximum hoplimit */ // 255
/*line: 293*/   IPV6_DEFHLIM = 0x40, /* default hlim */ // 64
/*line: 294*/   IPV6_FRAGTTL = 0x3c, /* ttl for fragment packets (seconds) */ // 60
/*line: 295*/   IPV6_HLIMDEC = 0x1, /* subtracted when forwarding */ // 1
};

enum macro_ipv6_limits {
/*line: 297*/   IPV6_MMTU = 0x500, /* minimal MTU and reassembly. 1024 + 256 */ // 1280
/*line: 298*/   IPV6_MAXPACKET = 0xffff, /* ip6 max packet size without Jumbo payload*/ // 65535
/*line: 299*/   IPV6_MAXOPTHDR = 0x800, /* max option header size, 256 64-bit words */ // 2048
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 119
// #define ip6_vfc ip6_ctlun.ip6_un2_vfc

// Line: 120
// #define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow

// Line: 121
// #define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen

// Line: 122
// #define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt

// Line: 123
// #define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim

// Line: 124
// #define ip6_hops ip6_ctlun.ip6_un1.ip6_un1_hlim

