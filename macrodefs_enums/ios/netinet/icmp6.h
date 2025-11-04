// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/icmp6.h

enum macro_icmpv6_pld_maxlen {
/*line: 100*/   ICMPV6_PLD_MAXLEN = 0x4d0, /* IPV6_MMTU - sizeof(struct ip6_hdr)
	                                 *  - sizeof(struct icmp6_hdr) */ // 1232
};

// Depends on identifiers
enum macro_icmp6_codes {
/*line: 123*/   ICMP6_DST_UNREACH = 0x1, /* dest unreachable, codes: */ // 1
/*line: 124*/   ICMP6_PACKET_TOO_BIG = 0x2, /* packet too big */ // 2
/*line: 125*/   ICMP6_TIME_EXCEEDED = 0x3, /* time exceeded, code: */ // 3
/*line: 126*/   ICMP6_PARAM_PROB = 0x4, /* ip6 header bad */ // 4
/*line: 128*/   ICMP6_ECHO_REQUEST = 0x80, /* echo service */ // 128
/*line: 129*/   ICMP6_ECHO_REPLY = 0x81, /* echo reply */ // 129
/*line: 130*/   MLD_LISTENER_QUERY = 0x82, /* multicast listener query */ // 130
/*line: 131*/   MLD_LISTENER_REPORT = 0x83, /* multicast listener report */ // 131
/*line: 132*/   MLD_LISTENER_DONE = 0x84, /* multicast listener done */ // 132
/*line: 133*/   MLD_LISTENER_REDUCTION = 0x84, /* RFC3542 definition */ // MLD_LISTENER_DONE
};

enum macro_icmp6_membership {
/* RFC2292 decls */
/*line: 136*/   ICMP6_MEMBERSHIP_QUERY = 0x82, /* group membership query */ // 130
/*line: 137*/   ICMP6_MEMBERSHIP_REPORT = 0x83, /* group membership report */ // 131
/*line: 138*/   ICMP6_MEMBERSHIP_REDUCTION = 0x84, /* group membership termination */ // 132
};

// Depends on identifiers
enum macro_icmp6_types {
/* the followings are for backward compatibility to old KAME apps. */
/*line: 141*/   MLD6_LISTENER_QUERY = 0x82,  // MLD_LISTENER_QUERY
/*line: 142*/   MLD6_LISTENER_REPORT = 0x83,  // MLD_LISTENER_REPORT
/*line: 143*/   MLD6_LISTENER_DONE = 0x84,  // MLD_LISTENER_DONE
/*line: 145*/   ND_ROUTER_SOLICIT = 0x85, /* router solicitation */ // 133
/*line: 146*/   ND_ROUTER_ADVERT = 0x86, /* router advertisement */ // 134
/*line: 147*/   ND_NEIGHBOR_SOLICIT = 0x87, /* neighbor solicitation */ // 135
/*line: 148*/   ND_NEIGHBOR_ADVERT = 0x88, /* neighbor advertisement */ // 136
/*line: 149*/   ND_REDIRECT = 0x89, /* redirect */ // 137
/*line: 151*/   ICMP6_ROUTER_RENUMBERING = 0x8a, /* router renumbering */ // 138
/*line: 153*/   ICMP6_WRUREQUEST = 0x8b, /* who are you request */ // 139
/*line: 154*/   ICMP6_WRUREPLY = 0x8c, /* who are you reply */ // 140
/*line: 155*/   ICMP6_FQDN_QUERY = 0x8b, /* FQDN query */ // 139
/*line: 156*/   ICMP6_FQDN_REPLY = 0x8c, /* FQDN reply */ // 140
/*line: 157*/   ICMP6_NI_QUERY = 0x8b, /* node information request */ // 139
/*line: 158*/   ICMP6_NI_REPLY = 0x8c, /* node information reply */ // 140
/*line: 159*/   MLDV2_LISTENER_REPORT = 0x8f, /* RFC3810 listener report */ // 143
};

enum macro_mld_message_type {
/* The definitions below are experimental. TBA */
/*line: 162*/   MLD_MTRACE_RESP = 0xc8, /* mtrace resp (to sender) */ // 200
/*line: 163*/   MLD_MTRACE = 0xc9, /* mtrace messages */ // 201
};

// Depends on identifiers
enum macro_mld6_trace {
/*line: 165*/   MLD6_MTRACE_RESP = 0xc8,  // MLD_MTRACE_RESP
/*line: 166*/   MLD6_MTRACE = 0xc9,  // MLD_MTRACE
};

enum macro_icmp6_max_type {
/*line: 168*/   ICMP6_MAXTYPE = 0xc9,  // 201
};

enum macro_icmp6_destination_unreach {
/*line: 170*/   ICMP6_DST_UNREACH_NOROUTE = 0x0, /* no route to destination */ // 0
/*line: 171*/   ICMP6_DST_UNREACH_ADMIN = 0x1, /* administratively prohibited */ // 1
/*line: 172*/   ICMP6_DST_UNREACH_NOTNEIGHBOR = 0x2, /* not a neighbor(obsolete) */ // 2
/*line: 173*/   ICMP6_DST_UNREACH_BEYONDSCOPE = 0x2, /* beyond scope of source address */ // 2
/*line: 174*/   ICMP6_DST_UNREACH_ADDR = 0x3, /* address unreachable */ // 3
/*line: 175*/   ICMP6_DST_UNREACH_NOPORT = 0x4, /* port unreachable */ // 4
};

enum macro_icmp6_time_exceed {
/*line: 177*/   ICMP6_TIME_EXCEED_TRANSIT = 0x0, /* ttl==0 in transit */ // 0
/*line: 178*/   ICMP6_TIME_EXCEED_REASSEMBLY = 0x1, /* ttl==0 in reass */ // 1
};

enum macro_icmp6_paramprob {
/*line: 180*/   ICMP6_PARAMPROB_HEADER = 0x0, /* erroneous header field */ // 0
/*line: 181*/   ICMP6_PARAMPROB_NEXTHEADER = 0x1, /* unrecognized next header */ // 1
/*line: 182*/   ICMP6_PARAMPROB_OPTION = 0x2, /* unrecognized option */ // 2
/*line: 183*/   ICMP6_PARAMPROB_FIRSTFRAG_INCOMP_HDR = 0x3, /* first fragment has incomplete IPv6 Header Chain */ // 3
};

enum macro_icmp6_info_mask {
/*line: 185*/   ICMP6_INFOMSG_MASK = 0x80, /* all informational messages */ // 0x80
};

enum macro_icmp6_subject {
/*line: 187*/   ICMP6_NI_SUBJ_IPV6 = 0x0, /* Query Subject is an IPv6 address */ // 0
/*line: 188*/   ICMP6_NI_SUBJ_FQDN = 0x1, /* Query Subject is a Domain name */ // 1
/*line: 189*/   ICMP6_NI_SUBJ_IPV4 = 0x2, /* Query Subject is an IPv4 address */ // 2
};

enum macro_icmp6_status {
/*line: 191*/   ICMP6_NI_SUCCESS = 0x0, /* node information successful reply */ // 0
/*line: 192*/   ICMP6_NI_REFUSED = 0x1, /* node information request is refused */ // 1
/*line: 193*/   ICMP6_NI_UNKNOWN = 0x2, /* unknown Qtype */ // 2
};

enum macro_router_renumbering_command {
/*line: 195*/   ICMP6_ROUTER_RENUMBERING_COMMAND = 0x0, /* rr command */ // 0
/*line: 196*/   ICMP6_ROUTER_RENUMBERING_RESULT = 0x1, /* rr result */ // 1
/*line: 197*/   ICMP6_ROUTER_RENUMBERING_SEQNUM_RESET = 0xff, /* rr seq num reset */ // 255
};

enum macro_icmp6_kernel_only_flags {
/* Used in kernel only */
/*line: 200*/   ND_REDIRECT_ONLINK = 0x0, /* redirect to an on-link node */ // 0
/*line: 201*/   ND_REDIRECT_ROUTER = 0x1, /* redirect to a better router */ // 1
/*line: 259*/   ND_RA_FLAG_MANAGED = 0x80,  // 0x80
/*line: 260*/   ND_RA_FLAG_OTHER = 0x40,  // 0x40
/*line: 261*/   ND_RA_FLAG_HA = 0x20,  // 0x20
};

enum macro_ra_flag_rtpref_mask {
/* Router preference values based on RFC 4191 */
/*line: 264*/   ND_RA_FLAG_RTPREF_MASK = 0x18, /* 00011000 */ // 0x18
};

enum macro_nd_flags {
/*line: 266*/   ND_RA_FLAG_RTPREF_HIGH = 0x8, /* 00001000 */ // 0x08
/*line: 267*/   ND_RA_FLAG_RTPREF_MEDIUM = 0x0, /* 00000000 */ // 0x00
/*line: 268*/   ND_RA_FLAG_RTPREF_LOW = 0x18, /* 00011000 */ // 0x18
/*line: 269*/   ND_RA_FLAG_RTPREF_RSV = 0x10, /* 00010000 */ // 0x10
/*line: 300*/   ND_NA_FLAG_ROUTER = 0x80,  // 0x80
/*line: 301*/   ND_NA_FLAG_SOLICITED = 0x40,  // 0x40
/*line: 302*/   ND_NA_FLAG_OVERRIDE = 0x20,  // 0x20
};

enum macro_nd_options {
/*line: 324*/   ND_OPT_SOURCE_LINKADDR = 0x1,  // 1
/*line: 325*/   ND_OPT_TARGET_LINKADDR = 0x2,  // 2
/*line: 326*/   ND_OPT_PREFIX_INFORMATION = 0x3,  // 3
/*line: 327*/   ND_OPT_REDIRECTED_HEADER = 0x4,  // 4
/*line: 328*/   ND_OPT_MTU = 0x5,  // 5
/*line: 329*/   ND_OPT_NONCE = 0xe, /* RFC 3971 */ // 14
/*line: 330*/   ND_OPT_PVD = 0x15, /* RFC 8801 */ // 21
/*line: 331*/   ND_OPT_ROUTE_INFO = 0x18, /* RFC 4191 */ // 24
/*line: 332*/   ND_OPT_RDNSS = 0x19, /* RFC 6106 */ // 25
/*line: 333*/   ND_OPT_DNSSL = 0x1f, /* RFC 6106 */ // 31
/*line: 334*/   ND_OPT_CAPTIVE_PORTAL = 0x25, /* RFC 7710 */ // 37
/*line: 335*/   ND_OPT_PREF64 = 0x26, /* RFC 8781 */ // 38
};

enum macro_pi_flags {
/*line: 348*/   ND_OPT_PI_FLAG_ONLINK = 0x80,  // 0x80
/*line: 349*/   ND_OPT_PI_FLAG_AUTO = 0x40,  // 0x40
};

enum macro_nonce_length {
/*line: 351*/   ND_OPT_NONCE_LEN = 0x6,  // ((1*8)-2)
};

enum macro_icmp6_options {
/*line: 412*/   ND_OPT_PREF64_SCALED_LIFETIME_MASK = 0xfff8,  // 0xfff8
/*line: 413*/   ND_OPT_PREF64_PLC_MASK = 0x7,  // 0x0007
/*line: 414*/   ND_OPT_PREF64_LIFETIME_MAX = 0xfff8,  // 65528
/*line: 415*/   ND_OPT_PREF64_PLC_32 = 0x5,  // 5
/*line: 416*/   ND_OPT_PREF64_PLC_40 = 0x4,  // 4
/*line: 417*/   ND_OPT_PREF64_PLC_48 = 0x3,  // 3
/*line: 418*/   ND_OPT_PREF64_PLC_56 = 0x2,  // 2
/*line: 419*/   ND_OPT_PREF64_PLC_64 = 0x1,  // 1
/*line: 420*/   ND_OPT_PREF64_PLC_96 = 0x0,  // 0
/*line: 439*/   ND_OPT_PVD_FLAGS_HTTP = 0x80,  // 0x80
/*line: 440*/   ND_OPT_PVD_FLAGS_LEGACY = 0x40,  // 0x40
/*line: 441*/   ND_OPT_PVD_FLAGS_RA = 0x20,  // 0x20
/*line: 442*/   ND_OPT_PVD_DELAY_MASK = 0xf,  // 0x0f
};

enum macro_icmp6_query_type {
/*line: 474*/   NI_QTYPE_NOOP = 0x0, /* NOOP  */ // 0
/*line: 475*/   NI_QTYPE_SUPTYPES = 0x1, /* Supported Qtypes */ // 1
/*line: 476*/   NI_QTYPE_FQDN = 0x2, /* FQDN (draft 04) */ // 2
/*line: 477*/   NI_QTYPE_DNSNAME = 0x2, /* DNS Name */ // 2
/*line: 478*/   NI_QTYPE_NODEADDR = 0x3, /* Node Addresses */ // 3
/*line: 479*/   NI_QTYPE_IPV4ADDR = 0x4, /* IPv4 Addresses */ // 4
/*line: 485*/   NI_SUPTYPE_FLAG_COMPRESS = 0x100,  // 0x0100
/*line: 486*/   NI_FQDN_FLAG_VALIDTTL = 0x100,  // 0x0100
};

enum macro_node_address_flags {
/*line: 515*/   NI_NODEADDR_FLAG_TRUNCATE = 0x100,  // 0x0100
/*line: 516*/   NI_NODEADDR_FLAG_ALL = 0x200,  // 0x0200
/*line: 517*/   NI_NODEADDR_FLAG_COMPAT = 0x400,  // 0x0400
/*line: 518*/   NI_NODEADDR_FLAG_LINKLOCAL = 0x800,  // 0x0800
/*line: 519*/   NI_NODEADDR_FLAG_SITELOCAL = 0x1000,  // 0x1000
/*line: 520*/   NI_NODEADDR_FLAG_GLOBAL = 0x2000,  // 0x2000
/*line: 521*/   NI_NODEADDR_FLAG_ANYCAST = 0x4000, /* just experimental. not in spec */ // 0x4000
};

enum macro_icmp6_rr_flags {
/*line: 542*/   ICMP6_RR_FLAGS_TEST = 0x80,  // 0x80
/*line: 543*/   ICMP6_RR_FLAGS_REQRESULT = 0x40,  // 0x40
/*line: 544*/   ICMP6_RR_FLAGS_FORCEAPPLY = 0x20,  // 0x20
/*line: 545*/   ICMP6_RR_FLAGS_SPECSITE = 0x10,  // 0x10
/*line: 546*/   ICMP6_RR_FLAGS_PREVDONE = 0x8,  // 0x08
};

enum macro_rpm_pco_options {
/*line: 564*/   RPM_PCO_ADD = 0x1,  // 1
/*line: 565*/   RPM_PCO_CHANGE = 0x2,  // 2
/*line: 566*/   RPM_PCO_SETGLOBAL = 0x3,  // 3
/*line: 567*/   RPM_PCO_MAX = 0x4,  // 4
};

enum macro_icmp6_ra_flags {
/*line: 579*/   ICMP6_RR_PCOUSE_RAFLAGS_ONLINK = 0x80,  // 0x80
/*line: 580*/   ICMP6_RR_PCOUSE_RAFLAGS_AUTO = 0x40,  // 0x40
/*line: 586*/   ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME = 0x80,  // 0x80
/*line: 587*/   ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME = 0x40,  // 0x40
/*line: 601*/   ICMP6_RR_RESULT_FLAGS_OOB = 0x200,  // 0x0200
/*line: 602*/   ICMP6_RR_RESULT_FLAGS_FORBIDDEN = 0x100,  // 0x0100
};

enum macro_icmpv6_ctl {
/*
 * Names for ICMP sysctl objects
 */
/*line: 694*/   ICMPV6CTL_STATS = 0x1,  // 1
/*line: 695*/   ICMPV6CTL_REDIRACCEPT = 0x2, /* accept/process redirects */ // 2
/*line: 696*/   ICMPV6CTL_REDIRTIMEOUT = 0x3, /* redirect cache time */ // 3
/*line: 700*/   ICMPV6CTL_ND6_PRUNE = 0x6,  // 6
/*line: 701*/   ICMPV6CTL_ND6_DELAY = 0x8,  // 8
/*line: 702*/   ICMPV6CTL_ND6_UMAXTRIES = 0x9,  // 9
/*line: 703*/   ICMPV6CTL_ND6_MMAXTRIES = 0xa,  // 10
/*line: 704*/   ICMPV6CTL_ND6_USELOOPBACK = 0xb,  // 11
/*#define ICMPV6CTL_ND6_PROXYALL	12	obsoleted, do not reuse here */
/*line: 706*/   ICMPV6CTL_NODEINFO = 0xd,  // 13
/*line: 707*/   ICMPV6CTL_ERRPPSLIMIT = 0xe, /* ICMPv6 error pps limitation */ // 14
/*line: 708*/   ICMPV6CTL_ND6_MAXNUDHINT = 0xf,  // 15
/*line: 709*/   ICMPV6CTL_MTUDISC_HIWAT = 0x10,  // 16
/*line: 710*/   ICMPV6CTL_MTUDISC_LOWAT = 0x11,  // 17
/*line: 711*/   ICMPV6CTL_ND6_DEBUG = 0x12,  // 18
/*line: 712*/   ICMPV6CTL_ND6_DRLIST = 0x13,  // 19
/*line: 713*/   ICMPV6CTL_ND6_PRLIST = 0x14,  // 20
/*line: 714*/   ICMPV6CTL_MLD_MAXSRCFILTER = 0x15,  // 21
/*line: 715*/   ICMPV6CTL_MLD_SOMAXSRC = 0x16,  // 22
/*line: 716*/   ICMPV6CTL_MLD_VERSION = 0x17,  // 23
/*line: 717*/   ICMPV6CTL_ND6_MAXQLEN = 0x18,  // 24
/*line: 718*/   ICMPV6CTL_ND6_ACCEPT_6TO4 = 0x19,  // 25
/*line: 719*/   ICMPV6CTL_ND6_OPTIMISTIC_DAD = 0x1a, /* RFC 4429 */ // 26
/*line: 720*/   ICMPV6CTL_ERRPPSLIMIT_RANDOM_INCR = 0x1b,  // 27
/*line: 721*/   ICMPV6CTL_MAXID = 0x1c,  // 28
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 114
// #define icmp6_data32 icmp6_dataun.icmp6_un_data32

// Line: 115
// #define icmp6_data16 icmp6_dataun.icmp6_un_data16

// Line: 116
// #define icmp6_data8 icmp6_dataun.icmp6_un_data8

// Line: 117
// #define icmp6_pptr icmp6_data32[0]

// Line: 118
// #define icmp6_mtu icmp6_data32[0]

// Line: 119
// #define icmp6_id icmp6_data16[0]

// Line: 120
// #define icmp6_seq icmp6_data16[1]

// Line: 121
// #define icmp6_maxdelay icmp6_data16[0]

// Line: 212
// #define mld6_hdr mld_hdr

// Line: 213
// #define mld6_type mld_type

// Line: 214
// #define mld6_code mld_code

// Line: 215
// #define mld6_cksum mld_cksum

// Line: 216
// #define mld6_maxdelay mld_maxdelay

// Line: 217
// #define mld6_reserved mld_reserved

// Line: 218
// #define mld6_addr mld_addr

// Line: 221
// #define mld_type mld_icmp6_hdr.icmp6_type

// Line: 222
// #define mld_code mld_icmp6_hdr.icmp6_code

// Line: 223
// #define mld_cksum mld_icmp6_hdr.icmp6_cksum

// Line: 224
// #define mld_maxdelay mld_icmp6_hdr.icmp6_data16[0]

// Line: 225
// #define mld_reserved mld_icmp6_hdr.icmp6_data16[1]

// Line: 226
// #define mld_v2_reserved mld_icmp6_hdr.icmp6_data16[0]

// Line: 227
// #define mld_v2_numrecs mld_icmp6_hdr.icmp6_data16[1]

// Line: 242
// #define nd_rs_type nd_rs_hdr.icmp6_type

// Line: 243
// #define nd_rs_code nd_rs_hdr.icmp6_code

// Line: 244
// #define nd_rs_cksum nd_rs_hdr.icmp6_cksum

// Line: 245
// #define nd_rs_reserved nd_rs_hdr.icmp6_data32[0]

// Line: 254
// #define nd_ra_type nd_ra_hdr.icmp6_type

// Line: 255
// #define nd_ra_code nd_ra_hdr.icmp6_code

// Line: 256
// #define nd_ra_cksum nd_ra_hdr.icmp6_cksum

// Line: 257
// #define nd_ra_curhoplimit nd_ra_hdr.icmp6_data8[0]

// Line: 258
// #define nd_ra_flags_reserved nd_ra_hdr.icmp6_data8[1]

// Line: 271
// #define nd_ra_router_lifetime nd_ra_hdr.icmp6_data16[1]

// Line: 279
// #define nd_ns_type nd_ns_hdr.icmp6_type

// Line: 280
// #define nd_ns_code nd_ns_hdr.icmp6_code

// Line: 281
// #define nd_ns_cksum nd_ns_hdr.icmp6_cksum

// Line: 282
// #define nd_ns_reserved nd_ns_hdr.icmp6_data32[0]

// Line: 290
// #define nd_na_type nd_na_hdr.icmp6_type

// Line: 291
// #define nd_na_code nd_na_hdr.icmp6_code

// Line: 292
// #define nd_na_cksum nd_na_hdr.icmp6_cksum

// Line: 293
// #define nd_na_flags_reserved nd_na_hdr.icmp6_data32[0]

// Line: 313
// #define nd_rd_type nd_rd_hdr.icmp6_type

// Line: 314
// #define nd_rd_code nd_rd_hdr.icmp6_code

// Line: 315
// #define nd_rd_cksum nd_rd_hdr.icmp6_cksum

// Line: 316
// #define nd_rd_reserved nd_rd_hdr.icmp6_data32[0]

// Line: 438
// #define ND_OPT_PVD_MIN_LENGTH offsetof(struct nd_opt_pvd, nd_opt_pvd_id)

// Line: 468
// #define ni_type icmp6_ni_hdr.icmp6_type

// Line: 469
// #define ni_code icmp6_ni_hdr.icmp6_code

// Line: 470
// #define ni_cksum icmp6_ni_hdr.icmp6_cksum

// Line: 471
// #define ni_qtype icmp6_ni_hdr.icmp6_data16[0]

// Line: 472
// #define ni_flags icmp6_ni_hdr.icmp6_data16[1]

// Line: 548
// #define rr_type rr_hdr.icmp6_type

// Line: 549
// #define rr_code rr_hdr.icmp6_code

// Line: 550
// #define rr_cksum rr_hdr.icmp6_cksum

// Line: 551
// #define rr_seqnum rr_hdr.icmp6_data32[0]

// Line: 662
// #define icp6s_odst_unreach_noroute icp6s_outerrhist.icp6errs_dst_unreach_noroute

// Line: 664
// #define icp6s_odst_unreach_admin icp6s_outerrhist.icp6errs_dst_unreach_admin

// Line: 665
// #define icp6s_odst_unreach_beyondscope icp6s_outerrhist.icp6errs_dst_unreach_beyondscope

// Line: 667
// #define icp6s_odst_unreach_addr icp6s_outerrhist.icp6errs_dst_unreach_addr

// Line: 668
// #define icp6s_odst_unreach_noport icp6s_outerrhist.icp6errs_dst_unreach_noport

// Line: 669
// #define icp6s_opacket_too_big icp6s_outerrhist.icp6errs_packet_too_big

// Line: 670
// #define icp6s_otime_exceed_transit icp6s_outerrhist.icp6errs_time_exceed_transit

// Line: 672
// #define icp6s_otime_exceed_reassembly icp6s_outerrhist.icp6errs_time_exceed_reassembly

// Line: 674
// #define icp6s_oparamprob_header icp6s_outerrhist.icp6errs_paramprob_header

// Line: 675
// #define icp6s_oparamprob_nextheader icp6s_outerrhist.icp6errs_paramprob_nextheader

// Line: 677
// #define icp6s_oparamprob_option icp6s_outerrhist.icp6errs_paramprob_option

// Line: 678
// #define icp6s_oredirect icp6s_outerrhist.icp6errs_redirect

// Line: 679
// #define icp6s_ounknown icp6s_outerrhist.icp6errs_unknown

