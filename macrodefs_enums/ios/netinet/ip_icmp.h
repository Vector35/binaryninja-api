// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/ip_icmp.h

// Depends on identifiers
enum macro_icmp_minlen {
/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enough to contain the returned ip header.
 * Only then can we do the check to see if 64 bits of packet
 * data have been returned, since we need to check the returned
 * ip header length.
 */
/*line: 155*/   ICMP_MINLEN = 0x8, /* abs minimum */ // 8
/*line: 157*/   ICMP_MASKLEN = 0xc, /* address mask */ // 12
/*line: 158*/   ICMP_ADVLENMIN = 0x10, /* min */ // (8+sizeof(structip)+8)
};

enum macro_icmp_types {
/*
 * Definition of type and code field values.
 */
/*line: 170*/   ICMP_ECHOREPLY = 0x0, /* echo reply */ // 0
/*line: 171*/   ICMP_UNREACH = 0x3, /* dest unreachable, codes: */ // 3
/*line: 172*/   ICMP_UNREACH_NET = 0x0, /* bad net */ // 0
/*line: 173*/   ICMP_UNREACH_HOST = 0x1, /* bad host */ // 1
/*line: 174*/   ICMP_UNREACH_PROTOCOL = 0x2, /* bad protocol */ // 2
/*line: 175*/   ICMP_UNREACH_PORT = 0x3, /* bad port */ // 3
/*line: 176*/   ICMP_UNREACH_NEEDFRAG = 0x4, /* IP_DF caused drop */ // 4
/*line: 177*/   ICMP_UNREACH_SRCFAIL = 0x5, /* src route failed */ // 5
/*line: 178*/   ICMP_UNREACH_NET_UNKNOWN = 0x6, /* unknown net */ // 6
/*line: 179*/   ICMP_UNREACH_HOST_UNKNOWN = 0x7, /* unknown host */ // 7
/*line: 180*/   ICMP_UNREACH_ISOLATED = 0x8, /* src host isolated */ // 8
/*line: 181*/   ICMP_UNREACH_NET_PROHIB = 0x9, /* prohibited access */ // 9
/*line: 182*/   ICMP_UNREACH_HOST_PROHIB = 0xa, /* ditto */ // 10
/*line: 183*/   ICMP_UNREACH_TOSNET = 0xb, /* bad tos for net */ // 11
/*line: 184*/   ICMP_UNREACH_TOSHOST = 0xc, /* bad tos for host */ // 12
/*line: 185*/   ICMP_UNREACH_FILTER_PROHIB = 0xd, /* admin prohib */ // 13
/*line: 186*/   ICMP_UNREACH_HOST_PRECEDENCE = 0xe, /* host prec vio. */ // 14
/*line: 187*/   ICMP_UNREACH_PRECEDENCE_CUTOFF = 0xf, /* prec cutoff */ // 15
/*line: 188*/   ICMP_SOURCEQUENCH = 0x4, /* packet lost, slow down */ // 4
/*line: 189*/   ICMP_REDIRECT = 0x5, /* shorter route, codes: */ // 5
/*line: 190*/   ICMP_REDIRECT_NET = 0x0, /* for network */ // 0
/*line: 191*/   ICMP_REDIRECT_HOST = 0x1, /* for host */ // 1
/*line: 192*/   ICMP_REDIRECT_TOSNET = 0x2, /* for tos and net */ // 2
/*line: 193*/   ICMP_REDIRECT_TOSHOST = 0x3, /* for tos and host */ // 3
/*line: 194*/   ICMP_ALTHOSTADDR = 0x6, /* alternate host address */ // 6
/*line: 195*/   ICMP_ECHO = 0x8, /* echo service */ // 8
/*line: 196*/   ICMP_ROUTERADVERT = 0x9, /* router advertisement */ // 9
/*line: 197*/   ICMP_ROUTERADVERT_NORMAL = 0x0, /* normal advertisement */ // 0
/*line: 198*/   ICMP_ROUTERADVERT_NOROUTE_COMMON = 0x10, /* selective routing */ // 16
/*line: 199*/   ICMP_ROUTERSOLICIT = 0xa, /* router solicitation */ // 10
/*line: 200*/   ICMP_TIMXCEED = 0xb, /* time exceeded, code: */ // 11
/*line: 201*/   ICMP_TIMXCEED_INTRANS = 0x0, /* ttl==0 in transit */ // 0
/*line: 202*/   ICMP_TIMXCEED_REASS = 0x1, /* ttl==0 in reass */ // 1
/*line: 203*/   ICMP_PARAMPROB = 0xc, /* ip header bad */ // 12
/*line: 204*/   ICMP_PARAMPROB_ERRATPTR = 0x0, /* error at param ptr */ // 0
/*line: 205*/   ICMP_PARAMPROB_OPTABSENT = 0x1, /* req. opt. absent */ // 1
/*line: 206*/   ICMP_PARAMPROB_LENGTH = 0x2, /* bad length */ // 2
/*line: 207*/   ICMP_TSTAMP = 0xd, /* timestamp request */ // 13
/*line: 208*/   ICMP_TSTAMPREPLY = 0xe, /* timestamp reply */ // 14
/*line: 209*/   ICMP_IREQ = 0xf, /* information request */ // 15
/*line: 210*/   ICMP_IREQREPLY = 0x10, /* information reply */ // 16
/*line: 211*/   ICMP_MASKREQ = 0x11, /* address mask request */ // 17
/*line: 212*/   ICMP_MASKREPLY = 0x12, /* address mask reply */ // 18
/*line: 213*/   ICMP_TRACEROUTE = 0x1e, /* traceroute */ // 30
/*line: 214*/   ICMP_DATACONVERR = 0x1f, /* data conversion error */ // 31
/*line: 215*/   ICMP_MOBILE_REDIRECT = 0x20, /* mobile host redirect */ // 32
/*line: 216*/   ICMP_IPV6_WHEREAREYOU = 0x21, /* IPv6 where-are-you */ // 33
/*line: 217*/   ICMP_IPV6_IAMHERE = 0x22, /* IPv6 i-am-here */ // 34
/*line: 218*/   ICMP_MOBILE_REGREQUEST = 0x23, /* mobile registration req */ // 35
/*line: 219*/   ICMP_MOBILE_REGREPLY = 0x24, /* mobile registration reply */ // 36
/*line: 220*/   ICMP_SKIP = 0x27, /* SKIP */ // 39
/*line: 221*/   ICMP_PHOTURIS = 0x28, /* Photuris */ // 40
/*line: 222*/   ICMP_PHOTURIS_UNKNOWN_INDEX = 0x1, /* unknown sec index */ // 1
/*line: 223*/   ICMP_PHOTURIS_AUTH_FAILED = 0x2, /* auth failed */ // 2
/*line: 224*/   ICMP_PHOTURIS_DECRYPT_FAILED = 0x3, /* decrypt failed */ // 3
};

enum macro_icmp_max_type {
/*line: 226*/   ICMP_MAXTYPE = 0x28,  // 40
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 114
// #define icmp_pptr icmp_hun.ih_pptr

// Line: 115
// #define icmp_gwaddr icmp_hun.ih_gwaddr

// Line: 116
// #define icmp_id icmp_hun.ih_idseq.icd_id

// Line: 117
// #define icmp_seq icmp_hun.ih_idseq.icd_seq

// Line: 118
// #define icmp_void icmp_hun.ih_void

// Line: 119
// #define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void

// Line: 120
// #define icmp_nextmtu icmp_hun.ih_pmtu.ipm_nextmtu

// Line: 121
// #define icmp_num_addrs icmp_hun.ih_rtradv.irt_num_addrs

// Line: 122
// #define icmp_wpa icmp_hun.ih_rtradv.irt_wpa

// Line: 123
// #define icmp_lifetime icmp_hun.ih_rtradv.irt_lifetime

// Line: 138
// #define icmp_otime icmp_dun.id_ts.its_otime

// Line: 139
// #define icmp_rtime icmp_dun.id_ts.its_rtime

// Line: 140
// #define icmp_ttime icmp_dun.id_ts.its_ttime

// Line: 141
// #define icmp_ip icmp_dun.id_ip.idi_ip

// Line: 142
// #define icmp_radv icmp_dun.id_radv

// Line: 143
// #define icmp_mask icmp_dun.id_mask

// Line: 144
// #define icmp_data icmp_dun.id_data

// Line: 156
// #define ICMP_TSLEN (8 + 3 * sizeof (n_time))

