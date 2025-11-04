// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet6/in6.h

enum macro_ipv6_ports {
/*
 * Local port number conventions:
 *
 * Ports < IPPORT_RESERVED are reserved for privileged processes (e.g. root),
 * unless a kernel is compiled with IPNOPRIVPORTS defined.
 *
 * When a user does a bind(2) or connect(2) with a port number of zero,
 * a non-conflicting local port address is chosen.
 *
 * The default range is IPPORT_ANONMIN to IPPORT_ANONMAX, although
 * that is settable by sysctl(3); net.inet.ip.anonportmin and
 * net.inet.ip.anonportmax respectively.
 *
 * A user may set the IPPROTO_IP option IP_PORTRANGE to change this
 * default assignment range.
 *
 * The value IP_PORTRANGE_DEFAULT causes the default behavior.
 *
 * The value IP_PORTRANGE_HIGH is the same as IP_PORTRANGE_DEFAULT,
 * and exists only for FreeBSD compatibility purposes.
 *
 * The value IP_PORTRANGE_LOW changes the range to the "low" are
 * that is (by convention) restricted to privileged processes.
 * This convention is based on "vouchsafe" principles only.
 * It is only secure if you trust the remote host to restrict these ports.
 * The range is IPPORT_RESERVEDMIN to IPPORT_RESERVEDMAX.
 */
/*line: 142*/   IPV6PORT_RESERVED = 0x400,  // 1024
/*line: 143*/   IPV6PORT_ANONMIN = 0xc000,  // 49152
/*line: 144*/   IPV6PORT_ANONMAX = 0xffff,  // 65535
/*line: 145*/   IPV6PORT_RESERVEDMIN = 0x258,  // 600
/*line: 146*/   IPV6PORT_RESERVEDMAX = 0x3ff,  // (IPV6PORT_RESERVED-1)
};

enum macro_inet6_addrstrlen {
/*line: 162*/   INET6_ADDRSTRLEN = 0x2e,  // 46
};

enum macro_ipv6_scope {
/*
 * KAME Scope Values
 */
/*line: 281*/   __IPV6_ADDR_SCOPE_NODELOCAL = 0x1,  // 0x01
/*line: 282*/   __IPV6_ADDR_SCOPE_INTFACELOCAL = 0x1,  // 0x01
/*line: 283*/   __IPV6_ADDR_SCOPE_LINKLOCAL = 0x2,  // 0x02
/*line: 284*/   __IPV6_ADDR_SCOPE_SITELOCAL = 0x5,  // 0x05
/*line: 285*/   __IPV6_ADDR_SCOPE_ORGLOCAL = 0x8, /* just used in this file */ // 0x08
/*line: 286*/   __IPV6_ADDR_SCOPE_GLOBAL = 0xe,  // 0x0e
};

enum macro_ipv6_mc_flags {
/*line: 304*/   IPV6_ADDR_MC_FLAGS_TRANSIENT = 0x10,  // 0x10
/*line: 305*/   IPV6_ADDR_MC_FLAGS_PREFIX = 0x20,  // 0x20
/*line: 306*/   IPV6_ADDR_MC_FLAGS_UNICAST_BASED = 0x30,  // (IPV6_ADDR_MC_FLAGS_TRANSIENT|IPV6_ADDR_MC_FLAGS_PREFIX)
};

enum macro_ipv6_socket_options {
/*line: 380*/   IPV6_SOCKOPT_RESERVED1 = 0x3, /* reserved for future use */ // 3
/*line: 382*/   IPV6_UNICAST_HOPS = 0x4, /* int; IP6 hops */ // 4
/*line: 383*/   IPV6_MULTICAST_IF = 0x9, /* u_int; set/get IP6 multicast i/f  */ // 9
/*line: 384*/   IPV6_MULTICAST_HOPS = 0xa, /* int; set/get IP6 multicast hops */ // 10
/*line: 385*/   IPV6_MULTICAST_LOOP = 0xb, /* u_int; set/get IP6 mcast loopback */ // 11
/*line: 386*/   IPV6_JOIN_GROUP = 0xc, /* ip6_mreq; join a group membership */ // 12
/*line: 387*/   IPV6_LEAVE_GROUP = 0xd, /* ip6_mreq; leave a group membership */ // 13
/*line: 390*/   IPV6_PORTRANGE = 0xe, /* int; range to choose for unspec port */ // 14
/*line: 391*/   ICMP6_FILTER = 0x12, /* icmp6_filter; icmp6 filter */ // 18
/*line: 392*/   IPV6_2292PKTINFO = 0x13, /* bool; send/recv if, src/dst addr */ // 19
/*line: 393*/   IPV6_2292HOPLIMIT = 0x14, /* bool; hop limit */ // 20
/*line: 394*/   IPV6_2292NEXTHOP = 0x15, /* bool; next hop addr */ // 21
/*line: 395*/   IPV6_2292HOPOPTS = 0x16, /* bool; hop-by-hop option */ // 22
/*line: 396*/   IPV6_2292DSTOPTS = 0x17, /* bool; destinaion option */ // 23
/*line: 397*/   IPV6_2292RTHDR = 0x18, /* ip6_rthdr: routing header */ // 24
/* buf/cmsghdr; set/get IPv6 options [obsoleted by RFC3542] */
/*line: 400*/   IPV6_2292PKTOPTIONS = 0x19,  // 25
/*line: 412*/   IPV6_CHECKSUM = 0x1a, /* int; checksum offset for raw socket */ // 26
/*line: 414*/   IPV6_V6ONLY = 0x1b, /* bool; only bind INET6 at wildcard bind */ // 27
/*line: 416*/   IPV6_BINDV6ONLY = 0x1b,  // IPV6_V6ONLY
/*line: 420*/   IPV6_IPSEC_POLICY = 0x1c, /* struct; get/set security policy */ // 28
/*line: 422*/   IPV6_FAITH = 0x1d, /* deprecated */ // 29
/*line: 425*/   IPV6_FW_ADD = 0x1e, /* add a firewall rule to chain */ // 30
/*line: 426*/   IPV6_FW_DEL = 0x1f, /* delete a firewall rule from chain */ // 31
/*line: 427*/   IPV6_FW_FLUSH = 0x20, /* flush firewall rule chain */ // 32
/*line: 428*/   IPV6_FW_ZERO = 0x21, /* clear single/all firewall counter(s) */ // 33
/*line: 429*/   IPV6_FW_GET = 0x22, /* get entire firewall rule chain */ // 34
/*
 * APPLE: NOTE the value of those 2 options is kept unchanged from
 *   previous version of darwin/OS X for binary compatibility reasons
 *   and differ from FreeBSD (values 57 and 61). See below.
 */
/*line: 437*/   IPV6_RECVTCLASS = 0x23, /* bool; recv traffic class values */ // 35
/*line: 438*/   IPV6_TCLASS = 0x24, /* int; send traffic class value */ // 36
};

enum macro_ipv6_bound_if {
/*line: 505*/   IPV6_BOUND_IF = 0x7d, /* int; set/get bound interface */ // 125
};

enum macro_ipv6_options {
/* to define items, should talk with KAME guys first, for *BSD compatibility */
/*line: 509*/   IPV6_RTHDR_LOOSE = 0x0, /* this hop need not be a neighbor. */ // 0
/*line: 510*/   IPV6_RTHDR_STRICT = 0x1, /* this hop must be a neighbor. */ // 1
/*line: 511*/   IPV6_RTHDR_TYPE_0 = 0x0, /* IPv6 routing header type 0 */ // 0
/*
 * Defaults and limits for options
 */
/*line: 516*/   IPV6_DEFAULT_MULTICAST_HOPS = 0x1, /* normally limit m'casts to 1 hop  */ // 1
/*line: 517*/   IPV6_DEFAULT_MULTICAST_LOOP = 0x1, /* normally hear sends if a member  */ // 1
/*
 * The im6o_membership vector for each socket is now dynamically allocated at
 * run-time, bounded by USHRT_MAX, and is reallocated when needed, sized
 * according to a power-of-two increment.
 */
/*line: 524*/   IPV6_MIN_MEMBERSHIPS = 0x1f,  // 31
/*line: 525*/   IPV6_MAX_MEMBERSHIPS = 0xfff,  // 4095
};

enum macro_ipv6_multicast_filter_limits {
/*
 * Default resource limits for IPv6 multicast source filtering.
 * These may be modified by sysctl.
 */
/*line: 531*/   IPV6_MAX_GROUP_SRC_FILTER = 0x200, /* sources per group */ // 512
/*line: 532*/   IPV6_MAX_SOCK_SRC_FILTER = 0x80, /* sources per socket/group */ // 128
};

enum macro_ipv6_portrange {
/*
 * Argument for IPV6_PORTRANGE:
 * - which range to search when port is unspecified at bind() or connect()
 */
/*line: 562*/   IPV6_PORTRANGE_DEFAULT = 0x0, /* default range */ // 0
/*line: 563*/   IPV6_PORTRANGE_HIGH = 0x1, /* "high" - request firewall bypass */ // 1
/*line: 564*/   IPV6_PORTRANGE_LOW = 0x2, /* "low" - vouchsafe security */ // 2
};

enum macro_ipv6_protocol {
/*
 * Definitions for inet6 sysctl operations.
 *
 * Third level is protocol number.
 * Fourth level is desired variable within that protocol.
 */
/*line: 572*/   IPV6PROTO_MAXID = 0x68, /* don't list to IPV6PROTO_MAX */ // (IPPROTO_PIM+1)
};

enum macro_ipv6ctl {
/*
 * Names for IP sysctl objects
 */
/*line: 577*/   IPV6CTL_FORWARDING = 0x1, /* act as router */ // 1
/*line: 578*/   IPV6CTL_SENDREDIRECTS = 0x2, /* may send redirects when forwarding */ // 2
/*line: 579*/   IPV6CTL_DEFHLIM = 0x3, /* default Hop-Limit */ // 3
/*line: 583*/   IPV6CTL_FORWSRCRT = 0x5, /* forward source-routed dgrams */ // 5
/*line: 584*/   IPV6CTL_STATS = 0x6, /* stats */ // 6
/*line: 585*/   IPV6CTL_MRTSTATS = 0x7, /* multicast forwarding stats */ // 7
/*line: 586*/   IPV6CTL_MRTPROTO = 0x8, /* multicast routing protocol */ // 8
/*line: 587*/   IPV6CTL_MAXFRAGPACKETS = 0x9, /* max packets reassembly queue */ // 9
/*line: 588*/   IPV6CTL_SOURCECHECK = 0xa, /* verify source route and intf */ // 10
/*line: 589*/   IPV6CTL_SOURCECHECK_LOGINT = 0xb, /* minimume logging interval */ // 11
/*line: 590*/   IPV6CTL_ACCEPT_RTADV = 0xc,  // 12
/*line: 591*/   IPV6CTL_KEEPFAITH = 0xd, /* deprecated */ // 13
/*line: 592*/   IPV6CTL_LOG_INTERVAL = 0xe,  // 14
/*line: 593*/   IPV6CTL_HDRNESTLIMIT = 0xf,  // 15
/*line: 594*/   IPV6CTL_DAD_COUNT = 0x10,  // 16
/*line: 595*/   IPV6CTL_AUTO_FLOWLABEL = 0x11,  // 17
/*line: 596*/   IPV6CTL_DEFMCASTHLIM = 0x12,  // 18
/*line: 597*/   IPV6CTL_GIF_HLIM = 0x13, /* default HLIM for gif encap packet */ // 19
/*line: 598*/   IPV6CTL_KAME_VERSION = 0x14,  // 20
/*line: 599*/   IPV6CTL_USE_DEPRECATED = 0x15, /* use deprec addr (RFC2462 5.5.4) */ // 21
/*line: 600*/   IPV6CTL_RR_PRUNE = 0x16, /* walk timer for router renumbering */ // 22
/*line: 604*/   IPV6CTL_V6ONLY = 0x18,  // 24
/*line: 605*/   IPV6CTL_RTEXPIRE = 0x19, /* cloned route expiration time */ // 25
/*line: 606*/   IPV6CTL_RTMINEXPIRE = 0x1a, /* min value for expiration time */ // 26
/*line: 607*/   IPV6CTL_RTMAXCACHE = 0x1b, /* trigger level for dynamic expire */ // 27
/*line: 609*/   IPV6CTL_USETEMPADDR = 0x20, /* use temporary addresses [RFC 4941] */ // 32
/*line: 610*/   IPV6CTL_TEMPPLTIME = 0x21, /* preferred lifetime for tmpaddrs */ // 33
/*line: 611*/   IPV6CTL_TEMPVLTIME = 0x22, /* valid lifetime for tmpaddrs */ // 34
/*line: 612*/   IPV6CTL_AUTO_LINKLOCAL = 0x23, /* automatic link-local addr assign */ // 35
/*line: 613*/   IPV6CTL_RIP6STATS = 0x24, /* raw_ip6 stats */ // 36
/*line: 614*/   IPV6CTL_PREFER_TEMPADDR = 0x25, /* prefer temporary addr as src */ // 37
/*line: 615*/   IPV6CTL_ADDRCTLPOLICY = 0x26, /* get/set address selection policy */ // 38
/*line: 616*/   IPV6CTL_USE_DEFAULTZONE = 0x27, /* use default scope zone */ // 39
/*line: 618*/   IPV6CTL_MAXFRAGS = 0x29, /* max fragments */ // 41
/*line: 619*/   IPV6CTL_MCAST_PMTU = 0x2c, /* enable pMTU discovery for mcast? */ // 44
/*line: 621*/   IPV6CTL_NEIGHBORGCTHRESH = 0x2e,  // 46
/*line: 622*/   IPV6CTL_MAXIFPREFIXES = 0x2f,  // 47
/*line: 623*/   IPV6CTL_MAXIFDEFROUTERS = 0x30,  // 48
/*line: 624*/   IPV6CTL_MAXDYNROUTES = 0x31,  // 49
/*line: 625*/   ICMPV6CTL_ND6_ONLINKNSRFC4861 = 0x32,  // 50
/*line: 626*/   IPV6CTL_ULA_USETEMPADDR = 0x33,  // 51
};

enum macro_ipv6ctl_maxid {
/* to define items, should talk with KAME guys first, for *BSD compatibility */
/*line: 631*/   IPV6CTL_MAXID = 0x33,  // 51
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 160
// #define s6_addr __u6_addr.__u6_addr8

// Line: 185
// #define IN6ADDR_ANY_INIT {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}

// Line: 188
// #define IN6ADDR_LOOPBACK_INIT {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}

// Line: 192
// #define IN6ADDR_NODELOCAL_ALLNODES_INIT {{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}

// Line: 195
// #define IN6ADDR_INTFACELOCAL_ALLNODES_INIT {{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}

// Line: 198
// #define IN6ADDR_LINKLOCAL_ALLNODES_INIT {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}

// Line: 201
// #define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}

// Line: 204
// #define IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT {{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 }}}

// Line: 207
// #define IN6ADDR_V4MAPPED_INIT {{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
// 	    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}}

// Line: 210
// #define IN6ADDR_MULTICAST_PREFIX IN6MASK8

