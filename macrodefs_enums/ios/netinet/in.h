// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/in.h

// Depends on identifiers
enum macro_ip_protocols {
/*
 * Protocols (RFC 1700)
 */
/*line: 97*/    IPPROTO_IP = 0x0, /* dummy for IP */ // 0
/*line: 99*/    IPPROTO_HOPOPTS = 0x0, /* IP6 hop-by-hop options */ // 0
/*line: 101*/   IPPROTO_ICMP = 0x1, /* control message protocol */ // 1
/*line: 103*/   IPPROTO_IGMP = 0x2, /* group mgmt protocol */ // 2
/*line: 104*/   IPPROTO_GGP = 0x3, /* gateway^2 (deprecated) */ // 3
/*line: 105*/   IPPROTO_IPV4 = 0x4, /* IPv4 encapsulation */ // 4
/*line: 106*/   IPPROTO_IPIP = 0x4, /* for compatibility */ // IPPROTO_IPV4
/*line: 108*/   IPPROTO_TCP = 0x6, /* tcp */ // 6
/*line: 110*/   IPPROTO_ST = 0x7, /* Stream protocol II */ // 7
/*line: 111*/   IPPROTO_EGP = 0x8, /* exterior gateway protocol */ // 8
/*line: 112*/   IPPROTO_PIGP = 0x9, /* private interior gateway */ // 9
/*line: 113*/   IPPROTO_RCCMON = 0xa, /* BBN RCC Monitoring */ // 10
/*line: 114*/   IPPROTO_NVPII = 0xb, /* network voice protocol*/ // 11
/*line: 115*/   IPPROTO_PUP = 0xc, /* pup */ // 12
/*line: 116*/   IPPROTO_ARGUS = 0xd, /* Argus */ // 13
/*line: 117*/   IPPROTO_EMCON = 0xe, /* EMCON */ // 14
/*line: 118*/   IPPROTO_XNET = 0xf, /* Cross Net Debugger */ // 15
/*line: 119*/   IPPROTO_CHAOS = 0x10, /* Chaos*/ // 16
/*line: 121*/   IPPROTO_UDP = 0x11, /* user datagram protocol */ // 17
/*line: 123*/   IPPROTO_MUX = 0x12, /* Multiplexing */ // 18
/*line: 124*/   IPPROTO_MEAS = 0x13, /* DCN Measurement Subsystems */ // 19
/*line: 125*/   IPPROTO_HMP = 0x14, /* Host Monitoring */ // 20
/*line: 126*/   IPPROTO_PRM = 0x15, /* Packet Radio Measurement */ // 21
/*line: 127*/   IPPROTO_IDP = 0x16, /* xns idp */ // 22
/*line: 128*/   IPPROTO_TRUNK1 = 0x17, /* Trunk-1 */ // 23
/*line: 129*/   IPPROTO_TRUNK2 = 0x18, /* Trunk-2 */ // 24
/*line: 130*/   IPPROTO_LEAF1 = 0x19, /* Leaf-1 */ // 25
/*line: 131*/   IPPROTO_LEAF2 = 0x1a, /* Leaf-2 */ // 26
/*line: 132*/   IPPROTO_RDP = 0x1b, /* Reliable Data */ // 27
/*line: 133*/   IPPROTO_IRTP = 0x1c, /* Reliable Transaction */ // 28
/*line: 134*/   IPPROTO_TP = 0x1d, /* tp-4 w/ class negotiation */ // 29
/*line: 135*/   IPPROTO_BLT = 0x1e, /* Bulk Data Transfer */ // 30
/*line: 136*/   IPPROTO_NSP = 0x1f, /* Network Services */ // 31
/*line: 137*/   IPPROTO_INP = 0x20, /* Merit Internodal */ // 32
/*line: 138*/   IPPROTO_SEP = 0x21, /* Sequential Exchange */ // 33
/*line: 139*/   IPPROTO_3PC = 0x22, /* Third Party Connect */ // 34
/*line: 140*/   IPPROTO_IDPR = 0x23, /* InterDomain Policy Routing */ // 35
/*line: 141*/   IPPROTO_XTP = 0x24, /* XTP */ // 36
/*line: 142*/   IPPROTO_DDP = 0x25, /* Datagram Delivery */ // 37
/*line: 143*/   IPPROTO_CMTP = 0x26, /* Control Message Transport */ // 38
/*line: 144*/   IPPROTO_TPXX = 0x27, /* TP++ Transport */ // 39
/*line: 145*/   IPPROTO_IL = 0x28, /* IL transport protocol */ // 40
/*line: 147*/   IPPROTO_IPV6 = 0x29, /* IP6 header */ // 41
/*line: 149*/   IPPROTO_SDRP = 0x2a, /* Source Demand Routing */ // 42
/*line: 150*/   IPPROTO_ROUTING = 0x2b, /* IP6 routing header */ // 43
/*line: 151*/   IPPROTO_FRAGMENT = 0x2c, /* IP6 fragmentation header */ // 44
/*line: 152*/   IPPROTO_IDRP = 0x2d, /* InterDomain Routing*/ // 45
/*line: 153*/   IPPROTO_RSVP = 0x2e, /* resource reservation */ // 46
/*line: 154*/   IPPROTO_GRE = 0x2f, /* General Routing Encap. */ // 47
/*line: 155*/   IPPROTO_MHRP = 0x30, /* Mobile Host Routing */ // 48
/*line: 156*/   IPPROTO_BHA = 0x31, /* BHA */ // 49
/*line: 157*/   IPPROTO_ESP = 0x32, /* IP6 Encap Sec. Payload */ // 50
/*line: 158*/   IPPROTO_AH = 0x33, /* IP6 Auth Header */ // 51
/*line: 159*/   IPPROTO_INLSP = 0x34, /* Integ. Net Layer Security */ // 52
/*line: 160*/   IPPROTO_SWIPE = 0x35, /* IP with encryption */ // 53
/*line: 161*/   IPPROTO_NHRP = 0x36, /* Next Hop Resolution */ // 54
/* 55-57: Unassigned */
/*line: 163*/   IPPROTO_ICMPV6 = 0x3a, /* ICMP6 */ // 58
/*line: 164*/   IPPROTO_NONE = 0x3b, /* IP6 no next header */ // 59
/*line: 165*/   IPPROTO_DSTOPTS = 0x3c, /* IP6 destination option */ // 60
/*line: 166*/   IPPROTO_AHIP = 0x3d, /* any host internal protocol */ // 61
/*line: 167*/   IPPROTO_CFTP = 0x3e, /* CFTP */ // 62
/*line: 168*/   IPPROTO_HELLO = 0x3f, /* "hello" routing protocol */ // 63
/*line: 169*/   IPPROTO_SATEXPAK = 0x40, /* SATNET/Backroom EXPAK */ // 64
/*line: 170*/   IPPROTO_KRYPTOLAN = 0x41, /* Kryptolan */ // 65
/*line: 171*/   IPPROTO_RVD = 0x42, /* Remote Virtual Disk */ // 66
/*line: 172*/   IPPROTO_IPPC = 0x43, /* Pluribus Packet Core */ // 67
/*line: 173*/   IPPROTO_ADFS = 0x44, /* Any distributed FS */ // 68
/*line: 174*/   IPPROTO_SATMON = 0x45, /* Satnet Monitoring */ // 69
/*line: 175*/   IPPROTO_VISA = 0x46, /* VISA Protocol */ // 70
/*line: 176*/   IPPROTO_IPCV = 0x47, /* Packet Core Utility */ // 71
/*line: 177*/   IPPROTO_CPNX = 0x48, /* Comp. Prot. Net. Executive */ // 72
/*line: 178*/   IPPROTO_CPHB = 0x49, /* Comp. Prot. HeartBeat */ // 73
/*line: 179*/   IPPROTO_WSN = 0x4a, /* Wang Span Network */ // 74
/*line: 180*/   IPPROTO_PVP = 0x4b, /* Packet Video Protocol */ // 75
/*line: 181*/   IPPROTO_BRSATMON = 0x4c, /* BackRoom SATNET Monitoring */ // 76
/*line: 182*/   IPPROTO_ND = 0x4d, /* Sun net disk proto (temp.) */ // 77
/*line: 183*/   IPPROTO_WBMON = 0x4e, /* WIDEBAND Monitoring */ // 78
/*line: 184*/   IPPROTO_WBEXPAK = 0x4f, /* WIDEBAND EXPAK */ // 79
/*line: 185*/   IPPROTO_EON = 0x50, /* ISO cnlp */ // 80
/*line: 186*/   IPPROTO_VMTP = 0x51, /* VMTP */ // 81
/*line: 187*/   IPPROTO_SVMTP = 0x52, /* Secure VMTP */ // 82
/*line: 188*/   IPPROTO_VINES = 0x53, /* Banyon VINES */ // 83
/*line: 189*/   IPPROTO_TTP = 0x54, /* TTP */ // 84
/*line: 190*/   IPPROTO_IGP = 0x55, /* NSFNET-IGP */ // 85
/*line: 191*/   IPPROTO_DGP = 0x56, /* dissimilar gateway prot. */ // 86
/*line: 192*/   IPPROTO_TCF = 0x57, /* TCF */ // 87
/*line: 193*/   IPPROTO_IGRP = 0x58, /* Cisco/GXS IGRP */ // 88
/*line: 194*/   IPPROTO_OSPFIGP = 0x59, /* OSPFIGP */ // 89
/*line: 195*/   IPPROTO_SRPC = 0x5a, /* Strite RPC protocol */ // 90
/*line: 196*/   IPPROTO_LARP = 0x5b, /* Locus Address Resoloution */ // 91
/*line: 197*/   IPPROTO_MTP = 0x5c, /* Multicast Transport */ // 92
/*line: 198*/   IPPROTO_AX25 = 0x5d, /* AX.25 Frames */ // 93
/*line: 199*/   IPPROTO_IPEIP = 0x5e, /* IP encapsulated in IP */ // 94
/*line: 200*/   IPPROTO_MICP = 0x5f, /* Mobile Int.ing control */ // 95
/*line: 201*/   IPPROTO_SCCSP = 0x60, /* Semaphore Comm. security */ // 96
/*line: 202*/   IPPROTO_ETHERIP = 0x61, /* Ethernet IP encapsulation */ // 97
/*line: 203*/   IPPROTO_ENCAP = 0x62, /* encapsulation header */ // 98
/*line: 204*/   IPPROTO_APES = 0x63, /* any private encr. scheme */ // 99
/*line: 205*/   IPPROTO_GMTP = 0x64, /* GMTP*/ // 100
/* 101-252: Partly Unassigned */
/*line: 207*/   IPPROTO_PIM = 0x67, /* Protocol Independent Mcast */ // 103
/*line: 208*/   IPPROTO_IPCOMP = 0x6c, /* payload compression (IPComp) */ // 108
/*line: 209*/   IPPROTO_PGM = 0x71, /* PGM */ // 113
/*line: 210*/   IPPROTO_SCTP = 0x84, /* SCTP */ // 132
/* BSD Private, local use, namespace incursion */
/*line: 213*/   IPPROTO_DIVERT = 0xfe, /* divert pseudo-protocol */ // 254
/*line: 215*/   IPPROTO_RAW = 0xff, /* raw IP packet */ // 255
/*line: 218*/   IPPROTO_MAX = 0x100,  // 256
/* last return value of *_input(), meaning "all job for this pkt is done".  */
/*line: 221*/   IPPROTO_DONE = 0x101,  // 257
};

enum macro_port_range {
/*
 * Local port number conventions:
 *
 * When a user does a bind(2) or connect(2) with a port number of zero,
 * a non-conflicting local port address is chosen.
 * The default range is IPPORT_RESERVED through
 * IPPORT_USERRESERVED, although that is settable by sysctl.
 *
 * A user may set the IPPROTO_IP option IP_PORTRANGE to change this
 * default assignment range.
 *
 * The value IP_PORTRANGE_DEFAULT causes the default behavior.
 *
 * The value IP_PORTRANGE_HIGH changes the range of candidate port numbers
 * into the "high" range.  These are reserved for client outbound connections
 * which do not want to be filtered by any firewalls.
 *
 * The value IP_PORTRANGE_LOW changes the range to the "low" are
 * that is (by convention) restricted to privileged processes.  This
 * convention is based on "vouchsafe" principles only.  It is only secure
 * if you trust the remote host to restrict these ports.
 *
 * The default range of ports and the high range can be changed by
 * sysctl(3).  (net.inet.ip.port{hi,low}{first,last}_auto)
 *
 * Changing those values has bad security implications if you are
 * using a a stateless firewall that is allowing packets outside of that
 * range in order to allow transparent outgoing connections.
 *
 * Such a firewall configuration will generally depend on the use of these
 * default values.  If you change them, you may find your Security
 * Administrator looking for you with a heavy object.
 *
 * For a slightly more orthodox text view on this:
 *
 *            ftp://ftp.isi.edu/in-notes/iana/assignments/port-numbers
 *
 *    port numbers are divided into three ranges:
 *
 *                0 -  1023 Well Known Ports
 *             1024 - 49151 Registered Ports
 *            49152 - 65535 Dynamic and/or Private Ports
 *
 */
/*line: 269*/   __DARWIN_IPPORT_RESERVED = 0x400,  // 1024
};

// Depends on identifiers
enum macro_ipports {
/*line: 279*/   IPPORT_RESERVED = 0x400,  // __DARWIN_IPPORT_RESERVED
/*line: 281*/   IPPORT_USERRESERVED = 0x1388,  // 5000
};

enum macro_auto_port_range {
/*
 * Default local port range to use by setting IP_PORTRANGE_HIGH
 */
/*line: 286*/   IPPORT_HIFIRSTAUTO = 0xc000,  // 49152
/*line: 287*/   IPPORT_HILASTAUTO = 0xffff,  // 65535
};

enum macro_reserved_port_range {
/*
 * Scanning for a free reserved port return a value below IPPORT_RESERVED,
 * but higher than IPPORT_RESERVEDSTART.  Traditionally the start value was
 * 512, but that conflicts with some well-known-services that firewalls may
 * have a fit if we use.
 */
/*line: 295*/   IPPORT_RESERVEDSTART = 0x258,  // 600
};

// Depends on identifiers
enum macro_ip_address_flags {
/*
 * Definitions of bits in internet address integers.
 * On subnets, the decomposition of addresses to host and net parts
 * is done according to subnet mask, not the masks here.
 */
/*line: 310*/   INADDR_ANY = 0x0,  // (u_int32_t)0x00000000
/*line: 311*/   INADDR_BROADCAST = 0xffffffff, /* must be masked */ // (u_int32_t)0xffffffff
};

enum macro_ip_address_class {
/*line: 315*/   IN_CLASSA_NET = 0xff000000,  // 0xff000000
/*line: 316*/   IN_CLASSA_NSHIFT = 0x18,  // 24
/*line: 317*/   IN_CLASSA_HOST = 0xffffff,  // 0x00ffffff
/*line: 318*/   IN_CLASSA_MAX = 0x80,  // 128
/*line: 321*/   IN_CLASSB_NET = 0xffff0000,  // 0xffff0000
/*line: 322*/   IN_CLASSB_NSHIFT = 0x10,  // 16
/*line: 323*/   IN_CLASSB_HOST = 0xffff,  // 0x0000ffff
/*line: 324*/   IN_CLASSB_MAX = 0x10000,  // 65536
};

enum macro_ip_class {
/*line: 327*/   IN_CLASSC_NET = 0xffffff00,  // 0xffffff00
/*line: 328*/   IN_CLASSC_NSHIFT = 0x8,  // 8
/*line: 329*/   IN_CLASSC_HOST = 0xff,  // 0x000000ff
};

enum macro_classful_network {
/*line: 332*/   IN_CLASSD_NET = 0xf0000000, /* These ones aren't really */ // 0xf0000000
/*line: 333*/   IN_CLASSD_NSHIFT = 0x1c, /* net and host fields, but */ // 28
/*line: 334*/   IN_CLASSD_HOST = 0xfffffff, /* routing needn't know.    */ // 0x0fffffff
};

// Depends on identifiers
enum macro_in_addr {
/*line: 340*/   INADDR_LOOPBACK = 0x7f000001,  // (u_int32_t)0x7f000001
/*line: 342*/   INADDR_NONE = 0xffffffff, /* -1 return */ // 0xffffffff
};

// Depends on identifiers
enum macro_multicast_groups {
/*line: 344*/   INADDR_UNSPEC_GROUP = 0xe0000000, /* 224.0.0.0 */ // (u_int32_t)0xe0000000
/*line: 345*/   INADDR_ALLHOSTS_GROUP = 0xe0000001, /* 224.0.0.1 */ // (u_int32_t)0xe0000001
/*line: 346*/   INADDR_ALLRTRS_GROUP = 0xe0000002, /* 224.0.0.2 */ // (u_int32_t)0xe0000002
/*line: 347*/   INADDR_ALLRPTS_GROUP = 0xe0000016, /* 224.0.0.22, IGMPv3 */ // (u_int32_t)0xe0000016
/*line: 348*/   INADDR_CARP_GROUP = 0xe0000012, /* 224.0.0.18 */ // (u_int32_t)0xe0000012
/*line: 349*/   INADDR_PFSYNC_GROUP = 0xe00000f0, /* 224.0.0.240 */ // (u_int32_t)0xe00000f0
/*line: 350*/   INADDR_ALLMDNS_GROUP = 0xe00000fb, /* 224.0.0.251 */ // (u_int32_t)0xe00000fb
/*line: 351*/   INADDR_MAX_LOCAL_GROUP = 0xe00000ff, /* 224.0.0.255 */ // (u_int32_t)0xe00000ff
};

// Depends on identifiers
enum macro_in_linklocalnetnum {
/*line: 354*/   IN_LINKLOCALNETNUM = 0xa9fe0000, /* 169.254.0.0 */ // (u_int32_t)0xA9FE0000
};

enum macro_loopbacknet {
/*line: 368*/   IN_LOOPBACKNET = 0x7f, /* official! */ // 127
};

enum macro_inet_addrstrlen {
/*line: 386*/   INET_ADDRSTRLEN = 0x10,  // 16
};

// Depends on identifiers
enum macro_ip_socket_options {
/*
 * Options for use with [gs]etsockopt at the IP level.
 * First word of comment is data type; bool is stored in int.
 */
/*line: 405*/   IP_OPTIONS = 0x1, /* buf/ip_opts; set/get IP options */ // 1
/*line: 406*/   IP_HDRINCL = 0x2, /* int; header is included with data */ // 2
/*line: 407*/   IP_TOS = 0x3, /* int; IP type of service and preced. */ // 3
/*line: 408*/   IP_TTL = 0x4, /* int; IP time to live */ // 4
/*line: 409*/   IP_RECVOPTS = 0x5, /* bool; receive all IP opts w/dgram */ // 5
/*line: 410*/   IP_RECVRETOPTS = 0x6, /* bool; receive IP opts for response */ // 6
/*line: 411*/   IP_RECVDSTADDR = 0x7, /* bool; receive IP dst addr w/dgram */ // 7
/*line: 412*/   IP_RETOPTS = 0x8, /* ip_opts; set/get IP options */ // 8
/*line: 413*/   IP_MULTICAST_IF = 0x9, /* u_char; set/get IP multicast i/f  */ // 9
/*line: 414*/   IP_MULTICAST_TTL = 0xa, /* u_char; set/get IP multicast ttl */ // 10
/*line: 415*/   IP_MULTICAST_LOOP = 0xb, /* u_char; set/get IP multicast loopback */ // 11
/*line: 416*/   IP_ADD_MEMBERSHIP = 0xc, /* ip_mreq; add an IP group membership */ // 12
/*line: 417*/   IP_DROP_MEMBERSHIP = 0xd, /* ip_mreq; drop an IP group membership */ // 13
/*line: 418*/   IP_MULTICAST_VIF = 0xe, /* set/get IP mcast virt. iface */ // 14
/*line: 419*/   IP_RSVP_ON = 0xf, /* enable RSVP in kernel */ // 15
/*line: 420*/   IP_RSVP_OFF = 0x10, /* disable RSVP in kernel */ // 16
/*line: 421*/   IP_RSVP_VIF_ON = 0x11, /* set RSVP per-vif socket */ // 17
/*line: 422*/   IP_RSVP_VIF_OFF = 0x12, /* unset RSVP per-vif socket */ // 18
/*line: 423*/   IP_PORTRANGE = 0x13, /* int; range to choose for unspec port */ // 19
/*line: 424*/   IP_RECVIF = 0x14, /* bool; receive reception if w/dgram */ // 20
/* for IPSEC */
/*line: 426*/   IP_IPSEC_POLICY = 0x15, /* int; set/get security policy */ // 21
/*line: 427*/   IP_FAITH = 0x16, /* deprecated */ // 22
/*line: 429*/   IP_STRIPHDR = 0x17, /* bool: drop receive of raw IP header */ // 23
/*line: 431*/   IP_RECVTTL = 0x18, /* bool; receive reception TTL w/dgram */ // 24
/*line: 432*/   IP_BOUND_IF = 0x19, /* int; set/get bound interface */ // 25
/*line: 433*/   IP_PKTINFO = 0x1a, /* get pktinfo on recv socket, set src on sent dgram  */ // 26
/*line: 434*/   IP_RECVPKTINFO = 0x1a, /* receive pktinfo w/dgram */ // IP_PKTINFO
/*line: 435*/   IP_RECVTOS = 0x1b, /* bool; receive IP TOS w/dgram */ // 27
/*line: 436*/   IP_DONTFRAG = 0x1c, /* don't fragment packet */ // 28
/*line: 438*/   IP_FW_ADD = 0x28, /* add a firewall rule to chain */ // 40
/*line: 439*/   IP_FW_DEL = 0x29, /* delete a firewall rule from chain */ // 41
/*line: 440*/   IP_FW_FLUSH = 0x2a, /* flush firewall rule chain */ // 42
/*line: 441*/   IP_FW_ZERO = 0x2b, /* clear single/all firewall counter(s) */ // 43
/*line: 442*/   IP_FW_GET = 0x2c, /* get entire firewall rule chain */ // 44
/*line: 443*/   IP_FW_RESETLOG = 0x2d, /* reset logging counters */ // 45
/* These older firewall socket option codes are maintained for backward compatibility. */
/*line: 446*/   IP_OLD_FW_ADD = 0x32, /* add a firewall rule to chain */ // 50
/*line: 447*/   IP_OLD_FW_DEL = 0x33, /* delete a firewall rule from chain */ // 51
/*line: 448*/   IP_OLD_FW_FLUSH = 0x34, /* flush firewall rule chain */ // 52
/*line: 449*/   IP_OLD_FW_ZERO = 0x35, /* clear single/all firewall counter(s) */ // 53
/*line: 450*/   IP_OLD_FW_GET = 0x36, /* get entire firewall rule chain */ // 54
/*line: 451*/   IP_NAT__XXX = 0x37, /* set/get NAT opts XXX Deprecated, do not use */ // 55
/*line: 452*/   IP_OLD_FW_RESETLOG = 0x38, /* reset logging counters */ // 56
/*line: 454*/   IP_DUMMYNET_CONFIGURE = 0x3c, /* add/configure a dummynet pipe */ // 60
/*line: 455*/   IP_DUMMYNET_DEL = 0x3d, /* delete a dummynet pipe from chain */ // 61
/*line: 456*/   IP_DUMMYNET_FLUSH = 0x3e, /* flush dummynet */ // 62
/*line: 457*/   IP_DUMMYNET_GET = 0x40, /* get entire dummynet pipes */ // 64
/*line: 459*/   IP_TRAFFIC_MGT_BACKGROUND = 0x41, /* int*; get background IO flags; set background IO */ // 65
/*line: 460*/   IP_MULTICAST_IFINDEX = 0x42, /* int*; set/get IP multicast i/f index */ // 66
/* IPv4 Source Filter Multicast API [RFC3678] */
/*line: 463*/   IP_ADD_SOURCE_MEMBERSHIP = 0x46, /* join a source-specific group */ // 70
/*line: 464*/   IP_DROP_SOURCE_MEMBERSHIP = 0x47, /* drop a single source */ // 71
/*line: 465*/   IP_BLOCK_SOURCE = 0x48, /* block a source */ // 72
/*line: 466*/   IP_UNBLOCK_SOURCE = 0x49, /* unblock a source */ // 73
/* The following option is private; do not use it from user applications. */
/*line: 469*/   IP_MSFILTER = 0x4a, /* set/get filter list */ // 74
};

enum macro_multicast_control {
/* Protocol Independent Multicast API [RFC3678] */
/*line: 472*/   MCAST_JOIN_GROUP = 0x50, /* join an any-source group */ // 80
/*line: 473*/   MCAST_LEAVE_GROUP = 0x51, /* leave all sources for group */ // 81
/*line: 474*/   MCAST_JOIN_SOURCE_GROUP = 0x52, /* join a source-specific group */ // 82
/*line: 475*/   MCAST_LEAVE_SOURCE_GROUP = 0x53, /* leave a single source */ // 83
/*line: 476*/   MCAST_BLOCK_SOURCE = 0x54, /* block a source */ // 84
/*line: 477*/   MCAST_UNBLOCK_SOURCE = 0x55, /* unblock a source */ // 85
};

enum macro_ip_options_constants {
/*
 * Defaults and limits for options
 */
/*line: 483*/   IP_DEFAULT_MULTICAST_TTL = 0x1, /* normally limit m'casts to 1 hop  */ // 1
/*line: 484*/   IP_DEFAULT_MULTICAST_LOOP = 0x1, /* normally hear sends if a member  */ // 1
/*
 * The imo_membership vector for each socket is now dynamically allocated at
 * run-time, bounded by USHRT_MAX, and is reallocated when needed, sized
 * according to a power-of-two increment.
 */
/*line: 491*/   IP_MIN_MEMBERSHIPS = 0x1f,  // 31
/*line: 492*/   IP_MAX_MEMBERSHIPS = 0xfff,  // 4095
};

enum macro_ip_multicast_limits {
/*
 * Default resource limits for IPv4 multicast source filtering.
 * These may be modified by sysctl.
 */
/*line: 498*/   IP_MAX_GROUP_SRC_FILTER = 0x200, /* sources per group */ // 512
/*line: 499*/   IP_MAX_SOCK_SRC_FILTER = 0x80, /* sources per socket/group */ // 128
/*line: 500*/   IP_MAX_SOCK_MUTE_FILTER = 0x80, /* XXX no longer used */ // 128
};

enum macro_multicast_filter_mode {
/*
 * Filter modes; also used to represent per-socket filter mode internally.
 */
/*line: 584*/   MCAST_UNDEFINED = 0x0, /* fmode: not yet defined */ // 0
/*line: 585*/   MCAST_INCLUDE = 0x1, /* fmode: include these source(s) */ // 1
/*line: 586*/   MCAST_EXCLUDE = 0x2, /* fmode: exclude these source(s) */ // 2
};

enum macro_ip_port_range {
/*
 * Argument for IP_PORTRANGE:
 * - which range to search when port is unspecified at bind() or connect()
 */
/*line: 592*/   IP_PORTRANGE_DEFAULT = 0x0, /* default range */ // 0
/*line: 593*/   IP_PORTRANGE_HIGH = 0x1, /* "high" - request firewall bypass */ // 1
/*line: 594*/   IP_PORTRANGE_LOW = 0x2, /* "low" - vouchsafe security */ // 2
};

// Depends on identifiers
enum macro_ip_protocol_id {
/*
 * Definitions for inet sysctl operations.
 *
 * Third level is protocol number.
 * Fourth level is desired variable within that protocol.
 */
/*line: 628*/   IPPROTO_MAXID = 0x34, /* don't list to IPPROTO_MAX */ // (IPPROTO_AH+1)
};

enum macro_ip_controls {
/*
 * Names for IP sysctl objects
 */
/*line: 633*/   IPCTL_FORWARDING = 0x1, /* act as router */ // 1
/*line: 634*/   IPCTL_SENDREDIRECTS = 0x2, /* may send redirects when forwarding */ // 2
/*line: 635*/   IPCTL_DEFTTL = 0x3, /* default TTL */ // 3
/*line: 639*/   IPCTL_RTEXPIRE = 0x5, /* cloned route expiration time */ // 5
/*line: 640*/   IPCTL_RTMINEXPIRE = 0x6, /* min value for expiration time */ // 6
/*line: 641*/   IPCTL_RTMAXCACHE = 0x7, /* trigger level for dynamic expire */ // 7
/*line: 642*/   IPCTL_SOURCEROUTE = 0x8, /* may perform source routes */ // 8
/*line: 643*/   IPCTL_DIRECTEDBROADCAST = 0x9, /* may re-broadcast received packets */ // 9
/*line: 644*/   IPCTL_INTRQMAXLEN = 0xa, /* max length of netisr queue */ // 10
/*line: 645*/   IPCTL_INTRQDROPS = 0xb, /* number of netisr q drops */ // 11
/*line: 646*/   IPCTL_STATS = 0xc, /* ipstat structure */ // 12
/*line: 647*/   IPCTL_ACCEPTSOURCEROUTE = 0xd, /* may accept source routed packets */ // 13
/*line: 648*/   IPCTL_FASTFORWARDING = 0xe, /* use fast IP forwarding code */ // 14
/*line: 649*/   IPCTL_KEEPFAITH = 0xf, /* deprecated */ // 15
/*line: 650*/   IPCTL_GIF_TTL = 0x10, /* default TTL for gif encap packet */ // 16
/*line: 651*/   IPCTL_MAXID = 0x11,  // 17
};

