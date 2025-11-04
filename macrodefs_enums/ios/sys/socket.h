// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/socket.h

enum macro_socket_type {
/*
 * Types
 */
/*line: 111*/   SOCK_STREAM = 0x1, /* stream socket */ // 1
/*line: 112*/   SOCK_DGRAM = 0x2, /* datagram socket */ // 2
/*line: 113*/   SOCK_RAW = 0x3, /* raw-protocol interface */ // 3
/*line: 115*/   SOCK_RDM = 0x4, /* reliably-delivered message */ // 4
/*line: 117*/   SOCK_SEQPACKET = 0x5, /* sequenced packet stream */ // 5
};

enum macro_socket_option_flags {
/*
 * Option flags per-socket.
 */
/*line: 122*/   SO_DEBUG = 0x1, /* turn on debugging info recording */ // 0x0001
/*line: 123*/   SO_ACCEPTCONN = 0x2, /* socket has had listen() */ // 0x0002
/*line: 124*/   SO_REUSEADDR = 0x4, /* allow local address reuse */ // 0x0004
/*line: 125*/   SO_KEEPALIVE = 0x8, /* keep connections alive */ // 0x0008
/*line: 126*/   SO_DONTROUTE = 0x10, /* just use interface addresses */ // 0x0010
/*line: 127*/   SO_BROADCAST = 0x20, /* permit sending of broadcast msgs */ // 0x0020
/*line: 129*/   SO_USELOOPBACK = 0x40, /* bypass hardware when possible */ // 0x0040
/*line: 130*/   SO_LINGER = 0x80, /* linger on close if data present (in ticks) */ // 0x0080
/*line: 131*/   SO_LINGER_SEC = 0x1080, /* linger on close if data present (in seconds) */ // 0x1080
/*line: 135*/   SO_OOBINLINE = 0x100, /* leave received OOB data in line */ // 0x0100
/*line: 137*/   SO_REUSEPORT = 0x200, /* allow local address & port reuse */ // 0x0200
/*line: 138*/   SO_TIMESTAMP = 0x400, /* timestamp received dgram traffic */ // 0x0400
/*line: 139*/   SO_TIMESTAMP_MONOTONIC = 0x800, /* Monotonically increasing timestamp on rcvd dgram */ // 0x0800
/*line: 143*/   SO_DONTTRUNC = 0x2000, /* APPLE: Retain unread data */ // 0x2000
/*  (ATOMIC proto) */
/*line: 145*/   SO_WANTMORE = 0x4000, /* APPLE: Give hint when more data ready */ // 0x4000
/*line: 146*/   SO_WANTOOBFLAG = 0x8000, /* APPLE: Want OOB in MSG_FLAG on receive */ // 0x8000
/*
 * Additional options, not kept in so_options.
 */
/*line: 155*/   SO_SNDBUF = 0x1001, /* send buffer size */ // 0x1001
/*line: 156*/   SO_RCVBUF = 0x1002, /* receive buffer size */ // 0x1002
/*line: 157*/   SO_SNDLOWAT = 0x1003, /* send low-water mark */ // 0x1003
/*line: 158*/   SO_RCVLOWAT = 0x1004, /* receive low-water mark */ // 0x1004
/*line: 159*/   SO_SNDTIMEO = 0x1005, /* send timeout */ // 0x1005
/*line: 160*/   SO_RCVTIMEO = 0x1006, /* receive timeout */ // 0x1006
/*line: 161*/   SO_ERROR = 0x1007, /* get error status and clear */ // 0x1007
/*line: 162*/   SO_TYPE = 0x1008, /* get socket type */ // 0x1008
/*line: 164*/   SO_LABEL = 0x1010, /* deprecated */ // 0x1010
/*line: 165*/   SO_PEERLABEL = 0x1011, /* deprecated */ // 0x1011
/*line: 167*/   SO_NREAD = 0x1020, /* APPLE: get 1st-packet byte count */ // 0x1020
/*line: 168*/   SO_NKE = 0x1021, /* APPLE: Install socket-level NKE */ // 0x1021
/*line: 169*/   SO_NOSIGPIPE = 0x1022, /* APPLE: No SIGPIPE on EPIPE */ // 0x1022
/*line: 170*/   SO_NOADDRERR = 0x1023, /* APPLE: Returns EADDRNOTAVAIL when src is not available anymore */ // 0x1023
/*line: 171*/   SO_NWRITE = 0x1024, /* APPLE: Get number of bytes currently in send socket buffer */ // 0x1024
/*line: 172*/   SO_REUSESHAREUID = 0x1025, /* APPLE: Allow reuse of port/socket by different userids */ // 0x1025
/*line: 174*/   SO_NOTIFYCONFLICT = 0x1026, /* APPLE: send notification if there is a bind on a port which is already in use */ // 0x1026
/*line: 175*/   SO_UPCALLCLOSEWAIT = 0x1027, /* APPLE: block on close until an upcall returns */ // 0x1027
/*line: 177*/   SO_RANDOMPORT = 0x1082, /* APPLE: request local port randomization */ // 0x1082
/*line: 178*/   SO_NP_EXTENSIONS = 0x1083, /* To turn off some POSIX behavior */ // 0x1083
/*line: 181*/   SO_NUMRCVPKT = 0x1112, /* number of datagrams in receive socket buffer */ // 0x1112
/*line: 182*/   SO_NET_SERVICE_TYPE = 0x1116, /* Network service type */ // 0x1116
/*line: 185*/   SO_NETSVC_MARKING_LEVEL = 0x1119, /* Get QoS marking in effect for socket */ // 0x1119
/*line: 188*/   SO_RESOLVER_SIGNATURE = 0x1131, /* A signed data blob from the system resolver */ // 0x1131
/*line: 190*/   SO_BINDTODEVICE = 0x1134, /* bind socket to a network device (max valid option length IFNAMSIZ) */ // 0x1134
};

enum macro_network_service_type {
/*
 * Network Service Type for option SO_NET_SERVICE_TYPE
 *
 * The vast majority of sockets should use Best Effort that is the default
 * Network Service Type. Other Network Service Types have to be used only if
 * the traffic actually matches the description of the Network Service Type.
 *
 * Network Service Types do not represent priorities but rather describe
 * different categories of delay, jitter and loss parameters.
 * Those parameters may influence protocols from layer 4 protocols like TCP
 * to layer 2 protocols like Wi-Fi. The Network Service Type can determine
 * how the traffic is queued and scheduled by the host networking stack and
 * by other entities on the network like switches and routers. For example
 * for Wi-Fi, the Network Service Type can select the marking of the
 * layer 2 packet with the appropriate WMM Access Category.
 *
 * There is no point in attempting to game the system and use
 * a Network Service Type that does not correspond to the actual
 * traffic characteristic but one that seems to have a higher precedence.
 * The reason is that for service classes that have lower tolerance
 * for delay and jitter, the queues size is lower than for service
 * classes that are more tolerant to delay and jitter.
 *
 * For example using a voice service type for bulk data transfer will lead
 * to disastrous results as soon as congestion happens because the voice
 * queue overflows and packets get dropped. This is not only bad for the bulk
 * data transfer but it is also bad for VoIP apps that legitimately are using
 * the voice  service type.
 *
 * The characteristics of the Network Service Types are based on the service
 * classes defined in RFC 4594 "Configuration Guidelines for DiffServ Service
 * Classes"
 *
 * When system detects the outgoing interface belongs to a DiffServ domain
 * that follows the recommendation of the IETF draft "Guidelines for DiffServ to
 * IEEE 802.11 Mapping", the packet will marked at layer 3 with a DSCP value
 * that corresponds to Network Service Type.
 *
 * NET_SERVICE_TYPE_BE
 *	"Best Effort", unclassified/standard.  This is the default service
 *	class and cover the majority of the traffic.
 *
 * NET_SERVICE_TYPE_BK
 *	"Background", high delay tolerant, loss tolerant. elastic flow,
 *	variable size & long-lived. E.g: non-interactive network bulk transfer
 *	like synching or backup.
 *
 * NET_SERVICE_TYPE_RD
 *	"Responsive Data", a notch higher than "Best Effort", medium delay
 *	tolerant, elastic & inelastic flow, bursty, long-lived. E.g. email,
 *	instant messaging, for which there is a sense of interactivity and
 *	urgency (user waiting for output).
 *
 * NET_SERVICE_TYPE_OAM
 *	"Operations, Administration, and Management", medium delay tolerant,
 *	low-medium loss tolerant, elastic & inelastic flows, variable size.
 *	E.g. VPN tunnels.
 *
 * NET_SERVICE_TYPE_AV
 *	"Multimedia Audio/Video Streaming", medium delay tolerant, low-medium
 *	loss tolerant, elastic flow, constant packet interval, variable rate
 *	and size. E.g. video and audio playback with buffering.
 *
 * NET_SERVICE_TYPE_RV
 *	"Responsive Multimedia Audio/Video", low delay tolerant, low-medium
 *	loss tolerant, elastic flow, variable packet interval, rate and size.
 *	E.g. screen sharing.
 *
 * NET_SERVICE_TYPE_VI
 *	"Interactive Video", low delay tolerant, low-medium loss tolerant,
 *	elastic flow, constant packet interval, variable rate & size. E.g.
 *	video telephony.
 *
 * NET_SERVICE_TYPE_SIG
 *	"Signaling", low delay tolerant, low loss tolerant, inelastic flow,
 *	jitter tolerant, rate is bursty but short, variable size. E.g. SIP.
 *
 * NET_SERVICE_TYPE_VO
 *	"Interactive Voice", very low delay tolerant, very low loss tolerant,
 *	inelastic flow, constant packet rate, somewhat fixed size.
 *	E.g. VoIP.
 */
/*line: 277*/   NET_SERVICE_TYPE_BE = 0x0, /* Best effort */ // 0
/*line: 278*/   NET_SERVICE_TYPE_BK = 0x1, /* Background system initiated */ // 1
/*line: 279*/   NET_SERVICE_TYPE_SIG = 0x2, /* Signaling */ // 2
/*line: 280*/   NET_SERVICE_TYPE_VI = 0x3, /* Interactive Video */ // 3
/*line: 281*/   NET_SERVICE_TYPE_VO = 0x4, /* Interactive Voice */ // 4
/*line: 282*/   NET_SERVICE_TYPE_RV = 0x5, /* Responsive Multimedia Audio/Video */ // 5
/*line: 283*/   NET_SERVICE_TYPE_AV = 0x6, /* Multimedia Audio/Video Streaming */ // 6
/*line: 284*/   NET_SERVICE_TYPE_OAM = 0x7, /* Operations, Administration, and Management */ // 7
/*line: 285*/   NET_SERVICE_TYPE_RD = 0x8, /* Responsive Data */ // 8
};

enum macro_net_service_marking {
/* These are supported values for SO_NETSVC_MARKING_LEVEL */
/*line: 289*/   NETSVC_MRKNG_UNKNOWN = 0x0, /* The outgoing network interface is not known */ // 0
/*line: 290*/   NETSVC_MRKNG_LVL_L2 = 0x1, /* Default marking at layer 2 (for example Wi-Fi WMM) */ // 1
/*line: 291*/   NETSVC_MRKNG_LVL_L3L2_ALL = 0x2, /* Layer 3 DSCP marking and layer 2 marking for all Network Service Types */ // 2
/*line: 292*/   NETSVC_MRKNG_LVL_L3L2_BK = 0x3, /* The system policy limits layer 3 DSCP marking and layer 2 marking
	                                         * to background Network Service Types */ // 3
};

// Depends on identifiers
enum macro_sae_associd {
/*line: 297*/   SAE_ASSOCID_ANY = 0x0,  // 0
/*line: 298*/   SAE_ASSOCID_ALL = -0x1,  // ((sae_associd_t)(-1ULL))
};

// Depends on identifiers
enum macro_sae_connid {
/*line: 301*/   SAE_CONNID_ANY = 0x0,  // 0
/*line: 302*/   SAE_CONNID_ALL = -0x1,  // ((sae_connid_t)(-1ULL))
};

enum macro_connect_flags {
/* connectx() flag parameters */
/*line: 305*/   CONNECT_RESUME_ON_READ_WRITE = 0x1, /* resume connect() on read/write */ // 0x1
/*line: 306*/   CONNECT_DATA_IDEMPOTENT = 0x2, /* data is idempotent */ // 0x2
/*line: 307*/   CONNECT_DATA_AUTHENTICATED = 0x4, /* data includes security that replaces the TFO-cookie */ // 0x4
};

enum macro_socket_options {
/*line: 345*/   SONPX_SETOPTSHUT = 0x1, /* flag for allowing setsockopt after shutdown */ // 0x000000001
/*
 * Level number for (get/set)sockopt() to apply to socket itself.
 */
/*line: 354*/   SOL_SOCKET = 0xffff, /* options for socket level */ // 0xffff
};

// Depends on identifiers
enum macro_address_families {
/*
 * Address families.
 */
/*line: 360*/   AF_UNSPEC = 0x0, /* unspecified */ // 0
/*line: 361*/   AF_UNIX = 0x1, /* local to host (pipes) */ // 1
/*line: 363*/   AF_LOCAL = 0x1, /* backward compatibility */ // AF_UNIX
/*line: 365*/   AF_INET = 0x2, /* internetwork: UDP, TCP, etc. */ // 2
/*line: 367*/   AF_IMPLINK = 0x3, /* arpanet imp addresses */ // 3
/*line: 368*/   AF_PUP = 0x4, /* pup protocols: e.g. BSP */ // 4
/*line: 369*/   AF_CHAOS = 0x5, /* mit CHAOS protocols */ // 5
/*line: 370*/   AF_NS = 0x6, /* XEROX NS protocols */ // 6
/*line: 371*/   AF_ISO = 0x7, /* ISO protocols */ // 7
/*line: 372*/   AF_OSI = 0x7,  // AF_ISO
/*line: 373*/   AF_ECMA = 0x8, /* European computer manufacturers */ // 8
/*line: 374*/   AF_DATAKIT = 0x9, /* datakit protocols */ // 9
/*line: 375*/   AF_CCITT = 0xa, /* CCITT protocols, X.25 etc */ // 10
/*line: 376*/   AF_SNA = 0xb, /* IBM SNA */ // 11
/*line: 377*/   AF_DECnet = 0xc, /* DECnet */ // 12
/*line: 378*/   AF_DLI = 0xd, /* DEC Direct data link interface */ // 13
/*line: 379*/   AF_LAT = 0xe, /* LAT */ // 14
/*line: 380*/   AF_HYLINK = 0xf, /* NSC Hyperchannel */ // 15
/*line: 381*/   AF_APPLETALK = 0x10, /* Apple Talk */ // 16
/*line: 382*/   AF_ROUTE = 0x11, /* Internal Routing Protocol */ // 17
/*line: 383*/   AF_LINK = 0x12, /* Link layer interface */ // 18
/*line: 384*/   pseudo_AF_XTP = 0x13, /* eXpress Transfer Protocol (no AF) */ // 19
/*line: 385*/   AF_COIP = 0x14, /* connection-oriented IP, aka ST II */ // 20
/*line: 386*/   AF_CNT = 0x15, /* Computer Network Technology */ // 21
/*line: 387*/   pseudo_AF_RTIP = 0x16, /* Help Identify RTIP packets */ // 22
/*line: 388*/   AF_IPX = 0x17, /* Novell Internet Protocol */ // 23
/*line: 389*/   AF_SIP = 0x18, /* Simple Internet Protocol */ // 24
/*line: 390*/   pseudo_AF_PIP = 0x19, /* Help Identify PIP packets */ // 25
/*line: 391*/   AF_NDRV = 0x1b, /* Network Driver 'raw' access */ // 27
/*line: 392*/   AF_ISDN = 0x1c, /* Integrated Services Digital Network */ // 28
/*line: 393*/   AF_E164 = 0x1c, /* CCITT E.164 recommendation */ // AF_ISDN
/*line: 394*/   pseudo_AF_KEY = 0x1d, /* Internal key-management function */ // 29
/*line: 396*/   AF_INET6 = 0x1e, /* IPv6 */ // 30
/*line: 398*/   AF_NATM = 0x1f, /* native ATM access */ // 31
/*line: 399*/   AF_SYSTEM = 0x20, /* Kernel event messages */ // 32
/*line: 400*/   AF_NETBIOS = 0x21, /* NetBIOS */ // 33
/*line: 401*/   AF_PPP = 0x22, /* PPP communication protocol */ // 34
/*line: 402*/   pseudo_AF_HDRCMPLT = 0x23, /* Used by BPF to not rewrite headers
	                                 *  in interface output routine */ // 35
/*line: 404*/   AF_RESERVED_36 = 0x24, /* Reserved for internal usage */ // 36
/*line: 405*/   AF_IEEE80211 = 0x25, /* IEEE 802.11 protocol */ // 37
/*line: 406*/   AF_UTUN = 0x26,  // 38
/*line: 407*/   AF_VSOCK = 0x28, /* VM Sockets */ // 40
/*line: 408*/   AF_MAX = 0x29,  // 41
};

enum macro_socket_limits {
/*line: 432*/   SOCK_MAXADDRLEN = 0xff, /* longest possible addresses */ // 255
/*
 * RFC 2553: protocol-independent placeholder for socket addresses
 */
/*line: 447*/   _SS_MAXSIZE = 0x80,  // 128
};

enum macro_protocol_families {
/*
 * Protocol families, same as address families for now.
 */
/*line: 470*/   PF_UNSPEC = 0x0,  // AF_UNSPEC
/*line: 471*/   PF_LOCAL = 0x1,  // AF_LOCAL
/*line: 472*/   PF_UNIX = 0x1, /* backward compatibility */ // PF_LOCAL
/*line: 473*/   PF_INET = 0x2,  // AF_INET
/*line: 474*/   PF_IMPLINK = 0x3,  // AF_IMPLINK
/*line: 475*/   PF_PUP = 0x4,  // AF_PUP
/*line: 476*/   PF_CHAOS = 0x5,  // AF_CHAOS
/*line: 477*/   PF_NS = 0x6,  // AF_NS
/*line: 478*/   PF_ISO = 0x7,  // AF_ISO
/*line: 479*/   PF_OSI = 0x7,  // AF_ISO
/*line: 480*/   PF_ECMA = 0x8,  // AF_ECMA
/*line: 481*/   PF_DATAKIT = 0x9,  // AF_DATAKIT
/*line: 482*/   PF_CCITT = 0xa,  // AF_CCITT
/*line: 483*/   PF_SNA = 0xb,  // AF_SNA
/*line: 484*/   PF_DECnet = 0xc,  // AF_DECnet
/*line: 485*/   PF_DLI = 0xd,  // AF_DLI
/*line: 486*/   PF_LAT = 0xe,  // AF_LAT
/*line: 487*/   PF_HYLINK = 0xf,  // AF_HYLINK
/*line: 488*/   PF_APPLETALK = 0x10,  // AF_APPLETALK
/*line: 489*/   PF_ROUTE = 0x11,  // AF_ROUTE
/*line: 490*/   PF_LINK = 0x12,  // AF_LINK
/*line: 491*/   PF_XTP = 0x13, /* really just proto family, no AF */ // pseudo_AF_XTP
/*line: 492*/   PF_COIP = 0x14,  // AF_COIP
/*line: 493*/   PF_CNT = 0x15,  // AF_CNT
/*line: 494*/   PF_SIP = 0x18,  // AF_SIP
/*line: 495*/   PF_IPX = 0x17, /* same format as AF_NS */ // AF_IPX
/*line: 496*/   PF_RTIP = 0x16, /* same format as AF_INET */ // pseudo_AF_RTIP
/*line: 497*/   PF_PIP = 0x19,  // pseudo_AF_PIP
/*line: 498*/   PF_NDRV = 0x1b,  // AF_NDRV
/*line: 499*/   PF_ISDN = 0x1c,  // AF_ISDN
/*line: 500*/   PF_KEY = 0x1d,  // pseudo_AF_KEY
/*line: 501*/   PF_INET6 = 0x1e,  // AF_INET6
/*line: 502*/   PF_NATM = 0x1f,  // AF_NATM
/*line: 503*/   PF_SYSTEM = 0x20,  // AF_SYSTEM
/*line: 504*/   PF_NETBIOS = 0x21,  // AF_NETBIOS
/*line: 505*/   PF_PPP = 0x22,  // AF_PPP
/*line: 506*/   PF_RESERVED_36 = 0x24,  // AF_RESERVED_36
/*line: 507*/   PF_UTUN = 0x26,  // AF_UTUN
/*line: 508*/   PF_VSOCK = 0x28,  // AF_VSOCK
/*line: 509*/   PF_MAX = 0x29,  // AF_MAX
/*
 * These do not have socket-layer support:
 */
/*line: 514*/   PF_VLAN = 0x766c616e, /* 'vlan' */ // ((uint32_t)0x766c616e)
/*line: 515*/   PF_BOND = 0x626f6e64, /* 'bond' */ // ((uint32_t)0x626f6e64)
};

// Depends on identifiers
enum macro_net_maxid {
/*line: 526*/   NET_MAXID = 0x29,  // AF_MAX
};

enum macro_net_route_flags {
/*
 * PF_ROUTE - Routing table
 *
 * Three additional levels are defined:
 *	Fourth: address family, 0 is wildcard
 *	Fifth: type of info, defined below
 *	Sixth: flag(s) to mask with for NET_RT_FLAGS
 */
/*line: 536*/   NET_RT_DUMP = 0x1, /* dump; may limit to a.f. */ // 1
/*line: 537*/   NET_RT_FLAGS = 0x2, /* by flags, e.g. RESOLVING */ // 2
/*line: 538*/   NET_RT_IFLIST = 0x3, /* survey interface list */ // 3
/*line: 539*/   NET_RT_STAT = 0x4, /* routing statistics */ // 4
/*line: 540*/   NET_RT_TRASH = 0x5, /* routes not in table but not freed */ // 5
/*line: 541*/   NET_RT_IFLIST2 = 0x6, /* interface list with addresses */ // 6
/*line: 542*/   NET_RT_DUMP2 = 0x7, /* dump; may limit to a.f. */ // 7
/*
 * Allows read access non-local host's MAC address
 * if the process has neighbor cache entitlement.
 */
/*line: 547*/   NET_RT_FLAGS_PRIV = 0xa,  // 10
/*line: 548*/   NET_RT_MAXID = 0xb,  // 11
};

enum macro_somaxconn {
/*
 * Maximum queue length specifiable by listen.
 */
/*line: 554*/   SOMAXCONN = 0x80,  // 128
};

enum macro_msg_flags {
/*line: 570*/   MSG_OOB = 0x1, /* process out-of-band data */ // 0x1
/*line: 571*/   MSG_PEEK = 0x2, /* peek at incoming message */ // 0x2
/*line: 572*/   MSG_DONTROUTE = 0x4, /* send without using routing tables */ // 0x4
/*line: 573*/   MSG_EOR = 0x8, /* data completes record */ // 0x8
/*line: 574*/   MSG_TRUNC = 0x10, /* data discarded before delivery */ // 0x10
/*line: 575*/   MSG_CTRUNC = 0x20, /* control data lost before delivery */ // 0x20
/*line: 576*/   MSG_WAITALL = 0x40, /* wait for full request or error */ // 0x40
/*line: 578*/   MSG_DONTWAIT = 0x80, /* this message should be nonblocking */ // 0x80
/*line: 579*/   MSG_EOF = 0x100, /* data completes connection */ // 0x100
/*line: 582*/   MSG_WAITSTREAM = 0x200, /* wait up to full request.. may return partial */ // 0x200
/*line: 584*/   MSG_FLUSH = 0x400, /* Start of 'hold' seq; dump so_temp, deprecated */ // 0x400
/*line: 585*/   MSG_HOLD = 0x800, /* Hold frag in so_temp, deprecated */ // 0x800
/*line: 586*/   MSG_SEND = 0x1000, /* Send the packet in so_temp, deprecated */ // 0x1000
/*line: 587*/   MSG_HAVEMORE = 0x2000, /* Data ready to be read */ // 0x2000
/*line: 588*/   MSG_RCVMORE = 0x4000, /* Data remains in current pkt */ // 0x4000
/*line: 590*/   MSG_NEEDSA = 0x10000, /* Fail receive if socket address cannot be allocated */ // 0x10000
/*line: 594*/   MSG_NOSIGNAL = 0x80000, /* do not generate SIGPIPE on EOF */ // 0x80000
};

enum macro_socket_control_msg_types {
/* "Socket"-level control message types: */
/*line: 677*/   SCM_RIGHTS = 0x1, /* access rights (array of int) */ // 0x01
/*line: 679*/   SCM_TIMESTAMP = 0x2, /* timestamp (struct timeval) */ // 0x02
/*line: 680*/   SCM_CREDS = 0x3, /* process creds (struct cmsgcred) */ // 0x03
/*line: 681*/   SCM_TIMESTAMP_MONOTONIC = 0x4, /* timestamp (uint64_t) */ // 0x04
};

enum macro_shutdown_direction {
/*
 * howto arguments for shutdown(2), specified by Posix.1g.
 */
/*line: 688*/   SHUT_RD = 0x0, /* shut down the reading side */ // 0
/*line: 689*/   SHUT_WR = 0x1, /* shut down the writing side */ // 1
/*line: 690*/   SHUT_RDWR = 0x2, /* shut down both sides */ // 2
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 448
// #define _SS_ALIGNSIZE (sizeof(__int64_t))

// Line: 449
// #define _SS_PAD1SIZE (_SS_ALIGNSIZE - sizeof(__uint8_t) - sizeof(sa_family_t))

// Line: 451
// #define _SS_PAD2SIZE (_SS_MAXSIZE - sizeof(__uint8_t) - sizeof(sa_family_t) - \
// 	                        _SS_PAD1SIZE - _SS_ALIGNSIZE)

