// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/tcp.h

// Depends on identifiers
enum macro_tcp_header_flags {
/*line: 101*/   TH_FIN = 0x1,  // 0x01
/*line: 102*/   TH_SYN = 0x2,  // 0x02
/*line: 103*/   TH_RST = 0x4,  // 0x04
/*line: 104*/   TH_PUSH = 0x8,  // 0x08
/*line: 105*/   TH_ACK = 0x10,  // 0x10
/*line: 106*/   TH_URG = 0x20,  // 0x20
/*line: 107*/   TH_ECE = 0x40,  // 0x40
/*line: 108*/   TH_CWR = 0x80,  // 0x80
/*line: 109*/   TH_AE = 0x100, /* maps into th_x2 */ // 0x100
/*line: 110*/   TH_FLAGS = 0xf7,  // (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
/*line: 111*/   TH_FLAGS_ALL = 0xff,  // (TH_FLAGS|TH_PUSH)
/*line: 112*/   TH_ACCEPT = 0x17,  // (TH_FIN|TH_SYN|TH_RST|TH_ACK)
/*line: 113*/   TH_ACE = 0x1c0,  // (TH_AE|TH_CWR|TH_ECE)
};

// Depends on identifiers
enum macro_tcp_option_kinds {
/*line: 120*/   TCPOPT_EOL = 0x0,  // 0
/*line: 121*/   TCPOPT_NOP = 0x1,  // 1
/*line: 122*/   TCPOPT_MAXSEG = 0x2,  // 2
/*line: 123*/   TCPOLEN_MAXSEG = 0x4,  // 4
/*line: 124*/   TCPOPT_WINDOW = 0x3,  // 3
/*line: 125*/   TCPOLEN_WINDOW = 0x3,  // 3
/*line: 126*/   TCPOPT_SACK_PERMITTED = 0x4, /* Experimental */ // 4
/*line: 127*/   TCPOLEN_SACK_PERMITTED = 0x2,  // 2
/*line: 128*/   TCPOPT_SACK = 0x5, /* Experimental */ // 5
/*line: 129*/   TCPOLEN_SACK = 0x8, /* len of sack block */ // 8
/*line: 130*/   TCPOPT_TIMESTAMP = 0x8,  // 8
/*line: 131*/   TCPOLEN_TIMESTAMP = 0xa,  // 10
/*line: 132*/   TCPOLEN_TSTAMP_APPA = 0xc, /* appendix A */ // (TCPOLEN_TIMESTAMP+2)
/*line: 133*/   TCPOPT_TSTAMP_HDR = 0x101080a,  // (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)
};

enum macro_max_tcpoptlen {
/*line: 136*/   MAX_TCPOPTLEN = 0x28, /* Absolute maximum TCP options len */ // 40
};

// Depends on identifiers
enum macro_tcp_extended_options {
/*line: 138*/   TCPOPT_CC = 0xb, /* CC options: RFC-1644 */ // 11
/*line: 139*/   TCPOPT_CCNEW = 0xc,  // 12
/*line: 140*/   TCPOPT_CCECHO = 0xd,  // 13
/*line: 141*/   TCPOLEN_CC = 0x6,  // 6
/*line: 142*/   TCPOLEN_CC_APPA = 0x8,  // (TCPOLEN_CC+2)
/*line: 145*/   TCPOPT_SIGNATURE = 0x13, /* Keyed MD5: RFC 2385 */ // 19
/*line: 146*/   TCPOLEN_SIGNATURE = 0x12,  // 18
/*line: 151*/   TCPOPT_FASTOPEN = 0x22,  // 34
/*line: 152*/   TCPOLEN_FASTOPEN_REQ = 0x2,  // 2
/*line: 154*/   TCPOPT_ACCECN0 = 0xac, /* AccECN Order 0 */ // 172
/*line: 155*/   TCPOPT_ACCECN1 = 0xae, /* AccECN Order 1 */ // 174
/*line: 156*/   TCPOLEN_ACCECN_EMPTY = 0x2, /* Empty option contains kind and length */ // 2
/*line: 157*/   TCPOLEN_ACCECN_COUNTER = 0x3, /* Length of each AccECN counter */ // 3
/*line: 162*/   TCPOPT_SACK_HDR = 0x1010500,  // (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_SACK<<8)
/* Miscellaneous constants */
/*line: 164*/   MAX_SACK_BLKS = 0x6, /* Max # SACK blocks stored at sender side */ // 6
};

enum macro_tcp_limits {
/*
 * A SACK option that specifies n blocks will have a length of (8*n + 2)
 * bytes, so the 40 bytes available for TCP options can specify a
 * maximum of 4 blocks.
 */
/*line: 172*/   TCP_MAX_SACK = 0x4, /* MAX # SACKs sent in any segment */ // 4
/*
 * Default maximum segment size for TCP.
 * With an IP MTU of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
/*line: 181*/   TCP_MSS = 0x200,  // 512
/*
 * TCP_MINMSS is defined to be 216 which is fine for the smallest
 * link MTU (256 bytes, SLIP interface) in the Internet.
 * However it is very unlikely to come across such low MTU interfaces
 * these days (anno dato 2004).
 * Probably it can be set to 512 without ill effects. But we play safe.
 * See tcp_subr.c tcp_minmss SYSCTL declaration for more comments.
 * Setting this to "0" disables the minmss check.
 */
/*line: 192*/   TCP_MINMSS = 0xd8,  // 216
/*
 * Default maximum segment size for TCP6.
 * With an IP6 MSS of 1280, this is 1220,
 * but 1024 is probably more convenient. (xxx kazu in doubt)
 * This should be defined as MIN(1024, IP6_MSS - sizeof (struct tcpip6hdr))
 */
/*line: 200*/   TCP6_MSS = 0x400,  // 1024
/*line: 202*/   TCP_MAXWIN = 0xffff, /* largest value for (unscaled) window */ // 65535
/*line: 203*/   TTCP_CLIENT_SND_WND = 0x1000, /* dflt send window for T/TCP client */ // 4096
/*line: 205*/   TCP_MAX_WINSHIFT = 0xe, /* maximum window shift */ // 14
/*line: 207*/   TCP_MAXHLEN = 0x3c, /* max length of header in bytes */ // (0xf<<2)
};

enum macro_tcp_socket_options{
/*
 * User-settable options (used with setsockopt).
 */
/*line: 215*/   TCP_NODELAY = 0x1, /* don't delay send to coalesce packets */ // 0x01
/*line: 217*/   TCP_MAXSEG = 0x2, /* set maximum segment size */ // 0x02
/*line: 218*/   TCP_NOPUSH = 0x4, /* don't push last block of write */ // 0x04
/*line: 219*/   TCP_NOOPT = 0x8, /* don't use TCP options */ // 0x08
/*line: 220*/   TCP_KEEPALIVE = 0x10, /* idle time used when SO_KEEPALIVE is enabled */ // 0x10
/*line: 221*/   TCP_CONNECTIONTIMEOUT = 0x20, /* connection timeout */ // 0x20
/*line: 222*/   PERSIST_TIMEOUT = 0x40, /* time after which a connection in
	                                 *  persist timeout will terminate.
	                                 *  see draft-ananth-tcpm-persist-02.txt
	                                 */ // 0x40
/*line: 226*/   TCP_RXT_CONNDROPTIME = 0x80, /* time after which tcp retransmissions will be
	                                 * stopped and the connection will be dropped
	                                 */ // 0x80
/*line: 229*/   TCP_RXT_FINDROP = 0x100, /* when this option is set, drop a connection
	                                 * after retransmitting the FIN 3 times. It will
	                                 * prevent holding too many mbufs in socket
	                                 * buffer queues.
	                                 */ // 0x100
/*line: 234*/   TCP_KEEPINTVL = 0x101, /* interval between keepalives */ // 0x101
/*line: 235*/   TCP_KEEPCNT = 0x102, /* number of keepalives before close */ // 0x102
/*line: 236*/   TCP_SENDMOREACKS = 0x103, /* always ack every other packet */ // 0x103
/*line: 237*/   TCP_ENABLE_ECN = 0x104, /* Enable ECN on a connection */ // 0x104
/*line: 238*/   TCP_FASTOPEN = 0x105, /* Enable/Disable TCP Fastopen on this socket */ // 0x105
/*line: 239*/   TCP_CONNECTION_INFO = 0x106, /* State of TCP connection */ // 0x106
/*line: 243*/   TCP_NOTSENT_LOWAT = 0x201, /* Low water mark for TCP unsent data */ // 0x201
};

enum macro_tcp_connection_info_flags {
/*line: 251*/   TCPCI_OPT_TIMESTAMPS = 0x1, /* Timestamps enabled */ // 0x00000001
/*line: 252*/   TCPCI_OPT_SACK = 0x2, /* SACK enabled */ // 0x00000002
/*line: 253*/   TCPCI_OPT_WSCALE = 0x4, /* Window scaling enabled */ // 0x00000004
/*line: 254*/   TCPCI_OPT_ECN = 0x8, /* ECN enabled */ // 0x00000008
/*line: 256*/   TCPCI_FLAG_LOSSRECOVERY = 0x1,  // 0x00000001
/*line: 257*/   TCPCI_FLAG_REORDERING_DETECTED = 0x2,  // 0x00000002
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 80
// #define tcp6_seq tcp_seq

// Line: 81
// #define tcp6hdr tcphdr

// Line: 160
// #define TCPOPT_SACK_PERMIT_HDR \
// (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_SACK_PERMITTED<<8|TCPOLEN_SACK_PERMITTED)

// Line: 208
// #define TCP_MAXOLEN (TCP_MAXHLEN - sizeof(struct tcphdr))

