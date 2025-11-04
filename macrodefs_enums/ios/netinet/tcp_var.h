// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/tcp_var.h

enum macro_tcp_flags {
/*line: 99*/    TF_ACKNOW = 0x1, /* ack peer immediately */ // 0x00001
/*line: 100*/   TF_DELACK = 0x2, /* ack, but try to delay it */ // 0x00002
/*line: 101*/   TF_NODELAY = 0x4, /* don't delay packets to coalesce */ // 0x00004
/*line: 102*/   TF_NOOPT = 0x8, /* don't use tcp options */ // 0x00008
/*line: 103*/   TF_SENTFIN = 0x10, /* have sent FIN */ // 0x00010
/*line: 104*/   TF_REQ_SCALE = 0x20, /* have/will request window scaling */ // 0x00020
/*line: 105*/   TF_RCVD_SCALE = 0x40, /* other side has requested scaling */ // 0x00040
/*line: 106*/   TF_REQ_TSTMP = 0x80, /* have/will request timestamps */ // 0x00080
/*line: 107*/   TF_RCVD_TSTMP = 0x100, /* a timestamp was received in SYN */ // 0x00100
/*line: 108*/   TF_SACK_PERMIT = 0x200, /* other side said I could SACK */ // 0x00200
/*line: 109*/   TF_NEEDSYN = 0x400, /* send SYN (implicit state) - unused but needed for backwards compatibility */ // 0x00400
/*line: 110*/   TF_NEEDFIN = 0x800, /* send FIN (implicit state) */ // 0x00800
/*line: 111*/   TF_NOPUSH = 0x1000, /* don't push */ // 0x01000
/*line: 112*/   TF_REQ_CC = 0x2000, /* have/will request CC */ // 0x02000
/*line: 113*/   TF_RCVD_CC = 0x4000, /* a CC was received in SYN */ // 0x04000
/*line: 114*/   TF_SENDCCNEW = 0x8000, /* Not implemented */ // 0x08000
/*line: 115*/   TF_MORETOCOME = 0x10000, /* More data to be appended to sock */ // 0x10000
/*line: 116*/   TF_LQ_OVERFLOW = 0x20000, /* listen queue overflow */ // 0x20000
/*line: 117*/   TF_RXWIN0SENT = 0x40000, /* sent a receiver win 0 in response */ // 0x40000
/*line: 118*/   TF_SLOWLINK = 0x80000, /* route is a on a modem speed link */ // 0x80000
};

enum macro_tcp_out_of_band {
/*line: 166*/   TCPOOB_HAVEDATA = 0x1,  // 0x01
/*line: 167*/   TCPOOB_HADDATA = 0x2,  // 0x02
};

enum macro_tcp_controls {
/*
 * Names for TCP sysctl objects
 */
/*line: 601*/   TCPCTL_DO_RFC1323 = 0x1, /* use RFC-1323 extensions */ // 1
/*line: 602*/   TCPCTL_DO_RFC1644 = 0x2, /* use RFC-1644 extensions */ // 2
/*line: 603*/   TCPCTL_MSSDFLT = 0x3, /* MSS default */ // 3
/*line: 604*/   TCPCTL_STATS = 0x4, /* statistics (read-only) */ // 4
/*line: 605*/   TCPCTL_RTTDFLT = 0x5, /* default RTT estimate */ // 5
/*line: 606*/   TCPCTL_KEEPIDLE = 0x6, /* keepalive idle timer */ // 6
/*line: 607*/   TCPCTL_KEEPINTVL = 0x7, /* interval to send keepalives */ // 7
/*line: 608*/   TCPCTL_SENDSPACE = 0x8, /* send buffer space */ // 8
/*line: 609*/   TCPCTL_RECVSPACE = 0x9, /* receive buffer space */ // 9
/*line: 610*/   TCPCTL_KEEPINIT = 0xa, /* timeout for establishing syn */ // 10
/*line: 611*/   TCPCTL_PCBLIST = 0xb, /* list of all outstanding PCBs */ // 11
/*line: 612*/   TCPCTL_DELACKTIME = 0xc, /* time before sending delayed ACK */ // 12
/*line: 613*/   TCPCTL_V6MSSDFLT = 0xd, /* MSS default for IPv6 */ // 13
/*line: 614*/   TCPCTL_MAXID = 0xe,  // 14
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 187
// #define tcps_ecn_setup tcps_ecn_client_success

// Line: 188
// #define tcps_sent_cwr tcps_ecn_recv_ece

// Line: 189
// #define tcps_sent_ece tcps_ecn_sent_ece

