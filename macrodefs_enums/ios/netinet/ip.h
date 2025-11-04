// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet/ip.h

enum macro_ip_flags {
/*
 * Definitions for internet protocol version 4.
 * Per RFC 791, September 1981.
 */
/*line: 76*/    IPVERSION = 0x4,  // 4
/*line: 98*/    IP_RF = 0x8000, /* reserved fragment flag */ // 0x8000
/*line: 99*/    IP_DF = 0x4000, /* dont fragment flag */ // 0x4000
/*line: 100*/   IP_MF = 0x2000, /* more fragments flag */ // 0x2000
/*line: 101*/   IP_OFFMASK = 0x1fff, /* mask for fragmenting bits */ // 0x1fff
};

enum macro_ip_maxpacket {
/*line: 115*/   IP_MAXPACKET = 0xffff, /* maximum packet size */ // 65535
};

enum macro_ip_tos {
/*
 * Definitions for IP type of service (ip_tos)
 */
/*line: 120*/   IPTOS_LOWDELAY = 0x10,  // 0x10
/*line: 121*/   IPTOS_THROUGHPUT = 0x8,  // 0x08
/*line: 122*/   IPTOS_RELIABILITY = 0x4,  // 0x04
/*line: 123*/   IPTOS_MINCOST = 0x2,  // 0x02
/* ECN RFC3168 obsoletes RFC2481, and these will be deprecated soon. */
/*line: 126*/   IPTOS_CE = 0x1,  // 0x01
/*line: 127*/   IPTOS_ECT = 0x2,  // 0x02
};

enum macro_dscp_shift {
/*line: 130*/   IPTOS_DSCP_SHIFT = 0x2,  // 2
};

enum macro_ip_ecn_flags {
/*
 * ECN (Explicit Congestion Notification) codepoints in RFC3168
 * mapped to the lower 2 bits of the TOS field.
 */
/*line: 136*/   IPTOS_ECN_NOTECT = 0x0, /* not-ECT */ // 0x00
/*line: 137*/   IPTOS_ECN_ECT1 = 0x1, /* ECN-capable transport (1) */ // 0x01
/*line: 138*/   IPTOS_ECN_ECT0 = 0x2, /* ECN-capable transport (0) */ // 0x02
/*line: 139*/   IPTOS_ECN_CE = 0x3, /* congestion experienced */ // 0x03
/*line: 140*/   IPTOS_ECN_MASK = 0x3, /* ECN field mask */ // 0x03
};

enum macro_ip_precedence {
/*
 * Definitions for IP precedence (also in ip_tos) (hopefully unused)
 */
/*line: 145*/   IPTOS_PREC_NETCONTROL = 0xe0,  // 0xe0
/*line: 146*/   IPTOS_PREC_INTERNETCONTROL = 0xc0,  // 0xc0
/*line: 147*/   IPTOS_PREC_CRITIC_ECP = 0xa0,  // 0xa0
/*line: 148*/   IPTOS_PREC_FLASHOVERRIDE = 0x80,  // 0x80
/*line: 149*/   IPTOS_PREC_FLASH = 0x60,  // 0x60
/*line: 150*/   IPTOS_PREC_IMMEDIATE = 0x40,  // 0x40
/*line: 151*/   IPTOS_PREC_PRIORITY = 0x20,  // 0x20
/*line: 152*/   IPTOS_PREC_ROUTINE = 0x0,  // 0x00
};

enum macro_ip_option_type {
/*line: 161*/   IPOPT_CONTROL = 0x0,  // 0x00
/*line: 162*/   IPOPT_RESERVED1 = 0x20,  // 0x20
/*line: 163*/   IPOPT_DEBMEAS = 0x40,  // 0x40
/*line: 164*/   IPOPT_RESERVED2 = 0x60,  // 0x60
};

enum macro_ip_options {
/*line: 166*/   IPOPT_EOL = 0x0, /* end of option list */ // 0
/*line: 167*/   IPOPT_NOP = 0x1, /* no operation */ // 1
/*line: 169*/   IPOPT_RR = 0x7, /* record packet route */ // 7
/*line: 170*/   IPOPT_TS = 0x44, /* timestamp */ // 68
/*line: 171*/   IPOPT_SECURITY = 0x82, /* provide s,c,h,tcc */ // 130
/*line: 172*/   IPOPT_LSRR = 0x83, /* loose source route */ // 131
/*line: 173*/   IPOPT_SATID = 0x88, /* satnet id */ // 136
/*line: 174*/   IPOPT_SSRR = 0x89, /* strict source route */ // 137
/*line: 175*/   IPOPT_RA = 0x94, /* router alert */ // 148
};

enum macro_ip_option_field_offsets {
/*
 * Offsets to fields in options other than EOL and NOP.
 */
/*line: 180*/   IPOPT_OPTVAL = 0x0, /* option ID */ // 0
/*line: 181*/   IPOPT_OLEN = 0x1, /* option length */ // 1
/*line: 182*/   IPOPT_OFFSET = 0x2, /* offset within option */ // 2
/*line: 183*/   IPOPT_MINOFF = 0x4, /* min value of above */ // 4
};

enum macro_ip_option_timestamp_bits {
/* flag bits for ipt_flg */
/*line: 210*/   IPOPT_TS_TSONLY = 0x0, /* timestamps only */ // 0
/*line: 211*/   IPOPT_TS_TSANDADDR = 0x1, /* timestamps and addresses */ // 1
/*line: 212*/   IPOPT_TS_PRESPEC = 0x3, /* specified modules only */ // 3
};

enum macro_ip_security_level {
/* bits for security (not byte swapped) */
/*line: 215*/   IPOPT_SECUR_UNCLASS = 0x0,  // 0x0000
/*line: 216*/   IPOPT_SECUR_CONFID = 0xf135,  // 0xf135
/*line: 217*/   IPOPT_SECUR_EFTO = 0x789a,  // 0x789a
/*line: 218*/   IPOPT_SECUR_MMMM = 0xbc4d,  // 0xbc4d
/*line: 219*/   IPOPT_SECUR_RESTR = 0xaf13,  // 0xaf13
/*line: 220*/   IPOPT_SECUR_SECRET = 0xd788,  // 0xd788
/*line: 221*/   IPOPT_SECUR_TOPSECRET = 0x6bc5,  // 0x6bc5
};

enum macro_ip_impl_parameters {
/*
 * Internet implementation parameters.
 */
/*line: 226*/   MAXTTL = 0xff, /* maximum time to live (seconds) */ // 255
/*line: 227*/   IPDEFTTL = 0x40, /* default ttl, from RFC 1340 */ // 64
/*line: 228*/   IPFRAGTTL = 0x1e, /* time to live for frags (seconds) */ // 30
/*line: 229*/   IPTTLDEC = 0x1, /* subtracted when forwarding */ // 1
};

enum macro_ip_default_mss {
/*line: 231*/   IP_MSS = 0x240, /* default maximum segment size */ // 576
};

