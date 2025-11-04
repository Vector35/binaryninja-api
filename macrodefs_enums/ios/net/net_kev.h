// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/net_kev.h

enum macro_inet_event {
/* Kernel event subclass identifiers for KEV_NETWORK_CLASS */
/*line: 35*/    KEV_INET_SUBCLASS = 0x1, /* inet subclass */ // 1
/* KEV_INET_SUBCLASS event codes */
/*line: 37*/    KEV_INET_NEW_ADDR = 0x1, /* Userland configured IP address */ // 1
/*line: 38*/    KEV_INET_CHANGED_ADDR = 0x2, /* Address changed event */ // 2
/*line: 39*/    KEV_INET_ADDR_DELETED = 0x3, /* IPv6 address was deleted */ // 3
/*line: 40*/    KEV_INET_SIFDSTADDR = 0x4, /* Dest. address was set */ // 4
/*line: 41*/    KEV_INET_SIFBRDADDR = 0x5, /* Broadcast address was set */ // 5
/*line: 42*/    KEV_INET_SIFNETMASK = 0x6, /* Netmask was set */ // 6
/*line: 43*/    KEV_INET_ARPCOLLISION = 0x7, /* ARP collision detected */ // 7
/*line: 45*/    KEV_INET_PORTINUSE = 0x8, /* use ken_in_portinuse */ // 8
/*line: 47*/    KEV_INET_ARPRTRFAILURE = 0x9, /* ARP resolution failed for router */ // 9
/*line: 48*/    KEV_INET_ARPRTRALIVE = 0xa, /* ARP resolution succeeded for router */ // 10
};

enum macro_data_link_events {
/*line: 50*/    KEV_DL_SUBCLASS = 0x2, /* Data Link subclass */ // 2
/*
 * Define Data-Link event subclass, and associated
 * events.
 */
/*line: 55*/    KEV_DL_SIFFLAGS = 0x1,  // 1
/*line: 56*/    KEV_DL_SIFMETRICS = 0x2,  // 2
/*line: 57*/    KEV_DL_SIFMTU = 0x3,  // 3
/*line: 58*/    KEV_DL_SIFPHYS = 0x4,  // 4
/*line: 59*/    KEV_DL_SIFMEDIA = 0x5,  // 5
/*line: 60*/    KEV_DL_SIFGENERIC = 0x6,  // 6
/*line: 61*/    KEV_DL_ADDMULTI = 0x7,  // 7
/*line: 62*/    KEV_DL_DELMULTI = 0x8,  // 8
/*line: 63*/    KEV_DL_IF_ATTACHED = 0x9,  // 9
/*line: 64*/    KEV_DL_IF_DETACHING = 0xa,  // 10
/*line: 65*/    KEV_DL_IF_DETACHED = 0xb,  // 11
/*line: 66*/    KEV_DL_LINK_OFF = 0xc,  // 12
/*line: 67*/    KEV_DL_LINK_ON = 0xd,  // 13
/*line: 68*/    KEV_DL_PROTO_ATTACHED = 0xe,  // 14
/*line: 69*/    KEV_DL_PROTO_DETACHED = 0xf,  // 15
/*line: 70*/    KEV_DL_LINK_ADDRESS_CHANGED = 0x10,  // 16
/*line: 71*/    KEV_DL_WAKEFLAGS_CHANGED = 0x11,  // 17
/*line: 72*/    KEV_DL_IF_IDLE_ROUTE_REFCNT = 0x12,  // 18
/*line: 73*/    KEV_DL_IFCAP_CHANGED = 0x13,  // 19
/*line: 74*/    KEV_DL_LINK_QUALITY_METRIC_CHANGED = 0x14,  // 20
/*line: 75*/    KEV_DL_NODE_PRESENCE = 0x15,  // 21
/*line: 76*/    KEV_DL_NODE_ABSENCE = 0x16,  // 22
/*line: 77*/    KEV_DL_PRIMARY_ELECTED = 0x17,  // 23
/*line: 78*/    KEV_DL_ISSUES = 0x18,  // 24
/*line: 79*/    KEV_DL_IFDELEGATE_CHANGED = 0x19,  // 25
/*line: 80*/    KEV_DL_AWDL_RESTRICTED = 0x1a,  // 26
/*line: 81*/    KEV_DL_AWDL_UNRESTRICTED = 0x1b,  // 27
/*line: 82*/    KEV_DL_RRC_STATE_CHANGED = 0x1c,  // 28
/*line: 83*/    KEV_DL_QOS_MODE_CHANGED = 0x1d,  // 29
/*line: 84*/    KEV_DL_LOW_POWER_MODE_CHANGED = 0x1e,  // 30
};

enum macro_inet6_event {
/*line: 89*/    KEV_INET6_SUBCLASS = 0x6, /* inet6 subclass */ // 6
/* KEV_INET6_SUBCLASS event codes */
/*line: 91*/    KEV_INET6_NEW_USER_ADDR = 0x1, /* Userland configured IPv6 address */ // 1
/*line: 92*/    KEV_INET6_CHANGED_ADDR = 0x2, /* Address changed event (future) */ // 2
/*line: 93*/    KEV_INET6_ADDR_DELETED = 0x3, /* IPv6 address was deleted */ // 3
/*line: 94*/    KEV_INET6_NEW_LL_ADDR = 0x4, /* Autoconf LL address appeared */ // 4
/*line: 95*/    KEV_INET6_NEW_RTADV_ADDR = 0x5, /* Autoconf address has appeared */ // 5
/*line: 96*/    KEV_INET6_DEFROUTER = 0x6, /* Default router detected */ // 6
/*line: 97*/    KEV_INET6_REQUEST_NAT64_PREFIX = 0x7, /* Asking for the NAT64-prefix */ // 7
};

