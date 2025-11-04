// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/if_var.h

enum macro_if_family {
/*line: 74*/    APPLE_IF_FAM_LOOPBACK = 0x1,  // 1
/*line: 75*/    APPLE_IF_FAM_ETHERNET = 0x2,  // 2
/*line: 76*/    APPLE_IF_FAM_SLIP = 0x3,  // 3
/*line: 77*/    APPLE_IF_FAM_TUN = 0x4,  // 4
/*line: 78*/    APPLE_IF_FAM_VLAN = 0x5,  // 5
/*line: 79*/    APPLE_IF_FAM_PPP = 0x6,  // 6
/*line: 80*/    APPLE_IF_FAM_PVC = 0x7,  // 7
/*line: 81*/    APPLE_IF_FAM_DISC = 0x8,  // 8
/*line: 82*/    APPLE_IF_FAM_MDECAP = 0x9,  // 9
/*line: 83*/    APPLE_IF_FAM_GIF = 0xa,  // 10
/*line: 84*/    APPLE_IF_FAM_FAITH = 0xb, /* deprecated */ // 11
/*line: 85*/    APPLE_IF_FAM_STF = 0xc,  // 12
/*line: 86*/    APPLE_IF_FAM_FIREWIRE = 0xd,  // 13
/*line: 87*/    APPLE_IF_FAM_BOND = 0xe,  // 14
/*line: 88*/    APPLE_IF_FAM_CELLULAR = 0xf,  // 15
/*line: 89*/    APPLE_IF_FAM_UNUSED_16 = 0x10, /* Un-used */ // 16
/*line: 90*/    APPLE_IF_FAM_UTUN = 0x11,  // 17
/*line: 91*/    APPLE_IF_FAM_IPSEC = 0x12,  // 18
};

enum macro_mtu_range {
/*
 * 72 was chosen below because it is the size of a TCP/IP
 * header (40) + the minimum mss (32).
 */
/*line: 98*/    IF_MINMTU = 0x48,  // 72
/*line: 99*/    IF_MAXMTU = 0xffff,  // 65535
};

enum macro_ifnam_size {
/*
 * Structures defining a network interface, providing a packet
 * transport mechanism (ala level 0 of the PUP protocols).
 *
 * Each interface accepts output datagrams of a specified maximum
 * length, and provides higher level routines with input datagrams
 * received from its medium.
 *
 * Output occurs when the routine if_output is called, with three parameters:
 *	(*ifp->if_output)(ifp, m, dst, rt)
 * Here m is the mbuf chain to be sent and dst is the destination address.
 * The output routine encapsulates the supplied datagram if necessary,
 * and then transmits it on its medium.
 *
 * On input, each interface unwraps the data received by it, and either
 * places it on the input queue of a internetwork datagram routine
 * and posts the associated software interrupt, or passes the datagram to a raw
 * packet input routine.
 *
 * Routines exist for locating interfaces by their addresses
 * or for locating a interface on a certain network, as well as more general
 * routing and gateway routines maintaining information used to locate
 * interfaces.  These routines live in the files if.c and route.c
 */
/*line: 126*/   IFNAMSIZ = 0x10,  // 16
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 140
// #define IF_DATA_TIMEVAL timeval32

