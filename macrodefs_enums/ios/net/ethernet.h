// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/ethernet.h

enum macro_ether_addr_len {
/*
 * The number of bytes in an ethernet (MAC) address.
 */
/*line: 41*/    ETHER_ADDR_LEN = 0x6,  // 6
};

// Depends on identifiers
enum macro_ether_lengths {
/*
 * The number of bytes in the type field.
 */
/*line: 46*/    ETHER_TYPE_LEN = 0x2,  // 2
/*
 * The number of bytes in the trailing CRC field.
 */
/*line: 51*/    ETHER_CRC_LEN = 0x4,  // 4
/*
 * The length of the combined header.
 */
/*line: 56*/    ETHER_HDR_LEN = 0xe,  // (ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)
/*
 * The minimum packet length.
 */
/*line: 61*/    ETHER_MIN_LEN = 0x40,  // 64
};

enum macro_ether_max_len {
/*
 * The maximum packet length.
 */
/*line: 66*/    ETHER_MAX_LEN = 0x5ee,  // 1518
};

enum macro_ethernet_types {
/*
 * Mbuf adjust factor to force 32-bit alignment of IP header.
 * Drivers should do m_adj(m, ETHER_ALIGN) when setting up a
 * receive so the upper layers get the IP header properly aligned
 * past the 14-byte Ethernet header.
 */
/*line: 74*/    ETHER_ALIGN = 0x2, /* driver adjust for IP hdr alignment */ // 2
/*line: 100*/   ETHERTYPE_PUP = 0x200, /* PUP protocol */ // 0x0200
/*line: 101*/   ETHERTYPE_IP = 0x800, /* IP protocol */ // 0x0800
/*line: 102*/   ETHERTYPE_ARP = 0x806, /* Addr. resolution protocol */ // 0x0806
/*line: 103*/   ETHERTYPE_REVARP = 0x8035, /* reverse Addr. resolution protocol */ // 0x8035
/*line: 104*/   ETHERTYPE_VLAN = 0x8100, /* IEEE 802.1Q VLAN tagging */ // 0x8100
/*line: 105*/   ETHERTYPE_IPV6 = 0x86dd, /* IPv6 */ // 0x86dd
/*line: 106*/   ETHERTYPE_PAE = 0x888e, /* EAPOL PAE/802.1x */ // 0x888e
/*line: 107*/   ETHERTYPE_RSN_PREAUTH = 0x88c7, /* 802.11i / RSN Pre-Authentication */ // 0x88c7
/*line: 108*/   ETHERTYPE_PTP = 0x88f7, /* IEEE 1588 Precision Time Protocol */ // 0x88f7
/*line: 109*/   ETHERTYPE_LOOPBACK = 0x9000, /* used to test interfaces */ // 0x9000
};

enum macro_ethertypes {
/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
/*line: 117*/   ETHERTYPE_TRAIL = 0x1000, /* Trailer packet */ // 0x1000
/*line: 118*/   ETHERTYPE_NTRAILER = 0x10,  // 16
};

// Depends on identifiers
enum macro_ether_mtu_min {
/*line: 120*/   ETHERMTU = 0x5dc,  // (ETHER_MAX_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)
/*line: 121*/   ETHERMIN = 0x2e,  // (ETHER_MIN_LEN-ETHER_HDR_LEN-ETHER_CRC_LEN)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 98
// #define ether_addr_octet octet

