// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/if.h

enum macro_if_namesize {
/*line: 66*/    IF_NAMESIZE = 0x10,  // 16
};

// Depends on identifiers
enum macro_interface_flags {
/*line: 93*/    IFF_UP = 0x1, /* interface is up */ // 0x1
/*line: 94*/    IFF_BROADCAST = 0x2, /* broadcast address valid */ // 0x2
/*line: 95*/    IFF_DEBUG = 0x4, /* turn on debugging */ // 0x4
/*line: 96*/    IFF_LOOPBACK = 0x8, /* is a loopback net */ // 0x8
/*line: 97*/    IFF_POINTOPOINT = 0x10, /* interface is point-to-point link */ // 0x10
/*line: 98*/    IFF_NOTRAILERS = 0x20, /* obsolete: avoid use of trailers */ // 0x20
/*line: 99*/    IFF_RUNNING = 0x40, /* resources allocated */ // 0x40
/*line: 100*/   IFF_NOARP = 0x80, /* no address resolution protocol */ // 0x80
/*line: 101*/   IFF_PROMISC = 0x100, /* receive all packets */ // 0x100
/*line: 102*/   IFF_ALLMULTI = 0x200, /* receive all multicast packets */ // 0x200
/*line: 103*/   IFF_OACTIVE = 0x400, /* transmission in progress */ // 0x400
/*line: 104*/   IFF_SIMPLEX = 0x800, /* can't hear own transmissions */ // 0x800
/*line: 105*/   IFF_LINK0 = 0x1000, /* per link layer defined bit */ // 0x1000
/*line: 106*/   IFF_LINK1 = 0x2000, /* per link layer defined bit */ // 0x2000
/*line: 107*/   IFF_LINK2 = 0x4000, /* per link layer defined bit */ // 0x4000
/*line: 108*/   IFF_ALTPHYS = 0x4000, /* use alternate physical connection */ // IFF_LINK2
/*line: 109*/   IFF_MULTICAST = 0x8000, /* supports multicast */ // 0x8000
};

enum macro_ifcapabilities {
/*
 * Capabilities that interfaces can advertise.
 *
 * struct ifnet.if_capabilities
 *   contains the optional features & capabilities a particular interface
 *   supports (not only the driver but also the detected hw revision).
 *   Capabilities are defined by IFCAP_* below.
 * struct ifnet.if_capenable
 *   contains the enabled (either by default or through ifconfig) optional
 *   features & capabilities on this interface.
 *   Capabilities are defined by IFCAP_* below.
 * struct if_data.ifi_hwassist in IFNET_* form, defined in net/kpi_interface.h,
 *   contains the enabled optional features & capabilites that can be used
 *   individually per packet and are specified in the mbuf pkthdr.csum_flags
 *   field.  IFCAP_* and IFNET_* do not match one to one and IFNET_* may be
 *   more detailed or differentiated than IFCAP_*.
 *   IFNET_* hwassist flags have corresponding CSUM_* in sys/mbuf.h
 */
/*line: 130*/   IFCAP_RXCSUM = 0x1, /* can offload checksum on RX */ // 0x00001
/*line: 131*/   IFCAP_TXCSUM = 0x2, /* can offload checksum on TX */ // 0x00002
/*line: 132*/   IFCAP_VLAN_MTU = 0x4, /* VLAN-compatible MTU */ // 0x00004
/*line: 133*/   IFCAP_VLAN_HWTAGGING = 0x8, /* hardware VLAN tag support */ // 0x00008
/*line: 134*/   IFCAP_JUMBO_MTU = 0x10, /* 9000 byte MTU supported */ // 0x00010
/*line: 135*/   IFCAP_TSO4 = 0x20, /* can do TCP Segmentation Offload */ // 0x00020
/*line: 136*/   IFCAP_TSO6 = 0x40, /* can do TCP6 Segmentation Offload */ // 0x00040
/*line: 137*/   IFCAP_LRO = 0x80, /* can do Large Receive Offload */ // 0x00080
/*line: 138*/   IFCAP_AV = 0x100, /* can do 802.1 AV Bridging */ // 0x00100
/*line: 139*/   IFCAP_TXSTATUS = 0x200, /* can return linklevel xmit status */ // 0x00200
/*line: 140*/   IFCAP_SKYWALK = 0x400, /* Skywalk mode supported/enabled */ // 0x00400
/*line: 141*/   IFCAP_HW_TIMESTAMP = 0x800, /* Time stamping in hardware */ // 0x00800
/*line: 142*/   IFCAP_SW_TIMESTAMP = 0x1000, /* Time stamping in software */ // 0x01000
/*line: 143*/   IFCAP_CSUM_PARTIAL = 0x2000, /* can offload partial checksum */ // 0x02000
/*line: 144*/   IFCAP_CSUM_ZERO_INVERT = 0x4000, /* can invert 0 to -0 (0xffff) */ // 0x04000
/*line: 145*/   IFCAP_LRO_NUM_SEG = 0x8000, /* NIC & driver can set the num of segments a LRO-packet is built of */ // 0x08000
};

// Depends on identifiers
enum macro_interface_capabilities {
/*line: 147*/   IFCAP_HWCSUM = 0x3,  // (IFCAP_RXCSUM|IFCAP_TXCSUM)
/*line: 148*/   IFCAP_TSO = 0x60,  // (IFCAP_TSO4|IFCAP_TSO6)
};

// Depends on identifiers
enum macro_ifcap_flags {
/*line: 150*/   IFCAP_VALID = 0xffff,  // (IFCAP_HWCSUM|IFCAP_TSO|IFCAP_LRO|IFCAP_VLAN_MTU|IFCAP_VLAN_HWTAGGING|IFCAP_JUMBO_MTU|IFCAP_AV|IFCAP_TXSTATUS|IFCAP_SKYWALK|IFCAP_SW_TIMESTAMP|IFCAP_HW_TIMESTAMP|IFCAP_CSUM_PARTIAL|IFCAP_CSUM_ZERO_INVERT|IFCAP_LRO_NUM_SEG)
};

enum macro_ifq_constants {
/*line: 155*/   IFQ_MAXLEN = 0x80,  // 128
/*line: 156*/   IFNET_SLOWHZ = 0x1, /* granularity is 1 second */ // 1
/*line: 157*/   IFQ_DEF_C_TARGET_DELAY = 0x989680, /* 10 ms */ // (10ULL*1000*1000)
/*line: 158*/   IFQ_DEF_C_UPDATE_INTERVAL = 0x5f5e100, /* 100 ms */ // (100ULL*1000*1000)
/*line: 159*/   IFQ_DEF_L4S_TARGET_DELAY = 0x1e8480, /* 2 ms */ // (2ULL*1000*1000)
/*line: 160*/   IFQ_DEF_L4S_WIRELESS_TARGET_DELAY = 0xe4e1c0, /* 15 ms */ // (15ULL*1000*1000)
/*line: 161*/   IFQ_DEF_L4S_UPDATE_INTERVAL = 0x5f5e100, /* 100 ms */ // (100ULL*1000*1000)
/*line: 162*/   IFQ_LL_C_TARGET_DELAY = 0x989680, /* 10 ms */ // (10ULL*1000*1000)
/*line: 163*/   IFQ_LL_C_UPDATE_INTERVAL = 0x5f5e100, /* 100 ms */ // (100ULL*1000*1000)
/*line: 164*/   IFQ_LL_L4S_TARGET_DELAY = 0x1e8480, /* 2 ms */ // (2ULL*1000*1000)
/*line: 165*/   IFQ_LL_L4S_WIRELESS_TARGET_DELAY = 0xe4e1c0, /* 15 ms */ // (15ULL*1000*1000)
/*line: 166*/   IFQ_LL_L4S_UPDATE_INTERVAL = 0x5f5e100, /* 100 ms */ // (100ULL*1000*1000)
};

enum macro_wake_on_magic_packet {
/* Wake capabilities of a interface */
/*line: 288*/   IF_WAKE_ON_MAGIC_PACKET = 0x1,  // 0x01
};

enum macro_ifr_type {
/*line: 323*/   IFRTYPE_FUNCTIONAL_UNKNOWN = 0x0,  // 0
/*line: 324*/   IFRTYPE_FUNCTIONAL_LOOPBACK = 0x1,  // 1
/*line: 325*/   IFRTYPE_FUNCTIONAL_WIRED = 0x2,  // 2
/*line: 326*/   IFRTYPE_FUNCTIONAL_WIFI_INFRA = 0x3,  // 3
/*line: 327*/   IFRTYPE_FUNCTIONAL_WIFI_AWDL = 0x4,  // 4
/*line: 328*/   IFRTYPE_FUNCTIONAL_CELLULAR = 0x5,  // 5
/*line: 329*/   IFRTYPE_FUNCTIONAL_INTCOPROC = 0x6,  // 6
/*line: 330*/   IFRTYPE_FUNCTIONAL_COMPANIONLINK = 0x7,  // 7
/*line: 331*/   IFRTYPE_FUNCTIONAL_MANAGEMENT = 0x8,  // 8
/*line: 332*/   IFRTYPE_FUNCTIONAL_LAST = 0x8,  // 8
};

enum macro_ifstatmax {
/*
 * Structure used to retrieve aux status data from interfaces.
 * Kernel suppliers to this interface should respect the formatting
 * needed by ifconfig(8): each line starts with a TAB and ends with
 * a newline.
 */
/*line: 415*/   IFSTATMAX = 0x320, /* 10 lines of text */ // 800
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 336
// #define ifr_addr ifr_ifru.ifru_addr

// Line: 337
// #define ifr_dstaddr ifr_ifru.ifru_dstaddr

// Line: 338
// #define ifr_broadaddr ifr_ifru.ifru_broadaddr

// Line: 340
// #define ifr_flags ifr_ifru.ifru_flags

// Line: 345
// #define ifr_metric ifr_ifru.ifru_metric

// Line: 346
// #define ifr_mtu ifr_ifru.ifru_mtu

// Line: 347
// #define ifr_phys ifr_ifru.ifru_phys

// Line: 348
// #define ifr_media ifr_ifru.ifru_media

// Line: 349
// #define ifr_data ifr_ifru.ifru_data

// Line: 350
// #define ifr_devmtu ifr_ifru.ifru_devmtu

// Line: 351
// #define ifr_intval ifr_ifru.ifru_intval

// Line: 352
// #define ifr_kpi ifr_ifru.ifru_kpi

// Line: 353
// #define ifr_wake_flags ifr_ifru.ifru_wake_flags

// Line: 354
// #define ifr_route_refcnt ifr_ifru.ifru_route_refcnt

// Line: 355
// #define ifr_reqcap ifr_ifru.ifru_cap[0]

// Line: 356
// #define ifr_curcap ifr_ifru.ifru_cap[1]

// Line: 436
// #define ifc_buf ifc_ifcu.ifcu_buf

// Line: 437
// #define ifc_req ifc_ifcu.ifcu_req

