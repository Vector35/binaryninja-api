// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/net/if_types.h

// Depends on identifiers
enum macro_interface_types {
/*
 * Interface types for benefit of parsing media address headers.
 * This list is derived from the SNMP list of ifTypes, currently
 * documented in RFC1573.
 * The current list of assignments is maintained at:
 *      http://www.iana.org/assignments/smi-numbers
 */
/*line: 76*/    IFT_OTHER = 0x1, /* none of the following */ // 0x1
/*line: 77*/    IFT_1822 = 0x2, /* old-style arpanet imp */ // 0x2
/*line: 78*/    IFT_HDH1822 = 0x3, /* HDH arpanet imp */ // 0x3
/*line: 79*/    IFT_X25DDN = 0x4, /* x25 to imp */ // 0x4
/*line: 80*/    IFT_X25 = 0x5, /* PDN X25 interface (RFC877) */ // 0x5
/*line: 81*/    IFT_ETHER = 0x6, /* Ethernet CSMACD */ // 0x6
/*line: 82*/    IFT_ISO88023 = 0x7, /* CMSA CD */ // 0x7
/*line: 83*/    IFT_ISO88024 = 0x8, /* Token Bus */ // 0x8
/*line: 84*/    IFT_ISO88025 = 0x9, /* Token Ring */ // 0x9
/*line: 85*/    IFT_ISO88026 = 0xa, /* MAN */ // 0xa
/*line: 86*/    IFT_STARLAN = 0xb,  // 0xb
/*line: 87*/    IFT_P10 = 0xc, /* Proteon 10MBit ring */ // 0xc
/*line: 88*/    IFT_P80 = 0xd, /* Proteon 80MBit ring */ // 0xd
/*line: 89*/    IFT_HY = 0xe, /* Hyperchannel */ // 0xe
/*line: 90*/    IFT_FDDI = 0xf,  // 0xf
/*line: 91*/    IFT_LAPB = 0x10,  // 0x10
/*line: 92*/    IFT_SDLC = 0x11,  // 0x11
/*line: 93*/    IFT_T1 = 0x12,  // 0x12
/*line: 94*/    IFT_CEPT = 0x13, /* E1 - european T1 */ // 0x13
/*line: 95*/    IFT_ISDNBASIC = 0x14,  // 0x14
/*line: 96*/    IFT_ISDNPRIMARY = 0x15,  // 0x15
/*line: 97*/    IFT_PTPSERIAL = 0x16, /* Proprietary PTP serial */ // 0x16
/*line: 98*/    IFT_PPP = 0x17, /* RFC 1331 */ // 0x17
/*line: 99*/    IFT_LOOP = 0x18, /* loopback */ // 0x18
/*line: 100*/   IFT_EON = 0x19, /* ISO over IP */ // 0x19
/*line: 101*/   IFT_XETHER = 0x1a, /* obsolete 3MB experimental ethernet */ // 0x1a
/*line: 102*/   IFT_NSIP = 0x1b, /* XNS over IP */ // 0x1b
/*line: 103*/   IFT_SLIP = 0x1c, /* IP over generic TTY */ // 0x1c
/*line: 104*/   IFT_ULTRA = 0x1d, /* Ultra Technologies */ // 0x1d
/*line: 105*/   IFT_DS3 = 0x1e, /* Generic T3 */ // 0x1e
/*line: 106*/   IFT_SIP = 0x1f, /* SMDS */ // 0x1f
/*line: 107*/   IFT_FRELAY = 0x20, /* Frame Relay DTE only */ // 0x20
/*line: 108*/   IFT_RS232 = 0x21,  // 0x21
/*line: 109*/   IFT_PARA = 0x22, /* parallel-port */ // 0x22
/*line: 110*/   IFT_ARCNET = 0x23,  // 0x23
/*line: 111*/   IFT_ARCNETPLUS = 0x24,  // 0x24
/*line: 112*/   IFT_ATM = 0x25, /* ATM cells */ // 0x25
/*line: 113*/   IFT_MIOX25 = 0x26,  // 0x26
/*line: 114*/   IFT_SONET = 0x27, /* SONET or SDH */ // 0x27
/*line: 115*/   IFT_X25PLE = 0x28,  // 0x28
/*line: 116*/   IFT_ISO88022LLC = 0x29,  // 0x29
/*line: 117*/   IFT_LOCALTALK = 0x2a,  // 0x2a
/*line: 118*/   IFT_SMDSDXI = 0x2b,  // 0x2b
/*line: 119*/   IFT_FRELAYDCE = 0x2c, /* Frame Relay DCE */ // 0x2c
/*line: 120*/   IFT_V35 = 0x2d,  // 0x2d
/*line: 121*/   IFT_HSSI = 0x2e,  // 0x2e
/*line: 122*/   IFT_HIPPI = 0x2f,  // 0x2f
/*line: 123*/   IFT_MODEM = 0x30, /* Generic Modem */ // 0x30
/*line: 124*/   IFT_AAL5 = 0x31, /* AAL5 over ATM */ // 0x31
/*line: 125*/   IFT_SONETPATH = 0x32,  // 0x32
/*line: 126*/   IFT_SONETVT = 0x33,  // 0x33
/*line: 127*/   IFT_SMDSICIP = 0x34, /* SMDS InterCarrier Interface */ // 0x34
/*line: 128*/   IFT_PROPVIRTUAL = 0x35, /* Proprietary Virtual/internal */ // 0x35
/*line: 129*/   IFT_PROPMUX = 0x36, /* Proprietary Multiplexing */ // 0x36
/*
 * IFT_GIF, IFT_FAITH and IFT_6LOWPAN are not based on IANA assignments.
 * Note: IFT_STF has a defined ifType: 0xd7 (215), but we use 0x39.
 */
/*line: 134*/   IFT_GIF = 0x37, /*0xf0*/ // 0x37
/*line: 135*/   IFT_FAITH = 0x38, /*0xf2*/ // 0x38
/*line: 136*/   IFT_STF = 0x39, /*0xf3*/ // 0x39
/*line: 137*/   IFT_6LOWPAN = 0x40, /* IETF RFC 6282 */ // 0x40
/*line: 139*/   IFT_L2VLAN = 0x87, /* Layer 2 Virtual LAN using 802.1Q */ // 0x87
/*line: 140*/   IFT_IEEE8023ADLAG = 0x88, /* IEEE802.3ad Link Aggregate */ // 0x88
/*line: 141*/   IFT_IEEE1394 = 0x90, /* IEEE1394 High Performance SerialBus*/ // 0x90
/*line: 142*/   IFT_BRIDGE = 0xd1, /* Transparent bridge interface */ // 0xd1
/*line: 144*/   IFT_ENC = 0xf4, /* Encapsulation */ // 0xf4
/*line: 145*/   IFT_PFLOG = 0xf5, /* Packet filter logging */ // 0xf5
/*line: 146*/   IFT_PFSYNC = 0xf6, /* Packet filter state syncing */ // 0xf6
/*line: 147*/   IFT_CARP = 0xf8, /* Common Address Redundancy Protocol */ // 0xf8
/*line: 148*/   IFT_PKTAP = 0xfe, /* Packet tap pseudo interface */ // 0xfe
/*line: 149*/   IFT_CELLULAR = 0xff, /* Packet Data over Cellular */ // 0xff
/*line: 150*/   IFT_PDP = 0xff, /* deprecated; use IFT_CELLULAR */ // IFT_CELLULAR
};

