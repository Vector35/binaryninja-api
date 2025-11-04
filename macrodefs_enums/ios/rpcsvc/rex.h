// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpcsvc/rex.h

enum macro_rpcgen_version {
/*line: 9*/     RPCGEN_VERSION = 0x30b52,  // 199506
};

enum macro_string_size {
/*line: 13*/    STRINGSIZE = 0x400,  // 1024
};

enum macro_rex_flags {
/*line: 24*/    SIGINT = 0x2,  // 2
/*line: 25*/    REX_INTERACTIVE = 0x1,  // 1
/*line: 82*/    B0 = 0x0,  // 0
/*line: 83*/    B50 = 0x1,  // 1
/*line: 84*/    B75 = 0x2,  // 2
/*line: 85*/    B110 = 0x3,  // 3
/*line: 86*/    B134 = 0x4,  // 4
/*line: 87*/    B150 = 0x5,  // 5
/*line: 88*/    B200 = 0x6,  // 6
/*line: 89*/    B300 = 0x7,  // 7
/*line: 90*/    B600 = 0x8,  // 8
/*line: 91*/    B1200 = 0x9,  // 9
/*line: 92*/    B1800 = 0xa,  // 10
/*line: 93*/    B2400 = 0xb,  // 11
/*line: 94*/    B4800 = 0xc,  // 12
/*line: 95*/    B9600 = 0xd,  // 13
/*line: 96*/    B19200 = 0xe,  // 14
/*line: 97*/    B38400 = 0xf,  // 15
/*line: 98*/    TANDEM = 0x1,  // 0x00000001
/*line: 99*/    CBREAK = 0x2,  // 0x00000002
/*line: 100*/   LCASE = 0x4,  // 0x00000004
/*line: 101*/   ECHO = 0x8,  // 0x00000008
/*line: 102*/   CRMOD = 0x10,  // 0x00000010
/*line: 103*/   RAW = 0x20,  // 0x00000020
/*line: 104*/   ODDP = 0x40,  // 0x00000040
/*line: 105*/   EVENP = 0x80,  // 0x00000080
/*line: 106*/   ANYP = 0xc0,  // 0x000000c0
/*line: 107*/   NLDELAY = 0x300,  // 0x00000300
/*line: 108*/   NL0 = 0x0,  // 0x00000000
/*line: 109*/   NL1 = 0x100,  // 0x00000100
/*line: 110*/   NL2 = 0x200,  // 0x00000200
/*line: 111*/   NL3 = 0x300,  // 0x00000300
/*line: 112*/   TBDELAY = 0xc00,  // 0x00000c00
/*line: 113*/   TAB0 = 0x0,  // 0x00000000
/*line: 114*/   TAB1 = 0x400,  // 0x00000400
/*line: 115*/   TAB2 = 0x800,  // 0x00000800
/*line: 116*/   XTABS = 0xc00,  // 0x00000c00
/*line: 117*/   CRDELAY = 0x3000,  // 0x00003000
/*line: 118*/   CR0 = 0x0,  // 0x00000000
/*line: 119*/   CR1 = 0x1000,  // 0x00001000
/*line: 120*/   CR2 = 0x2000,  // 0x00002000
/*line: 121*/   CR3 = 0x3000,  // 0x00003000
/*line: 122*/   VTDELAY = 0x4000,  // 0x00004000
/*line: 123*/   FF0 = 0x0,  // 0x00000000
/*line: 124*/   FF1 = 0x4000,  // 0x00004000
/*line: 125*/   BSDELAY = 0x8000,  // 0x00008000
/*line: 126*/   BS0 = 0x0,  // 0x00000000
/*line: 127*/   BS1 = 0x8000,  // 0x00008000
/*line: 128*/   CRTBS = 0x10000,  // 0x00010000
/*line: 129*/   PRTERA = 0x20000,  // 0x00020000
/*line: 130*/   CRTERA = 0x40000,  // 0x00040000
/*line: 131*/   TILDE = 0x80000,  // 0x00080000
/*line: 132*/   MDMBUF = 0x100000,  // 0x00100000
/*line: 133*/   LITOUT = 0x200000,  // 0x00200000
/*line: 134*/   TOSTOP = 0x400000,  // 0x00400000
/*line: 135*/   FLUSHO = 0x800000,  // 0x00800000
/*line: 136*/   NOHANG = 0x1000000,  // 0x01000000
/*line: 137*/   L001000 = 0x2000000,  // 0x02000000
/*line: 138*/   CRTKIL = 0x4000000,  // 0x04000000
/*line: 139*/   PASS8 = 0x8000000,  // 0x08000000
/*line: 140*/   CTLECH = 0x10000000,  // 0x10000000
/*line: 141*/   PENDIN = 0x20000000,  // 0x20000000
/*line: 142*/   DECCTQ = 0x40000000,  // 0x40000000
/*line: 143*/   NOFLSH = 0x80000000,  // 0x80000000
};

enum macro_line_control_flags {
/*line: 203*/   LCRTBS = 0x1,  // 0x0001
/*line: 204*/   LPRTERA = 0x2,  // 0x0002
/*line: 205*/   LCRTERA = 0x4,  // 0x0004
/*line: 206*/   LTILDE = 0x8,  // 0x0008
/*line: 207*/   LMDMBUF = 0x10,  // 0x0010
/*line: 208*/   LLITOUT = 0x20,  // 0x0020
/*line: 209*/   LTOSTOP = 0x40,  // 0x0040
/*line: 210*/   LFLUSHO = 0x80,  // 0x0080
/*line: 211*/   LNOHANG = 0x100,  // 0x0100
/*line: 212*/   LL001000 = 0x200,  // 0x0200
/*line: 213*/   LCRTKIL = 0x400,  // 0x0400
/*line: 214*/   LPASS8 = 0x800,  // 0x0800
/*line: 215*/   LCTLECH = 0x1000,  // 0x1000
/*line: 216*/   LPENDIN = 0x2000,  // 0x2000
/*line: 217*/   LDECCTQ = 0x4000,  // 0x4000
/*line: 218*/   LNOFLSH = 0x8000,  // 0x8000
};

// Depends on identifiers
enum macro_rex_identifiers {
/*line: 220*/   REXPROG = 0x186b1,  // ((rpc_uint)100017)
/*line: 221*/   REXVERS = 0x1,  // ((rpc_uint)1)
};

// Depends on identifiers
enum macro_rex_procedure {
/*line: 241*/   REXPROC_START = 0x1,  // ((rpc_uint)1)
/*line: 244*/   REXPROC_WAIT = 0x2,  // ((rpc_uint)2)
/*line: 247*/   REXPROC_MODES = 0x3,  // ((rpc_uint)3)
/*line: 250*/   REXPROC_WINCH = 0x4,  // ((rpc_uint)4)
/*line: 253*/   REXPROC_SIGNAL = 0x5,  // ((rpc_uint)5)
};

