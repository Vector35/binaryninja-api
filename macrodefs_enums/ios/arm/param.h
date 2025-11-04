// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/arm/param.h

// Depends on identifiers
enum macro_arm_alignbytes {
/*
 * Round p (pointer or byte index) up to a correctly-aligned value for all
 * data types (int, long, ...).   The result is unsigned int and must be
 * cast to any desired pointer type.
 */
/*line: 60*/    ALIGNBYTES = -0x1,  // __DARWIN_ALIGNBYTES
};

// Depends on identifiers
enum macro_arm_params {
/*line: 63*/    NBPG = 0x1000, /* bytes/page */ // 4096
/*line: 64*/    PGOFSET = 0xfff, /* byte offset into page */ // (NBPG-1)
/*line: 65*/    PGSHIFT = 0xc, /* LOG2(NBPG) */ // 12
/*line: 67*/    DEV_BSIZE = 0x200,  // 512
/*line: 68*/    DEV_BSHIFT = 0x9, /* log2(DEV_BSIZE) */ // 9
/*line: 69*/    BLKDEV_IOSIZE = 0x800,  // 2048
/*line: 70*/    MAXPHYS = 0x10000, /* max raw I/O transfer size */ // (64*1024)
/*line: 72*/    CLSIZE = 0x1,  // 1
/*line: 73*/    CLSIZELOG2 = 0x0,  // 0
};

// Depends on identifiers
enum macro_arm_mbuf_sizes {
/*
 * Constants related to network buffer management.
 * MCLBYTES must be no larger than CLBYTES (the software page size), and,
 * on machines that exchange pages of input or output buffers with mbuf
 * clusters (MAPPED_MBUFS), MCLBYTES must also be an integral multiple
 * of the hardware page size.
 */
/*line: 82*/    MSIZESHIFT = 0x8, /* 256 */ // 8
/*line: 83*/    MSIZE = 0x100, /* size of an mbuf */ // (1<<MSIZESHIFT)
/*line: 84*/    MCLSHIFT = 0xb, /* 2048 */ // 11
/*line: 85*/    MCLBYTES = 0x800, /* size of an mbuf cluster */ // (1<<MCLSHIFT)
/*line: 86*/    MBIGCLSHIFT = 0xc, /* 4096 */ // 12
/*line: 87*/    MBIGCLBYTES = 0x1000, /* size of a big cluster */ // (1<<MBIGCLSHIFT)
/*line: 88*/    M16KCLSHIFT = 0xe, /* 16384 */ // 14
/*line: 89*/    M16KCLBYTES = 0x4000, /* size of a jumbo cluster */ // (1<<M16KCLSHIFT)
/*line: 91*/    MCLOFSET = 0x7ff,  // (MCLBYTES-1)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 93
// #define NMBCLUSTERS CONFIG_NMBCLUSTERS

