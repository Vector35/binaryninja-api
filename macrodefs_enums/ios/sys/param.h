// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/param.h

enum macro_bsd_version {
/*line: 72*/    BSD = 0x30b52, /* System version (year & month). */ // 199506
/*line: 73*/    BSD4_3 = 0x1,  // 1
/*line: 74*/    BSD4_4 = 0x1,  // 1
};

enum macro_nextbsd_version {
/*line: 76*/    NeXTBSD = 0x1e7138, /* NeXTBSD version (year, month, release) */ // 1995064
/*line: 77*/    NeXTBSD4_0 = 0x0, /* NeXTBSD 4.0 */ // 0
};

// Depends on identifiers
enum macro_system_limits {
/*line: 95*/    MAXCOMLEN = 0x10, /* max command name remembered */ // 16
/*line: 96*/    MAXINTERP = 0x40, /* max interpreter file name length */ // 64
/*line: 97*/    MAXLOGNAME = 0xff, /* max login name length */ // 255
/*line: 98*/    MAXUPRC = 0x10a, /* max simultaneous processes */ // CHILD_MAX
/*line: 99*/    NCARGS = 0x40000, /* max bytes for an exec function */ // ARG_MAX
/*line: 100*/   NGROUPS = 0x10, /* max number groups */ // NGROUPS_MAX
/*line: 101*/   NOFILE = 0x100, /* default max open files per process */ // 256
/*line: 102*/   NOGROUP = 0xffff, /* marker for empty group set member */ // 65535
/*line: 103*/   MAXHOSTNAMELEN = 0x100, /* max hostname size */ // 256
/*line: 104*/   MAXDOMNAMELEN = 0x100, /* maximum domain name length */ // 256
};

enum macro_priority {
/*
 * Priorities.  Note that with 32 run queues, differences less than 4 are
 * insignificant.
 */
/*line: 119*/   PSWP = 0x0,  // 0
/*line: 120*/   PVM = 0x4,  // 4
/*line: 121*/   PINOD = 0x8,  // 8
/*line: 122*/   PRIBIO = 0x10,  // 16
/*line: 123*/   PVFS = 0x14,  // 20
/*line: 124*/   PZERO = 0x16, /* No longer magic, shouldn't be here.  XXX */ // 22
/*line: 125*/   PSOCK = 0x18,  // 24
/*line: 126*/   PWAIT = 0x20,  // 32
/*line: 127*/   PLOCK = 0x24,  // 36
/*line: 128*/   PPAUSE = 0x28,  // 40
/*line: 129*/   PUSER = 0x32,  // 50
/*line: 130*/   MAXPRI = 0x7f, /* Priorities range from 0 through MAXPRI. */ // 127
};

enum macro_priority_flags {
/*line: 132*/   PRIMASK = 0xff,  // 0x0ff
/*line: 133*/   PCATCH = 0x100, /* OR'd with pri for tsleep to check signals */ // 0x100
/*line: 134*/   PTTYBLOCK = 0x200, /* for tty SIGTTOU and SIGTTIN blocking */ // 0x200
/*line: 135*/   PDROP = 0x400, /* OR'd with pri to stop re-aquistion of mutex upon wakeup */ // 0x400
/*line: 136*/   PSPIN = 0x800, /* OR'd with pri to require mutex in spin mode upon wakeup */ // 0x800
};

// Depends on identifiers
enum macro_file_flags {
/*line: 140*/   CMASK = 0x12, /* default file mask: S_IWGRP|S_IWOTH */ // 022
/*line: 141*/   NODEV = -0x1, /* non-existent device */ // (dev_t)(-1)
};

// Depends on identifiers
enum macro_page_cluster {
/*
 * Clustering of hardware pages on machines with ridiculously small
 * page sizes is done here.  The paging subsystem deals with units of
 * CLSIZE pte's describing NBPG (from machine/param.h) pages each.
 */
/*line: 148*/   CLBYTES = 0x1000,  // (CLSIZE*NBPG)
/*line: 149*/   CLOFSET = 0xfff, /* for clusters, like PGOFSET */ // (CLSIZE*NBPG-1)
/*line: 151*/   CLOFF = 0xfff,  // CLOFSET
/*line: 152*/   CLSHIFT = 0xc,  // (PGSHIFT+CLSIZELOG2)
};

// Depends on identifiers
enum macro_clist_params {
/*line: 164*/   CBLOCK = 0x40, /* Clist block size, must be a power of 2. */ // 64
/*line: 168*/   CROUND = 0x3f, /* Clist rounding. */ // (CBLOCK-1)
};

// Depends on identifiers
enum macro_filesystem_params {
/*
 * File system parameters and macros.
 *
 * The file system is made out of blocks of at most MAXPHYS units, with
 * smaller units (fragments) only in the last direct block.  MAXBSIZE
 * primarily determines the size of buffers in the buffer pool.  It may be
 * made larger than MAXPHYS without any effect on existing file systems;
 * however making it smaller may make some file systems unmountable.
 * We set this to track the value of MAX_UPL_TRANSFER_BYTES from
 * osfmk/mach/memory_object_types.h to bound it at the maximum UPL size.
 */
/*line: 181*/   MAXBSIZE = 0x100000,  // (256*4096)
/*line: 182*/   MAXPHYSIO = 0x10000,  // MAXPHYS
/*line: 183*/   MAXFRAG = 0x8,  // 8
};

enum macro_maxphysio_wired {
/*line: 185*/   MAXPHYSIO_WIRED = 0x1000000,  // (16*1024*1024)
};

// Depends on identifiers
enum macro_path_limits {
/*
 * MAXPATHLEN defines the longest permissable path length after expanding
 * symbolic links. It is used to allocate a temporary buffer from the buffer
 * pool in which to do the name expansion, hence should be a power of two,
 * and must be less than or equal to MAXBSIZE.  MAXSYMLINKS defines the
 * maximum number of symbolic links that may be expanded in a path name.
 * It should be set high enough to allow all legitimate uses, but halt
 * infinite loops reasonably quickly.
 */
/*line: 196*/   MAXPATHLEN = 0x400,  // PATH_MAX
/*line: 197*/   MAXSYMLINKS = 0x20,  // 32
};

// Depends on identifiers
enum macro_fshift_fscale {
/*
 * Scale factor for scaled integers used to count %cpu time and load avgs.
 *
 * The number of CPU `tick's that map to a unique `%age' can be expressed
 * by the formula (1 / (2 ^ (FSHIFT - 11))).  The maximum load average that
 * can be calculated (assuming 32 bits) can be closely approximated using
 * the formula (2 ^ (2 * (16 - FSHIFT))) for (FSHIFT < 15).
 *
 * For the scheduler to maintain a 1:1 mapping of CPU `tick' to `%age',
 * FSHIFT must be at least 11; this gives us a maximum load avg of ~1024.
 */
/*line: 232*/   FSHIFT = 0xb, /* bits to right of fixed binary point */ // 11
/*line: 233*/   FSCALE = 0x800,  // (1<<FSHIFT)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 138
// #define NBPW sizeof(int)

// Line: 165
// #define CBQSIZE (CBLOCK/NBBY)

// Line: 167
// #define CBSIZE (CBLOCK - sizeof(struct cblock *) - CBQSIZE)

