// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/sysctl.h

enum macro_sysctl_names {
/*
 * Definitions for sysctl call.  The sysctl call uses a hierarchical name
 * for objects that can be examined or modified.  The name is expressed as
 * a sequence of integers.  Like a file path name, the meaning of each
 * component depends on its place in the hierarchy.  The top-level and kern
 * identifiers are defined here, and other identifiers are defined in the
 * respective subsystem header files.
 */
/*line: 97*/    CTL_MAXNAME = 0xc, /* largest number of components supported */ // 12
};

// Depends on identifiers
enum macro_sysctl_flags {
/*line: 138*/   CTLTYPE = 0xf, /* Mask for the type */ // 0xf
/*line: 139*/   CTLTYPE_NODE = 0x1, /* name is a node */ // 1
/*line: 140*/   CTLTYPE_INT = 0x2, /* name describes an integer */ // 2
/*line: 141*/   CTLTYPE_STRING = 0x3, /* name describes a string */ // 3
/*line: 142*/   CTLTYPE_QUAD = 0x4, /* name describes a 64-bit number */ // 4
/*line: 143*/   CTLTYPE_OPAQUE = 0x5, /* name describes a structure */ // 5
/*line: 144*/   CTLTYPE_STRUCT = 0x5, /* name describes a structure */ // CTLTYPE_OPAQUE
/*line: 146*/   CTLFLAG_RD = 0x80000000, /* Allow reads of variable */ // 0x80000000
/*line: 147*/   CTLFLAG_WR = 0x40000000, /* Allow writes to the variable */ // 0x40000000
/*line: 148*/   CTLFLAG_RW = 0xc0000000,  // (CTLFLAG_RD|CTLFLAG_WR)
/*line: 149*/   CTLFLAG_NOLOCK = 0x20000000, /* XXX Don't Lock */ // 0x20000000
/*line: 150*/   CTLFLAG_ANYBODY = 0x10000000, /* All users can set this var */ // 0x10000000
/*line: 151*/   CTLFLAG_SECURE = 0x8000000, /* Permit set only if securelevel<=0 */ // 0x08000000
/*line: 152*/   CTLFLAG_MASKED = 0x4000000, /* deprecated variable, do not display */ // 0x04000000
/*line: 153*/   CTLFLAG_NOAUTO = 0x2000000, /* do not auto-register */ // 0x02000000
/*line: 154*/   CTLFLAG_KERN = 0x1000000, /* valid inside the kernel */ // 0x01000000
/*line: 155*/   CTLFLAG_LOCKED = 0x800000, /* node will handle locking itself */ // 0x00800000
/*line: 156*/   CTLFLAG_OID2 = 0x400000, /* struct sysctl_oid has version info */ // 0x00400000
/*line: 157*/   CTLFLAG_EXPERIMENT = 0x100000, /* Allows writing w/ the trial experiment entitlement. */ // 0x00100000
};

enum macro_sysctl_oid {
/*
 * USE THIS instead of a hardwired number from the categories below
 * to get dynamically assigned sysctl entries using the linker-set
 * technology. This is the way nearly all new sysctl variables should
 * be implemented.
 *
 * e.g. SYSCTL_INT(_parent, OID_AUTO, name, CTLFLAG_RW, &variable, 0, "");
 *
 * Note that linker set technology will automatically register all nodes
 * declared like this on kernel initialization, UNLESS they are defined
 * in I/O-Kit. In this case, you have to call sysctl_register_oid()
 * manually - just like in a KEXT.
 */
/*line: 172*/   OID_AUTO = -0x1,  // (-1)
/*line: 173*/   OID_AUTO_START = 0x64, /* conventional */ // 100
};

enum macro_sysctl_id {
/*
 * Top-level identifiers
 */
/*line: 182*/   CTL_UNSPEC = 0x0, /* unused */ // 0
/*line: 183*/   CTL_KERN = 0x1, /* "high kernel": proc, limits */ // 1
/*line: 184*/   CTL_VM = 0x2, /* virtual memory */ // 2
/*line: 185*/   CTL_VFS = 0x3, /* file system, mount type is next */ // 3
/*line: 186*/   CTL_NET = 0x4, /* network, see socket.h */ // 4
/*line: 187*/   CTL_DEBUG = 0x5, /* debugging parameters */ // 5
/*line: 188*/   CTL_HW = 0x6, /* generic cpu/io */ // 6
/*line: 189*/   CTL_MACHDEP = 0x7, /* machine dependent */ // 7
/*line: 190*/   CTL_USER = 0x8, /* user-level */ // 8
/*line: 191*/   CTL_MAXID = 0x9, /* number of valid top-level ids */ // 9
};

// Depends on identifiers
enum macro_ctlkern_identifiers {
/*
 * CTL_KERN identifiers
 */
/*line: 208*/   KERN_OSTYPE = 0x1, /* string: system version */ // 1
/*line: 209*/   KERN_OSRELEASE = 0x2, /* string: system release */ // 2
/*line: 210*/   KERN_OSREV = 0x3, /* int: system revision */ // 3
/*line: 211*/   KERN_VERSION = 0x4, /* string: compile time info */ // 4
/*line: 212*/   KERN_MAXVNODES = 0x5, /* int: max vnodes */ // 5
/*line: 213*/   KERN_MAXPROC = 0x6, /* int: max processes */ // 6
/*line: 214*/   KERN_MAXFILES = 0x7, /* int: max open files */ // 7
/*line: 215*/   KERN_ARGMAX = 0x8, /* int: max arguments to exec */ // 8
/*line: 216*/   KERN_SECURELVL = 0x9, /* int: system security level */ // 9
/*line: 217*/   KERN_HOSTNAME = 0xa, /* string: hostname */ // 10
/*line: 218*/   KERN_HOSTID = 0xb, /* int: host identifier */ // 11
/*line: 219*/   KERN_CLOCKRATE = 0xc, /* struct: struct clockrate */ // 12
/*line: 220*/   KERN_VNODE = 0xd, /* struct: vnode structures */ // 13
/*line: 221*/   KERN_PROC = 0xe, /* struct: process entries */ // 14
/*line: 222*/   KERN_FILE = 0xf, /* struct: file entries */ // 15
/*line: 223*/   KERN_PROF = 0x10, /* node: kernel profiling info */ // 16
/*line: 224*/   KERN_POSIX1 = 0x11, /* int: POSIX.1 version */ // 17
/*line: 225*/   KERN_NGROUPS = 0x12, /* int: # of supplemental group ids */ // 18
/*line: 226*/   KERN_JOB_CONTROL = 0x13, /* int: is job control available */ // 19
/*line: 227*/   KERN_SAVED_IDS = 0x14, /* int: saved set-user/group-ID */ // 20
/*line: 228*/   KERN_BOOTTIME = 0x15, /* struct: time kernel was booted */ // 21
/*line: 229*/   KERN_NISDOMAINNAME = 0x16, /* string: YP domain name */ // 22
/*line: 230*/   KERN_DOMAINNAME = 0x16,  // KERN_NISDOMAINNAME
/*line: 231*/   KERN_MAXPARTITIONS = 0x17, /* int: number of partitions/disk */ // 23
/*line: 232*/   KERN_KDEBUG = 0x18, /* int: kernel trace points */ // 24
/*line: 233*/   KERN_UPDATEINTERVAL = 0x19, /* int: update process sleep time */ // 25
/*line: 234*/   KERN_OSRELDATE = 0x1a, /* int: OS release date */ // 26
/*line: 235*/   KERN_NTP_PLL = 0x1b, /* node: NTP PLL control */ // 27
/*line: 236*/   KERN_BOOTFILE = 0x1c, /* string: name of booted kernel */ // 28
/*line: 237*/   KERN_MAXFILESPERPROC = 0x1d, /* int: max open files per proc */ // 29
/*line: 238*/   KERN_MAXPROCPERUID = 0x1e, /* int: max processes per uid */ // 30
/*line: 239*/   KERN_DUMPDEV = 0x1f, /* dev_t: device to dump on */ // 31
/*line: 240*/   KERN_IPC = 0x20, /* node: anything related to IPC */ // 32
/*line: 241*/   KERN_DUMMY = 0x21, /* unused */ // 33
/*line: 242*/   KERN_PS_STRINGS = 0x22, /* int: address of PS_STRINGS */ // 34
/*line: 243*/   KERN_USRSTACK32 = 0x23, /* int: address of USRSTACK */ // 35
/*line: 244*/   KERN_LOGSIGEXIT = 0x24, /* int: do we log sigexit procs? */ // 36
/*line: 245*/   KERN_SYMFILE = 0x25, /* string: kernel symbol filename */ // 37
/*line: 246*/   KERN_PROCARGS = 0x26,  // 38
/* 39 was KERN_PCSAMPLES... now obsolete */
/*line: 248*/   KERN_NETBOOT = 0x28, /* int: are we netbooted? 1=yes,0=no */ // 40
/* 41 was KERN_PANICINFO : panic UI information (deprecated) */
/*line: 250*/   KERN_SYSV = 0x2a, /* node: System V IPC information */ // 42
/*line: 251*/   KERN_AFFINITY = 0x2b, /* xxx */ // 43
/*line: 252*/   KERN_TRANSLATE = 0x2c, /* xxx */ // 44
/*line: 253*/   KERN_CLASSIC = 0x2c, /* XXX backwards compat */ // KERN_TRANSLATE
/*line: 254*/   KERN_EXEC = 0x2d, /* xxx */ // 45
/*line: 255*/   KERN_CLASSICHANDLER = 0x2d, /* XXX backwards compatibility */ // KERN_EXEC
/*line: 256*/   KERN_AIOMAX = 0x2e, /* int: max aio requests */ // 46
/*line: 257*/   KERN_AIOPROCMAX = 0x2f, /* int: max aio requests per process */ // 47
/*line: 258*/   KERN_AIOTHREADS = 0x30, /* int: max aio worker threads */ // 48
/*line: 260*/   KERN_PROCARGS2 = 0x31,  // 49
/*line: 262*/   KERN_COREFILE = 0x32, /* string: corefile format string */ // 50
/*line: 263*/   KERN_COREDUMP = 0x33, /* int: whether to coredump at all */ // 51
/*line: 264*/   KERN_SUGID_COREDUMP = 0x34, /* int: whether to dump SUGID cores */ // 52
/*line: 265*/   KERN_PROCDELAYTERM = 0x35, /* int: set/reset current proc for delayed termination during shutdown */ // 53
/*line: 266*/   KERN_SHREG_PRIVATIZABLE = 0x36, /* int: can shared regions be privatized ? */ // 54
/* 55 was KERN_PROC_LOW_PRI_IO... now deprecated */
/*line: 268*/   KERN_LOW_PRI_WINDOW = 0x38, /* int: set/reset throttle window - milliseconds */ // 56
/*line: 269*/   KERN_LOW_PRI_DELAY = 0x39, /* int: set/reset throttle delay - milliseconds */ // 57
/*line: 270*/   KERN_POSIX = 0x3a, /* node: posix tunables */ // 58
/*line: 271*/   KERN_USRSTACK64 = 0x3b, /* LP64 user stack query */ // 59
/*line: 272*/   KERN_NX_PROTECTION = 0x3c, /* int: whether no-execute protection is enabled */ // 60
/*line: 273*/   KERN_TFP = 0x3d, /* Task for pid settings */ // 61
/*line: 274*/   KERN_PROCNAME = 0x3e, /* setup process program  name(2*MAXCOMLEN) */ // 62
/*line: 275*/   KERN_THALTSTACK = 0x3f, /* for compat with older x86 and does nothing */ // 63
/*line: 276*/   KERN_SPECULATIVE_READS = 0x40, /* int: whether speculative reads are disabled */ // 64
/*line: 277*/   KERN_OSVERSION = 0x41, /* for build number i.e. 9A127 */ // 65
/*line: 278*/   KERN_SAFEBOOT = 0x42, /* are we booted safe? */ // 66
/*	67 was KERN_LCTX (login context) */
/*line: 280*/   KERN_RAGEVNODE = 0x44,  // 68
/*line: 281*/   KERN_TTY = 0x45, /* node: tty settings */ // 69
/*line: 282*/   KERN_CHECKOPENEVT = 0x46, /* spi: check the VOPENEVT flag on vnodes at open time */ // 70
/*line: 283*/   KERN_THREADNAME = 0x47, /* set/get thread name */ // 71
/*line: 284*/   KERN_MAXID = 0x48, /* number of valid kern ids */ // 72
};

// Depends on identifiers
enum macro_ctl_kern_usrstack {
/*line: 293*/   KERN_USRSTACK = 0x3b,  // KERN_USRSTACK64
};

enum macro_kern_ragevnode {
/* KERN_RAGEVNODE types */
/*line: 300*/   KERN_RAGE_PROC = 0x1,  // 1
/*line: 301*/   KERN_RAGE_THREAD = 0x2,  // 2
/*line: 302*/   KERN_UNRAGE_PROC = 0x3,  // 3
/*line: 303*/   KERN_UNRAGE_THREAD = 0x4,  // 4
};

enum macro_kernevent_type {
/* KERN_OPENEVT types */
/*line: 306*/   KERN_OPENEVT_PROC = 0x1,  // 1
/*line: 307*/   KERN_UNOPENEVT_PROC = 0x2,  // 2
};

enum macro_kern_tfp_policy {
/* KERN_TFP types */
/*line: 310*/   KERN_TFP_POLICY = 0x1,  // 1
};

enum macro_tfp_policy {
/* KERN_TFP_POLICY values . All policies allow task port for self */
/*line: 313*/   KERN_TFP_POLICY_DENY = 0x0, /* Deny Mode: None allowed except privileged */ // 0
/*line: 314*/   KERN_TFP_POLICY_DEFAULT = 0x2, /* Default  Mode: related ones allowed and upcall authentication */ // 2
};

enum macro_kern_kdebug_types {
/* KERN_KDEBUG types */
/*line: 317*/   KERN_KDEFLAGS = 0x1,  // 1
/*line: 318*/   KERN_KDDFLAGS = 0x2,  // 2
/*line: 319*/   KERN_KDENABLE = 0x3,  // 3
/*line: 320*/   KERN_KDSETBUF = 0x4,  // 4
/*line: 321*/   KERN_KDGETBUF = 0x5,  // 5
/*line: 322*/   KERN_KDSETUP = 0x6,  // 6
/*line: 323*/   KERN_KDREMOVE = 0x7,  // 7
/*line: 324*/   KERN_KDSETREG = 0x8,  // 8
/*line: 325*/   KERN_KDGETREG = 0x9,  // 9
/*line: 326*/   KERN_KDREADTR = 0xa,  // 10
/*line: 327*/   KERN_KDPIDTR = 0xb,  // 11
/*line: 328*/   KERN_KDTHRMAP = 0xc,  // 12
/* Don't use 13 as it is overloaded with KERN_VNODE */
/*line: 330*/   KERN_KDPIDEX = 0xe,  // 14
/*line: 331*/   KERN_KDSETRTCDEC = 0xf, /* obsolete */ // 15
/*line: 332*/   KERN_KDGETENTROPY = 0x10, /* obsolete */ // 16
/*line: 333*/   KERN_KDWRITETR = 0x11,  // 17
/*line: 334*/   KERN_KDWRITEMAP = 0x12,  // 18
/*line: 335*/   KERN_KDTEST = 0x13,  // 19
/* 20 unused */
/*line: 337*/   KERN_KDREADCURTHRMAP = 0x15,  // 21
/*line: 338*/   KERN_KDSET_TYPEFILTER = 0x16,  // 22
/*line: 339*/   KERN_KDBUFWAIT = 0x17,  // 23
/*line: 340*/   KERN_KDCPUMAP = 0x18,  // 24
/*line: 341*/   KERN_KDCPUMAP_EXT = 0x19,  // 25
/*line: 342*/   KERN_KDSET_EDM = 0x1a,  // 26
/*line: 343*/   KERN_KDGET_EDM = 0x1b,  // 27
/*line: 344*/   KERN_KDWRITETR_V3 = 0x1c,  // 28
};

enum macro_kern_proc_subtype {
/*
 * KERN_PROC subtypes
 */
/*line: 431*/   KERN_PROC_ALL = 0x0, /* everything */ // 0
/*line: 432*/   KERN_PROC_PID = 0x1, /* by process id */ // 1
/*line: 433*/   KERN_PROC_PGRP = 0x2, /* by process group id */ // 2
/*line: 434*/   KERN_PROC_SESSION = 0x3, /* by session of pid */ // 3
/*line: 435*/   KERN_PROC_TTY = 0x4, /* by controlling tty */ // 4
/*line: 436*/   KERN_PROC_UID = 0x5, /* by effective uid */ // 5
/*line: 437*/   KERN_PROC_RUID = 0x6, /* by real uid */ // 6
/*line: 438*/   KERN_PROC_LCID = 0x7, /* by login context id */ // 7
};

enum macro_kern_vfsnspace_handle {
/*
 * KERN_VFSNSPACE subtypes
 */
/*line: 443*/   KERN_VFSNSPACE_HANDLE_PROC = 0x1,  // 1
/*line: 444*/   KERN_VFSNSPACE_UNHANDLE_PROC = 0x2,  // 2
};

enum macro_process_flags {
/*line: 481*/   WMESGLEN = 0x7,  // 7
/*line: 488*/   EPROC_CTTY = 0x1, /* controlling tty vnode active */ // 0x01
/*line: 489*/   EPROC_SLEADER = 0x2, /* session leader */ // 0x02
/*line: 490*/   COMAPT_MAXLOGNAME = 0xc,  // 12
};

enum macro_kernel_ipc_info {
/*
 * KERN_IPC identifiers
 */
/*line: 501*/   KIPC_MAXSOCKBUF = 0x1, /* int: max size of a socket buffer */ // 1
/*line: 502*/   KIPC_SOCKBUF_WASTE = 0x2, /* int: wastage factor in sockbuf */ // 2
/*line: 503*/   KIPC_SOMAXCONN = 0x3, /* int: max length of connection q */ // 3
/*line: 504*/   KIPC_MAX_LINKHDR = 0x4, /* int: max length of link header */ // 4
/*line: 505*/   KIPC_MAX_PROTOHDR = 0x5, /* int: max length of network header */ // 5
/*line: 506*/   KIPC_MAX_HDR = 0x6, /* int: max total length of headers */ // 6
/*line: 507*/   KIPC_MAX_DATALEN = 0x7, /* int: max length of data? */ // 7
/*line: 508*/   KIPC_MBSTAT = 0x8, /* struct: mbuf usage statistics */ // 8
/*line: 509*/   KIPC_NMBCLUSTERS = 0x9, /* int: maximum mbuf clusters */ // 9
/*line: 510*/   KIPC_SOQLIMITCOMPAT = 0xa, /* int: socket queue limit */ // 10
};

enum macro_vm_identifiers {
/*
 * CTL_VM identifiers
 */
/*line: 515*/   VM_METER = 0x1, /* struct vmmeter */ // 1
/*line: 516*/   VM_LOADAVG = 0x2, /* struct loadavg */ // 2
/*
 * Note: "3" was skipped sometime ago and should probably remain unused
 * to avoid any new entry from being accepted by older kernels...
 */
/*line: 521*/   VM_MACHFACTOR = 0x4, /* struct loadavg with mach factor*/ // 4
/*line: 522*/   VM_SWAPUSAGE = 0x5, /* total swap usage */ // 5
/*line: 523*/   VM_MAXID = 0x6, /* number of valid vm ids */ // 6
};

enum macro_lscale {
/*line: 550*/   LSCALE = 0x3e8, /* scaling for "fixed point" arithmetic */ // 1000
};

enum macro_hw_identifiers {
/*
 * CTL_HW identifiers
 */
/*line: 558*/   HW_MACHINE = 0x1, /* string: machine class (deprecated: use HW_PRODUCT) */ // 1
/*line: 559*/   HW_MODEL = 0x2, /* string: specific machine model (deprecated: use HW_TARGET) */ // 2
/*line: 560*/   HW_NCPU = 0x3, /* int: number of cpus */ // 3
/*line: 561*/   HW_BYTEORDER = 0x4, /* int: machine byte order */ // 4
/*line: 562*/   HW_PHYSMEM = 0x5, /* int: total memory */ // 5
/*line: 563*/   HW_USERMEM = 0x6, /* int: non-kernel memory */ // 6
/*line: 564*/   HW_PAGESIZE = 0x7, /* int: software page size */ // 7
/*line: 565*/   HW_DISKNAMES = 0x8, /* strings: disk drive names */ // 8
/*line: 566*/   HW_DISKSTATS = 0x9, /* struct: diskstats[] */ // 9
/*line: 567*/   HW_EPOCH = 0xa, /* int: 0 for Legacy, else NewWorld */ // 10
/*line: 568*/   HW_FLOATINGPT = 0xb, /* int: has HW floating point? */ // 11
/*line: 569*/   HW_MACHINE_ARCH = 0xc, /* string: machine architecture */ // 12
/*line: 570*/   HW_VECTORUNIT = 0xd, /* int: has HW vector unit? */ // 13
/*line: 571*/   HW_BUS_FREQ = 0xe, /* int: Bus Frequency */ // 14
/*line: 572*/   HW_CPU_FREQ = 0xf, /* int: CPU Frequency */ // 15
/*line: 573*/   HW_CACHELINE = 0x10, /* int: Cache Line Size in Bytes */ // 16
/*line: 574*/   HW_L1ICACHESIZE = 0x11, /* int: L1 I Cache Size in Bytes */ // 17
/*line: 575*/   HW_L1DCACHESIZE = 0x12, /* int: L1 D Cache Size in Bytes */ // 18
/*line: 576*/   HW_L2SETTINGS = 0x13, /* int: L2 Cache Settings */ // 19
/*line: 577*/   HW_L2CACHESIZE = 0x14, /* int: L2 Cache Size in Bytes */ // 20
/*line: 578*/   HW_L3SETTINGS = 0x15, /* int: L3 Cache Settings */ // 21
/*line: 579*/   HW_L3CACHESIZE = 0x16, /* int: L3 Cache Size in Bytes */ // 22
/*line: 580*/   HW_TB_FREQ = 0x17, /* int: Bus Frequency */ // 23
/*line: 581*/   HW_MEMSIZE = 0x18, /* uint64_t: physical ram size */ // 24
/*line: 582*/   HW_AVAILCPU = 0x19, /* int: number of available CPUs */ // 25
/*line: 583*/   HW_TARGET = 0x1a, /* string: model identifier */ // 26
/*line: 584*/   HW_PRODUCT = 0x1b, /* string: product identifier */ // 27
/*line: 585*/   HW_MAXID = 0x1c, /* number of valid hw ids */ // 28
};

enum macro_user_constants {
/*
 * CTL_USER definitions
 */
/*line: 729*/   USER_CS_PATH = 0x1, /* string: _CS_PATH */ // 1
/*line: 730*/   USER_BC_BASE_MAX = 0x2, /* int: BC_BASE_MAX */ // 2
/*line: 731*/   USER_BC_DIM_MAX = 0x3, /* int: BC_DIM_MAX */ // 3
/*line: 732*/   USER_BC_SCALE_MAX = 0x4, /* int: BC_SCALE_MAX */ // 4
/*line: 733*/   USER_BC_STRING_MAX = 0x5, /* int: BC_STRING_MAX */ // 5
/*line: 734*/   USER_COLL_WEIGHTS_MAX = 0x6, /* int: COLL_WEIGHTS_MAX */ // 6
/*line: 735*/   USER_EXPR_NEST_MAX = 0x7, /* int: EXPR_NEST_MAX */ // 7
/*line: 736*/   USER_LINE_MAX = 0x8, /* int: LINE_MAX */ // 8
/*line: 737*/   USER_RE_DUP_MAX = 0x9, /* int: RE_DUP_MAX */ // 9
/*line: 738*/   USER_POSIX2_VERSION = 0xa, /* int: POSIX2_VERSION */ // 10
/*line: 739*/   USER_POSIX2_C_BIND = 0xb, /* int: POSIX2_C_BIND */ // 11
/*line: 740*/   USER_POSIX2_C_DEV = 0xc, /* int: POSIX2_C_DEV */ // 12
/*line: 741*/   USER_POSIX2_CHAR_TERM = 0xd, /* int: POSIX2_CHAR_TERM */ // 13
/*line: 742*/   USER_POSIX2_FORT_DEV = 0xe, /* int: POSIX2_FORT_DEV */ // 14
/*line: 743*/   USER_POSIX2_FORT_RUN = 0xf, /* int: POSIX2_FORT_RUN */ // 15
/*line: 744*/   USER_POSIX2_LOCALEDEF = 0x10, /* int: POSIX2_LOCALEDEF */ // 16
/*line: 745*/   USER_POSIX2_SW_DEV = 0x11, /* int: POSIX2_SW_DEV */ // 17
/*line: 746*/   USER_POSIX2_UPE = 0x12, /* int: POSIX2_UPE */ // 18
/*line: 747*/   USER_STREAM_MAX = 0x13, /* int: POSIX2_STREAM_MAX */ // 19
/*line: 748*/   USER_TZNAME_MAX = 0x14, /* int: POSIX2_TZNAME_MAX */ // 20
/*line: 749*/   USER_MAXID = 0x15, /* number of valid user ids */ // 21
};

enum macro_debug_variable_type {
/*
 * CTL_DEBUG definitions
 *
 * Second level identifier specifies which debug variable.
 * Third level identifier specifies which stucture component.
 */
/*line: 783*/   CTL_DEBUG_NAME = 0x0, /* string: variable name */ // 0
/*line: 784*/   CTL_DEBUG_VALUE = 0x1, /* int: variable value */ // 1
/*line: 785*/   CTL_DEBUG_MAXID = 0x14,  // 20
};

