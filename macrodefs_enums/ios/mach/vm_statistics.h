// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/vm_statistics.h

enum macro_page_query_flags {
/* included for the vm_map_page_query call */
/*line: 222*/   VM_PAGE_QUERY_PAGE_PRESENT = 0x1,  // 0x1
/*line: 223*/   VM_PAGE_QUERY_PAGE_FICTITIOUS = 0x2,  // 0x2
/*line: 224*/   VM_PAGE_QUERY_PAGE_REF = 0x4,  // 0x4
/*line: 225*/   VM_PAGE_QUERY_PAGE_DIRTY = 0x8,  // 0x8
/*line: 226*/   VM_PAGE_QUERY_PAGE_PAGED_OUT = 0x10,  // 0x10
/*line: 227*/   VM_PAGE_QUERY_PAGE_COPIED = 0x20,  // 0x20
/*line: 228*/   VM_PAGE_QUERY_PAGE_SPECULATIVE = 0x40,  // 0x40
/*line: 229*/   VM_PAGE_QUERY_PAGE_EXTERNAL = 0x80,  // 0x80
/*line: 230*/   VM_PAGE_QUERY_PAGE_CS_VALIDATED = 0x100,  // 0x100
/*line: 231*/   VM_PAGE_QUERY_PAGE_CS_TAINTED = 0x200,  // 0x200
/*line: 232*/   VM_PAGE_QUERY_PAGE_CS_NX = 0x400,  // 0x400
/*line: 233*/   VM_PAGE_QUERY_PAGE_REUSABLE = 0x800,  // 0x800
};

enum macro_vm_flags {
/*
 * VM allocation flags:
 *
 * VM_FLAGS_FIXED
 *      (really the absence of VM_FLAGS_ANYWHERE)
 *	Allocate new VM region at the specified virtual address, if possible.
 *
 * VM_FLAGS_ANYWHERE
 *	Allocate new VM region anywhere it would fit in the address space.
 *
 * VM_FLAGS_PURGABLE
 *	Create a purgable VM object for that new VM region.
 *
 * VM_FLAGS_4GB_CHUNK
 *	The new VM region will be chunked up into 4GB sized pieces.
 *
 * VM_FLAGS_NO_PMAP_CHECK
 *	(for DEBUG kernel config only, ignored for other configs)
 *	Do not check that there is no stale pmap mapping for the new VM region.
 *	This is useful for kernel memory allocations at bootstrap when building
 *	the initial kernel address space while some memory is already in use.
 *
 * VM_FLAGS_OVERWRITE
 *	The new VM region can replace existing VM regions if necessary
 *	(to be used in combination with VM_FLAGS_FIXED).
 *
 * VM_FLAGS_NO_CACHE
 *	Pages brought in to this VM region are placed on the speculative
 *	queue instead of the active queue.  In other words, they are not
 *	cached so that they will be stolen first if memory runs low.
 */
/*line: 267*/   VM_FLAGS_FIXED = 0x0,  // 0x00000000
/*line: 268*/   VM_FLAGS_ANYWHERE = 0x1,  // 0x00000001
/*line: 269*/   VM_FLAGS_PURGABLE = 0x2,  // 0x00000002
/*line: 270*/   VM_FLAGS_4GB_CHUNK = 0x4,  // 0x00000004
/*line: 271*/   VM_FLAGS_RANDOM_ADDR = 0x8,  // 0x00000008
/*line: 272*/   VM_FLAGS_NO_CACHE = 0x10,  // 0x00000010
/*line: 273*/   VM_FLAGS_RESILIENT_CODESIGN = 0x20,  // 0x00000020
/*line: 274*/   VM_FLAGS_RESILIENT_MEDIA = 0x40,  // 0x00000040
/*line: 275*/   VM_FLAGS_PERMANENT = 0x80,  // 0x00000080
/*line: 276*/   VM_FLAGS_TPRO = 0x1000,  // 0x00001000
/*line: 277*/   VM_FLAGS_OVERWRITE = 0x4000, /* delete any existing mappings first */ // 0x00004000
/*
 * VM_FLAGS_SUPERPAGE_MASK
 *	3 bits that specify whether large pages should be used instead of
 *	base pages (!=0), as well as the requested page size.
 */
/*line: 283*/   VM_FLAGS_SUPERPAGE_MASK = 0x70000, /* bits 0x10000, 0x20000, 0x40000 */ // 0x00070000
/*line: 284*/   VM_FLAGS_RETURN_DATA_ADDR = 0x100000, /* Return address of target data, rather than base of page */ // 0x00100000
/*line: 285*/   VM_FLAGS_RETURN_4K_DATA_ADDR = 0x800000, /* Return 4K aligned address of target data */ // 0x00800000
/*line: 286*/   VM_FLAGS_ALIAS_MASK = 0xff000000,  // 0xFF000000
/*line: 293*/   VM_FLAGS_HW = 0x1000,  // (VM_FLAGS_TPRO)
/* These are the flags that we accept from user-space */
/*line: 296*/   VM_FLAGS_USER_ALLOCATE = 0xff07509f,  // (VM_FLAGS_FIXED|VM_FLAGS_ANYWHERE|VM_FLAGS_PURGABLE|VM_FLAGS_4GB_CHUNK|VM_FLAGS_RANDOM_ADDR|VM_FLAGS_NO_CACHE|VM_FLAGS_PERMANENT|VM_FLAGS_OVERWRITE|VM_FLAGS_SUPERPAGE_MASK|VM_FLAGS_HW|VM_FLAGS_ALIAS_MASK)
/*line: 308*/   VM_FLAGS_USER_MAP = 0xff97509f,  // (VM_FLAGS_USER_ALLOCATE|VM_FLAGS_RETURN_4K_DATA_ADDR|VM_FLAGS_RETURN_DATA_ADDR)
/*line: 312*/   VM_FLAGS_USER_REMAP = 0x104069,  // (VM_FLAGS_FIXED|VM_FLAGS_ANYWHERE|VM_FLAGS_RANDOM_ADDR|VM_FLAGS_OVERWRITE|VM_FLAGS_RETURN_DATA_ADDR|VM_FLAGS_RESILIENT_CODESIGN|VM_FLAGS_RESILIENT_MEDIA)
};

// Depends on identifiers
enum macro_superpage_flags {
/*line: 320*/   VM_FLAGS_SUPERPAGE_SHIFT = 0x10,  // 16
/*line: 321*/   SUPERPAGE_NONE = 0x0, /* no superpages, if all bits are 0 */ // 0
/*line: 322*/   SUPERPAGE_SIZE_ANY = 0x1,  // 1
/*line: 323*/   VM_FLAGS_SUPERPAGE_NONE = 0x0,  // (SUPERPAGE_NONE<<VM_FLAGS_SUPERPAGE_SHIFT)
/*line: 324*/   VM_FLAGS_SUPERPAGE_SIZE_ANY = 0x10000,  // (SUPERPAGE_SIZE_ANY<<VM_FLAGS_SUPERPAGE_SHIFT)
/*line: 325*/   SUPERPAGE_SIZE_2MB = 0x2,  // 2
/*line: 326*/   VM_FLAGS_SUPERPAGE_SIZE_2MB = 0x20000,  // (SUPERPAGE_SIZE_2MB<<VM_FLAGS_SUPERPAGE_SHIFT)
};

enum macro_guard_type {
/*
 * EXC_GUARD definitions for virtual memory.
 */
/*line: 331*/   GUARD_TYPE_VIRT_MEMORY = 0x5,  // 0x5
};

enum macro_ledger_postmark {
/* current accounting postmark */
/*line: 349*/   __VM_LEDGER_ACCOUNTING_POSTMARK = 0x7857fe18,  // 2019032600
};

enum macro_ledger_tag {
/* discrete values: */
/*line: 358*/   VM_LEDGER_TAG_NONE = 0x0,  // 0x00000000
/*line: 359*/   VM_LEDGER_TAG_DEFAULT = 0x1,  // 0x00000001
/*line: 360*/   VM_LEDGER_TAG_NETWORK = 0x2,  // 0x00000002
/*line: 361*/   VM_LEDGER_TAG_MEDIA = 0x3,  // 0x00000003
/*line: 362*/   VM_LEDGER_TAG_GRAPHICS = 0x4,  // 0x00000004
/*line: 363*/   VM_LEDGER_TAG_NEURAL = 0x5,  // 0x00000005
/*line: 364*/   VM_LEDGER_TAG_MAX = 0x5,  // 0x00000005
/*line: 365*/   VM_LEDGER_TAG_UNCHANGED = -0x1,  // ((int)-1)
};

enum macro_ledger_flag {
/* individual bits: */
/*line: 368*/   VM_LEDGER_FLAG_NO_FOOTPRINT = 0x1,  // (1<<0)
/*line: 369*/   VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG = 0x2,  // (1<<1)
/*line: 370*/   VM_LEDGER_FLAG_FROM_KERNEL = 0x4,  // (1<<2)
/*line: 372*/   VM_LEDGER_FLAGS_USER = 0x3,  // (VM_LEDGER_FLAG_NO_FOOTPRINT|VM_LEDGER_FLAG_NO_FOOTPRINT_FOR_DEBUG)
/*line: 373*/   VM_LEDGER_FLAGS_ALL = 0x7,  // (VM_LEDGER_FLAGS_USER|VM_LEDGER_FLAG_FROM_KERNEL)
};

enum macro_vm_memory_types {
/*line: 375*/   VM_MEMORY_MALLOC = 0x1,  // 1
/*line: 376*/   VM_MEMORY_MALLOC_SMALL = 0x2,  // 2
/*line: 377*/   VM_MEMORY_MALLOC_LARGE = 0x3,  // 3
/*line: 378*/   VM_MEMORY_MALLOC_HUGE = 0x4,  // 4
/*line: 379*/   VM_MEMORY_SBRK = 0x5,  // 5
/*line: 380*/   VM_MEMORY_REALLOC = 0x6,  // 6
/*line: 381*/   VM_MEMORY_MALLOC_TINY = 0x7,  // 7
/*line: 382*/   VM_MEMORY_MALLOC_LARGE_REUSABLE = 0x8,  // 8
/*line: 383*/   VM_MEMORY_MALLOC_LARGE_REUSED = 0x9,  // 9
/*line: 385*/   VM_MEMORY_ANALYSIS_TOOL = 0xa,  // 10
/*line: 387*/   VM_MEMORY_MALLOC_NANO = 0xb,  // 11
/*line: 388*/   VM_MEMORY_MALLOC_MEDIUM = 0xc,  // 12
/*line: 389*/   VM_MEMORY_MALLOC_PROB_GUARD = 0xd,  // 13
/*line: 391*/   VM_MEMORY_MACH_MSG = 0x14,  // 20
/*line: 392*/   VM_MEMORY_IOKIT = 0x15,  // 21
/*line: 393*/   VM_MEMORY_STACK = 0x1e,  // 30
/*line: 394*/   VM_MEMORY_GUARD = 0x1f,  // 31
/*line: 395*/   VM_MEMORY_SHARED_PMAP = 0x20,  // 32
/* memory containing a dylib */
/*line: 397*/   VM_MEMORY_DYLIB = 0x21,  // 33
/*line: 398*/   VM_MEMORY_OBJC_DISPATCHERS = 0x22,  // 34
/* Was a nested pmap (VM_MEMORY_SHARED_PMAP) which has now been unnested */
/*line: 401*/   VM_MEMORY_UNSHARED_PMAP = 0x23,  // 35
// use memory, we can make these labels more specific.
/*line: 406*/   VM_MEMORY_APPKIT = 0x28,  // 40
/*line: 407*/   VM_MEMORY_FOUNDATION = 0x29,  // 41
/*line: 408*/   VM_MEMORY_COREGRAPHICS = 0x2a,  // 42
/*line: 409*/   VM_MEMORY_CORESERVICES = 0x2b,  // 43
/*line: 410*/   VM_MEMORY_CARBON = 0x2b,  // VM_MEMORY_CORESERVICES
/*line: 411*/   VM_MEMORY_JAVA = 0x2c,  // 44
/*line: 412*/   VM_MEMORY_COREDATA = 0x2d,  // 45
/*line: 413*/   VM_MEMORY_COREDATA_OBJECTIDS = 0x2e,  // 46
/*line: 414*/   VM_MEMORY_ATS = 0x32,  // 50
/*line: 415*/   VM_MEMORY_LAYERKIT = 0x33,  // 51
/*line: 416*/   VM_MEMORY_CGIMAGE = 0x34,  // 52
/*line: 417*/   VM_MEMORY_TCMALLOC = 0x35,  // 53
/* private raster data (i.e. layers, some images, QGL allocator) */
/*line: 420*/   VM_MEMORY_COREGRAPHICS_DATA = 0x36,  // 54
/* shared image and font caches */
/*line: 423*/   VM_MEMORY_COREGRAPHICS_SHARED = 0x37,  // 55
/* Memory used for virtual framebuffers, shadowing buffers, etc... */
/*line: 426*/   VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS = 0x38,  // 56
/* Window backing stores, custom shadow data, and compressed backing stores */
/*line: 429*/   VM_MEMORY_COREGRAPHICS_BACKINGSTORES = 0x39,  // 57
/* x-alloc'd memory */
/*line: 432*/   VM_MEMORY_COREGRAPHICS_XALLOC = 0x3a,  // 58
/* catch-all for other uses, such as the read-only shared data page */
/*line: 435*/   VM_MEMORY_COREGRAPHICS_MISC = 0x2a,  // VM_MEMORY_COREGRAPHICS
/* memory allocated by the dynamic loader for itself */
/*line: 438*/   VM_MEMORY_DYLD = 0x3c,  // 60
/* malloc'd memory created by dyld */
/*line: 440*/   VM_MEMORY_DYLD_MALLOC = 0x3d,  // 61
/* Used for sqlite page cache */
/*line: 443*/   VM_MEMORY_SQLITE = 0x3e,  // 62
/* JavaScriptCore heaps */
/*line: 446*/   VM_MEMORY_JAVASCRIPT_CORE = 0x3f,  // 63
/*line: 447*/   VM_MEMORY_WEBASSEMBLY = 0x3f,  // VM_MEMORY_JAVASCRIPT_CORE
/* memory allocated for the JIT */
/*line: 449*/   VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR = 0x40,  // 64
/*line: 450*/   VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE = 0x41,  // 65
/* memory allocated for GLSL */
/*line: 453*/   VM_MEMORY_GLSL = 0x42,  // 66
/* memory allocated for OpenCL.framework */
/*line: 456*/   VM_MEMORY_OPENCL = 0x43,  // 67
/* memory allocated for QuartzCore.framework */
/*line: 459*/   VM_MEMORY_COREIMAGE = 0x44,  // 68
/* memory allocated for WebCore Purgeable Buffers */
/*line: 462*/   VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS = 0x45,  // 69
/* ImageIO memory */
/*line: 465*/   VM_MEMORY_IMAGEIO = 0x46,  // 70
/* CoreProfile memory */
/*line: 468*/   VM_MEMORY_COREPROFILE = 0x47,  // 71
/* assetsd / MobileSlideShow memory */
/*line: 471*/   VM_MEMORY_ASSETSD = 0x48,  // 72
/* libsystem_kernel os_once_alloc */
/*line: 474*/   VM_MEMORY_OS_ALLOC_ONCE = 0x49,  // 73
/* libdispatch internal allocator */
/*line: 477*/   VM_MEMORY_LIBDISPATCH = 0x4a,  // 74
/* Accelerate.framework image backing stores */
/*line: 480*/   VM_MEMORY_ACCELERATE = 0x4b,  // 75
/* CoreUI image block data */
/*line: 483*/   VM_MEMORY_COREUI = 0x4c,  // 76
/* CoreUI image file */
/*line: 486*/   VM_MEMORY_COREUIFILE = 0x4d,  // 77
/* Genealogy buffers */
/*line: 489*/   VM_MEMORY_GENEALOGY = 0x4e,  // 78
/* RawCamera VM allocated memory */
/*line: 492*/   VM_MEMORY_RAWCAMERA = 0x4f,  // 79
/* corpse info for dead process */
/*line: 495*/   VM_MEMORY_CORPSEINFO = 0x50,  // 80
/* Apple System Logger (ASL) messages */
/*line: 498*/   VM_MEMORY_ASL = 0x51,  // 81
/* Swift runtime */
/*line: 501*/   VM_MEMORY_SWIFT_RUNTIME = 0x52,  // 82
/* Swift metadata */
/*line: 504*/   VM_MEMORY_SWIFT_METADATA = 0x53,  // 83
/* DHMM data */
/*line: 507*/   VM_MEMORY_DHMM = 0x54,  // 84
/* memory allocated by SceneKit.framework */
/*line: 511*/   VM_MEMORY_SCENEKIT = 0x56,  // 86
/* memory allocated by skywalk networking */
/*line: 514*/   VM_MEMORY_SKYWALK = 0x57,  // 87
/*line: 516*/   VM_MEMORY_IOSURFACE = 0x58,  // 88
/*line: 518*/   VM_MEMORY_LIBNETWORK = 0x59,  // 89
/*line: 520*/   VM_MEMORY_AUDIO = 0x5a,  // 90
/*line: 522*/   VM_MEMORY_VIDEOBITSTREAM = 0x5b,  // 91
/* memory allocated by CoreMedia */
/*line: 525*/   VM_MEMORY_CM_XPC = 0x5c,  // 92
/*line: 527*/   VM_MEMORY_CM_RPC = 0x5d,  // 93
/*line: 529*/   VM_MEMORY_CM_MEMORYPOOL = 0x5e,  // 94
/*line: 531*/   VM_MEMORY_CM_READCACHE = 0x5f,  // 95
/*line: 533*/   VM_MEMORY_CM_CRABS = 0x60,  // 96
/* memory allocated for QuickLookThumbnailing */
/*line: 536*/   VM_MEMORY_QUICKLOOK_THUMBNAILS = 0x61,  // 97
/* memory allocated by Accounts framework */
/*line: 539*/   VM_MEMORY_ACCOUNTS = 0x62,  // 98
/* memory allocated by Sanitizer runtime libraries */
/*line: 542*/   VM_MEMORY_SANITIZER = 0x63,  // 99
/* Differentiate memory needed by GPU drivers and frameworks from generic IOKit allocations */
/*line: 545*/   VM_MEMORY_IOACCELERATOR = 0x64,  // 100
/* memory allocated by CoreMedia for global image registration of frames */
/*line: 548*/   VM_MEMORY_CM_REGWARP = 0x65,  // 101
/* memory allocated by EmbeddedAcousticRecognition for speech decoder */
/*line: 551*/   VM_MEMORY_EAR_DECODER = 0x66,  // 102
/* CoreUI cached image data */
/*line: 554*/   VM_MEMORY_COREUI_CACHED_IMAGE_DATA = 0x67,  // 103
/* ColorSync is using mmap for read-only copies of ICC profile data */
/*line: 557*/   VM_MEMORY_COLORSYNC = 0x68,  // 104
/* backtrace info for simulated crashes */
/*line: 560*/   VM_MEMORY_BTINFO = 0x69,  // 105
/* memory allocated by CoreMedia */
/*line: 563*/   VM_MEMORY_CM_HLS = 0x6a,  // 106
/* Reserve 230-239 for Rosetta */
/*line: 566*/   VM_MEMORY_ROSETTA = 0xe6,  // 230
/*line: 567*/   VM_MEMORY_ROSETTA_THREAD_CONTEXT = 0xe7,  // 231
/*line: 568*/   VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP = 0xe8,  // 232
/*line: 569*/   VM_MEMORY_ROSETTA_RETURN_STACK = 0xe9,  // 233
/*line: 570*/   VM_MEMORY_ROSETTA_EXECUTABLE_HEAP = 0xea,  // 234
/*line: 571*/   VM_MEMORY_ROSETTA_USER_LDT = 0xeb,  // 235
/*line: 572*/   VM_MEMORY_ROSETTA_ARENA = 0xec,  // 236
/*line: 573*/   VM_MEMORY_ROSETTA_10 = 0xef,  // 239
/* Reserve 240-255 for application */
/*line: 576*/   VM_MEMORY_APPLICATION_SPECIFIC_1 = 0xf0,  // 240
/*line: 577*/   VM_MEMORY_APPLICATION_SPECIFIC_16 = 0xff,  // 255
/*line: 579*/   VM_MEMORY_COUNT = 0x100,  // 256
};

