// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/mman.h

enum macro_memory_protection {
/*
 * Protections are chosen from these bits, or-ed together
 */
/*line: 99*/    PROT_NONE = 0x0, /* [MC2] no permissions */ // 0x00
/*line: 100*/   PROT_READ = 0x1, /* [MC2] pages can be read */ // 0x01
/*line: 101*/   PROT_WRITE = 0x2, /* [MC2] pages can be written */ // 0x02
/*line: 102*/   PROT_EXEC = 0x4, /* [MC2] pages can be executed */ // 0x04
};

// Depends on identifiers
enum macro_mmap_flag {
/*
 * Flags contain sharing type and options.
 * Sharing types; choose one.
 */
/*line: 108*/   MAP_SHARED = 0x1, /* [MF|SHM] share changes */ // 0x0001
/*line: 109*/   MAP_PRIVATE = 0x2, /* [MF|SHM] changes are private */ // 0x0002
/*line: 111*/   MAP_COPY = 0x2, /* Obsolete */ // MAP_PRIVATE
/*
 * Other flags
 */
/*line: 117*/   MAP_FIXED = 0x10, /* [MF|SHM] interpret addr exactly */ // 0x0010
/*line: 119*/   MAP_RENAME = 0x20, /* Sun: rename private pages to file */ // 0x0020
/*line: 120*/   MAP_NORESERVE = 0x40, /* Sun: don't reserve needed swap area */ // 0x0040
/*line: 121*/   MAP_RESERVED0080 = 0x80, /* previously unimplemented MAP_INHERIT */ // 0x0080
/*line: 122*/   MAP_NOEXTEND = 0x100, /* for MAP_FILE, don't change file size */ // 0x0100
/*line: 123*/   MAP_HASSEMAPHORE = 0x200, /* region may contain semaphores */ // 0x0200
/*line: 124*/   MAP_NOCACHE = 0x400, /* don't cache pages for this mapping */ // 0x0400
/*line: 125*/   MAP_JIT = 0x800, /* Allocate a region that will be used for JIT purposes */ // 0x0800
/*
 * Mapping type
 */
/*line: 130*/   MAP_FILE = 0x0, /* map from file (default) */ // 0x0000
/*line: 131*/   MAP_ANON = 0x1000, /* allocated from memory, swap space */ // 0x1000
/*line: 132*/   MAP_ANONYMOUS = 0x1000,  // MAP_ANON
/*
 * The MAP_RESILIENT_* flags can be used when the caller wants to map some
 * possibly unreliable memory and be able to access it safely, possibly
 * getting the wrong contents rather than raising any exception.
 * For safety reasons, such mappings have to be read-only (PROT_READ access
 * only).
 *
 * MAP_RESILIENT_CODESIGN:
 *      accessing this mapping will not generate code-signing violations,
 *	even if the contents are tainted.
 * MAP_RESILIENT_MEDIA:
 *	accessing this mapping will not generate an exception if the contents
 *	are not available (unreachable removable or remote media, access beyond
 *	end-of-file, ...).  Missing contents will be replaced with zeroes.
 */
/*line: 149*/   MAP_RESILIENT_CODESIGN = 0x2000, /* no code-signing failures */ // 0x2000
/*line: 150*/   MAP_RESILIENT_MEDIA = 0x4000, /* no backing-store failures */ // 0x4000
/*
 * Flags used to support translated processes.
 */
/*line: 160*/   MAP_TRANSLATED_ALLOW_EXECUTE = 0x20000, /* allow execute in translated processes */ // 0x20000
/*line: 162*/   MAP_UNIX03 = 0x40000, /* UNIX03 compliance */ // 0x40000
/*line: 164*/   MAP_TPRO = 0x80000, /* Allocate a region that will be protected by TPRO */ // 0x80000
};

enum macro_memory_locking {
/*
 * Process memory locking
 */
/*line: 171*/   MCL_CURRENT = 0x1, /* [ML] Lock only current memory */ // 0x0001
/*line: 172*/   MCL_FUTURE = 0x2, /* [ML] Lock all future memory as well */ // 0x0002
};

enum macro_mmap_err {
    /*
 * Error return from mmap()
 */
/*line: 177*/   MAP_FAILED = -0x1, /* [MF|SHM] mmap failed */ // ((void*)-1)
};

enum macro_msync_flags {
/*
 * msync() flags
 *
 * When making a new MS_*, update tests vm_parameter_validation_[user|kern]
 * and their expected results; they deliberately call VM functions with invalid
 * msync values and you may be turning one of those invalid msyncs valid.
 */
/*line: 186*/   MS_ASYNC = 0x1, /* [MF|SIO] return immediately */ // 0x0001
/*line: 187*/   MS_INVALIDATE = 0x2, /* [MF|SIO] invalidate all cached data */ // 0x0002
/*line: 188*/   MS_SYNC = 0x10, /* [MF|SIO] msync synchronously */ // 0x0010
/*line: 191*/   MS_KILLPAGES = 0x4, /* invalidate pages, leave mapped */ // 0x0004
/*line: 192*/   MS_DEACTIVATE = 0x8, /* deactivate pages, leave mapped */ // 0x0008
};

enum macro_madvise_hints {
/*
 * Advice to madvise
 *
 * When making a new MADV_*, update tests vm_parameter_validation_[user|kern]
 * and their expected results; they deliberately call VM functions with invalid
 * madvise values and you may be turning one of those invalid madvises valid.
 */
/*line: 204*/   POSIX_MADV_NORMAL = 0x0, /* [MC1] no further special treatment */ // 0
/*line: 205*/   POSIX_MADV_RANDOM = 0x1, /* [MC1] expect random page refs */ // 1
/*line: 206*/   POSIX_MADV_SEQUENTIAL = 0x2, /* [MC1] expect sequential page refs */ // 2
/*line: 207*/   POSIX_MADV_WILLNEED = 0x3, /* [MC1] will need these pages */ // 3
/*line: 208*/   POSIX_MADV_DONTNEED = 0x4, /* [MC1] dont need these pages */ // 4
/*line: 211*/   MADV_NORMAL = 0x0,  // POSIX_MADV_NORMAL
/*line: 212*/   MADV_RANDOM = 0x1,  // POSIX_MADV_RANDOM
/*line: 213*/   MADV_SEQUENTIAL = 0x2,  // POSIX_MADV_SEQUENTIAL
/*line: 214*/   MADV_WILLNEED = 0x3,  // POSIX_MADV_WILLNEED
/*line: 215*/   MADV_DONTNEED = 0x4,  // POSIX_MADV_DONTNEED
/*line: 216*/   MADV_FREE = 0x5, /* pages unneeded, discard contents */ // 5
/*line: 217*/   MADV_ZERO_WIRED_PAGES = 0x6, /* zero the wired pages that have not been unwired before the entry is deleted */ // 6
/*line: 218*/   MADV_FREE_REUSABLE = 0x7, /* pages can be reused (by anyone) */ // 7
/*line: 219*/   MADV_FREE_REUSE = 0x8, /* caller wants to reuse those pages */ // 8
/*line: 220*/   MADV_CAN_REUSE = 0x9,  // 9
/*line: 221*/   MADV_PAGEOUT = 0xa, /* page out now (internal only) */ // 10
/*line: 222*/   MADV_ZERO = 0xb, /* zero pages without faulting in additional pages */ // 11
};

enum macro_mincore_bits {
/*
 * Return bits from mincore
 */
/*line: 227*/   MINCORE_INCORE = 0x1, /* Page is incore */ // 0x1
/*line: 228*/   MINCORE_REFERENCED = 0x2, /* Page has been referenced by us */ // 0x2
/*line: 229*/   MINCORE_MODIFIED = 0x4, /* Page has been modified by us */ // 0x4
/*line: 230*/   MINCORE_REFERENCED_OTHER = 0x8, /* Page has been referenced */ // 0x8
/*line: 231*/   MINCORE_MODIFIED_OTHER = 0x10, /* Page has been modified */ // 0x10
/*line: 232*/   MINCORE_PAGED_OUT = 0x20, /* Page has been paged out */ // 0x20
/*line: 233*/   MINCORE_COPIED = 0x40, /* Page has been copied */ // 0x40
/*line: 234*/   MINCORE_ANONYMOUS = 0x80, /* Page belongs to an anonymous object */ // 0x80
};

