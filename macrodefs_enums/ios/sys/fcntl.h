// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/fcntl.h

enum macro_open_access_modes {
/* open-only flags */
/*line: 96*/    O_RDONLY = 0x0, /* open for reading only */ // 0x0000
/*line: 97*/    O_WRONLY = 0x1, /* open for writing only */ // 0x0001
/*line: 98*/    O_RDWR = 0x2, /* open for reading and writing */ // 0x0002
/*line: 99*/    O_ACCMODE = 0x3, /* mask for above modes */ // 0x0003
};

enum macro_file_flags {
/*line: 110*/   FREAD = 0x1,  // 0x00000001
/*line: 111*/   FWRITE = 0x2,  // 0x00000002
/*line: 113*/   O_NONBLOCK = 0x4, /* no delay */ // 0x00000004
/*line: 114*/   O_APPEND = 0x8, /* set append mode */ // 0x00000008
};

// Depends on identifiers
enum macro_open_behavior_flags {
/*line: 119*/   O_SHLOCK = 0x10, /* open with shared file lock */ // 0x00000010
/*line: 120*/   O_EXLOCK = 0x20, /* open with exclusive file lock */ // 0x00000020
/*line: 121*/   O_ASYNC = 0x40, /* signal pgrp when data ready */ // 0x00000040
/*line: 122*/   O_FSYNC = 0x80, /* source compatibility: do not use */ // O_SYNC
/*line: 123*/   O_NOFOLLOW = 0x100, /* don't follow symlinks */ // 0x00000100
/*line: 125*/   O_CREAT = 0x200, /* create if nonexistant */ // 0x00000200
/*line: 126*/   O_TRUNC = 0x400, /* truncate to zero length */ // 0x00000400
/*line: 127*/   O_EXCL = 0x800, /* error if already exists */ // 0x00000800
/*line: 128*/   O_RESOLVE_BENEATH = 0x1000, /* only for open(2), same value as FMARK */ // 0x00001000
/*line: 132*/   O_EVTONLY = 0x8000, /* descriptor requested for event notifications only */ // 0x00008000
/*line: 136*/   O_NOCTTY = 0x20000, /* don't assign controlling terminal */ // 0x00020000
/*line: 140*/   O_DIRECTORY = 0x100000,  // 0x00100000
/*line: 144*/   O_SYMLINK = 0x200000, /* allow open of a symlink */ // 0x00200000
/*line: 152*/   O_CLOEXEC = 0x1000000, /* implicitly set FD_CLOEXEC */ // 0x01000000
/*line: 157*/   O_NOFOLLOW_ANY = 0x20000000, /* no symlinks allowed in path */ // 0x20000000
/*line: 161*/   O_EXEC = 0x40000000, /* open file for execute only */ // 0x40000000
/*line: 162*/   O_SEARCH = 0x40100000, /* open directory for search only */ // (O_EXEC|O_DIRECTORY)
};

enum macro_at_flags {
/*
 * Descriptor value for the current working directory
 */
/*line: 171*/   AT_FDCWD = -0x2,  // -2
/*
 * Flags for the at functions
 */
/*line: 176*/   AT_EACCESS = 0x10, /* Use effective ids in access check */ // 0x0010
/*line: 177*/   AT_SYMLINK_NOFOLLOW = 0x20, /* Act on the symlink itself not the target */ // 0x0020
/*line: 178*/   AT_SYMLINK_FOLLOW = 0x40, /* Act on target of symlink */ // 0x0040
/*line: 179*/   AT_REMOVEDIR = 0x80, /* Path refers to directory */ // 0x0080
/*line: 181*/   AT_REALDEV = 0x200, /* Return real device inodes resides on for fstatat(2) */ // 0x0200
/*line: 182*/   AT_FDONLY = 0x400, /* Use only the fd and Ignore the path for fstatat(2) */ // 0x0400
/*line: 183*/   AT_SYMLINK_NOFOLLOW_ANY = 0x800, /* Path should not contain any symlinks */ // 0x0800
};

enum macro_data_protection_flags {
/* Data Protection Flags */
/*line: 189*/   O_DP_GETRAWENCRYPTED = 0x1,  // 0x0001
/*line: 190*/   O_DP_GETRAWUNENCRYPTED = 0x2,  // 0x0002
/*line: 191*/   O_DP_AUTHENTICATE = 0x4,  // 0x0004
};

enum macro_auth_open_noauthfd {
/* Descriptor value for openat_authenticated_np() to skip authentication with another fd */
/*line: 194*/   AUTH_OPEN_NOAUTHFD = -0x1,  // -1
};

// Depends on identifiers
enum macro_file_kernel_compat_flags {
/*line: 205*/   FAPPEND = 0x8, /* kernel/compat */ // O_APPEND
/*line: 206*/   FASYNC = 0x40, /* kernel/compat */ // O_ASYNC
/*line: 207*/   FFSYNC = 0x80, /* kernel */ // O_FSYNC
/*line: 208*/   FFDSYNC = 0x400000, /* kernel */ // O_DSYNC
/*line: 209*/   FNONBLOCK = 0x4, /* kernel */ // O_NONBLOCK
/*line: 210*/   FNDELAY = 0x4, /* compat */ // O_NONBLOCK
/*line: 211*/   O_NDELAY = 0x4, /* compat */ // O_NONBLOCK
};

// Depends on identifiers
enum macro_cpf_flags {
/*line: 219*/   CPF_OVERWRITE = 0x1,  // 0x0001
/*line: 220*/   CPF_IGNORE_MODE = 0x2,  // 0x0002
/*line: 221*/   CPF_MASK = 0x3,  // (CPF_OVERWRITE|CPF_IGNORE_MODE)
};

enum macro_fcntl_commands {
/* command values */
/*line: 229*/   F_DUPFD = 0x0, /* duplicate file descriptor */ // 0
/*line: 230*/   F_GETFD = 0x1, /* get file descriptor flags */ // 1
/*line: 231*/   F_SETFD = 0x2, /* set file descriptor flags */ // 2
/*line: 232*/   F_GETFL = 0x3, /* get file status flags */ // 3
/*line: 233*/   F_SETFL = 0x4, /* set file status flags */ // 4
/*line: 234*/   F_GETOWN = 0x5, /* get SIGIO/SIGURG proc/pgrp */ // 5
/*line: 235*/   F_SETOWN = 0x6, /* set SIGIO/SIGURG proc/pgrp */ // 6
/*line: 236*/   F_GETLK = 0x7, /* get record locking information */ // 7
/*line: 237*/   F_SETLK = 0x8, /* set record locking information */ // 8
/*line: 238*/   F_SETLKW = 0x9, /* F_SETLK; wait if blocked */ // 9
/*line: 240*/   F_SETLKWTIMEOUT = 0xa, /* F_SETLK; wait if blocked, return on timeout */ // 10
/*line: 243*/   F_FLUSH_DATA = 0x28,  // 40
/*line: 244*/   F_CHKCLEAN = 0x29, /* Used for regression test */ // 41
/*line: 245*/   F_PREALLOCATE = 0x2a, /* Preallocate storage */ // 42
/*line: 246*/   F_SETSIZE = 0x2b, /* Truncate a file. Equivalent to calling truncate(2) */ // 43
/*line: 247*/   F_RDADVISE = 0x2c, /* Issue an advisory read async with no copy to user */ // 44
/*line: 248*/   F_RDAHEAD = 0x2d, /* turn read ahead off/on for this fd */ // 45
/*
 * 46,47 used to be F_READBOOTSTRAP and F_WRITEBOOTSTRAP
 */
/*line: 252*/   F_NOCACHE = 0x30, /* turn data caching off/on for this fd */ // 48
/*line: 253*/   F_LOG2PHYS = 0x31, /* file offset to device offset */ // 49
/*line: 254*/   F_GETPATH = 0x32, /* return the full path of the fd */ // 50
/*line: 255*/   F_FULLFSYNC = 0x33, /* fsync + ask the drive to flush to the media */ // 51
/*line: 256*/   F_PATHPKG_CHECK = 0x34, /* find which component (if any) is a package */ // 52
/*line: 257*/   F_FREEZE_FS = 0x35, /* "freeze" all fs operations */ // 53
/*line: 258*/   F_THAW_FS = 0x36, /* "thaw" all fs operations */ // 54
/*line: 259*/   F_GLOBAL_NOCACHE = 0x37, /* turn data caching off/on (globally) for this file */ // 55
/*line: 262*/   F_ADDSIGS = 0x3b, /* add detached signatures */ // 59
/*line: 265*/   F_ADDFILESIGS = 0x3d, /* add signature from same file (used by dyld for shared libs) */ // 61
/*line: 267*/   F_NODIRECT = 0x3e, /* used in conjunction with F_NOCACHE to indicate that DIRECT, synchonous writes */ // 62
/* should not be used (i.e. its ok to temporaily create cached pages) */
/*line: 270*/   F_GETPROTECTIONCLASS = 0x3f, /* Get the protection class of a file from the EA, returns int */ // 63
/*line: 271*/   F_SETPROTECTIONCLASS = 0x40, /* Set the protection class of a file for the EA, requires int */ // 64
/*line: 273*/   F_LOG2PHYS_EXT = 0x41, /* file offset to device offset, extended */ // 65
/*line: 275*/   F_GETLKPID = 0x42, /* See man fcntl(2) F_GETLK
	                                 * Similar to F_GETLK but in addition l_pid is treated as an input parameter
	                                 * which is used as a matching value when searching locks on the file
	                                 * so that only locks owned by the process with pid l_pid are returned.
	                                 * However, any flock(2) type lock will also be found with the returned value
	                                 * of l_pid set to -1 (as with F_GETLK).
	                                 */ // 66
/* See F_DUPFD_CLOEXEC below for 67 */
/*line: 286*/   F_SETBACKINGSTORE = 0x46, /* Mark the file as being the backing store for another filesystem */ // 70
/*line: 287*/   F_GETPATH_MTMINFO = 0x47, /* return the full path of the FD, but error in specific mtmd circumstances */ // 71
/*line: 289*/   F_GETCODEDIR = 0x48, /* Returns the code directory, with associated hashes, to the caller */ // 72
/*line: 291*/   F_SETNOSIGPIPE = 0x49, /* No SIGPIPE generated on EPIPE */ // 73
/*line: 292*/   F_GETNOSIGPIPE = 0x4a, /* Status of SIGPIPE for this fd */ // 74
/*line: 294*/   F_TRANSCODEKEY = 0x4b, /* For some cases, we need to rewrap the key for AKS/MKB */ // 75
/*line: 296*/   F_SINGLE_WRITER = 0x4c, /* file being written to a by single writer... if throttling enabled, writes */ // 76
/* may be broken into smaller chunks with throttling in between */
/*line: 299*/   F_GETPROTECTIONLEVEL = 0x4d, /* Get the protection version number for this filesystem */ // 77
/*line: 301*/   F_FINDSIGS = 0x4e, /* Add detached code signatures (used by dyld for shared libs) */ // 78
/*line: 304*/   F_ADDFILESIGS_FOR_DYLD_SIM = 0x53, /* Add signature from same file, only if it is signed by Apple (used by dyld for simulator) */ // 83
/*line: 307*/   F_BARRIERFSYNC = 0x55, /* fsync + issue barrier to drive */ // 85
/*line: 310*/   F_OFD_SETLK = 0x5a, /* Acquire or release open file description lock */ // 90
/*line: 311*/   F_OFD_SETLKW = 0x5b, /* (as F_OFD_SETLK but blocking if conflicting lock) */ // 91
/*line: 312*/   F_OFD_GETLK = 0x5c, /* Examine OFD lock */ // 92
/*line: 314*/   F_OFD_SETLKWTIMEOUT = 0x5d, /* (as F_OFD_SETLKW but return if timeout) */ // 93
/*line: 318*/   F_ADDFILESIGS_RETURN = 0x61, /* Add signature from same file, return end offset in structure on success */ // 97
/*line: 319*/   F_CHECK_LV = 0x62, /* Check if Library Validation allows this Mach-O file to be mapped into the calling process */ // 98
/*line: 321*/   F_PUNCHHOLE = 0x63, /* Deallocate a range of the file */ // 99
/*line: 323*/   F_TRIM_ACTIVE_FILE = 0x64, /* Trim an active file */ // 100
/*line: 325*/   F_SPECULATIVE_READ = 0x65, /* Asynchronous advisory read fcntl for regular and compressed file */ // 101
/*line: 327*/   F_GETPATH_NOFIRMLINK = 0x66, /* return the full path without firmlinks of the fd */ // 102
/*line: 329*/   F_ADDFILESIGS_INFO = 0x67, /* Add signature from same file, return information */ // 103
/*line: 330*/   F_ADDFILESUPPL = 0x68, /* Add supplemental signature from same file with fd reference to original */ // 104
/*line: 331*/   F_GETSIGSINFO = 0x69, /* Look up code signature information attached to a file or slice */ // 105
/*line: 333*/   F_SETLEASE = 0x6a, /* Acquire or release lease */ // 106
/*line: 334*/   F_GETLEASE = 0x6b, /* Retrieve lease information */ // 107
/*line: 339*/   F_TRANSFEREXTENTS = 0x6e, /* Transfer allocated extents beyond leof to a different file */ // 110
/*line: 341*/   F_ATTRIBUTION_TAG = 0x6f, /* Based on flags, query/set/delete a file's attribution tag */ // 111
};

enum macro_add_sigs_main_binary {
/*line: 343*/   F_ADDSIGS_MAIN_BINARY = 0x71, /* add detached signatures for main binary -- development only */ // 113
};

enum macro_fcntl_base {
// FS-specific fcntl()'s numbers begin at 0x00010000 and go up
/*line: 346*/   FCNTL_FS_SPECIFIC_BASE = 0x10000,  // 0x00010000
};

enum macro_dupfd_cloexec {
/*line: 351*/   F_DUPFD_CLOEXEC = 0x43, /* mark the dup with FD_CLOEXEC */ // 67
};

enum macro_fd_cloexec {
/* file descriptor flags (F_GETFD, F_SETFD) */
/*line: 355*/   FD_CLOEXEC = 0x1, /* close-on-exec flag */ // 1
};

enum macro_lock_flags {
/* record locking flags (F_GETLK, F_SETLK, F_SETLKW) */
/*line: 358*/   F_RDLCK = 0x1, /* shared or read lock */ // 1
/*line: 359*/   F_UNLCK = 0x2, /* unlock */ // 2
/*line: 360*/   F_WRLCK = 0x3, /* exclusive or write lock */ // 3
};

enum macro_allocate_flags {
/* allocate flags (F_PREALLOCATE) */
/*line: 378*/   F_ALLOCATECONTIG = 0x2, /* allocate contigious space */ // 0x00000002
/*line: 379*/   F_ALLOCATEALL = 0x4, /* allocate all requested space or no space at all */ // 0x00000004
/*line: 380*/   F_ALLOCATEPERSIST = 0x8, /* do not free space upon close(2) */ // 0x00000008
};

enum macro_file_position_mode {
/* Position Modes (fst_posmode) for F_PREALLOCATE */
/*line: 384*/   F_PEOFPOSMODE = 0x3, /* Make it past all of the SEEK pos modes so that */ // 3
/* we can keep them in sync should we desire */
/*line: 386*/   F_VOLPOSMODE = 0x4, /* specify volume starting postion */ // 4
};

enum macro_user_fsignatures_cdhash_len {
/*
 * detached code signatures data type -
 * information passed by user to system used by F_ADDSIGS and F_ADDFILESIGS.
 * F_ADDFILESIGS is a shortcut for files that contain their own signature and
 * doesn't require mapping of the file in order to load the signature.
 */
/*line: 433*/   USER_FSIGNATURES_CDHASH_LEN = 0x14,  // 20
};

enum macro_get_sigsinfo_platform {
/* At this time F_GETSIGSINFO can only indicate platformness.
 *  As additional requestable information is defined, new keys will be added and the
 *  fgetsigsinfo_t structure will be lengthened to add space for the additional information
 */
/*line: 476*/   GETSIGSINFO_PLATFORM_BINARY = 0x1,  // 1
};

enum macro_flock_options {
/* lock operations for flock(2) */
/*line: 487*/   LOCK_SH = 0x1, /* shared file lock */ // 0x01
/*line: 488*/   LOCK_EX = 0x2, /* exclusive file lock */ // 0x02
/*line: 489*/   LOCK_NB = 0x4, /* don't block when locking */ // 0x04
/*line: 490*/   LOCK_UN = 0x8, /* unlock file */ // 0x08
};

enum macro_attribution_name_max {
/* fattributiontag_t used by F_ATTRIBUTION_TAG */
/*line: 526*/   ATTRIBUTION_NAME_MAX = 0xff,  // 255
};

enum macro_file_tag_flags {
/* ft_flags (F_ATTRIBUTION_TAG)*/
/*line: 534*/   F_CREATE_TAG = 0x1,  // 0x00000001
/*line: 535*/   F_DELETE_TAG = 0x2,  // 0x00000002
/*line: 536*/   F_QUERY_TAG = 0x4,  // 0x00000004
};

enum macro_open_flags {
/*line: 573*/   O_POPUP = 0x80000000, /* force window to popup on open */ // 0x80000000
/*line: 574*/   O_ALERT = 0x20000000, /* small, clean popup window */ // 0x20000000
};

enum macro_filesec_property {
/*line: 626*/   _FILESEC_UNSET_PROPERTY = 0x0,  // ((void*)0)
/*line: 627*/   _FILESEC_REMOVE_ACL = 0x1,  // ((void*)1)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 598
// #define FILESEC_GUID FILESEC_UUID

