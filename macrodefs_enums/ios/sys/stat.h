// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/stat.h

// Depends on identifiers
enum macro_file_permissions {
/*line: 297*/   ACCESSPERMS = 0x1ff, /* 0777 */ // (S_IRWXU|S_IRWXG|S_IRWXO)
/* 7777 */
/*line: 299*/   ALLPERMS = 0xfff,  // (S_ISUID|S_ISGID|S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO)
/* 0666 */
/*line: 301*/   DEFFILEMODE = 0x1b6,  // (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
};

enum macro_block_size {
/*line: 303*/   S_BLKSIZE = 0x200, /* block size used in the stat struct */ // 512
};

enum macro_uf_flags {
/*
 * Definitions of flags stored in file flags word.
 *
 * Super-user and owner changeable flags.
 */
/*line: 310*/   UF_SETTABLE = 0xffff, /* mask of owner changeable flags */ // 0x0000ffff
/*line: 311*/   UF_NODUMP = 0x1, /* do not dump file */ // 0x00000001
/*line: 312*/   UF_IMMUTABLE = 0x2, /* file may not be changed */ // 0x00000002
/*line: 313*/   UF_APPEND = 0x4, /* writes to file may only append */ // 0x00000004
/*line: 314*/   UF_OPAQUE = 0x8, /* directory is opaque wrt. union */ // 0x00000008
/*line: 320*/   UF_COMPRESSED = 0x20, /* file is compressed (some file-systems) */ // 0x00000020
/* UF_TRACKED is used for dealing with document IDs.  We no longer issue
 *  notifications for deletes or renames for files which have UF_TRACKED set. */
/*line: 324*/   UF_TRACKED = 0x40,  // 0x00000040
/*line: 326*/   UF_DATAVAULT = 0x80, /* entitlement required for reading */ // 0x00000080
/* Bits 0x0100 through 0x4000 are currently undefined. */
/*line: 330*/   UF_HIDDEN = 0x8000, /* hint that this item should not be */ // 0x00008000
};

enum macro_sf_flags {
/*
 * Super-user changeable flags.
 */
/*line: 335*/   SF_SUPPORTED = 0x9f0000, /* mask of superuser supported flags */ // 0x009f0000
/*line: 336*/   SF_SETTABLE = 0x3fff0000, /* mask of superuser changeable flags */ // 0x3fff0000
/*line: 337*/   SF_SYNTHETIC = 0xc0000000, /* mask of system read-only synthetic flags */ // 0xc0000000
/*line: 338*/   SF_ARCHIVED = 0x10000, /* file is archived */ // 0x00010000
/*line: 339*/   SF_IMMUTABLE = 0x20000, /* file may not be changed */ // 0x00020000
/*line: 340*/   SF_APPEND = 0x40000, /* writes to file may only append */ // 0x00040000
/*line: 341*/   SF_RESTRICTED = 0x80000, /* entitlement required for writing */ // 0x00080000
/*line: 342*/   SF_NOUNLINK = 0x100000, /* Item may not be removed, renamed or mounted on */ // 0x00100000
/* NOTE: There is no SF_HIDDEN bit. */
/*line: 351*/   SF_FIRMLINK = 0x800000, /* file is a firmlink */ // 0x00800000
/*
 * Synthetic flags.
 *
 * These are read-only.  We keep them out of SF_SUPPORTED so that
 * attempts to set them will fail.
 */
/*line: 359*/   SF_DATALESS = 0x40000000, /* file is dataless object */ // 0x40000000
};

enum macro_extended_file_flags {
/*
 * Extended flags ("EF") returned by ATTR_CMNEXT_EXT_FLAGS from getattrlist/getattrlistbulk
 */
/*line: 368*/   EF_MAY_SHARE_BLOCKS = 0x1, /* file may share blocks with another file */ // 0x00000001
/*line: 369*/   EF_NO_XATTRS = 0x2, /* file has no xattrs at all */ // 0x00000002
/*line: 370*/   EF_IS_SYNC_ROOT = 0x4, /* file is a sync root for iCloud */ // 0x00000004
/*line: 371*/   EF_IS_PURGEABLE = 0x8, /* file is purgeable */ // 0x00000008
/*line: 372*/   EF_IS_SPARSE = 0x10, /* file has at least one sparse region */ // 0x00000010
/*line: 373*/   EF_IS_SYNTHETIC = 0x20, /* a synthetic directory/symlink */ // 0x00000020
/*line: 374*/   EF_SHARES_ALL_BLOCKS = 0x40, /* file shares all of its blocks with another file */ // 0x00000040
};

enum macro_utime_flags {
/*line: 398*/   UTIME_NOW = -0x1,  // -1
/*line: 399*/   UTIME_OMIT = -0x2,  // -2
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 128
// #define __DARWIN_STRUCT_STAT64_TIMES struct timespec st_atimespec;           /* time of last access */ \
// 	struct timespec st_mtimespec;           /* time of last data modification */ \
// 	struct timespec st_ctimespec;           /* time of last status change */ \
// 	struct timespec st_birthtimespec;

// Line: 158
// #define __DARWIN_STRUCT_STAT64 { \
// 	dev_t		st_dev;                 /* [XSI] ID of device containing file */ \
// 	mode_t		st_mode;                /* [XSI] Mode of file (see below) */ \
// 	nlink_t		st_nlink;               /* [XSI] Number of hard links */ \
// 	__darwin_ino64_t st_ino;                /* [XSI] File serial number */ \
// 	uid_t		st_uid;                 /* [XSI] User ID of the file */ \
// 	gid_t		st_gid;                 /* [XSI] Group ID of the file */ \
// 	dev_t		st_rdev;                /* [XSI] Device ID */ \
// 	__DARWIN_STRUCT_STAT64_TIMES \
// 	off_t		st_size;                /* [XSI] file size, in bytes */ \
// 	blkcnt_t	st_blocks;              /* [XSI] blocks allocated for file */ \
// 	blksize_t	st_blksize;             /* [XSI] optimal blocksize for I/O */ \
// 	__uint32_t	st_flags;               /* user defined flags for file */ \
// 	__uint32_t	st_gen;                 /* file generation number */ \
// 	__int32_t	st_lspare;              /* RESERVED: DO NOT USE! */ \
// 	__int64_t	st_qspare[2];           /* RESERVED: DO NOT USE! */ \
// }

// Line: 231
// #define st_atime st_atimespec.tv_sec

// Line: 232
// #define st_mtime st_mtimespec.tv_sec

// Line: 233
// #define st_ctime st_ctimespec.tv_sec

// Line: 234
// #define st_birthtime st_birthtimespec.tv_sec

