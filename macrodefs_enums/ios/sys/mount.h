// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/mount.h

enum macro_fs_name_length {
/*
 * file system statistics
 */
/*line: 93*/    MFSNAMELEN = 0xf, /* length of fs type name, not inc. null */ // 15
/*line: 94*/    MFSTYPENAMELEN = 0x10, /* length of fs type name including null */ // 16
};

// Depends on identifiers
enum macro_maxpathlen {
/*line: 97*/    MNAMELEN = 0x400, /* length of buffer for returned name */ // MAXPATHLEN
};

enum macro_mount_options {
/*line: 102*/   MNT_EXT_ROOT_DATA_VOL = 0x1, /* Data volume of root volume group */ // 0x00000001
/*line: 103*/   MNT_EXT_FSKIT = 0x2, /* this is an FSKit mount */ // 0x00000002
};

enum macro_mount_flags {
/*
 * User specifiable flags.
 *
 * Unmount uses MNT_FORCE flag.
 */
/*line: 194*/   MNT_RDONLY = 0x1, /* read only filesystem */ // 0x00000001
/*line: 195*/   MNT_SYNCHRONOUS = 0x2, /* file system written synchronously */ // 0x00000002
/*line: 196*/   MNT_NOEXEC = 0x4, /* can't exec from filesystem */ // 0x00000004
/*line: 197*/   MNT_NOSUID = 0x8, /* don't honor setuid bits on fs */ // 0x00000008
/*line: 198*/   MNT_NODEV = 0x10, /* don't interpret special files */ // 0x00000010
/*line: 199*/   MNT_UNION = 0x20, /* union with underlying filesystem */ // 0x00000020
/*line: 200*/   MNT_ASYNC = 0x40, /* file system written asynchronously */ // 0x00000040
/*line: 201*/   MNT_CPROTECT = 0x80, /* file system supports content protection */ // 0x00000080
/*
 * NFS export related mount flags.
 */
/*line: 206*/   MNT_EXPORTED = 0x100, /* file system is exported */ // 0x00000100
/*
 * Denotes storage which can be removed from the system by the user.
 */
/*line: 212*/   MNT_REMOVABLE = 0x200,  // 0x00000200
/*
 * MAC labeled / "quarantined" flag
 */
/*line: 217*/   MNT_QUARANTINE = 0x400, /* file system is quarantined */ // 0x00000400
/*
 * Flags set by internal operations.
 */
/*line: 222*/   MNT_LOCAL = 0x1000, /* filesystem is stored locally */ // 0x00001000
/*line: 223*/   MNT_QUOTA = 0x2000, /* quotas are enabled on filesystem */ // 0x00002000
/*line: 224*/   MNT_ROOTFS = 0x4000, /* identifies the root filesystem */ // 0x00004000
/*line: 225*/   MNT_DOVOLFS = 0x8000, /* FS supports volfs (deprecated flag in Mac OS X 10.5) */ // 0x00008000
/*line: 228*/   MNT_DONTBROWSE = 0x100000, /* file system is not appropriate path to user data */ // 0x00100000
/*line: 229*/   MNT_IGNORE_OWNERSHIP = 0x200000, /* VFS will ignore ownership information on filesystem objects */ // 0x00200000
/*line: 230*/   MNT_AUTOMOUNTED = 0x400000, /* filesystem was mounted by automounter */ // 0x00400000
/*line: 231*/   MNT_JOURNALED = 0x800000, /* filesystem is journaled */ // 0x00800000
/*line: 232*/   MNT_NOUSERXATTR = 0x1000000, /* Don't allow user extended attributes */ // 0x01000000
/*line: 233*/   MNT_DEFWRITE = 0x2000000, /* filesystem should defer writes */ // 0x02000000
/*line: 234*/   MNT_MULTILABEL = 0x4000000, /* MAC support for individual labels */ // 0x04000000
/*line: 235*/   MNT_NOFOLLOW = 0x8000000, /* don't follow symlink when resolving mount point */ // 0x08000000
/*line: 236*/   MNT_NOATIME = 0x10000000, /* disable update of file access time */ // 0x10000000
/*line: 237*/   MNT_SNAPSHOT = 0x40000000, /* The mount is a snapshot */ // 0x40000000
/*line: 238*/   MNT_STRICTATIME = 0x80000000, /* enable strict update of file access time */ // 0x80000000
/* backwards compatibility only */
/*line: 241*/   MNT_UNKNOWNPERMISSIONS = 0x200000,  // MNT_IGNORE_OWNERSHIP
/*
 * XXX I think that this could now become (~(MNT_CMDFLAGS))
 * but the 'mount' program may need changing to handle this.
 */
/*line: 248*/   MNT_VISFLAGMASK = 0xdff0f7ff,  // (MNT_RDONLY|MNT_SYNCHRONOUS|MNT_NOEXEC|MNT_NOSUID|MNT_NODEV|MNT_UNION|MNT_ASYNC|MNT_EXPORTED|MNT_QUARANTINE|MNT_LOCAL|MNT_QUOTA|MNT_REMOVABLE|MNT_ROOTFS|MNT_DOVOLFS|MNT_DONTBROWSE|MNT_IGNORE_OWNERSHIP|MNT_AUTOMOUNTED|MNT_JOURNALED|MNT_NOUSERXATTR|MNT_DEFWRITE|MNT_MULTILABEL|MNT_NOFOLLOW|MNT_NOATIME|MNT_STRICTATIME|MNT_SNAPSHOT|MNT_CPROTECT)
/*
 * External filesystem command modifier flags.
 * Unmount can use the MNT_FORCE flag.
 * XXX These are not STATES and really should be somewhere else.
 * External filesystem control flags.
 */
/*line: 263*/   MNT_UPDATE = 0x10000, /* not a real mount, just an update */ // 0x00010000
/*line: 264*/   MNT_NOBLOCK = 0x20000, /* don't block unmount if not responding */ // 0x00020000
/*line: 265*/   MNT_RELOAD = 0x40000, /* reload filesystem data */ // 0x00040000
/*line: 266*/   MNT_FORCE = 0x80000, /* force unmount or readonly change */ // 0x00080000
/*line: 267*/   MNT_CMDFLAGS = 0xf0000,  // (MNT_UPDATE|MNT_NOBLOCK|MNT_RELOAD|MNT_FORCE)
};

enum macro_ctl_vfs {
/*
 * Sysctl CTL_VFS definitions.
 *
 * Second level identifier specifies which filesystem. Second level
 * identifier VFS_GENERIC returns information about all filesystems.
 */
/*line: 277*/   VFS_GENERIC = 0x0, /* generic filesystem information */ // 0
/*line: 278*/   VFS_NUMMNTOPS = 0x1, /* int: total num of vfs mount/unmount operations */ // 1
};

enum macro_ctl_vfs_generic {
/*
 * Third level identifiers for VFS_GENERIC are given below; third
 * level identifiers for specific filesystems are given in their
 * mount specific header files.
 */
/*line: 284*/   VFS_MAXTYPENUM = 0x1, /* int: highest defined filesystem type */ // 1
/*line: 285*/   VFS_CONF = 0x2, /* struct: vfsconf for filesystem given
	                         *  as next argument */ // 2
};

enum macro_waitfor_flags {
/*
 * Flags for various system call interfaces.
 *
 * waitfor flags to vfs_sync() and getfsstat()
 */
/*line: 293*/   MNT_WAIT = 0x1, /* synchronized I/O file integrity completion */ // 1
/*line: 294*/   MNT_NOWAIT = 0x2, /* start all I/O, but do not wait for it */ // 2
/*line: 295*/   MNT_DWAIT = 0x4, /* synchronized I/O data integrity completion */ // 4
};

// enum macro_vfsidctl_flags {
// /* vfsidctl API version. */
// /*line: 319*/   VFS_CTL_VERS1 = 0x1,  // 0x01

enum macro_vfsctl_values {
/*
 * New style VFS sysctls, do not reuse/conflict with the namespace for
 * private sysctls.
 */
/*line: 326*/   VFS_CTL_OSTATFS = 0x10001, /* old legacy statfs */ // 0x00010001
/*line: 327*/   VFS_CTL_UMOUNT = 0x10002, /* unmount */ // 0x00010002
/*line: 328*/   VFS_CTL_QUERY = 0x10003, /* anything wrong? (vfsquery) */ // 0x00010003
/*line: 329*/   VFS_CTL_NEWADDR = 0x10004, /* reconnect to new address */ // 0x00010004
/*line: 330*/   VFS_CTL_TIMEO = 0x10005, /* set timeout for vfs notification */ // 0x00010005
/*line: 331*/   VFS_CTL_NOLOCKS = 0x10006, /* disable file locking */ // 0x00010006
/*line: 332*/   VFS_CTL_SADDR = 0x10007, /* get server address */ // 0x00010007
/*line: 333*/   VFS_CTL_DISC = 0x10008, /* server disconnected */ // 0x00010008
/*line: 334*/   VFS_CTL_SERVERINFO = 0x10009, /* information about fs server */ // 0x00010009
/*line: 335*/   VFS_CTL_NSTATUS = 0x1000a, /* netfs mount status */ // 0x0001000A
/*line: 336*/   VFS_CTL_STATFS64 = 0x1000b, /* statfs64 */ // 0x0001000B
/*line: 343*/   VFS_CTL_STATFS = 0x1000b,  // VFS_CTL_STATFS64
};

enum macro_vfsquery_flags {
/* vfsquery flags */
/*line: 370*/   VQ_NOTRESP = 0x1, /* server down */ // 0x0001
/*line: 371*/   VQ_NEEDAUTH = 0x2, /* server bad auth */ // 0x0002
/*line: 372*/   VQ_LOWDISK = 0x4, /* we're low on space */ // 0x0004
/*line: 373*/   VQ_MOUNT = 0x8, /* new filesystem arrived */ // 0x0008
/*line: 374*/   VQ_UNMOUNT = 0x10, /* filesystem has left */ // 0x0010
/*line: 375*/   VQ_DEAD = 0x20, /* filesystem is dead, needs force unmount */ // 0x0020
/*line: 376*/   VQ_ASSIST = 0x40, /* filesystem needs assistance from external program */ // 0x0040
/*line: 377*/   VQ_NOTRESPLOCK = 0x80, /* server lockd down */ // 0x0080
/*line: 378*/   VQ_UPDATE = 0x100, /* filesystem information has changed */ // 0x0100
/*line: 379*/   VQ_VERYLOWDISK = 0x200, /* file system has *very* little disk space left */ // 0x0200
/*line: 380*/   VQ_SYNCEVENT = 0x400, /* a sync just happened (not set by kernel starting Mac OS X 10.9) */ // 0x0400
/*line: 381*/   VQ_SERVEREVENT = 0x800, /* server issued notification/warning */ // 0x0800
/*line: 382*/   VQ_QUOTA = 0x1000, /* a user quota has been hit */ // 0x1000
/*line: 383*/   VQ_NEARLOWDISK = 0x2000, /* Above lowdisk and below desired disk space */ // 0x2000
/*line: 384*/   VQ_DESIRED_DISK = 0x4000, /* the desired disk space */ // 0x4000
/*line: 385*/   VQ_FREE_SPACE_CHANGE = 0x8000, /* free disk space has significantly changed */ // 0x8000
/*line: 386*/   VQ_PURGEABLE_SPACE_CHANGE = 0x10000, /* purgeable disk space has significantly changed */ // 0x10000
/*line: 387*/   VQ_FLAG20000 = 0x20000, /* placeholder */ // 0x20000
};

// Depends on identifiers
enum macro_nfs_file_handle_size {
/*
 * Generic file handle
 */
/*line: 394*/   NFS_MAX_FH_SIZE = 0x80,  // NFSV4_MAX_FH_SIZE
/*line: 395*/   NFSV4_MAX_FH_SIZE = 0x80,  // 128
/*line: 396*/   NFSV3_MAX_FH_SIZE = 0x40,  // 64
/*line: 397*/   NFSV2_MAX_FH_SIZE = 0x20,  // 32
};

// enum macro_cryptex_version {
// // bump up the version for any change that has kext dependency
// /*line: 411*/   CRYPTEX_AUTH_STRUCT_VERSION = 0x2,  // 2
// };

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 105
// #define __DARWIN_STRUCT_STATFS64 { \
// 	uint32_t	f_bsize;        /* fundamental file system block size */ \
// 	int32_t		f_iosize;       /* optimal transfer block size */ \
// 	uint64_t	f_blocks;       /* total data blocks in file system */ \
// 	uint64_t	f_bfree;        /* free blocks in fs */ \
// 	uint64_t	f_bavail;       /* free blocks avail to non-superuser */ \
// 	uint64_t	f_files;        /* total file nodes in file system */ \
// 	uint64_t	f_ffree;        /* free file nodes in fs */ \
// 	fsid_t		f_fsid;         /* file system id */ \
// 	uid_t		f_owner;        /* user that mounted the filesystem */ \
// 	uint32_t	f_type;         /* type of filesystem */ \
// 	uint32_t	f_flags;        /* copy of mount exported flags */ \
// 	uint32_t	f_fssubtype;    /* fs sub-type (flavor) */ \
// 	char		f_fstypename[MFSTYPENAMELEN];   /* fs type name */ \
// 	char		f_mntonname[MAXPATHLEN];        /* directory on which mounted */ \
// 	char		f_mntfromname[MAXPATHLEN];      /* mounted filesystem */ \
// 	uint32_t    f_flags_ext;    /* extended flags */ \
// 	uint32_t	f_reserved[7];  /* For future use */ \
// }

