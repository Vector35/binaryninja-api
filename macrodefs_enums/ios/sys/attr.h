// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/attr.h

enum macro_fs_options {
/*line: 46*/    FSOPT_NOFOLLOW = 0x1,  // 0x00000001
/*line: 47*/    FSOPT_NOINMEMUPDATE = 0x2,  // 0x00000002
/*line: 48*/    FSOPT_REPORT_FULLSIZE = 0x4,  // 0x00000004
/* The following option only valid when requesting ATTR_CMN_RETURNED_ATTRS */
/*line: 50*/    FSOPT_PACK_INVAL_ATTRS = 0x8,  // 0x00000008
/*line: 53*/    FSOPT_ATTR_CMN_EXTENDED = 0x20,  // 0x00000020
/*line: 54*/    FSOPT_RETURN_REALDEV = 0x200,  // 0x00000200
/*line: 55*/    FSOPT_NOFOLLOW_ANY = 0x800,  // 0x00000800
};

enum macro_searchfs_max_searchparms {
/* we currently aren't anywhere near this amount for a valid
 * fssearchblock.sizeofsearchparams1 or fssearchblock.sizeofsearchparams2
 * but we put a sanity check in to avoid abuse of the value passed in from
 * user land.
 */
/*line: 62*/    SEARCHFS_MAX_SEARCHPARMS = 0x1000,  // 4096
};

enum macro_bit_map_count {
/*line: 88*/    ATTR_BIT_MAP_COUNT = 0x5,  // 5
};

enum macro_vol_capabilities {
/*line: 117*/   VOL_CAPABILITIES_FORMAT = 0x0,  // 0
/*line: 118*/   VOL_CAPABILITIES_INTERFACES = 0x1,  // 1
/*line: 119*/   VOL_CAPABILITIES_RESERVED1 = 0x2,  // 2
/*line: 120*/   VOL_CAPABILITIES_RESERVED2 = 0x3,  // 3
};

enum macro_max_buffer {
/*
 * XXX this value needs to be raised - 3893388
 */
/*line: 130*/   ATTR_MAX_BUFFER = 0x2000,  // 8192
};

// Depends on identifiers
enum macro_attr_max_buffer {
/*
 * Max size of attribute buffer if IOPOL_TYPE_VFS_SUPPORT_LONG_PATHS is enabled
 */
/*line: 136*/   ATTR_MAX_BUFFER_LONGPATHS = 0x3c00,  // (ATTR_MAX_BUFFER-MAXPATHLEN+MAXLONGPATHLEN)
};

enum macro_volume_capabilities {
/*
 * VOL_CAP_FMT_PERSISTENTOBJECTIDS: When set, the volume has object IDs
 * that are persistent (retain their values even when the volume is
 * unmounted and remounted), and a file or directory can be looked up
 * by ID.  Volumes that support VolFS and can support Carbon File ID
 * references should set this bit.
 *
 * VOL_CAP_FMT_SYMBOLICLINKS: When set, the volume supports symbolic
 * links.  The symlink(), readlink(), and lstat() calls all use this
 * symbolic link.
 *
 * VOL_CAP_FMT_HARDLINKS: When set, the volume supports hard links.
 * The link() call creates hard links.
 *
 * VOL_CAP_FMT_JOURNAL: When set, the volume is capable of supporting
 * a journal used to speed recovery in case of unplanned shutdown
 * (such as a power outage or crash).  This bit does not necessarily
 * mean the volume is actively using a journal for recovery.
 *
 * VOL_CAP_FMT_JOURNAL_ACTIVE: When set, the volume is currently using
 * a journal for use in speeding recovery after an unplanned shutdown.
 * This bit can be set only if VOL_CAP_FMT_JOURNAL is also set.
 *
 * VOL_CAP_FMT_NO_ROOT_TIMES: When set, the volume format does not
 * store reliable times for the root directory, so you should not
 * depend on them to detect changes, etc.
 *
 * VOL_CAP_FMT_SPARSE_FILES: When set, the volume supports sparse files.
 * That is, files which can have "holes" that have never been written
 * to, and are not allocated on disk.  Sparse files may have an
 * allocated size that is less than the file's logical length.
 *
 * VOL_CAP_FMT_ZERO_RUNS: For security reasons, parts of a file (runs)
 * that have never been written to must appear to contain zeroes.  When
 * this bit is set, the volume keeps track of allocated but unwritten
 * runs of a file so that it can substitute zeroes without actually
 * writing zeroes to the media.  This provides performance similar to
 * sparse files, but not the space savings.
 *
 * VOL_CAP_FMT_CASE_SENSITIVE: When set, file and directory names are
 * case sensitive (upper and lower case are different).  When clear,
 * an upper case character is equivalent to a lower case character,
 * and you can't have two names that differ solely in the case of
 * the characters.
 *
 * VOL_CAP_FMT_CASE_PRESERVING: When set, file and directory names
 * preserve the difference between upper and lower case.  If clear,
 * the volume may change the case of some characters (typically
 * making them all upper or all lower case).  A volume that sets
 * VOL_CAP_FMT_CASE_SENSITIVE should also set VOL_CAP_FMT_CASE_PRESERVING.
 *
 * VOL_CAP_FMT_FAST_STATFS: This bit is used as a hint to upper layers
 * (especially Carbon) that statfs() is fast enough that its results
 * need not be cached by those upper layers.  A volume that caches
 * the statfs information in its in-memory structures should set this bit.
 * A volume that must always read from disk or always perform a network
 * transaction should not set this bit.
 *
 * VOL_CAP_FMT_2TB_FILESIZE: If this bit is set the volume format supports
 * file sizes larger than 4GB, and potentially up to 2TB; it does not
 * indicate whether the filesystem supports files larger than that.
 *
 * VOL_CAP_FMT_OPENDENYMODES: When set, the volume supports open deny
 * modes (e.g. "open for read write, deny write"; effectively, mandatory
 * file locking based on open modes).
 *
 * VOL_CAP_FMT_HIDDEN_FILES: When set, the volume supports the UF_HIDDEN
 * file flag, and the UF_HIDDEN flag is mapped to that volume's native
 * "hidden" or "invisible" bit (which may be the invisible bit from the
 * Finder Info extended attribute).
 *
 * VOL_CAP_FMT_PATH_FROM_ID:  When set, the volume supports the ability
 * to derive a pathname to the root of the file system given only the
 * id of an object.  This also implies that object ids on this file
 * system are persistent and not recycled.  This is a very specialized
 * capability and it is assumed that most file systems will not support
 * it.  Its use is for legacy non-posix APIs like ResolveFileIDRef.
 *
 * VOL_CAP_FMT_NO_VOLUME_SIZES: When set, the volume does not support
 * returning values for total data blocks, available blocks, or free blocks
 * (as in f_blocks, f_bavail, or f_bfree in "struct statfs").  Historically,
 * those values were set to 0xFFFFFFFF for volumes that did not support them.
 *
 * VOL_CAP_FMT_DECMPFS_COMPRESSION: When set, the volume supports transparent
 * decompression of compressed files using decmpfs.
 *
 * VOL_CAP_FMT_64BIT_OBJECT_IDS: When set, the volume uses object IDs that
 * are 64-bit. This means that ATTR_CMN_FILEID and ATTR_CMN_PARENTID are the
 * only legitimate attributes for obtaining object IDs from this volume and the
 * 32-bit fid_objno fields of the fsobj_id_t returned by ATTR_CMN_OBJID,
 * ATTR_CMN_OBJPERMID, and ATTR_CMN_PAROBJID are undefined.
 *
 * VOL_CAP_FMT_DIR_HARDLINKS: When set, the volume supports directory
 * hard links.
 *
 * VOL_CAP_FMT_DOCUMENT_ID: When set, the volume supports document IDs
 * (an ID which persists across object ID changes) for document revisions.
 *
 * VOL_CAP_FMT_WRITE_GENERATION_COUNT: When set, the volume supports write
 * generation counts (a count of how many times an object has been modified)
 *
 * VOL_CAP_FMT_NO_IMMUTABLE_FILES: When set, the volume does not support
 * setting the UF_IMMUTABLE flag.
 *
 * VOL_CAP_FMT_NO_PERMISSIONS: When set, the volume does not support setting
 * permissions.
 *
 * VOL_CAP_FMT_SHARED_SPACE: When set, the volume supports sharing space with
 * other filesystems i.e. multiple logical filesystems can exist in the same
 * "partition". An implication of this is that the filesystem which sets
 * this capability treats waitfor arguments to VFS_SYNC as bit flags.
 *
 * VOL_CAP_FMT_VOL_GROUPS: When set, this volume is part of a volume-group
 * that implies multiple volumes must be mounted in order to boot and root the
 * operating system. Typically, this means a read-only system volume and a
 * writable data volume.
 *
 * VOL_CAP_FMT_SEALED: When set, this volume is cryptographically sealed.
 * Any modifications to volume data or metadata will be detected and may
 * render the volume unusable.
 *
 * VOL_CAP_FMT_CLONE_MAPPING: When set, this volume supports full clone tracking.
 * See ATTR_CMNEXT_CLONE_REFCNT and ATTR_CMNEXT_CLONEID for more details.
 * Other features like extended directory statistics, for fast directory sizing,
 * and attribution tags may be supported as well.
 * See VOL_CAP_INT_ATTRIBUTION_TAG for more details related to tagging.
 */
/*line: 265*/   VOL_CAP_FMT_PERSISTENTOBJECTIDS = 0x1,  // 0x00000001
/*line: 266*/   VOL_CAP_FMT_SYMBOLICLINKS = 0x2,  // 0x00000002
/*line: 267*/   VOL_CAP_FMT_HARDLINKS = 0x4,  // 0x00000004
/*line: 268*/   VOL_CAP_FMT_JOURNAL = 0x8,  // 0x00000008
/*line: 269*/   VOL_CAP_FMT_JOURNAL_ACTIVE = 0x10,  // 0x00000010
/*line: 270*/   VOL_CAP_FMT_NO_ROOT_TIMES = 0x20,  // 0x00000020
/*line: 271*/   VOL_CAP_FMT_SPARSE_FILES = 0x40,  // 0x00000040
/*line: 272*/   VOL_CAP_FMT_ZERO_RUNS = 0x80,  // 0x00000080
/*line: 273*/   VOL_CAP_FMT_CASE_SENSITIVE = 0x100,  // 0x00000100
/*line: 274*/   VOL_CAP_FMT_CASE_PRESERVING = 0x200,  // 0x00000200
/*line: 275*/   VOL_CAP_FMT_FAST_STATFS = 0x400,  // 0x00000400
/*line: 276*/   VOL_CAP_FMT_2TB_FILESIZE = 0x800,  // 0x00000800
/*line: 277*/   VOL_CAP_FMT_OPENDENYMODES = 0x1000,  // 0x00001000
/*line: 278*/   VOL_CAP_FMT_HIDDEN_FILES = 0x2000,  // 0x00002000
/*line: 279*/   VOL_CAP_FMT_PATH_FROM_ID = 0x4000,  // 0x00004000
/*line: 280*/   VOL_CAP_FMT_NO_VOLUME_SIZES = 0x8000,  // 0x00008000
/*line: 281*/   VOL_CAP_FMT_DECMPFS_COMPRESSION = 0x10000,  // 0x00010000
/*line: 282*/   VOL_CAP_FMT_64BIT_OBJECT_IDS = 0x20000,  // 0x00020000
/*line: 283*/   VOL_CAP_FMT_DIR_HARDLINKS = 0x40000,  // 0x00040000
/*line: 284*/   VOL_CAP_FMT_DOCUMENT_ID = 0x80000,  // 0x00080000
/*line: 285*/   VOL_CAP_FMT_WRITE_GENERATION_COUNT = 0x100000,  // 0x00100000
/*line: 286*/   VOL_CAP_FMT_NO_IMMUTABLE_FILES = 0x200000,  // 0x00200000
/*line: 287*/   VOL_CAP_FMT_NO_PERMISSIONS = 0x400000,  // 0x00400000
/*line: 288*/   VOL_CAP_FMT_SHARED_SPACE = 0x800000,  // 0x00800000
/*line: 289*/   VOL_CAP_FMT_VOL_GROUPS = 0x1000000,  // 0x01000000
/*line: 290*/   VOL_CAP_FMT_SEALED = 0x2000000,  // 0x02000000
/*line: 291*/   VOL_CAP_FMT_CLONE_MAPPING = 0x4000000,  // 0x04000000
};

enum macro_volume_internal_capabilities {
/*
 * VOL_CAP_INT_SEARCHFS: When set, the volume implements the
 * searchfs() system call (the vnop_searchfs vnode operation).
 *
 * VOL_CAP_INT_ATTRLIST: When set, the volume implements the
 * getattrlist() and setattrlist() system calls (vnop_getattrlist
 * and vnop_setattrlist vnode operations) for the volume, files,
 * and directories.  The volume may or may not implement the
 * readdirattr() system call.  XXX Is there any minimum set
 * of attributes that should be supported?  To determine the
 * set of supported attributes, get the ATTR_VOL_ATTRIBUTES
 * attribute of the volume.
 *
 * VOL_CAP_INT_NFSEXPORT: When set, the volume implements exporting
 * of NFS volumes.
 *
 * VOL_CAP_INT_READDIRATTR: When set, the volume implements the
 * readdirattr() system call (vnop_readdirattr vnode operation).
 *
 * VOL_CAP_INT_EXCHANGEDATA: When set, the volume implements the
 * exchangedata() system call (VNOP_EXCHANGE vnode operation).
 *
 * VOL_CAP_INT_COPYFILE: When set, the volume implements the
 * VOP_COPYFILE vnode operation.  (XXX There should be a copyfile()
 * system call in <unistd.h>.)
 *
 * VOL_CAP_INT_ALLOCATE: When set, the volume implements the
 * VNOP_ALLOCATE vnode operation, which means it implements the
 * F_PREALLOCATE selector of fcntl(2).
 *
 * VOL_CAP_INT_VOL_RENAME: When set, the volume implements the
 * ATTR_VOL_NAME attribute for both getattrlist() and setattrlist().
 * The volume can be renamed by setting ATTR_VOL_NAME with setattrlist().
 *
 * VOL_CAP_INT_ADVLOCK: When set, the volume implements POSIX style
 * byte range locks via vnop_advlock (accessible from fcntl(2)).
 *
 * VOL_CAP_INT_FLOCK: When set, the volume implements whole-file flock(2)
 * style locks via vnop_advlock.  This includes the O_EXLOCK and O_SHLOCK
 * flags of the open(2) call.
 *
 * VOL_CAP_INT_EXTENDED_SECURITY: When set, the volume implements
 * extended security (ACLs).
 *
 * VOL_CAP_INT_USERACCESS:  When set, the volume supports the
 * ATTR_CMN_USERACCESS attribute (used to get the user's access
 * mode to the file).
 *
 * VOL_CAP_INT_MANLOCK: When set, the volume supports AFP-style
 * mandatory byte range locks via an ioctl().
 *
 * VOL_CAP_INT_EXTENDED_ATTR: When set, the volume implements
 * native extended attribues.
 *
 * VOL_CAP_INT_NAMEDSTREAMS: When set, the volume supports
 * native named streams.
 *
 * VOL_CAP_INT_CLONE: When set, the volume supports clones.
 *
 * VOL_CAP_INT_SNAPSHOT: When set, the volume supports snapshots.
 *
 * VOL_CAP_INT_RENAME_SWAP: When set, the volume supports swapping
 * file system objects.
 *
 * VOL_CAP_INT_RENAME_EXCL: When set, the volume supports an
 * exclusive rename operation.
 *
 * VOL_CAP_INT_RENAME_OPENFAIL: When set, the volume may fail rename
 * operations on files that are open.
 *
 * VOL_CAP_INT_RENAME_SECLUDE: When set, the volume supports a
 * seclude rename operation.
 *
 * VOL_CAP_INT_ATTRIBUTION_TAG: When set, the volume supports establishing
 * an owner relationship between a file (excluding small files) and a process
 * on the first read/write/truncate/clone operation.
 *
 * VOL_CAP_INT_PUNCHHOLE: When set, the volume supports the F_PUNCHHOLE
 * fcntl.
 */
/*line: 373*/   VOL_CAP_INT_SEARCHFS = 0x1,  // 0x00000001
/*line: 374*/   VOL_CAP_INT_ATTRLIST = 0x2,  // 0x00000002
/*line: 375*/   VOL_CAP_INT_NFSEXPORT = 0x4,  // 0x00000004
/*line: 376*/   VOL_CAP_INT_READDIRATTR = 0x8,  // 0x00000008
/*line: 377*/   VOL_CAP_INT_EXCHANGEDATA = 0x10,  // 0x00000010
/*line: 378*/   VOL_CAP_INT_COPYFILE = 0x20,  // 0x00000020
/*line: 379*/   VOL_CAP_INT_ALLOCATE = 0x40,  // 0x00000040
/*line: 380*/   VOL_CAP_INT_VOL_RENAME = 0x80,  // 0x00000080
/*line: 381*/   VOL_CAP_INT_ADVLOCK = 0x100,  // 0x00000100
/*line: 382*/   VOL_CAP_INT_FLOCK = 0x200,  // 0x00000200
/*line: 383*/   VOL_CAP_INT_EXTENDED_SECURITY = 0x400,  // 0x00000400
/*line: 384*/   VOL_CAP_INT_USERACCESS = 0x800,  // 0x00000800
/*line: 385*/   VOL_CAP_INT_MANLOCK = 0x1000,  // 0x00001000
/*line: 386*/   VOL_CAP_INT_NAMEDSTREAMS = 0x2000,  // 0x00002000
/*line: 387*/   VOL_CAP_INT_EXTENDED_ATTR = 0x4000,  // 0x00004000
/*line: 388*/   VOL_CAP_INT_CLONE = 0x10000,  // 0x00010000
/*line: 389*/   VOL_CAP_INT_SNAPSHOT = 0x20000,  // 0x00020000
/*line: 390*/   VOL_CAP_INT_RENAME_SWAP = 0x40000,  // 0x00040000
/*line: 391*/   VOL_CAP_INT_RENAME_EXCL = 0x80000,  // 0x00080000
/*line: 392*/   VOL_CAP_INT_RENAME_OPENFAIL = 0x100000,  // 0x00100000
/*line: 393*/   VOL_CAP_INT_RENAME_SECLUDE = 0x200000,  // 0x00200000
/*line: 394*/   VOL_CAP_INT_ATTRIBUTION_TAG = 0x400000,  // 0x00400000
/*line: 395*/   VOL_CAP_INT_PUNCHHOLE = 0x800000,  // 0x00800000
};

enum macro_common_attributes {
/*line: 402*/   ATTR_CMN_NAME = 0x1,  // 0x00000001
/*line: 403*/   ATTR_CMN_DEVID = 0x2,  // 0x00000002
/*line: 404*/   ATTR_CMN_FSID = 0x4,  // 0x00000004
/*line: 405*/   ATTR_CMN_OBJTYPE = 0x8,  // 0x00000008
/*line: 406*/   ATTR_CMN_OBJTAG = 0x10,  // 0x00000010
/*line: 407*/   ATTR_CMN_OBJID = 0x20,  // 0x00000020
/*line: 408*/   ATTR_CMN_OBJPERMANENTID = 0x40,  // 0x00000040
/*line: 409*/   ATTR_CMN_PAROBJID = 0x80,  // 0x00000080
/*line: 410*/   ATTR_CMN_SCRIPT = 0x100,  // 0x00000100
/*line: 411*/   ATTR_CMN_CRTIME = 0x200,  // 0x00000200
/*line: 412*/   ATTR_CMN_MODTIME = 0x400,  // 0x00000400
/*line: 413*/   ATTR_CMN_CHGTIME = 0x800,  // 0x00000800
/*line: 414*/   ATTR_CMN_ACCTIME = 0x1000,  // 0x00001000
/*line: 415*/   ATTR_CMN_BKUPTIME = 0x2000,  // 0x00002000
/*line: 416*/   ATTR_CMN_FNDRINFO = 0x4000,  // 0x00004000
/*line: 417*/   ATTR_CMN_OWNERID = 0x8000,  // 0x00008000
/*line: 418*/   ATTR_CMN_GRPID = 0x10000,  // 0x00010000
/*line: 419*/   ATTR_CMN_ACCESSMASK = 0x20000,  // 0x00020000
/*line: 420*/   ATTR_CMN_FLAGS = 0x40000,  // 0x00040000
/* option flag.                                                 */
/*line: 431*/   ATTR_CMN_GEN_COUNT = 0x80000,  // 0x00080000
/*line: 432*/   ATTR_CMN_DOCUMENT_ID = 0x100000,  // 0x00100000
/*line: 434*/   ATTR_CMN_USERACCESS = 0x200000,  // 0x00200000
/*line: 435*/   ATTR_CMN_EXTENDED_SECURITY = 0x400000,  // 0x00400000
/*line: 436*/   ATTR_CMN_UUID = 0x800000,  // 0x00800000
/*line: 437*/   ATTR_CMN_GRPUUID = 0x1000000,  // 0x01000000
/*line: 438*/   ATTR_CMN_FILEID = 0x2000000,  // 0x02000000
/*line: 439*/   ATTR_CMN_PARENTID = 0x4000000,  // 0x04000000
/*line: 440*/   ATTR_CMN_FULLPATH = 0x8000000,  // 0x08000000
/*line: 441*/   ATTR_CMN_ADDEDTIME = 0x10000000,  // 0x10000000
/*line: 442*/   ATTR_CMN_ERROR = 0x20000000,  // 0x20000000
/*line: 443*/   ATTR_CMN_DATA_PROTECT_FLAGS = 0x40000000,  // 0x40000000
/*
 * ATTR_CMN_RETURNED_ATTRS is only valid with getattrlist(2) and
 * getattrlistbulk(2). It is always the first attribute in the return buffer.
 */
/*line: 449*/   ATTR_CMN_RETURNED_ATTRS = 0x80000000,  // 0x80000000
/*line: 451*/   ATTR_CMN_VALIDMASK = 0xffffffff,  // 0xFFFFFFFF
/*
 * The settable ATTR_CMN_* attributes include the following:
 * ATTR_CMN_SCRIPT
 * ATTR_CMN_CRTIME
 * ATTR_CMN_MODTIME
 * ATTR_CMN_CHGTIME
 *
 * ATTR_CMN_ACCTIME
 * ATTR_CMN_BKUPTIME
 * ATTR_CMN_FNDRINFO
 * ATTR_CMN_OWNERID
 *
 * ATTR_CMN_GRPID
 * ATTR_CMN_ACCESSMASK
 * ATTR_CMN_FLAGS
 *
 * ATTR_CMN_EXTENDED_SECURITY
 * ATTR_CMN_UUID
 *
 * ATTR_CMN_GRPUUID
 *
 * ATTR_CMN_DATA_PROTECT_FLAGS
 */
/*line: 475*/   ATTR_CMN_SETMASK = 0x51c7ff00,  // 0x51C7FF00
/*line: 476*/   ATTR_CMN_VOLSETMASK = 0x6700,  // 0x00006700
};

enum macro_volume_attributes {
/*line: 478*/   ATTR_VOL_FSTYPE = 0x1,  // 0x00000001
/*line: 479*/   ATTR_VOL_SIGNATURE = 0x2,  // 0x00000002
/*line: 480*/   ATTR_VOL_SIZE = 0x4,  // 0x00000004
/*line: 481*/   ATTR_VOL_SPACEFREE = 0x8,  // 0x00000008
/*line: 482*/   ATTR_VOL_SPACEAVAIL = 0x10,  // 0x00000010
/*line: 483*/   ATTR_VOL_MINALLOCATION = 0x20,  // 0x00000020
/*line: 484*/   ATTR_VOL_ALLOCATIONCLUMP = 0x40,  // 0x00000040
/*line: 485*/   ATTR_VOL_IOBLOCKSIZE = 0x80,  // 0x00000080
/*line: 486*/   ATTR_VOL_OBJCOUNT = 0x100,  // 0x00000100
/*line: 487*/   ATTR_VOL_FILECOUNT = 0x200,  // 0x00000200
/*line: 488*/   ATTR_VOL_DIRCOUNT = 0x400,  // 0x00000400
/*line: 489*/   ATTR_VOL_MAXOBJCOUNT = 0x800,  // 0x00000800
/*line: 490*/   ATTR_VOL_MOUNTPOINT = 0x1000,  // 0x00001000
/*line: 491*/   ATTR_VOL_NAME = 0x2000,  // 0x00002000
/*line: 492*/   ATTR_VOL_MOUNTFLAGS = 0x4000,  // 0x00004000
/*line: 493*/   ATTR_VOL_MOUNTEDDEVICE = 0x8000,  // 0x00008000
/*line: 494*/   ATTR_VOL_ENCODINGSUSED = 0x10000,  // 0x00010000
/*line: 495*/   ATTR_VOL_CAPABILITIES = 0x20000,  // 0x00020000
/*line: 496*/   ATTR_VOL_UUID = 0x40000,  // 0x00040000
/*line: 497*/   ATTR_VOL_MOUNTEXTFLAGS = 0x80000,  // 0x00080000
/*line: 498*/   ATTR_VOL_FSTYPENAME = 0x100000,  // 0x00100000
/*line: 499*/   ATTR_VOL_FSSUBTYPE = 0x200000,  // 0x00200000
/*line: 500*/   ATTR_VOL_OWNER = 0x400000,  // 0x00400000
/*line: 501*/   ATTR_VOL_SPACEUSED = 0x800000,  // 0x00800000
/*line: 502*/   ATTR_VOL_QUOTA_SIZE = 0x10000000,  // 0x10000000
/*line: 503*/   ATTR_VOL_RESERVED_SIZE = 0x20000000,  // 0x20000000
/*line: 504*/   ATTR_VOL_ATTRIBUTES = 0x40000000,  // 0x40000000
/*line: 505*/   ATTR_VOL_INFO = 0x80000000,  // 0x80000000
};

enum macro_volume_valid_mask {
/*line: 507*/   ATTR_VOL_VALIDMASK = 0xf0ffffff,  // 0xF0FFFFFF
};

enum macro_volume_attributes_mask {
/*
 * The list of settable ATTR_VOL_* attributes include the following:
 * ATTR_VOL_NAME
 * ATTR_VOL_INFO
 */
/*line: 514*/   ATTR_VOL_SETMASK = 0x80002000,  // 0x80002000
};

enum macro_directory_attributes {
/* File/directory attributes: */
/*line: 518*/   ATTR_DIR_LINKCOUNT = 0x1,  // 0x00000001
/*line: 519*/   ATTR_DIR_ENTRYCOUNT = 0x2,  // 0x00000002
/*line: 520*/   ATTR_DIR_MOUNTSTATUS = 0x4,  // 0x00000004
/*line: 521*/   ATTR_DIR_ALLOCSIZE = 0x8,  // 0x00000008
/*line: 522*/   ATTR_DIR_IOBLOCKSIZE = 0x10,  // 0x00000010
/*line: 523*/   ATTR_DIR_DATALENGTH = 0x20,  // 0x00000020
};

enum macro_directory_mount_status {
/* ATTR_DIR_MOUNTSTATUS Flags: */
/*line: 526*/   DIR_MNTSTATUS_MNTPOINT = 0x1,  // 0x00000001
/*line: 527*/   DIR_MNTSTATUS_TRIGGER = 0x2,  // 0x00000002
};

enum macro_directory_attributes_mask {
/*line: 529*/   ATTR_DIR_VALIDMASK = 0x3f,  // 0x0000003f
/*line: 530*/   ATTR_DIR_SETMASK = 0x0,  // 0x00000000
};

enum macro_file_attributes {
/*line: 532*/   ATTR_FILE_LINKCOUNT = 0x1,  // 0x00000001
/*line: 533*/   ATTR_FILE_TOTALSIZE = 0x2,  // 0x00000002
/*line: 534*/   ATTR_FILE_ALLOCSIZE = 0x4,  // 0x00000004
/*line: 535*/   ATTR_FILE_IOBLOCKSIZE = 0x8,  // 0x00000008
/*line: 536*/   ATTR_FILE_DEVTYPE = 0x20,  // 0x00000020
/*line: 537*/   ATTR_FILE_FORKCOUNT = 0x80,  // 0x00000080
/*line: 538*/   ATTR_FILE_FORKLIST = 0x100,  // 0x00000100
/*line: 539*/   ATTR_FILE_DATALENGTH = 0x200,  // 0x00000200
/*line: 540*/   ATTR_FILE_DATAALLOCSIZE = 0x400,  // 0x00000400
/*line: 541*/   ATTR_FILE_RSRCLENGTH = 0x1000,  // 0x00001000
/*line: 542*/   ATTR_FILE_RSRCALLOCSIZE = 0x2000,  // 0x00002000
/*line: 544*/   ATTR_FILE_VALIDMASK = 0x37ff,  // 0x000037FF
/*
 * Settable ATTR_FILE_* attributes include:
 * ATTR_FILE_DEVTYPE
 */
/*line: 549*/   ATTR_FILE_SETMASK = 0x20,  // 0x00000020
};

enum macro_cmnext_attributes {
/* CMNEXT attributes extend the common attributes, but in the forkattr field */
/*line: 552*/   ATTR_CMNEXT_RELPATH = 0x4,  // 0x00000004
/*line: 553*/   ATTR_CMNEXT_PRIVATESIZE = 0x8,  // 0x00000008
/*line: 554*/   ATTR_CMNEXT_LINKID = 0x10,  // 0x00000010
/*line: 555*/   ATTR_CMNEXT_NOFIRMLINKPATH = 0x20,  // 0x00000020
/*line: 556*/   ATTR_CMNEXT_REALDEVID = 0x40,  // 0x00000040
/*line: 557*/   ATTR_CMNEXT_REALFSID = 0x80,  // 0x00000080
/*line: 558*/   ATTR_CMNEXT_CLONEID = 0x100,  // 0x00000100
/*line: 559*/   ATTR_CMNEXT_EXT_FLAGS = 0x200,  // 0x00000200
/*line: 560*/   ATTR_CMNEXT_RECURSIVE_GENCOUNT = 0x400,  // 0x00000400
/*line: 561*/   ATTR_CMNEXT_ATTRIBUTION_TAG = 0x800,  // 0x00000800
/*line: 562*/   ATTR_CMNEXT_CLONE_REFCNT = 0x1000,  // 0x00001000
/*line: 564*/   ATTR_CMNEXT_VALIDMASK = 0x1ffc,  // 0x00001ffc
/*line: 565*/   ATTR_CMNEXT_SETMASK = 0x0,  // 0x00000000
};

enum macro_fork_attributes {
/* Deprecated fork attributes */
/*line: 568*/   ATTR_FORK_TOTALSIZE = 0x1,  // 0x00000001
/*line: 569*/   ATTR_FORK_ALLOCSIZE = 0x2,  // 0x00000002
/*line: 570*/   ATTR_FORK_RESERVED = 0xffffffff,  // 0xffffffff
};

enum macro_file_attributes_mask {
/*line: 572*/   ATTR_FORK_VALIDMASK = 0x3,  // 0x00000003
/*line: 573*/   ATTR_FORK_SETMASK = 0x0,  // 0x00000000
/* Obsolete, implemented, not supported */
/*line: 576*/   ATTR_CMN_NAMEDATTRCOUNT = 0x80000,  // 0x00080000
/*line: 577*/   ATTR_CMN_NAMEDATTRLIST = 0x100000,  // 0x00100000
/*line: 578*/   ATTR_FILE_CLUMPSIZE = 0x10, /* obsolete */ // 0x00000010
/*line: 579*/   ATTR_FILE_FILETYPE = 0x40, /* always zero */ // 0x00000040
/*line: 580*/   ATTR_FILE_DATAEXTENTS = 0x800, /* obsolete, HFS-specific */ // 0x00000800
/*line: 581*/   ATTR_FILE_RSRCEXTENTS = 0x4000, /* obsolete, HFS-specific */ // 0x00004000
/* Required attributes for getattrlistbulk(2) */
/*line: 584*/   ATTR_BULK_REQUIRED = 0x80000001,  // (ATTR_CMN_NAME|ATTR_CMN_RETURNED_ATTRS)
};

enum macro_searchfs_flags {
/*
 * Searchfs
 */
/*line: 589*/   SRCHFS_START = 0x1,  // 0x00000001
/*line: 590*/   SRCHFS_MATCHPARTIALNAMES = 0x2,  // 0x00000002
/*line: 591*/   SRCHFS_MATCHDIRS = 0x4,  // 0x00000004
/*line: 592*/   SRCHFS_MATCHFILES = 0x8,  // 0x00000008
/*line: 593*/   SRCHFS_SKIPLINKS = 0x10,  // 0x00000010
/*line: 594*/   SRCHFS_SKIPINVISIBLE = 0x20,  // 0x00000020
/*line: 595*/   SRCHFS_SKIPPACKAGES = 0x40,  // 0x00000040
/*line: 596*/   SRCHFS_SKIPINAPPROPRIATE = 0x80,  // 0x00000080
/*line: 598*/   SRCHFS_NEGATEPARAMS = 0x80000000,  // 0x80000000
/*line: 599*/   SRCHFS_VALIDOPTIONSMASK = 0x800000ff,  // 0x800000FF
};

enum macro_file_eof {
/*line: 621*/   FST_EOF = -0x1, /* end-of-file offset */ // (-1)
};

