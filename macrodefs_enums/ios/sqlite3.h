// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sqlite3.h

enum macro_sqlite_version {
/*line: 162*/   SQLITE_VERSION_NUMBER = 0x2e6eba,  // 3043002
};

// Depends on identifiers
enum macro_sqlite_result_codes {
/*
** CAPI3REF: Result Codes
** KEYWORDS: {result code definitions}
**
** Many SQLite functions return an integer result code from the set shown
** here in order to indicate success or failure.
**
** New error codes may be added in future versions of SQLite.
**
** See also: [extended result code definitions]
*/
/*line: 451*/   SQLITE_OK = 0x0, /* Successful result */ // 0
/* beginning-of-error-codes */
/*line: 453*/   SQLITE_ERROR = 0x1, /* Generic error */ // 1
/*line: 454*/   SQLITE_INTERNAL = 0x2, /* Internal logic error in SQLite */ // 2
/*line: 455*/   SQLITE_PERM = 0x3, /* Access permission denied */ // 3
/*line: 456*/   SQLITE_ABORT = 0x4, /* Callback routine requested an abort */ // 4
/*line: 457*/   SQLITE_BUSY = 0x5, /* The database file is locked */ // 5
/*line: 458*/   SQLITE_LOCKED = 0x6, /* A table in the database is locked */ // 6
/*line: 459*/   SQLITE_NOMEM = 0x7, /* A malloc() failed */ // 7
/*line: 460*/   SQLITE_READONLY = 0x8, /* Attempt to write a readonly database */ // 8
/*line: 461*/   SQLITE_INTERRUPT = 0x9, /* Operation terminated by sqlite3_interrupt()*/ // 9
/*line: 462*/   SQLITE_IOERR = 0xa, /* Some kind of disk I/O error occurred */ // 10
/*line: 463*/   SQLITE_CORRUPT = 0xb, /* The database disk image is malformed */ // 11
/*line: 464*/   SQLITE_NOTFOUND = 0xc, /* Unknown opcode in sqlite3_file_control() */ // 12
/*line: 465*/   SQLITE_FULL = 0xd, /* Insertion failed because database is full */ // 13
/*line: 466*/   SQLITE_CANTOPEN = 0xe, /* Unable to open the database file */ // 14
/*line: 467*/   SQLITE_PROTOCOL = 0xf, /* Database lock protocol error */ // 15
/*line: 468*/   SQLITE_EMPTY = 0x10, /* Internal use only */ // 16
/*line: 469*/   SQLITE_SCHEMA = 0x11, /* The database schema changed */ // 17
/*line: 470*/   SQLITE_TOOBIG = 0x12, /* String or BLOB exceeds size limit */ // 18
/*line: 471*/   SQLITE_CONSTRAINT = 0x13, /* Abort due to constraint violation */ // 19
/*line: 472*/   SQLITE_MISMATCH = 0x14, /* Data type mismatch */ // 20
/*line: 473*/   SQLITE_MISUSE = 0x15, /* Library used incorrectly */ // 21
/*line: 474*/   SQLITE_NOLFS = 0x16, /* Uses OS features not supported on host */ // 22
/*line: 475*/   SQLITE_AUTH = 0x17, /* Authorization denied */ // 23
/*line: 476*/   SQLITE_FORMAT = 0x18, /* Not used */ // 24
/*line: 477*/   SQLITE_RANGE = 0x19, /* 2nd parameter to sqlite3_bind out of range */ // 25
/*line: 478*/   SQLITE_NOTADB = 0x1a, /* File opened that is not a database file */ // 26
/*line: 479*/   SQLITE_NOTICE = 0x1b, /* Notifications from sqlite3_log() */ // 27
/*line: 480*/   SQLITE_WARNING = 0x1c, /* Warnings from sqlite3_log() */ // 28
/*line: 481*/   SQLITE_ROW = 0x64, /* sqlite3_step() has another row ready */ // 100
/*line: 482*/   SQLITE_DONE = 0x65, /* sqlite3_step() has finished executing */ // 101
/*
** CAPI3REF: Extended Result Codes
** KEYWORDS: {extended result code definitions}
**
** In its default configuration, SQLite API routines return one of 30 integer
** [result codes].  However, experience has shown that many of
** these result codes are too coarse-grained.  They do not provide as
** much information about problems as programmers might like.  In an effort to
** address this, newer versions of SQLite (version 3.3.8 [dateof:3.3.8]
** and later) include
** support for additional result codes that provide more detailed information
** about errors. These [extended result codes] are enabled or disabled
** on a per database connection basis using the
** [sqlite3_extended_result_codes()] API.  Or, the extended code for
** the most recent error can be obtained using
** [sqlite3_extended_errcode()].
*/
/*line: 502*/   SQLITE_ERROR_MISSING_COLLSEQ = 0x101,  // (SQLITE_ERROR|(1<<8))
/*line: 503*/   SQLITE_ERROR_RETRY = 0x201,  // (SQLITE_ERROR|(2<<8))
/*line: 504*/   SQLITE_ERROR_SNAPSHOT = 0x301,  // (SQLITE_ERROR|(3<<8))
/*line: 505*/   SQLITE_IOERR_READ = 0x10a,  // (SQLITE_IOERR|(1<<8))
/*line: 506*/   SQLITE_IOERR_SHORT_READ = 0x20a,  // (SQLITE_IOERR|(2<<8))
/*line: 507*/   SQLITE_IOERR_WRITE = 0x30a,  // (SQLITE_IOERR|(3<<8))
/*line: 508*/   SQLITE_IOERR_FSYNC = 0x40a,  // (SQLITE_IOERR|(4<<8))
/*line: 509*/   SQLITE_IOERR_DIR_FSYNC = 0x50a,  // (SQLITE_IOERR|(5<<8))
/*line: 510*/   SQLITE_IOERR_TRUNCATE = 0x60a,  // (SQLITE_IOERR|(6<<8))
/*line: 511*/   SQLITE_IOERR_FSTAT = 0x70a,  // (SQLITE_IOERR|(7<<8))
/*line: 512*/   SQLITE_IOERR_UNLOCK = 0x80a,  // (SQLITE_IOERR|(8<<8))
/*line: 513*/   SQLITE_IOERR_RDLOCK = 0x90a,  // (SQLITE_IOERR|(9<<8))
/*line: 514*/   SQLITE_IOERR_DELETE = 0xa0a,  // (SQLITE_IOERR|(10<<8))
/*line: 515*/   SQLITE_IOERR_BLOCKED = 0xb0a,  // (SQLITE_IOERR|(11<<8))
/*line: 516*/   SQLITE_IOERR_NOMEM = 0xc0a,  // (SQLITE_IOERR|(12<<8))
/*line: 517*/   SQLITE_IOERR_ACCESS = 0xd0a,  // (SQLITE_IOERR|(13<<8))
/*line: 518*/   SQLITE_IOERR_CHECKRESERVEDLOCK = 0xe0a,  // (SQLITE_IOERR|(14<<8))
/*line: 519*/   SQLITE_IOERR_LOCK = 0xf0a,  // (SQLITE_IOERR|(15<<8))
/*line: 520*/   SQLITE_IOERR_CLOSE = 0x100a,  // (SQLITE_IOERR|(16<<8))
/*line: 521*/   SQLITE_IOERR_DIR_CLOSE = 0x110a,  // (SQLITE_IOERR|(17<<8))
/*line: 522*/   SQLITE_IOERR_SHMOPEN = 0x120a,  // (SQLITE_IOERR|(18<<8))
/*line: 523*/   SQLITE_IOERR_SHMSIZE = 0x130a,  // (SQLITE_IOERR|(19<<8))
/*line: 524*/   SQLITE_IOERR_SHMLOCK = 0x140a,  // (SQLITE_IOERR|(20<<8))
/*line: 525*/   SQLITE_IOERR_SHMMAP = 0x150a,  // (SQLITE_IOERR|(21<<8))
/*line: 526*/   SQLITE_IOERR_SEEK = 0x160a,  // (SQLITE_IOERR|(22<<8))
/*line: 527*/   SQLITE_IOERR_DELETE_NOENT = 0x170a,  // (SQLITE_IOERR|(23<<8))
/*line: 528*/   SQLITE_IOERR_MMAP = 0x180a,  // (SQLITE_IOERR|(24<<8))
/*line: 529*/   SQLITE_IOERR_GETTEMPPATH = 0x190a,  // (SQLITE_IOERR|(25<<8))
/*line: 530*/   SQLITE_IOERR_CONVPATH = 0x1a0a,  // (SQLITE_IOERR|(26<<8))
/*line: 531*/   SQLITE_IOERR_VNODE = 0x1b0a,  // (SQLITE_IOERR|(27<<8))
/*line: 532*/   SQLITE_IOERR_AUTH = 0x1c0a,  // (SQLITE_IOERR|(28<<8))
/*line: 533*/   SQLITE_IOERR_BEGIN_ATOMIC = 0x1d0a,  // (SQLITE_IOERR|(29<<8))
/*line: 534*/   SQLITE_IOERR_COMMIT_ATOMIC = 0x1e0a,  // (SQLITE_IOERR|(30<<8))
/*line: 535*/   SQLITE_IOERR_ROLLBACK_ATOMIC = 0x1f0a,  // (SQLITE_IOERR|(31<<8))
/*line: 536*/   SQLITE_IOERR_DATA = 0x200a,  // (SQLITE_IOERR|(32<<8))
/*line: 537*/   SQLITE_IOERR_CORRUPTFS = 0x210a,  // (SQLITE_IOERR|(33<<8))
/*line: 538*/   SQLITE_IOERR_IN_PAGE = 0x220a,  // (SQLITE_IOERR|(34<<8))
/*line: 539*/   SQLITE_LOCKED_SHAREDCACHE = 0x106,  // (SQLITE_LOCKED|(1<<8))
/*line: 540*/   SQLITE_LOCKED_VTAB = 0x206,  // (SQLITE_LOCKED|(2<<8))
/*line: 541*/   SQLITE_BUSY_RECOVERY = 0x105,  // (SQLITE_BUSY|(1<<8))
/*line: 542*/   SQLITE_BUSY_SNAPSHOT = 0x205,  // (SQLITE_BUSY|(2<<8))
/*line: 543*/   SQLITE_BUSY_TIMEOUT = 0x305,  // (SQLITE_BUSY|(3<<8))
/*line: 544*/   SQLITE_CANTOPEN_NOTEMPDIR = 0x10e,  // (SQLITE_CANTOPEN|(1<<8))
/*line: 545*/   SQLITE_CANTOPEN_ISDIR = 0x20e,  // (SQLITE_CANTOPEN|(2<<8))
/*line: 546*/   SQLITE_CANTOPEN_FULLPATH = 0x30e,  // (SQLITE_CANTOPEN|(3<<8))
/*line: 547*/   SQLITE_CANTOPEN_CONVPATH = 0x40e,  // (SQLITE_CANTOPEN|(4<<8))
/*line: 548*/   SQLITE_CANTOPEN_DIRTYWAL = 0x50e, /* Not Used */ // (SQLITE_CANTOPEN|(5<<8))
/*line: 549*/   SQLITE_CANTOPEN_SYMLINK = 0x60e,  // (SQLITE_CANTOPEN|(6<<8))
/*line: 550*/   SQLITE_CORRUPT_VTAB = 0x10b,  // (SQLITE_CORRUPT|(1<<8))
/*line: 551*/   SQLITE_CORRUPT_SEQUENCE = 0x20b,  // (SQLITE_CORRUPT|(2<<8))
/*line: 552*/   SQLITE_CORRUPT_INDEX = 0x30b,  // (SQLITE_CORRUPT|(3<<8))
/*line: 553*/   SQLITE_READONLY_RECOVERY = 0x108,  // (SQLITE_READONLY|(1<<8))
/*line: 554*/   SQLITE_READONLY_CANTLOCK = 0x208,  // (SQLITE_READONLY|(2<<8))
/*line: 555*/   SQLITE_READONLY_ROLLBACK = 0x308,  // (SQLITE_READONLY|(3<<8))
/*line: 556*/   SQLITE_READONLY_DBMOVED = 0x408,  // (SQLITE_READONLY|(4<<8))
/*line: 557*/   SQLITE_READONLY_CANTINIT = 0x508,  // (SQLITE_READONLY|(5<<8))
/*line: 558*/   SQLITE_READONLY_DIRECTORY = 0x608,  // (SQLITE_READONLY|(6<<8))
/*line: 559*/   SQLITE_ABORT_ROLLBACK = 0x204,  // (SQLITE_ABORT|(2<<8))
/*line: 560*/   SQLITE_CONSTRAINT_CHECK = 0x113,  // (SQLITE_CONSTRAINT|(1<<8))
/*line: 561*/   SQLITE_CONSTRAINT_COMMITHOOK = 0x213,  // (SQLITE_CONSTRAINT|(2<<8))
/*line: 562*/   SQLITE_CONSTRAINT_FOREIGNKEY = 0x313,  // (SQLITE_CONSTRAINT|(3<<8))
/*line: 563*/   SQLITE_CONSTRAINT_FUNCTION = 0x413,  // (SQLITE_CONSTRAINT|(4<<8))
/*line: 564*/   SQLITE_CONSTRAINT_NOTNULL = 0x513,  // (SQLITE_CONSTRAINT|(5<<8))
/*line: 565*/   SQLITE_CONSTRAINT_PRIMARYKEY = 0x613,  // (SQLITE_CONSTRAINT|(6<<8))
/*line: 566*/   SQLITE_CONSTRAINT_TRIGGER = 0x713,  // (SQLITE_CONSTRAINT|(7<<8))
/*line: 567*/   SQLITE_CONSTRAINT_UNIQUE = 0x813,  // (SQLITE_CONSTRAINT|(8<<8))
/*line: 568*/   SQLITE_CONSTRAINT_VTAB = 0x913,  // (SQLITE_CONSTRAINT|(9<<8))
/*line: 569*/   SQLITE_CONSTRAINT_ROWID = 0xa13,  // (SQLITE_CONSTRAINT|(10<<8))
/*line: 570*/   SQLITE_CONSTRAINT_PINNED = 0xb13,  // (SQLITE_CONSTRAINT|(11<<8))
/*line: 571*/   SQLITE_CONSTRAINT_DATATYPE = 0xc13,  // (SQLITE_CONSTRAINT|(12<<8))
/*line: 572*/   SQLITE_NOTICE_RECOVER_WAL = 0x11b,  // (SQLITE_NOTICE|(1<<8))
/*line: 573*/   SQLITE_NOTICE_RECOVER_ROLLBACK = 0x21b,  // (SQLITE_NOTICE|(2<<8))
/*line: 574*/   SQLITE_NOTICE_RBU = 0x31b,  // (SQLITE_NOTICE|(3<<8))
/*line: 575*/   SQLITE_WARNING_AUTOINDEX = 0x11c,  // (SQLITE_WARNING|(1<<8))
/*line: 576*/   SQLITE_AUTH_USER = 0x117,  // (SQLITE_AUTH|(1<<8))
/*line: 577*/   SQLITE_OK_LOAD_PERMANENTLY = 0x100,  // (SQLITE_OK|(1<<8))
/*line: 578*/   SQLITE_OK_SYMLINK = 0x200, /* internal use only */ // (SQLITE_OK|(2<<8))
};

enum macro_sqlite_open_flags {
/*
** CAPI3REF: Flags For File Open Operations
**
** These bit values are intended for use in the
** 3rd parameter to the [sqlite3_open_v2()] interface and
** in the 4th parameter to the [sqlite3_vfs.xOpen] method.
**
** Only those flags marked as "Ok for sqlite3_open_v2()" may be
** used as the third argument to the [sqlite3_open_v2()] interface.
** The other flags have historically been ignored by sqlite3_open_v2(),
** though future versions of SQLite might change so that an error is
** raised if any of the disallowed bits are passed into sqlite3_open_v2().
** Applications should not depend on the historical behavior.
**
** Note in particular that passing the SQLITE_OPEN_EXCLUSIVE flag into
** [sqlite3_open_v2()] does *not* cause the underlying database file
** to be opened using O_EXCL.  Passing SQLITE_OPEN_EXCLUSIVE into
** [sqlite3_open_v2()] has historically be a no-op and might become an
** error in future versions of SQLite.
*/
/*line: 600*/   SQLITE_OPEN_READONLY = 0x1, /* Ok for sqlite3_open_v2() */ // 0x00000001
/*line: 601*/   SQLITE_OPEN_READWRITE = 0x2, /* Ok for sqlite3_open_v2() */ // 0x00000002
/*line: 602*/   SQLITE_OPEN_CREATE = 0x4, /* Ok for sqlite3_open_v2() */ // 0x00000004
/*line: 603*/   SQLITE_OPEN_DELETEONCLOSE = 0x8, /* VFS only */ // 0x00000008
/*line: 604*/   SQLITE_OPEN_EXCLUSIVE = 0x10, /* VFS only */ // 0x00000010
/*line: 605*/   SQLITE_OPEN_AUTOPROXY = 0x20, /* Ok for sqlite3_open_v2() */ // 0x00000020
/*line: 606*/   SQLITE_OPEN_URI = 0x40, /* Ok for sqlite3_open_v2() */ // 0x00000040
/*line: 607*/   SQLITE_OPEN_MEMORY = 0x80, /* Ok for sqlite3_open_v2() */ // 0x00000080
/*line: 608*/   SQLITE_OPEN_MAIN_DB = 0x100, /* VFS only */ // 0x00000100
/*line: 609*/   SQLITE_OPEN_TEMP_DB = 0x200, /* VFS only */ // 0x00000200
/*line: 610*/   SQLITE_OPEN_TRANSIENT_DB = 0x400, /* VFS only */ // 0x00000400
/*line: 611*/   SQLITE_OPEN_MAIN_JOURNAL = 0x800, /* VFS only */ // 0x00000800
/*line: 612*/   SQLITE_OPEN_TEMP_JOURNAL = 0x1000, /* VFS only */ // 0x00001000
/*line: 613*/   SQLITE_OPEN_SUBJOURNAL = 0x2000, /* VFS only */ // 0x00002000
/*line: 614*/   SQLITE_OPEN_SUPER_JOURNAL = 0x4000, /* VFS only */ // 0x00004000
/*line: 615*/   SQLITE_OPEN_NOMUTEX = 0x8000, /* Ok for sqlite3_open_v2() */ // 0x00008000
/*line: 616*/   SQLITE_OPEN_FULLMUTEX = 0x10000, /* Ok for sqlite3_open_v2() */ // 0x00010000
/*line: 617*/   SQLITE_OPEN_SHAREDCACHE = 0x20000, /* Ok for sqlite3_open_v2() */ // 0x00020000
/*line: 618*/   SQLITE_OPEN_PRIVATECACHE = 0x40000, /* Ok for sqlite3_open_v2() */ // 0x00040000
/*line: 619*/   SQLITE_OPEN_WAL = 0x80000, /* VFS only */ // 0x00080000
/*line: 620*/   SQLITE_OPEN_FILEPROTECTION_COMPLETE = 0x100000,  // 0x00100000
/*line: 621*/   SQLITE_OPEN_FILEPROTECTION_COMPLETEUNLESSOPEN = 0x200000,  // 0x00200000
/*line: 622*/   SQLITE_OPEN_FILEPROTECTION_COMPLETEUNTILFIRSTUSERAUTHENTICATION = 0x300000,  // 0x00300000
/*line: 623*/   SQLITE_OPEN_FILEPROTECTION_NONE = 0x400000,  // 0x00400000
/*line: 624*/   SQLITE_OPEN_FILEPROTECTION_MASK = 0x700000,  // 0x00700000
/*line: 626*/   SQLITE_OPEN_NOFOLLOW = 0x1000000, /* Ok for sqlite3_open_v2() */ // 0x01000000
/*line: 627*/   SQLITE_OPEN_EXRESCODE = 0x2000000, /* Extended result codes */ // 0x02000000
};

// Depends on identifiers
enum macro_sqlite_open_master_journal {
/* Legacy compatibility: */
/*line: 630*/   SQLITE_OPEN_MASTER_JOURNAL = 0x4000, /* VFS only */ // SQLITE_OPEN_SUPER_JOURNAL
};

enum macro_device_capabilities {
/*
** CAPI3REF: Device Characteristics
**
** The xDeviceCharacteristics method of the [sqlite3_io_methods]
** object returns an integer which is a vector of these
** bit values expressing I/O characteristics of the mass storage
** device that holds the file that the [sqlite3_io_methods]
** refers to.
**
** The SQLITE_IOCAP_ATOMIC property means that all writes of
** any size are atomic.  The SQLITE_IOCAP_ATOMICnnn values
** mean that writes of blocks that are nnn bytes in size and
** are aligned to an address which is an integer multiple of
** nnn are atomic.  The SQLITE_IOCAP_SAFE_APPEND value means
** that when data is appended to a file, the data is appended
** first then the size of the file is extended, never the other
** way around.  The SQLITE_IOCAP_SEQUENTIAL property means that
** information is written to disk in the same order as calls
** to xWrite().  The SQLITE_IOCAP_POWERSAFE_OVERWRITE property means that
** after reboot following a crash or power loss, the only bytes in a
** file that were written at the application level might have changed
** and that adjacent bytes, even bytes within the same sector are
** guaranteed to be unchanged.  The SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN
** flag indicates that a file cannot be deleted when open.  The
** SQLITE_IOCAP_IMMUTABLE flag indicates that the file is on
** read-only media and cannot be changed even by processes with
** elevated privileges.
**
** The SQLITE_IOCAP_BATCH_ATOMIC property means that the underlying
** filesystem supports doing multiple write operations atomically when those
** write operations are bracketed by [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] and
** [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE].
*/
/*line: 666*/   SQLITE_IOCAP_ATOMIC = 0x1,  // 0x00000001
/*line: 667*/   SQLITE_IOCAP_ATOMIC512 = 0x2,  // 0x00000002
/*line: 668*/   SQLITE_IOCAP_ATOMIC1K = 0x4,  // 0x00000004
/*line: 669*/   SQLITE_IOCAP_ATOMIC2K = 0x8,  // 0x00000008
/*line: 670*/   SQLITE_IOCAP_ATOMIC4K = 0x10,  // 0x00000010
/*line: 671*/   SQLITE_IOCAP_ATOMIC8K = 0x20,  // 0x00000020
/*line: 672*/   SQLITE_IOCAP_ATOMIC16K = 0x40,  // 0x00000040
/*line: 673*/   SQLITE_IOCAP_ATOMIC32K = 0x80,  // 0x00000080
/*line: 674*/   SQLITE_IOCAP_ATOMIC64K = 0x100,  // 0x00000100
/*line: 675*/   SQLITE_IOCAP_SAFE_APPEND = 0x200,  // 0x00000200
/*line: 676*/   SQLITE_IOCAP_SEQUENTIAL = 0x400,  // 0x00000400
/*line: 677*/   SQLITE_IOCAP_UNDELETABLE_WHEN_OPEN = 0x800,  // 0x00000800
/*line: 678*/   SQLITE_IOCAP_POWERSAFE_OVERWRITE = 0x1000,  // 0x00001000
/*line: 679*/   SQLITE_IOCAP_IMMUTABLE = 0x2000,  // 0x00002000
/*line: 680*/   SQLITE_IOCAP_BATCH_ATOMIC = 0x4000,  // 0x00004000
};

enum macro_file_lock_level {
/*
** CAPI3REF: File Locking Levels
**
** SQLite uses one of these integer values as the second
** argument to calls it makes to the xLock() and xUnlock() methods
** of an [sqlite3_io_methods] object.  These values are ordered from
** lest restrictive to most restrictive.
**
** The argument to xLock() is always SHARED or higher.  The argument to
** xUnlock is either SHARED or NONE.
*/
/*line: 693*/   SQLITE_LOCK_NONE = 0x0, /* xUnlock() only */ // 0
/*line: 694*/   SQLITE_LOCK_SHARED = 0x1, /* xLock() or xUnlock() */ // 1
/*line: 695*/   SQLITE_LOCK_RESERVED = 0x2, /* xLock() only */ // 2
/*line: 696*/   SQLITE_LOCK_PENDING = 0x3, /* xLock() only */ // 3
/*line: 697*/   SQLITE_LOCK_EXCLUSIVE = 0x4, /* xLock() only */ // 4
};

enum macro_sync_flags {
/*
** CAPI3REF: Synchronization Type Flags
**
** When SQLite invokes the xSync() method of an
** [sqlite3_io_methods] object it uses a combination of
** these integer values as the second argument.
**
** When the SQLITE_SYNC_DATAONLY flag is used, it means that the
** sync operation only needs to flush data to mass storage.  Inode
** information need not be flushed. If the lower four bits of the flag
** equal SQLITE_SYNC_NORMAL, that means to use normal fsync() semantics.
** If the lower four bits equal SQLITE_SYNC_FULL, that means
** to use Mac OS X style fullsync instead of fsync().
**
** Do not confuse the SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL flags
** with the [PRAGMA synchronous]=NORMAL and [PRAGMA synchronous]=FULL
** settings.  The [synchronous pragma] determines when calls to the
** xSync VFS method occur and applies uniformly across all platforms.
** The SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL flags determine how
** energetic or rigorous or forceful the sync operations are and
** only make a difference on Mac OSX for the default SQLite code.
** (Third-party VFS implementations might also make the distinction
** between SQLITE_SYNC_NORMAL and SQLITE_SYNC_FULL, but among the
** operating systems natively supported by SQLite, only Mac OSX
** cares about the difference.)
*/
/*line: 725*/   SQLITE_SYNC_NORMAL = 0x2,  // 0x00002
/*line: 726*/   SQLITE_SYNC_FULL = 0x3,  // 0x00003
/*line: 727*/   SQLITE_SYNC_DATAONLY = 0x10,  // 0x00010
};

enum macro_sqlite_fcntl_opcodes {
/*
** CAPI3REF: Standard File Control Opcodes
** KEYWORDS: {file control opcodes} {file control opcode}
**
** These integer constants are opcodes for the xFileControl method
** of the [sqlite3_io_methods] object and for the [sqlite3_file_control()]
** interface.
**
** <ul>
** <li>[[SQLITE_FCNTL_LOCKSTATE]]
** The [SQLITE_FCNTL_LOCKSTATE] opcode is used for debugging.  This
** opcode causes the xFileControl method to write the current state of
** the lock (one of [SQLITE_LOCK_NONE], [SQLITE_LOCK_SHARED],
** [SQLITE_LOCK_RESERVED], [SQLITE_LOCK_PENDING], or [SQLITE_LOCK_EXCLUSIVE])
** into an integer that the pArg argument points to.
** This capability is only available if SQLite is compiled with [SQLITE_DEBUG].
**
** <li>[[SQLITE_FCNTL_SIZE_HINT]]
** The [SQLITE_FCNTL_SIZE_HINT] opcode is used by SQLite to give the VFS
** layer a hint of how large the database file will grow to be during the
** current transaction.  This hint is not guaranteed to be accurate but it
** is often close.  The underlying VFS might choose to preallocate database
** file space based on this hint in order to help writes to the database
** file run faster.
**
** <li>[[SQLITE_FCNTL_SIZE_LIMIT]]
** The [SQLITE_FCNTL_SIZE_LIMIT] opcode is used by in-memory VFS that
** implements [sqlite3_deserialize()] to set an upper bound on the size
** of the in-memory database.  The argument is a pointer to a [sqlite3_int64].
** If the integer pointed to is negative, then it is filled in with the
** current limit.  Otherwise the limit is set to the larger of the value
** of the integer pointed to and the current database size.  The integer
** pointed to is set to the new limit.
**
** <li>[[SQLITE_FCNTL_CHUNK_SIZE]]
** The [SQLITE_FCNTL_CHUNK_SIZE] opcode is used to request that the VFS
** extends and truncates the database file in chunks of a size specified
** by the user. The fourth argument to [sqlite3_file_control()] should
** point to an integer (type int) containing the new chunk-size to use
** for the nominated database. Allocating database file space in large
** chunks (say 1MB at a time), may reduce file-system fragmentation and
** improve performance on some systems.
**
** <li>[[SQLITE_FCNTL_FILE_POINTER]]
** The [SQLITE_FCNTL_FILE_POINTER] opcode is used to obtain a pointer
** to the [sqlite3_file] object associated with a particular database
** connection.  See also [SQLITE_FCNTL_JOURNAL_POINTER].
**
** <li>[[SQLITE_FCNTL_JOURNAL_POINTER]]
** The [SQLITE_FCNTL_JOURNAL_POINTER] opcode is used to obtain a pointer
** to the [sqlite3_file] object associated with the journal file (either
** the [rollback journal] or the [write-ahead log]) for a particular database
** connection.  See also [SQLITE_FCNTL_FILE_POINTER].
**
** <li>[[SQLITE_FCNTL_SYNC_OMITTED]]
** No longer in use.
**
** <li>[[SQLITE_FCNTL_SYNC]]
** The [SQLITE_FCNTL_SYNC] opcode is generated internally by SQLite and
** sent to the VFS immediately before the xSync method is invoked on a
** database file descriptor. Or, if the xSync method is not invoked
** because the user has configured SQLite with
** [PRAGMA synchronous | PRAGMA synchronous=OFF] it is invoked in place
** of the xSync method. In most cases, the pointer argument passed with
** this file-control is NULL. However, if the database file is being synced
** as part of a multi-database commit, the argument points to a nul-terminated
** string containing the transactions super-journal file name. VFSes that
** do not need this signal should silently ignore this opcode. Applications
** should not call [sqlite3_file_control()] with this opcode as doing so may
** disrupt the operation of the specialized VFSes that do require it.
**
** <li>[[SQLITE_FCNTL_COMMIT_PHASETWO]]
** The [SQLITE_FCNTL_COMMIT_PHASETWO] opcode is generated internally by SQLite
** and sent to the VFS after a transaction has been committed immediately
** but before the database is unlocked. VFSes that do not need this signal
** should silently ignore this opcode. Applications should not call
** [sqlite3_file_control()] with this opcode as doing so may disrupt the
** operation of the specialized VFSes that do require it.
**
** <li>[[SQLITE_FCNTL_WIN32_AV_RETRY]]
** ^The [SQLITE_FCNTL_WIN32_AV_RETRY] opcode is used to configure automatic
** retry counts and intervals for certain disk I/O operations for the
** windows [VFS] in order to provide robustness in the presence of
** anti-virus programs.  By default, the windows VFS will retry file read,
** file write, and file delete operations up to 10 times, with a delay
** of 25 milliseconds before the first retry and with the delay increasing
** by an additional 25 milliseconds with each subsequent retry.  This
** opcode allows these two values (10 retries and 25 milliseconds of delay)
** to be adjusted.  The values are changed for all database connections
** within the same process.  The argument is a pointer to an array of two
** integers where the first integer is the new retry count and the second
** integer is the delay.  If either integer is negative, then the setting
** is not changed but instead the prior value of that setting is written
** into the array entry, allowing the current retry settings to be
** interrogated.  The zDbName parameter is ignored.
**
** <li>[[SQLITE_FCNTL_PERSIST_WAL]]
** ^The [SQLITE_FCNTL_PERSIST_WAL] opcode is used to set or query the
** persistent [WAL | Write Ahead Log] setting.  By default, the auxiliary
** write ahead log ([WAL file]) and shared memory
** files used for transaction control
** are automatically deleted when the latest connection to the database
** closes.  Setting persistent WAL mode causes those files to persist after
** close.  Persisting the files is useful when other processes that do not
** have write permission on the directory containing the database file want
** to read the database file, as the WAL and shared memory files must exist
** in order for the database to be readable.  The fourth parameter to
** [sqlite3_file_control()] for this opcode should be a pointer to an integer.
** That integer is 0 to disable persistent WAL mode or 1 to enable persistent
** WAL mode.  If the integer is -1, then it is overwritten with the current
** WAL persistence setting.
**
** <li>[[SQLITE_FCNTL_POWERSAFE_OVERWRITE]]
** ^The [SQLITE_FCNTL_POWERSAFE_OVERWRITE] opcode is used to set or query the
** persistent "powersafe-overwrite" or "PSOW" setting.  The PSOW setting
** determines the [SQLITE_IOCAP_POWERSAFE_OVERWRITE] bit of the
** xDeviceCharacteristics methods. The fourth parameter to
** [sqlite3_file_control()] for this opcode should be a pointer to an integer.
** That integer is 0 to disable zero-damage mode or 1 to enable zero-damage
** mode.  If the integer is -1, then it is overwritten with the current
** zero-damage mode setting.
**
** <li>[[SQLITE_FCNTL_OVERWRITE]]
** ^The [SQLITE_FCNTL_OVERWRITE] opcode is invoked by SQLite after opening
** a write transaction to indicate that, unless it is rolled back for some
** reason, the entire database file will be overwritten by the current
** transaction. This is used by VACUUM operations.
**
** <li>[[SQLITE_FCNTL_VFSNAME]]
** ^The [SQLITE_FCNTL_VFSNAME] opcode can be used to obtain the names of
** all [VFSes] in the VFS stack.  The names are of all VFS shims and the
** final bottom-level VFS are written into memory obtained from
** [sqlite3_malloc()] and the result is stored in the char* variable
** that the fourth parameter of [sqlite3_file_control()] points to.
** The caller is responsible for freeing the memory when done.  As with
** all file-control actions, there is no guarantee that this will actually
** do anything.  Callers should initialize the char* variable to a NULL
** pointer in case this file-control is not implemented.  This file-control
** is intended for diagnostic use only.
**
** <li>[[SQLITE_FCNTL_VFS_POINTER]]
** ^The [SQLITE_FCNTL_VFS_POINTER] opcode finds a pointer to the top-level
** [VFSes] currently in use.  ^(The argument X in
** sqlite3_file_control(db,SQLITE_FCNTL_VFS_POINTER,X) must be
** of type "[sqlite3_vfs] **".  This opcodes will set *X
** to a pointer to the top-level VFS.)^
** ^When there are multiple VFS shims in the stack, this opcode finds the
** upper-most shim only.
**
** <li>[[SQLITE_FCNTL_PRAGMA]]
** ^Whenever a [PRAGMA] statement is parsed, an [SQLITE_FCNTL_PRAGMA]
** file control is sent to the open [sqlite3_file] object corresponding
** to the database file to which the pragma statement refers. ^The argument
** to the [SQLITE_FCNTL_PRAGMA] file control is an array of
** pointers to strings (char**) in which the second element of the array
** is the name of the pragma and the third element is the argument to the
** pragma or NULL if the pragma has no argument.  ^The handler for an
** [SQLITE_FCNTL_PRAGMA] file control can optionally make the first element
** of the char** argument point to a string obtained from [sqlite3_mprintf()]
** or the equivalent and that string will become the result of the pragma or
** the error message if the pragma fails. ^If the
** [SQLITE_FCNTL_PRAGMA] file control returns [SQLITE_NOTFOUND], then normal
** [PRAGMA] processing continues.  ^If the [SQLITE_FCNTL_PRAGMA]
** file control returns [SQLITE_OK], then the parser assumes that the
** VFS has handled the PRAGMA itself and the parser generates a no-op
** prepared statement if result string is NULL, or that returns a copy
** of the result string if the string is non-NULL.
** ^If the [SQLITE_FCNTL_PRAGMA] file control returns
** any result code other than [SQLITE_OK] or [SQLITE_NOTFOUND], that means
** that the VFS encountered an error while handling the [PRAGMA] and the
** compilation of the PRAGMA fails with an error.  ^The [SQLITE_FCNTL_PRAGMA]
** file control occurs at the beginning of pragma statement analysis and so
** it is able to override built-in [PRAGMA] statements.
**
** <li>[[SQLITE_FCNTL_BUSYHANDLER]]
** ^The [SQLITE_FCNTL_BUSYHANDLER]
** file-control may be invoked by SQLite on the database file handle
** shortly after it is opened in order to provide a custom VFS with access
** to the connection's busy-handler callback. The argument is of type (void**)
** - an array of two (void *) values. The first (void *) actually points
** to a function of type (int (*)(void *)). In order to invoke the connection's
** busy-handler, this function should be invoked with the second (void *) in
** the array as the only argument. If it returns non-zero, then the operation
** should be retried. If it returns zero, the custom VFS should abandon the
** current operation.
**
** <li>[[SQLITE_FCNTL_TEMPFILENAME]]
** ^Applications can invoke the [SQLITE_FCNTL_TEMPFILENAME] file-control
** to have SQLite generate a
** temporary filename using the same algorithm that is followed to generate
** temporary filenames for TEMP tables and other internal uses.  The
** argument should be a char** which will be filled with the filename
** written into memory obtained from [sqlite3_malloc()].  The caller should
** invoke [sqlite3_free()] on the result to avoid a memory leak.
**
** <li>[[SQLITE_FCNTL_MMAP_SIZE]]
** The [SQLITE_FCNTL_MMAP_SIZE] file control is used to query or set the
** maximum number of bytes that will be used for memory-mapped I/O.
** The argument is a pointer to a value of type sqlite3_int64 that
** is an advisory maximum number of bytes in the file to memory map.  The
** pointer is overwritten with the old value.  The limit is not changed if
** the value originally pointed to is negative, and so the current limit
** can be queried by passing in a pointer to a negative number.  This
** file-control is used internally to implement [PRAGMA mmap_size].
**
** <li>[[SQLITE_FCNTL_TRACE]]
** The [SQLITE_FCNTL_TRACE] file control provides advisory information
** to the VFS about what the higher layers of the SQLite stack are doing.
** This file control is used by some VFS activity tracing [shims].
** The argument is a zero-terminated string.  Higher layers in the
** SQLite stack may generate instances of this file control if
** the [SQLITE_USE_FCNTL_TRACE] compile-time option is enabled.
**
** <li>[[SQLITE_FCNTL_HAS_MOVED]]
** The [SQLITE_FCNTL_HAS_MOVED] file control interprets its argument as a
** pointer to an integer and it writes a boolean into that integer depending
** on whether or not the file has been renamed, moved, or deleted since it
** was first opened.
**
** <li>[[SQLITE_FCNTL_WIN32_GET_HANDLE]]
** The [SQLITE_FCNTL_WIN32_GET_HANDLE] opcode can be used to obtain the
** underlying native file handle associated with a file handle.  This file
** control interprets its argument as a pointer to a native file handle and
** writes the resulting value there.
**
** <li>[[SQLITE_FCNTL_WIN32_SET_HANDLE]]
** The [SQLITE_FCNTL_WIN32_SET_HANDLE] opcode is used for debugging.  This
** opcode causes the xFileControl method to swap the file handle with the one
** pointed to by the pArg argument.  This capability is used during testing
** and only needs to be supported when SQLITE_TEST is defined.
**
** <li>[[SQLITE_FCNTL_WAL_BLOCK]]
** The [SQLITE_FCNTL_WAL_BLOCK] is a signal to the VFS layer that it might
** be advantageous to block on the next WAL lock if the lock is not immediately
** available.  The WAL subsystem issues this signal during rare
** circumstances in order to fix a problem with priority inversion.
** Applications should <em>not</em> use this file-control.
**
** <li>[[SQLITE_FCNTL_ZIPVFS]]
** The [SQLITE_FCNTL_ZIPVFS] opcode is implemented by zipvfs only. All other
** VFS should return SQLITE_NOTFOUND for this opcode.
**
** <li>[[SQLITE_FCNTL_RBU]]
** The [SQLITE_FCNTL_RBU] opcode is implemented by the special VFS used by
** the RBU extension only.  All other VFS should return SQLITE_NOTFOUND for
** this opcode.
**
** <li>[[SQLITE_FCNTL_BEGIN_ATOMIC_WRITE]]
** If the [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] opcode returns SQLITE_OK, then
** the file descriptor is placed in "batch write mode", which
** means all subsequent write operations will be deferred and done
** atomically at the next [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE].  Systems
** that do not support batch atomic writes will return SQLITE_NOTFOUND.
** ^Following a successful SQLITE_FCNTL_BEGIN_ATOMIC_WRITE and prior to
** the closing [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE] or
** [SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE], SQLite will make
** no VFS interface calls on the same [sqlite3_file] file descriptor
** except for calls to the xWrite method and the xFileControl method
** with [SQLITE_FCNTL_SIZE_HINT].
**
** <li>[[SQLITE_FCNTL_COMMIT_ATOMIC_WRITE]]
** The [SQLITE_FCNTL_COMMIT_ATOMIC_WRITE] opcode causes all write
** operations since the previous successful call to
** [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] to be performed atomically.
** This file control returns [SQLITE_OK] if and only if the writes were
** all performed successfully and have been committed to persistent storage.
** ^Regardless of whether or not it is successful, this file control takes
** the file descriptor out of batch write mode so that all subsequent
** write operations are independent.
** ^SQLite will never invoke SQLITE_FCNTL_COMMIT_ATOMIC_WRITE without
** a prior successful call to [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE].
**
** <li>[[SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE]]
** The [SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE] opcode causes all write
** operations since the previous successful call to
** [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE] to be rolled back.
** ^This file control takes the file descriptor out of batch write mode
** so that all subsequent write operations are independent.
** ^SQLite will never invoke SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE without
** a prior successful call to [SQLITE_FCNTL_BEGIN_ATOMIC_WRITE].
**
** <li>[[SQLITE_FCNTL_LOCK_TIMEOUT]]
** The [SQLITE_FCNTL_LOCK_TIMEOUT] opcode is used to configure a VFS
** to block for up to M milliseconds before failing when attempting to
** obtain a file lock using the xLock or xShmLock methods of the VFS.
** The parameter is a pointer to a 32-bit signed integer that contains
** the value that M is to be set to. Before returning, the 32-bit signed
** integer is overwritten with the previous value of M.
**
** <li>[[SQLITE_FCNTL_DATA_VERSION]]
** The [SQLITE_FCNTL_DATA_VERSION] opcode is used to detect changes to
** a database file.  The argument is a pointer to a 32-bit unsigned integer.
** The "data version" for the pager is written into the pointer.  The
** "data version" changes whenever any change occurs to the corresponding
** database file, either through SQL statements on the same database
** connection or through transactions committed by separate database
** connections possibly in other processes. The [sqlite3_total_changes()]
** interface can be used to find if any database on the connection has changed,
** but that interface responds to changes on TEMP as well as MAIN and does
** not provide a mechanism to detect changes to MAIN only.  Also, the
** [sqlite3_total_changes()] interface responds to internal changes only and
** omits changes made by other database connections.  The
** [PRAGMA data_version] command provides a mechanism to detect changes to
** a single attached database that occur due to other database connections,
** but omits changes implemented by the database connection on which it is
** called.  This file control is the only mechanism to detect changes that
** happen either internally or externally and that are associated with
** a particular attached database.
**
** <li>[[SQLITE_FCNTL_CKPT_START]]
** The [SQLITE_FCNTL_CKPT_START] opcode is invoked from within a checkpoint
** in wal mode before the client starts to copy pages from the wal
** file to the database file.
**
** <li>[[SQLITE_FCNTL_CKPT_DONE]]
** The [SQLITE_FCNTL_CKPT_DONE] opcode is invoked from within a checkpoint
** in wal mode after the client has finished copying pages from the wal
** file to the database file, but before the *-shm file is updated to
** record the fact that the pages have been checkpointed.
**
** <li>[[SQLITE_FCNTL_EXTERNAL_READER]]
** The EXPERIMENTAL [SQLITE_FCNTL_EXTERNAL_READER] opcode is used to detect
** whether or not there is a database client in another process with a wal-mode
** transaction open on the database or not. It is only available on unix.The
** (void*) argument passed with this file-control should be a pointer to a
** value of type (int). The integer value is set to 1 if the database is a wal
** mode database and there exists at least one client in another process that
** currently has an SQL transaction open on the database. It is set to 0 if
** the database is not a wal-mode db, or if there is no such connection in any
** other process. This opcode cannot be used to detect transactions opened
** by clients within the current process, only within other processes.
**
** <li>[[SQLITE_FCNTL_CKSM_FILE]]
** The [SQLITE_FCNTL_CKSM_FILE] opcode is for use internally by the
** [checksum VFS shim] only.
**
** <li>[[SQLITE_FCNTL_RESET_CACHE]]
** If there is currently no transaction open on the database, and the
** database is not a temp db, then the [SQLITE_FCNTL_RESET_CACHE] file-control
** purges the contents of the in-memory page cache. If there is an open
** transaction, or if the db is a temp-db, this opcode is a no-op, not an error.
** </ul>
*/
/*line: 1216*/  SQLITE_FCNTL_LOCKSTATE = 0x1,  // 1
/*line: 1217*/  SQLITE_FCNTL_GET_LOCKPROXYFILE = 0x2,  // 2
/*line: 1218*/  SQLITE_FCNTL_SET_LOCKPROXYFILE = 0x3,  // 3
/*line: 1219*/  SQLITE_FCNTL_LAST_ERRNO = 0x4,  // 4
/*line: 1220*/  SQLITE_FCNTL_SIZE_HINT = 0x5,  // 5
/*line: 1221*/  SQLITE_FCNTL_CHUNK_SIZE = 0x6,  // 6
/*line: 1222*/  SQLITE_FCNTL_FILE_POINTER = 0x7,  // 7
/*line: 1223*/  SQLITE_FCNTL_SYNC_OMITTED = 0x8,  // 8
/*line: 1224*/  SQLITE_FCNTL_WIN32_AV_RETRY = 0x9,  // 9
/*line: 1225*/  SQLITE_FCNTL_PERSIST_WAL = 0xa,  // 10
/*line: 1226*/  SQLITE_FCNTL_OVERWRITE = 0xb,  // 11
/*line: 1227*/  SQLITE_FCNTL_VFSNAME = 0xc,  // 12
/*line: 1228*/  SQLITE_FCNTL_POWERSAFE_OVERWRITE = 0xd,  // 13
/*line: 1229*/  SQLITE_FCNTL_PRAGMA = 0xe,  // 14
/*line: 1230*/  SQLITE_FCNTL_BUSYHANDLER = 0xf,  // 15
/*line: 1231*/  SQLITE_FCNTL_TEMPFILENAME = 0x10,  // 16
/*line: 1232*/  SQLITE_FCNTL_MMAP_SIZE = 0x12,  // 18
/*line: 1233*/  SQLITE_FCNTL_TRACE = 0x13,  // 19
/*line: 1234*/  SQLITE_FCNTL_HAS_MOVED = 0x14,  // 20
/*line: 1235*/  SQLITE_FCNTL_SYNC = 0x15,  // 21
/*line: 1236*/  SQLITE_FCNTL_COMMIT_PHASETWO = 0x16,  // 22
/*line: 1237*/  SQLITE_FCNTL_WIN32_SET_HANDLE = 0x17,  // 23
/*line: 1238*/  SQLITE_FCNTL_WAL_BLOCK = 0x18,  // 24
/*line: 1239*/  SQLITE_FCNTL_ZIPVFS = 0x19,  // 25
/*line: 1240*/  SQLITE_FCNTL_RBU = 0x1a,  // 26
/*line: 1241*/  SQLITE_FCNTL_VFS_POINTER = 0x1b,  // 27
/*line: 1242*/  SQLITE_FCNTL_JOURNAL_POINTER = 0x1c,  // 28
/*line: 1243*/  SQLITE_FCNTL_WIN32_GET_HANDLE = 0x1d,  // 29
/*line: 1244*/  SQLITE_FCNTL_PDB = 0x1e,  // 30
/*line: 1245*/  SQLITE_FCNTL_BEGIN_ATOMIC_WRITE = 0x1f,  // 31
/*line: 1246*/  SQLITE_FCNTL_COMMIT_ATOMIC_WRITE = 0x20,  // 32
/*line: 1247*/  SQLITE_FCNTL_ROLLBACK_ATOMIC_WRITE = 0x21,  // 33
/*line: 1248*/  SQLITE_FCNTL_LOCK_TIMEOUT = 0x22,  // 34
/*line: 1249*/  SQLITE_FCNTL_DATA_VERSION = 0x23,  // 35
/*line: 1250*/  SQLITE_FCNTL_SIZE_LIMIT = 0x24,  // 36
/*line: 1251*/  SQLITE_FCNTL_CKPT_DONE = 0x25,  // 37
/*line: 1252*/  SQLITE_FCNTL_RESERVE_BYTES = 0x26,  // 38
/*line: 1253*/  SQLITE_FCNTL_CKPT_START = 0x27,  // 39
/*line: 1254*/  SQLITE_FCNTL_EXTERNAL_READER = 0x28,  // 40
/*line: 1255*/  SQLITE_FCNTL_CKSM_FILE = 0x29,  // 41
/*line: 1256*/  SQLITE_FCNTL_RESET_CACHE = 0x2a,  // 42
};

// Depends on identifiers
enum macro_fcntl_options {
/* deprecated names */
/*line: 1259*/  SQLITE_GET_LOCKPROXYFILE = 0x2,  // SQLITE_FCNTL_GET_LOCKPROXYFILE
/*line: 1260*/  SQLITE_SET_LOCKPROXYFILE = 0x3,  // SQLITE_FCNTL_SET_LOCKPROXYFILE
/*line: 1261*/  SQLITE_LAST_ERRNO = 0x4,  // SQLITE_FCNTL_LAST_ERRNO
};

enum macro_access_flags {
/*
** CAPI3REF: Flags for the xAccess VFS method
**
** These integer constants can be used as the third parameter to
** the xAccess method of an [sqlite3_vfs] object.  They determine
** what kind of permissions the xAccess method is looking for.
** With SQLITE_ACCESS_EXISTS, the xAccess method
** simply checks whether the file exists.
** With SQLITE_ACCESS_READWRITE, the xAccess method
** checks whether the named directory is both readable and writable
** (in other words, if files can be added, removed, and renamed within
** the directory).
** The SQLITE_ACCESS_READWRITE constant is currently used only by the
** [temp_store_directory pragma], though this could change in a future
** release of SQLite.
** With SQLITE_ACCESS_READ, the xAccess method
** checks whether the file is readable.  The SQLITE_ACCESS_READ constant is
** currently unused, though it might be used in a future release of
** SQLite.
*/
/*line: 1536*/  SQLITE_ACCESS_EXISTS = 0x0,  // 0
/*line: 1537*/  SQLITE_ACCESS_READWRITE = 0x1, /* Used by PRAGMA temp_store_directory */ // 1
/*line: 1538*/  SQLITE_ACCESS_READ = 0x2, /* Unused */ // 2
};

enum macro_shm_lock_flags {
/*
** CAPI3REF: Flags for the xShmLock VFS method
**
** These integer constants define the various locking operations
** allowed by the xShmLock method of [sqlite3_io_methods].  The
** following are the only legal combinations of flags to the
** xShmLock method:
**
** <ul>
** <li>  SQLITE_SHM_LOCK | SQLITE_SHM_SHARED
** <li>  SQLITE_SHM_LOCK | SQLITE_SHM_EXCLUSIVE
** <li>  SQLITE_SHM_UNLOCK | SQLITE_SHM_SHARED
** <li>  SQLITE_SHM_UNLOCK | SQLITE_SHM_EXCLUSIVE
** </ul>
**
** When unlocking, the same SHARED or EXCLUSIVE flag must be supplied as
** was given on the corresponding lock.
**
** The xShmLock method can transition between unlocked and SHARED or
** between unlocked and EXCLUSIVE.  It cannot transition between SHARED
** and EXCLUSIVE.
*/
/*line: 1562*/  SQLITE_SHM_UNLOCK = 0x1,  // 1
/*line: 1563*/  SQLITE_SHM_LOCK = 0x2,  // 2
/*line: 1564*/  SQLITE_SHM_SHARED = 0x4,  // 4
/*line: 1565*/  SQLITE_SHM_EXCLUSIVE = 0x8,  // 8
};

enum macro_sqlite_shm_nlock {
/*
** CAPI3REF: Maximum xShmLock index
**
** The xShmLock method on [sqlite3_io_methods] may use values
** between 0 and this upper bound as its "offset" argument.
** The SQLite core will never attempt to acquire or release a
** lock outside of this range
*/
/*line: 1575*/  SQLITE_SHM_NLOCK = 0x8,  // 8
};

enum macro_sqlite_config {
/*
** CAPI3REF: Configuration Options
** KEYWORDS: {configuration option}
**
** These constants are the available integer configuration options that
** can be passed as the first argument to the [sqlite3_config()] interface.
**
** Most of the configuration options for sqlite3_config()
** will only work if invoked prior to [sqlite3_initialize()] or after
** [sqlite3_shutdown()].  The few exceptions to this rule are called
** "anytime configuration options".
** ^Calling [sqlite3_config()] with a first argument that is not an
** anytime configuration option in between calls to [sqlite3_initialize()] and
** [sqlite3_shutdown()] is a no-op that returns SQLITE_MISUSE.
**
** The set of anytime configuration options can change (by insertions
** and/or deletions) from one release of SQLite to the next.
** As of SQLite version 3.42.0, the complete set of anytime configuration
** options is:
** <ul>
** <li> SQLITE_CONFIG_LOG
** <li> SQLITE_CONFIG_PCACHE_HDRSZ
** </ul>
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlite3_config()] to make sure that
** the call worked.  The [sqlite3_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** [[SQLITE_CONFIG_SINGLETHREAD]] <dt>SQLITE_CONFIG_SINGLETHREAD</dt>
** <dd>The system-provided library does not support single-threaded behaviour
** and [sqlite3_config()] will return [SQLITE_ERROR] if called with the
** SQLITE_CONFIG_SINGLETHREAD configuration option.</dd>
**
** [[SQLITE_CONFIG_MULTITHREAD]] <dt>SQLITE_CONFIG_MULTITHREAD</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Multi-thread.  In other words, it disables
** mutexing on [database connection] and [prepared statement] objects.
** The application is responsible for serializing access to
** [database connections] and [prepared statements].  But other mutexes
** are enabled so that SQLite will be safe to use in a multi-threaded
** environment as long as no two threads attempt to use the same
** [database connection] at the same time.  ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** it is not possible to set the Multi-thread [threading mode] and
** [sqlite3_config()] will return [SQLITE_ERROR] if called with the
** SQLITE_CONFIG_MULTITHREAD configuration option.</dd>
**
** [[SQLITE_CONFIG_SERIALIZED]] <dt>SQLITE_CONFIG_SERIALIZED</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Serialized. In other words, this option enables
** all mutexes including the recursive
** mutexes on [database connection] and [prepared statement] objects.
** In this mode (which is the default when SQLite is compiled with
** [SQLITE_THREADSAFE=1]) the SQLite library will itself serialize access
** to [database connections] and [prepared statements] so that the
** application is free to use the same [database connection] or the
** same [prepared statement] in different threads at the same time.
** ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** it is not possible to set the Serialized [threading mode] and
** [sqlite3_config()] will return [SQLITE_ERROR] if called with the
** SQLITE_CONFIG_SERIALIZED configuration option.</dd>
**
** [[SQLITE_CONFIG_MALLOC]] <dt>SQLITE_CONFIG_MALLOC</dt>
** <dd> ^(The SQLITE_CONFIG_MALLOC option takes a single argument which is
** a pointer to an instance of the [sqlite3_mem_methods] structure.
** The argument specifies
** alternative low-level memory allocation routines to be used in place of
** the memory allocation routines built into SQLite.)^ ^SQLite makes
** its own private copy of the content of the [sqlite3_mem_methods] structure
** before the [sqlite3_config()] call returns.</dd>
**
** [[SQLITE_CONFIG_GETMALLOC]] <dt>SQLITE_CONFIG_GETMALLOC</dt>
** <dd> ^(The SQLITE_CONFIG_GETMALLOC option takes a single argument which
** is a pointer to an instance of the [sqlite3_mem_methods] structure.
** The [sqlite3_mem_methods]
** structure is filled with the currently defined memory allocation routines.)^
** This option can be used to overload the default memory allocation
** routines with a wrapper that simulations memory allocation failure or
** tracks memory usage, for example. </dd>
**
** [[SQLITE_CONFIG_SMALL_MALLOC]] <dt>SQLITE_CONFIG_SMALL_MALLOC</dt>
** <dd> ^The SQLITE_CONFIG_SMALL_MALLOC option takes single argument of
** type int, interpreted as a boolean, which if true provides a hint to
** SQLite that it should avoid large memory allocations if possible.
** SQLite will run faster if it is free to make large memory allocations,
** but some application might prefer to run slower in exchange for
** guarantees about memory fragmentation that are possible if large
** allocations are avoided.  This hint is normally off.
** </dd>
**
** [[SQLITE_CONFIG_MEMSTATUS]] <dt>SQLITE_CONFIG_MEMSTATUS</dt>
** <dd> ^The SQLITE_CONFIG_MEMSTATUS option takes single argument of type int,
** interpreted as a boolean, which enables or disables the collection of
** memory allocation statistics. ^(When memory allocation statistics are
** disabled, the following SQLite interfaces become non-operational:
**   <ul>
**   <li> [sqlite3_memory_used()]
**   <li> [sqlite3_memory_highwater()]
**   <li> [sqlite3_soft_heap_limit64()]
**   <li> [sqlite3_status64()]
**   </ul>)^
** ^Memory allocation statistics are enabled by default unless SQLite is
** compiled with [SQLITE_DEFAULT_MEMSTATUS]=0 in which case memory
** allocation statistics are disabled by default.
** </dd>
**
** [[SQLITE_CONFIG_SCRATCH]] <dt>SQLITE_CONFIG_SCRATCH</dt>
** <dd> The SQLITE_CONFIG_SCRATCH option is no longer used.
** </dd>
**
** [[SQLITE_CONFIG_PAGECACHE]] <dt>SQLITE_CONFIG_PAGECACHE</dt>
** <dd> ^The SQLITE_CONFIG_PAGECACHE option specifies a memory pool
** that SQLite can use for the database page cache with the default page
** cache implementation.
** This configuration option is a no-op if an application-defined page
** cache implementation is loaded using the [SQLITE_CONFIG_PCACHE2].
** ^There are three arguments to SQLITE_CONFIG_PAGECACHE: A pointer to
** 8-byte aligned memory (pMem), the size of each page cache line (sz),
** and the number of cache lines (N).
** The sz argument should be the size of the largest database page
** (a power of two between 512 and 65536) plus some extra bytes for each
** page header.  ^The number of extra bytes needed by the page header
** can be determined using [SQLITE_CONFIG_PCACHE_HDRSZ].
** ^It is harmless, apart from the wasted memory,
** for the sz parameter to be larger than necessary.  The pMem
** argument must be either a NULL pointer or a pointer to an 8-byte
** aligned block of memory of at least sz*N bytes, otherwise
** subsequent behavior is undefined.
** ^When pMem is not NULL, SQLite will strive to use the memory provided
** to satisfy page cache needs, falling back to [sqlite3_malloc()] if
** a page cache line is larger than sz bytes or if all of the pMem buffer
** is exhausted.
** ^If pMem is NULL and N is non-zero, then each database connection
** does an initial bulk allocation for page cache memory
** from [sqlite3_malloc()] sufficient for N cache lines if N is positive or
** of -1024*N bytes if N is negative, . ^If additional
** page cache memory is needed beyond what is provided by the initial
** allocation, then SQLite goes to [sqlite3_malloc()] separately for each
** additional cache line. </dd>
**
** [[SQLITE_CONFIG_HEAP]] <dt>SQLITE_CONFIG_HEAP</dt>
** <dd> ^The SQLITE_CONFIG_HEAP option specifies a static memory buffer
** that SQLite will use for all of its dynamic memory allocation needs
** beyond those provided for by [SQLITE_CONFIG_PAGECACHE].
** ^The SQLITE_CONFIG_HEAP option is only available if SQLite is compiled
** with either [SQLITE_ENABLE_MEMSYS3] or [SQLITE_ENABLE_MEMSYS5] and returns
** [SQLITE_ERROR] if invoked otherwise.
** ^There are three arguments to SQLITE_CONFIG_HEAP:
** An 8-byte aligned pointer to the memory,
** the number of bytes in the memory buffer, and the minimum allocation size.
** ^If the first pointer (the memory pointer) is NULL, then SQLite reverts
** to using its default memory allocator (the system malloc() implementation),
** undoing any prior invocation of [SQLITE_CONFIG_MALLOC].  ^If the
** memory pointer is not NULL then the alternative memory
** allocator is engaged to handle all of SQLites memory allocation needs.
** The first pointer (the memory pointer) must be aligned to an 8-byte
** boundary or subsequent behavior of SQLite will be undefined.
** The minimum allocation size is capped at 2**12. Reasonable values
** for the minimum allocation size are 2**5 through 2**8.</dd>
**
** [[SQLITE_CONFIG_MUTEX]] <dt>SQLITE_CONFIG_MUTEX</dt>
** <dd> ^(The SQLITE_CONFIG_MUTEX option takes a single argument which is a
** pointer to an instance of the [sqlite3_mutex_methods] structure.
** The argument specifies alternative low-level mutex routines to be used
** in place the mutex routines built into SQLite.)^  ^SQLite makes a copy of
** the content of the [sqlite3_mutex_methods] structure before the call to
** [sqlite3_config()] returns. ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlite3_config()] with the SQLITE_CONFIG_MUTEX configuration option will
** return [SQLITE_ERROR].</dd>
**
** [[SQLITE_CONFIG_GETMUTEX]] <dt>SQLITE_CONFIG_GETMUTEX</dt>
** <dd> ^(The SQLITE_CONFIG_GETMUTEX option takes a single argument which
** is a pointer to an instance of the [sqlite3_mutex_methods] structure.  The
** [sqlite3_mutex_methods]
** structure is filled with the currently defined mutex routines.)^
** This option can be used to overload the default mutex allocation
** routines with a wrapper used to track mutex usage for performance
** profiling or testing, for example.   ^If SQLite is compiled with
** the [SQLITE_THREADSAFE | SQLITE_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlite3_config()] with the SQLITE_CONFIG_GETMUTEX configuration option will
** return [SQLITE_ERROR].</dd>
**
** [[SQLITE_CONFIG_LOOKASIDE]] <dt>SQLITE_CONFIG_LOOKASIDE</dt>
** <dd> ^(The SQLITE_CONFIG_LOOKASIDE option takes two arguments that determine
** the default size of lookaside memory on each [database connection].
** The first argument is the
** size of each lookaside buffer slot and the second is the number of
** slots allocated to each database connection.)^  ^(SQLITE_CONFIG_LOOKASIDE
** sets the <i>default</i> lookaside size. The [SQLITE_DBCONFIG_LOOKASIDE]
** option to [sqlite3_db_config()] can be used to change the lookaside
** configuration on individual connections.)^ </dd>
**
** [[SQLITE_CONFIG_PCACHE2]] <dt>SQLITE_CONFIG_PCACHE2</dt>
** <dd> ^(The SQLITE_CONFIG_PCACHE2 option takes a single argument which is
** a pointer to an [sqlite3_pcache_methods2] object.  This object specifies
** the interface to a custom page cache implementation.)^
** ^SQLite makes a copy of the [sqlite3_pcache_methods2] object.</dd>
**
** [[SQLITE_CONFIG_GETPCACHE2]] <dt>SQLITE_CONFIG_GETPCACHE2</dt>
** <dd> ^(The SQLITE_CONFIG_GETPCACHE2 option takes a single argument which
** is a pointer to an [sqlite3_pcache_methods2] object.  SQLite copies of
** the current page cache implementation into that object.)^ </dd>
**
** [[SQLITE_CONFIG_LOG]] <dt>SQLITE_CONFIG_LOG</dt>
** <dd> The SQLITE_CONFIG_LOG option is used to configure the SQLite
** global [error log].
** (^The SQLITE_CONFIG_LOG option takes two arguments: a pointer to a
** function with a call signature of void(*)(void*,int,const char*),
** and a pointer to void. ^If the function pointer is not NULL, it is
** invoked by [sqlite3_log()] to process each logging event.  ^If the
** function pointer is NULL, the [sqlite3_log()] interface becomes a no-op.
** ^The void pointer that is the second argument to SQLITE_CONFIG_LOG is
** passed through as the first parameter to the application-defined logger
** function whenever that function is invoked.  ^The second parameter to
** the logger function is a copy of the first parameter to the corresponding
** [sqlite3_log()] call and is intended to be a [result code] or an
** [extended result code].  ^The third parameter passed to the logger is
** log message after formatting via [sqlite3_snprintf()].
** The SQLite logging interface is not reentrant; the logger function
** supplied by the application must not invoke any SQLite interface.
** In a multi-threaded application, the application-defined logger
** function must be threadsafe. </dd>
**
** [[SQLITE_CONFIG_URI]] <dt>SQLITE_CONFIG_URI
** <dd>^(The SQLITE_CONFIG_URI option takes a single argument of type int.
** If non-zero, then URI handling is globally enabled. If the parameter is zero,
** then URI handling is globally disabled.)^ ^If URI handling is globally
** enabled, all filenames passed to [sqlite3_open()], [sqlite3_open_v2()],
** [sqlite3_open16()] or
** specified as part of [ATTACH] commands are interpreted as URIs, regardless
** of whether or not the [SQLITE_OPEN_URI] flag is set when the database
** connection is opened. ^If it is globally disabled, filenames are
** only interpreted as URIs if the SQLITE_OPEN_URI flag is set when the
** database connection is opened. ^(By default, URI handling is globally
** disabled. The default value may be changed by compiling with the
** [SQLITE_USE_URI] symbol defined.)^
**
** [[SQLITE_CONFIG_COVERING_INDEX_SCAN]] <dt>SQLITE_CONFIG_COVERING_INDEX_SCAN
** <dd>^The SQLITE_CONFIG_COVERING_INDEX_SCAN option takes a single integer
** argument which is interpreted as a boolean in order to enable or disable
** the use of covering indices for full table scans in the query optimizer.
** ^The default setting is determined
** by the [SQLITE_ALLOW_COVERING_INDEX_SCAN] compile-time option, or is "on"
** if that compile-time option is omitted.
** The ability to disable the use of covering indices for full table scans
** is because some incorrectly coded legacy applications might malfunction
** when the optimization is enabled.  Providing the ability to
** disable the optimization allows the older, buggy application code to work
** without change even with newer versions of SQLite.
**
** [[SQLITE_CONFIG_PCACHE]] [[SQLITE_CONFIG_GETPCACHE]]
** <dt>SQLITE_CONFIG_PCACHE and SQLITE_CONFIG_GETPCACHE
** <dd> These options are obsolete and should not be used by new code.
** They are retained for backwards compatibility but are now no-ops.
** </dd>
**
** [[SQLITE_CONFIG_SQLLOG]]
** <dt>SQLITE_CONFIG_SQLLOG
** <dd>This option is only available if sqlite is compiled with the
** [SQLITE_ENABLE_SQLLOG] pre-processor macro defined. The first argument should
** be a pointer to a function of type void(*)(void*,sqlite3*,const char*, int).
** The second should be of type (void*). The callback is invoked by the library
** in three separate circumstances, identified by the value passed as the
** fourth parameter. If the fourth parameter is 0, then the database connection
** passed as the second argument has just been opened. The third argument
** points to a buffer containing the name of the main database file. If the
** fourth parameter is 1, then the SQL statement that the third parameter
** points to has just been executed. Or, if the fourth parameter is 2, then
** the connection being passed as the second parameter is being closed. The
** third parameter is passed NULL In this case.  An example of using this
** configuration option can be seen in the "test_sqllog.c" source file in
** the canonical SQLite source tree.</dd>
**
** [[SQLITE_CONFIG_MMAP_SIZE]]
** <dt>SQLITE_CONFIG_MMAP_SIZE
** <dd>^SQLITE_CONFIG_MMAP_SIZE takes two 64-bit integer (sqlite3_int64) values
** that are the default mmap size limit (the default setting for
** [PRAGMA mmap_size]) and the maximum allowed mmap size limit.
** ^The default setting can be overridden by each database connection using
** either the [PRAGMA mmap_size] command, or by using the
** [SQLITE_FCNTL_MMAP_SIZE] file control.  ^(The maximum allowed mmap size
** will be silently truncated if necessary so that it does not exceed the
** compile-time maximum mmap size set by the
** [SQLITE_MAX_MMAP_SIZE] compile-time option.)^
** ^If either argument to this option is negative, then that argument is
** changed to its compile-time default.
**
** [[SQLITE_CONFIG_WIN32_HEAPSIZE]]
** <dt>SQLITE_CONFIG_WIN32_HEAPSIZE
** <dd>^The SQLITE_CONFIG_WIN32_HEAPSIZE option is only available if SQLite is
** compiled for Windows with the [SQLITE_WIN32_MALLOC] pre-processor macro
** defined. ^SQLITE_CONFIG_WIN32_HEAPSIZE takes a 32-bit unsigned integer value
** that specifies the maximum size of the created heap.
**
** [[SQLITE_CONFIG_PCACHE_HDRSZ]]
** <dt>SQLITE_CONFIG_PCACHE_HDRSZ
** <dd>^The SQLITE_CONFIG_PCACHE_HDRSZ option takes a single parameter which
** is a pointer to an integer and writes into that integer the number of extra
** bytes per page required for each page in [SQLITE_CONFIG_PAGECACHE].
** The amount of extra space required can change depending on the compiler,
** target platform, and SQLite version.
**
** [[SQLITE_CONFIG_PMASZ]]
** <dt>SQLITE_CONFIG_PMASZ
** <dd>^The SQLITE_CONFIG_PMASZ option takes a single parameter which
** is an unsigned integer and sets the "Minimum PMA Size" for the multithreaded
** sorter to that integer.  The default minimum PMA Size is set by the
** [SQLITE_SORTER_PMASZ] compile-time option.  New threads are launched
** to help with sort operations when multithreaded sorting
** is enabled (using the [PRAGMA threads] command) and the amount of content
** to be sorted exceeds the page size times the minimum of the
** [PRAGMA cache_size] setting and this value.
**
** [[SQLITE_CONFIG_STMTJRNL_SPILL]]
** <dt>SQLITE_CONFIG_STMTJRNL_SPILL
** <dd>^The SQLITE_CONFIG_STMTJRNL_SPILL option takes a single parameter which
** becomes the [statement journal] spill-to-disk threshold.
** [Statement journals] are held in memory until their size (in bytes)
** exceeds this threshold, at which point they are written to disk.
** Or if the threshold is -1, statement journals are always held
** exclusively in memory.
** Since many statement journals never become large, setting the spill
** threshold to a value such as 64KiB can greatly reduce the amount of
** I/O required to support statement rollback.
** The default value for this setting is controlled by the
** [SQLITE_STMTJRNL_SPILL] compile-time option.
**
** [[SQLITE_CONFIG_SORTERREF_SIZE]]
** <dt>SQLITE_CONFIG_SORTERREF_SIZE
** <dd>The SQLITE_CONFIG_SORTERREF_SIZE option accepts a single parameter
** of type (int) - the new value of the sorter-reference size threshold.
** Usually, when SQLite uses an external sort to order records according
** to an ORDER BY clause, all fields required by the caller are present in the
** sorted records. However, if SQLite determines based on the declared type
** of a table column that its values are likely to be very large - larger
** than the configured sorter-reference size threshold - then a reference
** is stored in each sorted record and the required column values loaded
** from the database as records are returned in sorted order. The default
** value for this option is to never use this optimization. Specifying a
** negative value for this option restores the default behaviour.
** This option is only available if SQLite is compiled with the
** [SQLITE_ENABLE_SORTER_REFERENCES] compile-time option.
**
** [[SQLITE_CONFIG_MEMDB_MAXSIZE]]
** <dt>SQLITE_CONFIG_MEMDB_MAXSIZE
** <dd>The SQLITE_CONFIG_MEMDB_MAXSIZE option accepts a single parameter
** [sqlite3_int64] parameter which is the default maximum size for an in-memory
** database created using [sqlite3_deserialize()].  This default maximum
** size can be adjusted up or down for individual databases using the
** [SQLITE_FCNTL_SIZE_LIMIT] [sqlite3_file_control|file-control].  If this
** configuration setting is never used, then the default maximum is determined
** by the [SQLITE_MEMDB_DEFAULT_MAXSIZE] compile-time option.  If that
** compile-time option is not set, then the default maximum is 1073741824.
** </dl>
*/
/*line: 2151*/  SQLITE_CONFIG_SINGLETHREAD = 0x1, /* not supported */ // 1
/*line: 2152*/  SQLITE_CONFIG_MULTITHREAD = 0x2, /* nil */ // 2
/*line: 2153*/  SQLITE_CONFIG_SERIALIZED = 0x3, /* nil */ // 3
/*line: 2154*/  SQLITE_CONFIG_MALLOC = 0x4, /* sqlite3_mem_methods* */ // 4
/*line: 2155*/  SQLITE_CONFIG_GETMALLOC = 0x5, /* sqlite3_mem_methods* */ // 5
/*line: 2156*/  SQLITE_CONFIG_SCRATCH = 0x6, /* No longer used */ // 6
/*line: 2157*/  SQLITE_CONFIG_PAGECACHE = 0x7, /* void*, int sz, int N */ // 7
/*line: 2158*/  SQLITE_CONFIG_HEAP = 0x8, /* void*, int nByte, int min */ // 8
/*line: 2159*/  SQLITE_CONFIG_MEMSTATUS = 0x9, /* boolean */ // 9
/*line: 2160*/  SQLITE_CONFIG_MUTEX = 0xa, /* sqlite3_mutex_methods* */ // 10
/*line: 2161*/  SQLITE_CONFIG_GETMUTEX = 0xb, /* sqlite3_mutex_methods* */ // 11
/* previously SQLITE_CONFIG_CHUNKALLOC    12 which is now unused. */
/*line: 2163*/  SQLITE_CONFIG_LOOKASIDE = 0xd, /* int int */ // 13
/*line: 2164*/  SQLITE_CONFIG_PCACHE = 0xe, /* no-op */ // 14
/*line: 2165*/  SQLITE_CONFIG_GETPCACHE = 0xf, /* no-op */ // 15
/*line: 2166*/  SQLITE_CONFIG_LOG = 0x10, /* xFunc, void* */ // 16
/*line: 2167*/  SQLITE_CONFIG_URI = 0x11, /* int */ // 17
/*line: 2168*/  SQLITE_CONFIG_PCACHE2 = 0x12, /* sqlite3_pcache_methods2* */ // 18
/*line: 2169*/  SQLITE_CONFIG_GETPCACHE2 = 0x13, /* sqlite3_pcache_methods2* */ // 19
/*line: 2170*/  SQLITE_CONFIG_COVERING_INDEX_SCAN = 0x14, /* int */ // 20
/*line: 2171*/  SQLITE_CONFIG_SQLLOG = 0x15, /* xSqllog, void* */ // 21
/*line: 2172*/  SQLITE_CONFIG_MMAP_SIZE = 0x16, /* sqlite3_int64, sqlite3_int64 */ // 22
/*line: 2173*/  SQLITE_CONFIG_WIN32_HEAPSIZE = 0x17, /* int nByte */ // 23
/*line: 2174*/  SQLITE_CONFIG_PCACHE_HDRSZ = 0x18, /* int *psz */ // 24
/*line: 2175*/  SQLITE_CONFIG_PMASZ = 0x19, /* unsigned int szPma */ // 25
/*line: 2176*/  SQLITE_CONFIG_STMTJRNL_SPILL = 0x1a, /* int nByte */ // 26
/*line: 2177*/  SQLITE_CONFIG_SMALL_MALLOC = 0x1b, /* boolean */ // 27
/*line: 2178*/  SQLITE_CONFIG_SORTERREF_SIZE = 0x1c, /* int nByte */ // 28
/*line: 2179*/  SQLITE_CONFIG_MEMDB_MAXSIZE = 0x1d, /* sqlite3_int64 */ // 29
};

enum macro_db_config {
/*
** CAPI3REF: Database Connection Configuration Options
**
** These constants are the available integer configuration options that
** can be passed as the second argument to the [sqlite3_db_config()] interface.
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlite3_db_config()] to make sure that
** the call worked.  ^The [sqlite3_db_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** [[SQLITE_DBCONFIG_LOOKASIDE]]
** <dt>SQLITE_DBCONFIG_LOOKASIDE</dt>
** <dd> ^This option takes three additional arguments that determine the
** [lookaside memory allocator] configuration for the [database connection].
** ^The first argument (the third parameter to [sqlite3_db_config()] is a
** pointer to a memory buffer to use for lookaside memory.
** ^The first argument after the SQLITE_DBCONFIG_LOOKASIDE verb
** may be NULL in which case SQLite will allocate the
** lookaside buffer itself using [sqlite3_malloc()]. ^The second argument is the
** size of each lookaside buffer slot.  ^The third argument is the number of
** slots.  The size of the buffer in the first argument must be greater than
** or equal to the product of the second and third arguments.  The buffer
** must be aligned to an 8-byte boundary.  ^If the second argument to
** SQLITE_DBCONFIG_LOOKASIDE is not a multiple of 8, it is internally
** rounded down to the next smaller multiple of 8.  ^(The lookaside memory
** configuration for a database connection can only be changed when that
** connection is not currently using lookaside memory, or in other words
** when the "current value" returned by
** [sqlite3_db_status](D,[SQLITE_DBSTATUS_LOOKASIDE_USED],...) is zero.
** Any attempt to change the lookaside memory configuration when lookaside
** memory is in use leaves the configuration unchanged and returns
** [SQLITE_BUSY].)^</dd>
**
** [[SQLITE_DBCONFIG_ENABLE_FKEY]]
** <dt>SQLITE_DBCONFIG_ENABLE_FKEY</dt>
** <dd> ^This option is used to enable or disable the enforcement of
** [foreign key constraints].  There should be two additional arguments.
** The first argument is an integer which is 0 to disable FK enforcement,
** positive to enable FK enforcement or negative to leave FK enforcement
** unchanged.  The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether FK enforcement is off or on
** following this call.  The second parameter may be a NULL pointer, in
** which case the FK enforcement setting is not reported back. </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_TRIGGER]]
** <dt>SQLITE_DBCONFIG_ENABLE_TRIGGER</dt>
** <dd> ^This option is used to enable or disable [CREATE TRIGGER | triggers].
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable triggers,
** positive to enable triggers or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether triggers are disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the trigger setting is not reported back.
**
** <p>Originally this option disabled all triggers.  ^(However, since
** SQLite version 3.35.0, TEMP triggers are still allowed even if
** this option is off.  So, in other words, this option now only disables
** triggers in the main database schema or in the schemas of ATTACH-ed
** databases.)^ </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_VIEW]]
** <dt>SQLITE_DBCONFIG_ENABLE_VIEW</dt>
** <dd> ^This option is used to enable or disable [CREATE VIEW | views].
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable views,
** positive to enable views or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether views are disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the view setting is not reported back.
**
** <p>Originally this option disabled all views.  ^(However, since
** SQLite version 3.35.0, TEMP views are still allowed even if
** this option is off.  So, in other words, this option now only disables
** views in the main database schema or in the schemas of ATTACH-ed
** databases.)^ </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER]]
** <dt>SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER</dt>
** <dd> ^This option is not supported on the system-provided version of SQLite.
**
** For compatibility purposes, this sqlite3_db_config will always return
** SQLITE_OK when this opcode is used, and will always report that the
** [fts3_tokenizer() function] is disabled.
**
** In use, the fts3_tokenizer() function requires bound parameters and will
** return an error if passed literals.</dd>
**
** [[SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION]]
** <dt>SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION</dt>
** <dd> ^This option is not supported in the system-provided version of SQLite.
** </dd>
**
** [[SQLITE_DBCONFIG_MAINDBNAME]] <dt>SQLITE_DBCONFIG_MAINDBNAME</dt>
** <dd> ^This option is used to change the name of the "main" database
** schema.  ^The sole argument is a pointer to a constant UTF8 string
** which will become the new schema name in place of "main".  ^SQLite
** does not make a copy of the new main schema name string, so the application
** must ensure that the argument passed into this DBCONFIG option is unchanged
** until after the database connection closes.
** </dd>
**
** [[SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE]]
** <dt>SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE</dt>
** <dd> Usually, when a database in wal mode is closed or detached from a
** database handle, SQLite checks if this will mean that there are now no
** connections at all to the database. If so, it performs a checkpoint
** operation before closing the connection. This option may be used to
** override this behaviour. The first parameter passed to this operation
** is an integer - positive to disable checkpoints-on-close, or zero (the
** default) to enable them, and negative to leave the setting unchanged.
** The second parameter is a pointer to an integer
** into which is written 0 or 1 to indicate whether checkpoints-on-close
** have been disabled - 0 if they are not disabled, 1 if they are.
** </dd>
**
** [[SQLITE_DBCONFIG_ENABLE_QPSG]] <dt>SQLITE_DBCONFIG_ENABLE_QPSG</dt>
** <dd>^(The SQLITE_DBCONFIG_ENABLE_QPSG option activates or deactivates
** the [query planner stability guarantee] (QPSG).  When the QPSG is active,
** a single SQL query statement will always use the same algorithm regardless
** of values of [bound parameters].)^ The QPSG disables some query optimizations
** that look at the values of bound parameters, which can make some queries
** slower.  But the QPSG has the advantage of more predictable behavior.  With
** the QPSG active, SQLite will always use the same query plan in the field as
** was used during testing in the lab.
** The first argument to this setting is an integer which is 0 to disable
** the QPSG, positive to enable QPSG, or negative to leave the setting
** unchanged. The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether the QPSG is disabled or enabled
** following this call.
** </dd>
**
** [[SQLITE_DBCONFIG_TRIGGER_EQP]] <dt>SQLITE_DBCONFIG_TRIGGER_EQP</dt>
** <dd> By default, the output of EXPLAIN QUERY PLAN commands does not
** include output for any operations performed by trigger programs. This
** option is used to set or clear (the default) a flag that governs this
** behavior. The first parameter passed to this operation is an integer -
** positive to enable output for trigger programs, or zero to disable it,
** or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which is written
** 0 or 1 to indicate whether output-for-triggers has been disabled - 0 if
** it is not disabled, 1 if it is.
** </dd>
**
** [[SQLITE_DBCONFIG_RESET_DATABASE]] <dt>SQLITE_DBCONFIG_RESET_DATABASE</dt>
** <dd> Set the SQLITE_DBCONFIG_RESET_DATABASE flag and then run
** [VACUUM] in order to reset a database back to an empty database
** with no schema and no content. The following process works even for
** a badly corrupted database file:
** <ol>
** <li> If the database connection is newly opened, make sure it has read the
**      database schema by preparing then discarding some query against the
**      database, or calling sqlite3_table_column_metadata(), ignoring any
**      errors.  This step is only necessary if the application desires to keep
**      the database in WAL mode after the reset if it was in WAL mode before
**      the reset.
** <li> sqlite3_db_config(db, SQLITE_DBCONFIG_RESET_DATABASE, 1, 0);
** <li> [sqlite3_exec](db, "[VACUUM]", 0, 0, 0);
** <li> sqlite3_db_config(db, SQLITE_DBCONFIG_RESET_DATABASE, 0, 0);
** </ol>
** Because resetting a database is destructive and irreversible, the
** process requires the use of this obscure API and multiple steps to
** help ensure that it does not happen by accident. Because this
** feature must be capable of resetting corrupt databases, and
** shutting down virtual tables may require access to that corrupt
** storage, the library must abandon any installed virtual tables
** without calling their xDestroy() methods.
**
** [[SQLITE_DBCONFIG_DEFENSIVE]] <dt>SQLITE_DBCONFIG_DEFENSIVE</dt>
** <dd>The SQLITE_DBCONFIG_DEFENSIVE option activates or deactivates the
** "defensive" flag for a database connection.  When the defensive
** flag is enabled, language features that allow ordinary SQL to
** deliberately corrupt the database file are disabled.  The disabled
** features include but are not limited to the following:
** <ul>
** <li> The [PRAGMA writable_schema=ON] statement.
** <li> The [PRAGMA journal_mode=OFF] statement.
** <li> The [PRAGMA schema_version=N] statement.
** <li> Writes to the [sqlite_dbpage] virtual table.
** <li> Direct writes to [shadow tables].
** </ul>
** </dd>
**
** [[SQLITE_DBCONFIG_WRITABLE_SCHEMA]] <dt>SQLITE_DBCONFIG_WRITABLE_SCHEMA</dt>
** <dd>The SQLITE_DBCONFIG_WRITABLE_SCHEMA option activates or deactivates the
** "writable_schema" flag. This has the same effect and is logically equivalent
** to setting [PRAGMA writable_schema=ON] or [PRAGMA writable_schema=OFF].
** The first argument to this setting is an integer which is 0 to disable
** the writable_schema, positive to enable writable_schema, or negative to
** leave the setting unchanged. The second parameter is a pointer to an
** integer into which is written 0 or 1 to indicate whether the writable_schema
** is enabled or disabled following this call.
** </dd>
**
** [[SQLITE_DBCONFIG_LEGACY_ALTER_TABLE]]
** <dt>SQLITE_DBCONFIG_LEGACY_ALTER_TABLE</dt>
** <dd>The SQLITE_DBCONFIG_LEGACY_ALTER_TABLE option activates or deactivates
** the legacy behavior of the [ALTER TABLE RENAME] command such it
** behaves as it did prior to [version 3.24.0] (2018-06-04).  See the
** "Compatibility Notice" on the [ALTER TABLE RENAME documentation] for
** additional information. This feature can also be turned on and off
** using the [PRAGMA legacy_alter_table] statement.
** </dd>
**
** [[SQLITE_DBCONFIG_DQS_DML]]
** <dt>SQLITE_DBCONFIG_DQS_DML</dt>
** <dd>The SQLITE_DBCONFIG_DQS_DML option activates or deactivates
** the legacy [double-quoted string literal] misfeature for DML statements
** only, that is DELETE, INSERT, SELECT, and UPDATE statements. The
** default value of this setting is determined by the [-DSQLITE_DQS]
** compile-time option.
** </dd>
**
** [[SQLITE_DBCONFIG_DQS_DDL]]
** <dt>SQLITE_DBCONFIG_DQS_DDL</dt>
** <dd>The SQLITE_DBCONFIG_DQS option activates or deactivates
** the legacy [double-quoted string literal] misfeature for DDL statements,
** such as CREATE TABLE and CREATE INDEX. The
** default value of this setting is determined by the [-DSQLITE_DQS]
** compile-time option.
** </dd>
**
** [[SQLITE_DBCONFIG_TRUSTED_SCHEMA]]
** <dt>SQLITE_DBCONFIG_TRUSTED_SCHEMA</dt>
** <dd>The SQLITE_DBCONFIG_TRUSTED_SCHEMA option tells SQLite to
** assume that database schemas are untainted by malicious content.
** When the SQLITE_DBCONFIG_TRUSTED_SCHEMA option is disabled, SQLite
** takes additional defensive steps to protect the application from harm
** including:
** <ul>
** <li> Prohibit the use of SQL functions inside triggers, views,
** CHECK constraints, DEFAULT clauses, expression indexes,
** partial indexes, or generated columns
** unless those functions are tagged with [SQLITE_INNOCUOUS].
** <li> Prohibit the use of virtual tables inside of triggers or views
** unless those virtual tables are tagged with [SQLITE_VTAB_INNOCUOUS].
** </ul>
** This setting defaults to "on" for legacy compatibility, however
** all applications are advised to turn it off if possible. This setting
** can also be controlled using the [PRAGMA trusted_schema] statement.
** </dd>
**
** [[SQLITE_DBCONFIG_LEGACY_FILE_FORMAT]]
** <dt>SQLITE_DBCONFIG_LEGACY_FILE_FORMAT</dt>
** <dd>The SQLITE_DBCONFIG_LEGACY_FILE_FORMAT option activates or deactivates
** the legacy file format flag.  When activated, this flag causes all newly
** created database file to have a schema format version number (the 4-byte
** integer found at offset 44 into the database header) of 1.  This in turn
** means that the resulting database file will be readable and writable by
** any SQLite version back to 3.0.0 ([dateof:3.0.0]).  Without this setting,
** newly created databases are generally not understandable by SQLite versions
** prior to 3.3.0 ([dateof:3.3.0]).  As these words are written, there
** is now scarcely any need to generate database files that are compatible
** all the way back to version 3.0.0, and so this setting is of little
** practical use, but is provided so that SQLite can continue to claim the
** ability to generate new database files that are compatible with  version
** 3.0.0.
** <p>Note that when the SQLITE_DBCONFIG_LEGACY_FILE_FORMAT setting is on,
** the [VACUUM] command will fail with an obscure error when attempting to
** process a table with generated columns and a descending index.  This is
** not considered a bug since SQLite versions 3.3.0 and earlier do not support
** either generated columns or descending indexes.
** </dd>
**
** [[SQLITE_DBCONFIG_STMT_SCANSTATUS]]
** <dt>SQLITE_DBCONFIG_STMT_SCANSTATUS</dt>
** <dd>The SQLITE_DBCONFIG_STMT_SCANSTATUS option is only useful in
** SQLITE_ENABLE_STMT_SCANSTATUS builds. In this case, it sets or clears
** a flag that enables collection of the sqlite3_stmt_scanstatus_v2()
** statistics. For statistics to be collected, the flag must be set on
** the database handle both when the SQL statement is prepared and when it
** is stepped. The flag is set (collection of statistics is enabled)
** by default.  This option takes two arguments: an integer and a pointer to
** an integer..  The first argument is 1, 0, or -1 to enable, disable, or
** leave unchanged the statement scanstatus option.  If the second argument
** is not NULL, then the value of the statement scanstatus setting after
** processing the first argument is written into the integer that the second
** argument points to.
** </dd>
**
** [[SQLITE_DBCONFIG_REVERSE_SCANORDER]]
** <dt>SQLITE_DBCONFIG_REVERSE_SCANORDER</dt>
** <dd>The SQLITE_DBCONFIG_REVERSE_SCANORDER option changes the default order
** in which tables and indexes are scanned so that the scans start at the end
** and work toward the beginning rather than starting at the beginning and
** working toward the end. Setting SQLITE_DBCONFIG_REVERSE_SCANORDER is the
** same as setting [PRAGMA reverse_unordered_selects].  This option takes
** two arguments which are an integer and a pointer to an integer.  The first
** argument is 1, 0, or -1 to enable, disable, or leave unchanged the
** reverse scan order flag, respectively.  If the second argument is not NULL,
** then 0 or 1 is written into the integer that the second argument points to
** depending on if the reverse scan order flag is set after processing the
** first argument.
** </dd>
**
** </dl>
*/
/*line: 2483*/  SQLITE_DBCONFIG_MAINDBNAME = 0x3e8, /* const char* */ // 1000
/*line: 2484*/  SQLITE_DBCONFIG_LOOKASIDE = 0x3e9, /* void* int int */ // 1001
/*line: 2485*/  SQLITE_DBCONFIG_ENABLE_FKEY = 0x3ea, /* int int* */ // 1002
/*line: 2486*/  SQLITE_DBCONFIG_ENABLE_TRIGGER = 0x3eb, /* int int* */ // 1003
/*line: 2487*/  SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER = 0x3ec, /* no op* */ // 1004
/*line: 2488*/  SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION = 0x3ed, /* no op */ // 1005
/*line: 2489*/  SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE = 0x3ee, /* int int* */ // 1006
/*line: 2490*/  SQLITE_DBCONFIG_ENABLE_QPSG = 0x3ef, /* int int* */ // 1007
/*line: 2491*/  SQLITE_DBCONFIG_TRIGGER_EQP = 0x3f0, /* int int* */ // 1008
/*line: 2492*/  SQLITE_DBCONFIG_RESET_DATABASE = 0x3f1, /* int int* */ // 1009
/*line: 2493*/  SQLITE_DBCONFIG_DEFENSIVE = 0x3f2, /* int int* */ // 1010
/*line: 2494*/  SQLITE_DBCONFIG_WRITABLE_SCHEMA = 0x3f3, /* int int* */ // 1011
/*line: 2495*/  SQLITE_DBCONFIG_LEGACY_ALTER_TABLE = 0x3f4, /* int int* */ // 1012
/*line: 2496*/  SQLITE_DBCONFIG_DQS_DML = 0x3f5, /* int int* */ // 1013
/*line: 2497*/  SQLITE_DBCONFIG_DQS_DDL = 0x3f6, /* int int* */ // 1014
/*line: 2498*/  SQLITE_DBCONFIG_ENABLE_VIEW = 0x3f7, /* int int* */ // 1015
/*line: 2499*/  SQLITE_DBCONFIG_LEGACY_FILE_FORMAT = 0x3f8, /* int int* */ // 1016
/*line: 2500*/  SQLITE_DBCONFIG_TRUSTED_SCHEMA = 0x3f9, /* int int* */ // 1017
/*line: 2501*/  SQLITE_DBCONFIG_STMT_SCANSTATUS = 0x3fa, /* int int* */ // 1018
/*line: 2502*/  SQLITE_DBCONFIG_REVERSE_SCANORDER = 0x3fb, /* int int* */ // 1019
/*line: 2503*/  SQLITE_DBCONFIG_MAX = 0x3fb, /* Largest DBCONFIG */ // 1019
};

enum macro_authorizer_codes {
/*
** CAPI3REF: Authorizer Return Codes
**
** The [sqlite3_set_authorizer | authorizer callback function] must
** return either [SQLITE_OK] or one of these two constants in order
** to signal SQLite whether or not the action is permitted.  See the
** [sqlite3_set_authorizer | authorizer documentation] for additional
** information.
**
** Note that SQLITE_IGNORE is also used as a [conflict resolution mode]
** returned from the [sqlite3_vtab_on_conflict()] interface.
*/
/*line: 3235*/  SQLITE_DENY = 0x1, /* Abort the SQL statement with an error */ // 1
/*line: 3236*/  SQLITE_IGNORE = 0x2, /* Don't allow access, but don't generate an error */ // 2
};

enum macro_sqlite_operation {
/******************************************* 3rd ************ 4th ***********/
/*line: 3258*/  SQLITE_CREATE_INDEX = 0x1, /* Index Name      Table Name      */ // 1
/*line: 3259*/  SQLITE_CREATE_TABLE = 0x2, /* Table Name      NULL            */ // 2
/*line: 3260*/  SQLITE_CREATE_TEMP_INDEX = 0x3, /* Index Name      Table Name      */ // 3
/*line: 3261*/  SQLITE_CREATE_TEMP_TABLE = 0x4, /* Table Name      NULL            */ // 4
/*line: 3262*/  SQLITE_CREATE_TEMP_TRIGGER = 0x5, /* Trigger Name    Table Name      */ // 5
/*line: 3263*/  SQLITE_CREATE_TEMP_VIEW = 0x6, /* View Name       NULL            */ // 6
/*line: 3264*/  SQLITE_CREATE_TRIGGER = 0x7, /* Trigger Name    Table Name      */ // 7
/*line: 3265*/  SQLITE_CREATE_VIEW = 0x8, /* View Name       NULL            */ // 8
/*line: 3266*/  SQLITE_DELETE = 0x9, /* Table Name      NULL            */ // 9
/*line: 3267*/  SQLITE_DROP_INDEX = 0xa, /* Index Name      Table Name      */ // 10
/*line: 3268*/  SQLITE_DROP_TABLE = 0xb, /* Table Name      NULL            */ // 11
/*line: 3269*/  SQLITE_DROP_TEMP_INDEX = 0xc, /* Index Name      Table Name      */ // 12
/*line: 3270*/  SQLITE_DROP_TEMP_TABLE = 0xd, /* Table Name      NULL            */ // 13
/*line: 3271*/  SQLITE_DROP_TEMP_TRIGGER = 0xe, /* Trigger Name    Table Name      */ // 14
/*line: 3272*/  SQLITE_DROP_TEMP_VIEW = 0xf, /* View Name       NULL            */ // 15
/*line: 3273*/  SQLITE_DROP_TRIGGER = 0x10, /* Trigger Name    Table Name      */ // 16
/*line: 3274*/  SQLITE_DROP_VIEW = 0x11, /* View Name       NULL            */ // 17
/*line: 3275*/  SQLITE_INSERT = 0x12, /* Table Name      NULL            */ // 18
/*line: 3276*/  SQLITE_PRAGMA = 0x13, /* Pragma Name     1st arg or NULL */ // 19
/*line: 3277*/  SQLITE_READ = 0x14, /* Table Name      Column Name     */ // 20
/*line: 3278*/  SQLITE_SELECT = 0x15, /* NULL            NULL            */ // 21
/*line: 3279*/  SQLITE_TRANSACTION = 0x16, /* Operation       NULL            */ // 22
/*line: 3280*/  SQLITE_UPDATE = 0x17, /* Table Name      Column Name     */ // 23
/*line: 3281*/  SQLITE_ATTACH = 0x18, /* Filename        NULL            */ // 24
/*line: 3282*/  SQLITE_DETACH = 0x19, /* Database Name   NULL            */ // 25
/*line: 3283*/  SQLITE_ALTER_TABLE = 0x1a, /* Database Name   Table Name      */ // 26
/*line: 3284*/  SQLITE_REINDEX = 0x1b, /* Index Name      NULL            */ // 27
/*line: 3285*/  SQLITE_ANALYZE = 0x1c, /* Table Name      NULL            */ // 28
/*line: 3286*/  SQLITE_CREATE_VTABLE = 0x1d, /* Table Name      Module Name     */ // 29
/*line: 3287*/  SQLITE_DROP_VTABLE = 0x1e, /* Table Name      Module Name     */ // 30
/*line: 3288*/  SQLITE_FUNCTION = 0x1f, /* NULL            Function Name   */ // 31
/*line: 3289*/  SQLITE_SAVEPOINT = 0x20, /* Operation       Savepoint Name  */ // 32
/*line: 3290*/  SQLITE_COPY = 0x0, /* No longer used */ // 0
/*line: 3291*/  SQLITE_RECURSIVE = 0x21, /* NULL            NULL            */ // 33
};

enum macro_sqlite_trace_events {
/*
** CAPI3REF: SQL Trace Event Codes
** KEYWORDS: SQLITE_TRACE
**
** These constants identify classes of events that can be monitored
** using the [sqlite3_trace_v2()] tracing logic.  The M argument
** to [sqlite3_trace_v2(D,M,X,P)] is an OR-ed combination of one or more of
** the following constants.  ^The first argument to the trace callback
** is one of the following constants.
**
** New tracing constants may be added in future releases.
**
** ^A trace callback has four arguments: xCallback(T,C,P,X).
** ^The T argument is one of the integer type codes above.
** ^The C argument is a copy of the context pointer passed in as the
** fourth argument to [sqlite3_trace_v2()].
** The P and X arguments are pointers whose meanings depend on T.
**
** <dl>
** [[SQLITE_TRACE_STMT]] <dt>SQLITE_TRACE_STMT</dt>
** <dd>^An SQLITE_TRACE_STMT callback is invoked when a prepared statement
** first begins running and possibly at other times during the
** execution of the prepared statement, such as at the start of each
** trigger subprogram. ^The P argument is a pointer to the
** [prepared statement]. ^The X argument is a pointer to a string which
** is the unexpanded SQL text of the prepared statement or an SQL comment
** that indicates the invocation of a trigger.  ^The callback can compute
** the same text that would have been returned by the legacy [sqlite3_trace()]
** interface by using the X argument when X begins with "--" and invoking
** [sqlite3_expanded_sql(P)] otherwise.
**
** [[SQLITE_TRACE_PROFILE]] <dt>SQLITE_TRACE_PROFILE</dt>
** <dd>^An SQLITE_TRACE_PROFILE callback provides approximately the same
** information as is provided by the [sqlite3_profile()] callback.
** ^The P argument is a pointer to the [prepared statement] and the
** X argument points to a 64-bit integer which is approximately
** the number of nanoseconds that the prepared statement took to run.
** ^The SQLITE_TRACE_PROFILE callback is invoked when the statement finishes.
**
** [[SQLITE_TRACE_ROW]] <dt>SQLITE_TRACE_ROW</dt>
** <dd>^An SQLITE_TRACE_ROW callback is invoked whenever a prepared
** statement generates a single row of result.
** ^The P argument is a pointer to the [prepared statement] and the
** X argument is unused.
**
** [[SQLITE_TRACE_CLOSE]] <dt>SQLITE_TRACE_CLOSE</dt>
** <dd>^An SQLITE_TRACE_CLOSE callback is invoked when a database
** connection closes.
** ^The P argument is a pointer to the [database connection] object
** and the X argument is unused.
** </dl>
*/
/*line: 3391*/  SQLITE_TRACE_STMT = 0x1,  // 0x01
/*line: 3392*/  SQLITE_TRACE_PROFILE = 0x2,  // 0x02
/*line: 3393*/  SQLITE_TRACE_ROW = 0x4,  // 0x04
/*line: 3394*/  SQLITE_TRACE_CLOSE = 0x8,  // 0x08
};

enum macro_sqlite_limits {
/*
** CAPI3REF: Run-Time Limit Categories
** KEYWORDS: {limit category} {*limit categories}
**
** These constants define various performance limits
** that can be lowered at run-time using [sqlite3_limit()].
** The synopsis of the meanings of the various limits is shown below.
** Additional information is available at [limits | Limits in SQLite].
**
** <dl>
** [[SQLITE_LIMIT_LENGTH]] ^(<dt>SQLITE_LIMIT_LENGTH</dt>
** <dd>The maximum size of any string or BLOB or table row, in bytes.<dd>)^
**
** [[SQLITE_LIMIT_SQL_LENGTH]] ^(<dt>SQLITE_LIMIT_SQL_LENGTH</dt>
** <dd>The maximum length of an SQL statement, in bytes.</dd>)^
**
** [[SQLITE_LIMIT_COLUMN]] ^(<dt>SQLITE_LIMIT_COLUMN</dt>
** <dd>The maximum number of columns in a table definition or in the
** result set of a [SELECT] or the maximum number of columns in an index
** or in an ORDER BY or GROUP BY clause.</dd>)^
**
** [[SQLITE_LIMIT_EXPR_DEPTH]] ^(<dt>SQLITE_LIMIT_EXPR_DEPTH</dt>
** <dd>The maximum depth of the parse tree on any expression.</dd>)^
**
** [[SQLITE_LIMIT_COMPOUND_SELECT]] ^(<dt>SQLITE_LIMIT_COMPOUND_SELECT</dt>
** <dd>The maximum number of terms in a compound SELECT statement.</dd>)^
**
** [[SQLITE_LIMIT_VDBE_OP]] ^(<dt>SQLITE_LIMIT_VDBE_OP</dt>
** <dd>The maximum number of instructions in a virtual machine program
** used to implement an SQL statement.  If [sqlite3_prepare_v2()] or
** the equivalent tries to allocate space for more than this many opcodes
** in a single prepared statement, an SQLITE_NOMEM error is returned.</dd>)^
**
** [[SQLITE_LIMIT_FUNCTION_ARG]] ^(<dt>SQLITE_LIMIT_FUNCTION_ARG</dt>
** <dd>The maximum number of arguments on a function.</dd>)^
**
** [[SQLITE_LIMIT_ATTACHED]] ^(<dt>SQLITE_LIMIT_ATTACHED</dt>
** <dd>The maximum number of [ATTACH | attached databases].)^</dd>
**
** [[SQLITE_LIMIT_LIKE_PATTERN_LENGTH]]
** ^(<dt>SQLITE_LIMIT_LIKE_PATTERN_LENGTH</dt>
** <dd>The maximum length of the pattern argument to the [LIKE] or
** [GLOB] operators.</dd>)^
**
** [[SQLITE_LIMIT_VARIABLE_NUMBER]]
** ^(<dt>SQLITE_LIMIT_VARIABLE_NUMBER</dt>
** <dd>The maximum index number of any [parameter] in an SQL statement.)^
**
** [[SQLITE_LIMIT_TRIGGER_DEPTH]] ^(<dt>SQLITE_LIMIT_TRIGGER_DEPTH</dt>
** <dd>The maximum depth of recursion for triggers.</dd>)^
**
** [[SQLITE_LIMIT_WORKER_THREADS]] ^(<dt>SQLITE_LIMIT_WORKER_THREADS</dt>
** <dd>The maximum number of auxiliary worker threads that a single
** [prepared statement] may start.</dd>)^
** </dl>
*/
/*line: 4151*/  SQLITE_LIMIT_LENGTH = 0x0,  // 0
/*line: 4152*/  SQLITE_LIMIT_SQL_LENGTH = 0x1,  // 1
/*line: 4153*/  SQLITE_LIMIT_COLUMN = 0x2,  // 2
/*line: 4154*/  SQLITE_LIMIT_EXPR_DEPTH = 0x3,  // 3
/*line: 4155*/  SQLITE_LIMIT_COMPOUND_SELECT = 0x4,  // 4
/*line: 4156*/  SQLITE_LIMIT_VDBE_OP = 0x5,  // 5
/*line: 4157*/  SQLITE_LIMIT_FUNCTION_ARG = 0x6,  // 6
/*line: 4158*/  SQLITE_LIMIT_ATTACHED = 0x7,  // 7
/*line: 4159*/  SQLITE_LIMIT_LIKE_PATTERN_LENGTH = 0x8,  // 8
/*line: 4160*/  SQLITE_LIMIT_VARIABLE_NUMBER = 0x9,  // 9
/*line: 4161*/  SQLITE_LIMIT_TRIGGER_DEPTH = 0xa,  // 10
/*line: 4162*/  SQLITE_LIMIT_WORKER_THREADS = 0xb,  // 11
};

enum macro_prepare_flags {
/*
** CAPI3REF: Prepare Flags
**
** These constants define various flags that can be passed into
** "prepFlags" parameter of the [sqlite3_prepare_v3()] and
** [sqlite3_prepare16_v3()] interfaces.
**
** New flags may be added in future releases of SQLite.
**
** <dl>
** [[SQLITE_PREPARE_PERSISTENT]] ^(<dt>SQLITE_PREPARE_PERSISTENT</dt>
** <dd>The SQLITE_PREPARE_PERSISTENT flag is a hint to the query planner
** that the prepared statement will be retained for a long time and
** probably reused many times.)^ ^Without this flag, [sqlite3_prepare_v3()]
** and [sqlite3_prepare16_v3()] assume that the prepared statement will
** be used just once or at most a few times and then destroyed using
** [sqlite3_finalize()] relatively soon. The current implementation acts
** on this hint by avoiding the use of [lookaside memory] so as not to
** deplete the limited store of lookaside memory. Future versions of
** SQLite may act on this hint differently.
**
** [[SQLITE_PREPARE_NORMALIZE]] <dt>SQLITE_PREPARE_NORMALIZE</dt>
** <dd>The SQLITE_PREPARE_NORMALIZE flag is a no-op. This flag used
** to be required for any prepared statement that wanted to use the
** [sqlite3_normalized_sql()] interface.  However, the
** [sqlite3_normalized_sql()] interface is now available to all
** prepared statements, regardless of whether or not they use this
** flag.
**
** [[SQLITE_PREPARE_NO_VTAB]] <dt>SQLITE_PREPARE_NO_VTAB</dt>
** <dd>The SQLITE_PREPARE_NO_VTAB flag causes the SQL compiler
** to return an error (error code SQLITE_ERROR) if the statement uses
** any virtual tables.
** </dl>
*/
/*line: 4199*/  SQLITE_PREPARE_PERSISTENT = 0x1,  // 0x01
/*line: 4200*/  SQLITE_PREPARE_NORMALIZE = 0x2,  // 0x02
/*line: 4201*/  SQLITE_PREPARE_NO_VTAB = 0x4,  // 0x04
};

enum macro_sqlite_datatype {
/*
** CAPI3REF: Fundamental Datatypes
** KEYWORDS: SQLITE_TEXT
**
** ^(Every value in SQLite has one of five fundamental datatypes:
**
** <ul>
** <li> 64-bit signed integer
** <li> 64-bit IEEE floating point number
** <li> string
** <li> BLOB
** <li> NULL
** </ul>)^
**
** These constants are codes for each of those types.
**
** Note that the SQLITE_TEXT constant was also used in SQLite version 2
** for a completely different meaning.  Software that links against both
** SQLite version 2 and SQLite version 3 should use SQLITE3_TEXT, not
** SQLITE_TEXT.
*/
/*line: 5073*/  SQLITE_INTEGER = 0x1,  // 1
/*line: 5074*/  SQLITE_FLOAT = 0x2,  // 2
/*line: 5075*/  SQLITE_BLOB = 0x4,  // 4
/*line: 5076*/  SQLITE_NULL = 0x5,  // 5
/*line: 5080*/  SQLITE_TEXT = 0x3,  // 3
/*line: 5082*/  SQLITE3_TEXT = 0x3,  // 3
};

enum macro_text_encoding {
/*
** CAPI3REF: Text Encodings
**
** These constant define integer codes that represent the various
** text encodings supported by SQLite.
*/
/*line: 5552*/  SQLITE_UTF8 = 0x1, /* IMP: R-37514-35566 */ // 1
/*line: 5553*/  SQLITE_UTF16LE = 0x2, /* IMP: R-03371-37637 */ // 2
/*line: 5554*/  SQLITE_UTF16BE = 0x3, /* IMP: R-51971-34154 */ // 3
/*line: 5555*/  SQLITE_UTF16 = 0x4, /* Use native byte order */ // 4
/*line: 5556*/  SQLITE_ANY = 0x5, /* Deprecated */ // 5
/*line: 5557*/  SQLITE_UTF16_ALIGNED = 0x8, /* sqlite3_create_collation only */ // 8
};

enum macro_sqlite_function_flags {
/*
** CAPI3REF: Function Flags
**
** These constants may be ORed together with the
** [SQLITE_UTF8 | preferred text encoding] as the fourth argument
** to [sqlite3_create_function()], [sqlite3_create_function16()], or
** [sqlite3_create_function_v2()].
**
** <dl>
** [[SQLITE_DETERMINISTIC]] <dt>SQLITE_DETERMINISTIC</dt><dd>
** The SQLITE_DETERMINISTIC flag means that the new function always gives
** the same output when the input parameters are the same.
** The [abs|abs() function] is deterministic, for example, but
** [randomblob|randomblob()] is not.  Functions must
** be deterministic in order to be used in certain contexts such as
** with the WHERE clause of [partial indexes] or in [generated columns].
** SQLite might also optimize deterministic functions by factoring them
** out of inner loops.
** </dd>
**
** [[SQLITE_DIRECTONLY]] <dt>SQLITE_DIRECTONLY</dt><dd>
** The SQLITE_DIRECTONLY flag means that the function may only be invoked
** from top-level SQL, and cannot be used in VIEWs or TRIGGERs nor in
** schema structures such as [CHECK constraints], [DEFAULT clauses],
** [expression indexes], [partial indexes], or [generated columns].
** <p>
** The SQLITE_DIRECTONLY flag is recommended for any
** [application-defined SQL function]
** that has side-effects or that could potentially leak sensitive information.
** This will prevent attacks in which an application is tricked
** into using a database file that has had its schema surreptitiously
** modified to invoke the application-defined function in ways that are
** harmful.
** <p>
** Some people say it is good practice to set SQLITE_DIRECTONLY on all
** [application-defined SQL functions], regardless of whether or not they
** are security sensitive, as doing so prevents those functions from being used
** inside of the database schema, and thus ensures that the database
** can be inspected and modified using generic tools (such as the [CLI])
** that do not have access to the application-defined functions.
** </dd>
**
** [[SQLITE_INNOCUOUS]] <dt>SQLITE_INNOCUOUS</dt><dd>
** The SQLITE_INNOCUOUS flag means that the function is unlikely
** to cause problems even if misused.  An innocuous function should have
** no side effects and should not depend on any values other than its
** input parameters. The [abs|abs() function] is an example of an
** innocuous function.
** The [load_extension() SQL function] is not innocuous because of its
** side effects.
** <p> SQLITE_INNOCUOUS is similar to SQLITE_DETERMINISTIC, but is not
** exactly the same.  The [random|random() function] is an example of a
** function that is innocuous but not deterministic.
** <p>Some heightened security settings
** ([SQLITE_DBCONFIG_TRUSTED_SCHEMA] and [PRAGMA trusted_schema=OFF])
** disable the use of SQL functions inside views and triggers and in
** schema structures such as [CHECK constraints], [DEFAULT clauses],
** [expression indexes], [partial indexes], and [generated columns] unless
** the function is tagged with SQLITE_INNOCUOUS.  Most built-in functions
** are innocuous.  Developers are advised to avoid using the
** SQLITE_INNOCUOUS flag for application-defined functions unless the
** function has been carefully audited and found to be free of potentially
** security-adverse side-effects and information-leaks.
** </dd>
**
** [[SQLITE_SUBTYPE]] <dt>SQLITE_SUBTYPE</dt><dd>
** The SQLITE_SUBTYPE flag indicates to SQLite that a function may call
** [sqlite3_value_subtype()] to inspect the sub-types of its arguments.
** Specifying this flag makes no difference for scalar or aggregate user
** functions. However, if it is not specified for a user-defined window
** function, then any sub-types belonging to arguments passed to the window
** function may be discarded before the window function is called (i.e.
** sqlite3_value_subtype() will always return 0).
** </dd>
** </dl>
*/
/*line: 5635*/  SQLITE_DETERMINISTIC = 0x800,  // 0x000000800
/*line: 5636*/  SQLITE_DIRECTONLY = 0x80000,  // 0x000080000
/*line: 5637*/  SQLITE_SUBTYPE = 0x100000,  // 0x000100000
/*line: 5638*/  SQLITE_INNOCUOUS = 0x200000,  // 0x000200000
};

// Depends on identifiers
enum macro_destructor_type {
/*line: 6025*/  SQLITE_STATIC = 0x0,  // ((sqlite3_destructor_type)0)
/*line: 6026*/  SQLITE_TRANSIENT = -0x1,  // ((sqlite3_destructor_type)-1)
};

enum macro_transaction_state {
/*
** CAPI3REF: Allowed return values from [sqlite3_txn_state()]
** KEYWORDS: {transaction state}
**
** These constants define the current transaction state of a database file.
** ^The [sqlite3_txn_state(D,S)] interface returns one of these
** constants in order to describe the transaction state of schema S
** in [database connection] D.
**
** <dl>
** [[SQLITE_TXN_NONE]] <dt>SQLITE_TXN_NONE</dt>
** <dd>The SQLITE_TXN_NONE state means that no transaction is currently
** pending.</dd>
**
** [[SQLITE_TXN_READ]] <dt>SQLITE_TXN_READ</dt>
** <dd>The SQLITE_TXN_READ state means that the database is currently
** in a read transaction.  Content has been read from the database file
** but nothing in the database file has changed.  The transaction state
** will advanced to SQLITE_TXN_WRITE if any changes occur and there are
** no other conflicting concurrent write transactions.  The transaction
** state will revert to SQLITE_TXN_NONE following a [ROLLBACK] or
** [COMMIT].</dd>
**
** [[SQLITE_TXN_WRITE]] <dt>SQLITE_TXN_WRITE</dt>
** <dd>The SQLITE_TXN_WRITE state means that the database is currently
** in a write transaction.  Content has been written to the database file
** but has not yet committed.  The transaction state will change to
** to SQLITE_TXN_NONE at the next [ROLLBACK] or [COMMIT].</dd>
*/
/*line: 6635*/  SQLITE_TXN_NONE = 0x0,  // 0
/*line: 6636*/  SQLITE_TXN_READ = 0x1,  // 1
/*line: 6637*/  SQLITE_TXN_WRITE = 0x2,  // 2
};

enum macro_sqlite_index {
/*
** CAPI3REF: Virtual Table Scan Flags
**
** Virtual table implementations are allowed to set the
** [sqlite3_index_info].idxFlags field to some combination of
** these bits.
*/
/*line: 7312*/  SQLITE_INDEX_SCAN_UNIQUE = 0x1, /* Scan visits at most 1 row */ // 1
/*
** CAPI3REF: Virtual Table Constraint Operator Codes
**
** These macros define the allowed values for the
** [sqlite3_index_info].aConstraint[].op field.  Each value represents
** an operator that is part of a constraint term in the WHERE clause of
** a query that uses a [virtual table].
**
** ^The left-hand operand of the operator is given by the corresponding
** aConstraint[].iColumn field.  ^An iColumn of -1 indicates the left-hand
** operand is the rowid.
** The SQLITE_INDEX_CONSTRAINT_LIMIT and SQLITE_INDEX_CONSTRAINT_OFFSET
** operators have no left-hand operand, and so for those operators the
** corresponding aConstraint[].iColumn is meaningless and should not be
** used.
**
** All operator values from SQLITE_INDEX_CONSTRAINT_FUNCTION through
** value 255 are reserved to represent functions that are overloaded
** by the [xFindFunction|xFindFunction method] of the virtual table
** implementation.
**
** The right-hand operands for each constraint might be accessible using
** the [sqlite3_vtab_rhs_value()] interface.  Usually the right-hand
** operand is only available if it appears as a single constant literal
** in the input SQL.  If the right-hand operand is another column or an
** expression (even a constant expression) or a parameter, then the
** sqlite3_vtab_rhs_value() probably will not be able to extract it.
** ^The SQLITE_INDEX_CONSTRAINT_ISNULL and
** SQLITE_INDEX_CONSTRAINT_ISNOTNULL operators have no right-hand operand
** and hence calls to sqlite3_vtab_rhs_value() for those operators will
** always return SQLITE_NOTFOUND.
**
** The collating sequence to be used for comparison can be found using
** the [sqlite3_vtab_collation()] interface.  For most real-world virtual
** tables, the collating sequence of constraints does not matter (for example
** because the constraints are numeric) and so the sqlite3_vtab_collation()
** interface is not commonly needed.
*/
/*line: 7352*/  SQLITE_INDEX_CONSTRAINT_EQ = 0x2,  // 2
/*line: 7353*/  SQLITE_INDEX_CONSTRAINT_GT = 0x4,  // 4
/*line: 7354*/  SQLITE_INDEX_CONSTRAINT_LE = 0x8,  // 8
/*line: 7355*/  SQLITE_INDEX_CONSTRAINT_LT = 0x10,  // 16
/*line: 7356*/  SQLITE_INDEX_CONSTRAINT_GE = 0x20,  // 32
/*line: 7357*/  SQLITE_INDEX_CONSTRAINT_MATCH = 0x40,  // 64
/*line: 7358*/  SQLITE_INDEX_CONSTRAINT_LIKE = 0x41,  // 65
/*line: 7359*/  SQLITE_INDEX_CONSTRAINT_GLOB = 0x42,  // 66
/*line: 7360*/  SQLITE_INDEX_CONSTRAINT_REGEXP = 0x43,  // 67
/*line: 7361*/  SQLITE_INDEX_CONSTRAINT_NE = 0x44,  // 68
/*line: 7362*/  SQLITE_INDEX_CONSTRAINT_ISNOT = 0x45,  // 69
/*line: 7363*/  SQLITE_INDEX_CONSTRAINT_ISNOTNULL = 0x46,  // 70
/*line: 7364*/  SQLITE_INDEX_CONSTRAINT_ISNULL = 0x47,  // 71
/*line: 7365*/  SQLITE_INDEX_CONSTRAINT_IS = 0x48,  // 72
/*line: 7366*/  SQLITE_INDEX_CONSTRAINT_LIMIT = 0x49,  // 73
/*line: 7367*/  SQLITE_INDEX_CONSTRAINT_OFFSET = 0x4a,  // 74
/*line: 7368*/  SQLITE_INDEX_CONSTRAINT_FUNCTION = 0x96,  // 150
};

enum macro_mutex_types {
/*
** CAPI3REF: Mutex Types
**
** The [sqlite3_mutex_alloc()] interface takes a single argument
** which is one of these integer constants.
**
** The set of static mutexes may change from one SQLite release to the
** next.  Applications that override the built-in mutex logic must be
** prepared to accommodate additional static mutexes.
*/
/*line: 7994*/  SQLITE_MUTEX_FAST = 0x0,  // 0
/*line: 7995*/  SQLITE_MUTEX_RECURSIVE = 0x1,  // 1
/*line: 7996*/  SQLITE_MUTEX_STATIC_MAIN = 0x2,  // 2
/*line: 7997*/  SQLITE_MUTEX_STATIC_MEM = 0x3, /* sqlite3_malloc() */ // 3
/*line: 7998*/  SQLITE_MUTEX_STATIC_MEM2 = 0x4, /* NOT USED */ // 4
/*line: 7999*/  SQLITE_MUTEX_STATIC_OPEN = 0x4, /* sqlite3BtreeOpen() */ // 4
/*line: 8000*/  SQLITE_MUTEX_STATIC_PRNG = 0x5, /* sqlite3_randomness() */ // 5
/*line: 8001*/  SQLITE_MUTEX_STATIC_LRU = 0x6, /* lru page list */ // 6
/*line: 8002*/  SQLITE_MUTEX_STATIC_LRU2 = 0x7, /* NOT USED */ // 7
/*line: 8003*/  SQLITE_MUTEX_STATIC_PMEM = 0x7, /* sqlite3PageMalloc() */ // 7
/*line: 8004*/  SQLITE_MUTEX_STATIC_APP1 = 0x8, /* For use by application */ // 8
/*line: 8005*/  SQLITE_MUTEX_STATIC_APP2 = 0x9, /* For use by application */ // 9
/*line: 8006*/  SQLITE_MUTEX_STATIC_APP3 = 0xa, /* For use by application */ // 10
/*line: 8007*/  SQLITE_MUTEX_STATIC_VFS1 = 0xb, /* For use by built-in VFS */ // 11
/*line: 8008*/  SQLITE_MUTEX_STATIC_VFS2 = 0xc, /* For use by extension VFS */ // 12
/*line: 8009*/  SQLITE_MUTEX_STATIC_VFS3 = 0xd, /* For use by application VFS */ // 13
};

// Depends on identifiers
enum macro_sqlite_mutex {
/* Legacy compatibility: */
/*line: 8012*/  SQLITE_MUTEX_STATIC_MASTER = 0x2,  // SQLITE_MUTEX_STATIC_MAIN
};

enum macro_test_control {
/*
** CAPI3REF: Testing Interface Operation Codes
**
** These constants are the valid operation code parameters used
** as the first argument to [sqlite3_test_control()].
**
** These parameters and their meanings are subject to change
** without notice.  These values are for testing purposes only.
** Applications should not use any of these parameters or the
** [sqlite3_test_control()] interface.
*/
/*line: 8100*/  SQLITE_TESTCTRL_FIRST = 0x5,  // 5
/*line: 8101*/  SQLITE_TESTCTRL_PRNG_SAVE = 0x5,  // 5
/*line: 8102*/  SQLITE_TESTCTRL_PRNG_RESTORE = 0x6,  // 6
/*line: 8103*/  SQLITE_TESTCTRL_PRNG_RESET = 0x7, /* NOT USED */ // 7
/*line: 8104*/  SQLITE_TESTCTRL_BITVEC_TEST = 0x8,  // 8
/*line: 8105*/  SQLITE_TESTCTRL_FAULT_INSTALL = 0x9,  // 9
/*line: 8106*/  SQLITE_TESTCTRL_BENIGN_MALLOC_HOOKS = 0xa,  // 10
/*line: 8107*/  SQLITE_TESTCTRL_PENDING_BYTE = 0xb,  // 11
/*line: 8108*/  SQLITE_TESTCTRL_ASSERT = 0xc,  // 12
/*line: 8109*/  SQLITE_TESTCTRL_ALWAYS = 0xd,  // 13
/*line: 8110*/  SQLITE_TESTCTRL_RESERVE = 0xe, /* NOT USED */ // 14
/*line: 8111*/  SQLITE_TESTCTRL_OPTIMIZATIONS = 0xf,  // 15
/*line: 8112*/  SQLITE_TESTCTRL_ISKEYWORD = 0x10, /* NOT USED */ // 16
/*line: 8113*/  SQLITE_TESTCTRL_SCRATCHMALLOC = 0x11, /* NOT USED */ // 17
/*line: 8114*/  SQLITE_TESTCTRL_INTERNAL_FUNCTIONS = 0x11,  // 17
/*line: 8115*/  SQLITE_TESTCTRL_LOCALTIME_FAULT = 0x12,  // 18
/*line: 8116*/  SQLITE_TESTCTRL_EXPLAIN_STMT = 0x13, /* NOT USED */ // 19
/*line: 8117*/  SQLITE_TESTCTRL_ONCE_RESET_THRESHOLD = 0x13,  // 19
/*line: 8118*/  SQLITE_TESTCTRL_NEVER_CORRUPT = 0x14,  // 20
/*line: 8119*/  SQLITE_TESTCTRL_VDBE_COVERAGE = 0x15,  // 21
/*line: 8120*/  SQLITE_TESTCTRL_BYTEORDER = 0x16,  // 22
/*line: 8121*/  SQLITE_TESTCTRL_ISINIT = 0x17,  // 23
/*line: 8122*/  SQLITE_TESTCTRL_SORTER_MMAP = 0x18,  // 24
/*line: 8123*/  SQLITE_TESTCTRL_IMPOSTER = 0x19,  // 25
/*line: 8124*/  SQLITE_TESTCTRL_PARSER_COVERAGE = 0x1a,  // 26
/*line: 8125*/  SQLITE_TESTCTRL_RESULT_INTREAL = 0x1b,  // 27
/*line: 8126*/  SQLITE_TESTCTRL_PRNG_SEED = 0x1c,  // 28
/*line: 8127*/  SQLITE_TESTCTRL_EXTRA_SCHEMA_CHECKS = 0x1d,  // 29
/*line: 8128*/  SQLITE_TESTCTRL_SEEK_COUNT = 0x1e,  // 30
/*line: 8129*/  SQLITE_TESTCTRL_TRACEFLAGS = 0x1f,  // 31
/*line: 8130*/  SQLITE_TESTCTRL_TUNE = 0x20,  // 32
/*line: 8131*/  SQLITE_TESTCTRL_LOGEST = 0x21,  // 33
/*line: 8132*/  SQLITE_TESTCTRL_USELONGDOUBLE = 0x22,  // 34
/*line: 8133*/  SQLITE_TESTCTRL_LAST = 0x22, /* Largest TESTCTRL */ // 34
};

enum macro_sqlite3_status {
/*
** CAPI3REF: Status Parameters
** KEYWORDS: {status parameters}
**
** These integer constants designate various run-time status parameters
** that can be returned by [sqlite3_status()].
**
** <dl>
** [[SQLITE_STATUS_MEMORY_USED]] ^(<dt>SQLITE_STATUS_MEMORY_USED</dt>
** <dd>This parameter is the current amount of memory checked out
** using [sqlite3_malloc()], either directly or indirectly.  The
** figure includes calls made to [sqlite3_malloc()] by the application
** and internal memory usage by the SQLite library.  Auxiliary page-cache
** memory controlled by [SQLITE_CONFIG_PAGECACHE] is not included in
** this parameter.  The amount returned is the sum of the allocation
** sizes as reported by the xSize method in [sqlite3_mem_methods].</dd>)^
**
** [[SQLITE_STATUS_MALLOC_SIZE]] ^(<dt>SQLITE_STATUS_MALLOC_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [sqlite3_malloc()] or [sqlite3_realloc()] (or their
** internal equivalents).  Only the value returned in the
** *pHighwater parameter to [sqlite3_status()] is of interest.
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLITE_STATUS_MALLOC_COUNT]] ^(<dt>SQLITE_STATUS_MALLOC_COUNT</dt>
** <dd>This parameter records the number of separate memory allocations
** currently checked out.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_USED]] ^(<dt>SQLITE_STATUS_PAGECACHE_USED</dt>
** <dd>This parameter returns the number of pages used out of the
** [pagecache memory allocator] that was configured using
** [SQLITE_CONFIG_PAGECACHE].  The
** value returned is in pages, not in bytes.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_OVERFLOW]]
** ^(<dt>SQLITE_STATUS_PAGECACHE_OVERFLOW</dt>
** <dd>This parameter returns the number of bytes of page cache
** allocation which could not be satisfied by the [SQLITE_CONFIG_PAGECACHE]
** buffer and where forced to overflow to [sqlite3_malloc()].  The
** returned value includes allocations that overflowed because they
** where too large (they were larger than the "sz" parameter to
** [SQLITE_CONFIG_PAGECACHE]) and allocations that overflowed because
** no space was left in the page cache.</dd>)^
**
** [[SQLITE_STATUS_PAGECACHE_SIZE]] ^(<dt>SQLITE_STATUS_PAGECACHE_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to the [pagecache memory allocator].  Only the value returned in the
** *pHighwater parameter to [sqlite3_status()] is of interest.
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLITE_STATUS_SCRATCH_USED]] <dt>SQLITE_STATUS_SCRATCH_USED</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_SCRATCH_OVERFLOW]] ^(<dt>SQLITE_STATUS_SCRATCH_OVERFLOW</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_SCRATCH_SIZE]] <dt>SQLITE_STATUS_SCRATCH_SIZE</dt>
** <dd>No longer used.</dd>
**
** [[SQLITE_STATUS_PARSER_STACK]] ^(<dt>SQLITE_STATUS_PARSER_STACK</dt>
** <dd>The *pHighwater parameter records the deepest parser stack.
** The *pCurrent value is undefined.  The *pHighwater value is only
** meaningful if SQLite is compiled with [YYTRACKMAXSTACKDEPTH].</dd>)^
** </dl>
**
** New status parameters may be added from time to time.
*/
/*line: 8444*/  SQLITE_STATUS_MEMORY_USED = 0x0,  // 0
/*line: 8445*/  SQLITE_STATUS_PAGECACHE_USED = 0x1,  // 1
/*line: 8446*/  SQLITE_STATUS_PAGECACHE_OVERFLOW = 0x2,  // 2
/*line: 8447*/  SQLITE_STATUS_SCRATCH_USED = 0x3, /* NOT USED */ // 3
/*line: 8448*/  SQLITE_STATUS_SCRATCH_OVERFLOW = 0x4, /* NOT USED */ // 4
/*line: 8449*/  SQLITE_STATUS_MALLOC_SIZE = 0x5,  // 5
/*line: 8450*/  SQLITE_STATUS_PARSER_STACK = 0x6,  // 6
/*line: 8451*/  SQLITE_STATUS_PAGECACHE_SIZE = 0x7,  // 7
/*line: 8452*/  SQLITE_STATUS_SCRATCH_SIZE = 0x8, /* NOT USED */ // 8
/*line: 8453*/  SQLITE_STATUS_MALLOC_COUNT = 0x9,  // 9
};

enum macro_db_status_options {
/*
** CAPI3REF: Status Parameters for database connections
** KEYWORDS: {SQLITE_DBSTATUS options}
**
** These constants are the available integer "verbs" that can be passed as
** the second argument to the [sqlite3_db_status()] interface.
**
** New verbs may be added in future releases of SQLite. Existing verbs
** might be discontinued. Applications should check the return code from
** [sqlite3_db_status()] to make sure that the call worked.
** The [sqlite3_db_status()] interface will return a non-zero error code
** if a discontinued or unsupported verb is invoked.
**
** <dl>
** [[SQLITE_DBSTATUS_LOOKASIDE_USED]] ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_USED</dt>
** <dd>This parameter returns the number of lookaside memory slots currently
** checked out.</dd>)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_HIT]] ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_HIT</dt>
** <dd>This parameter returns the number of malloc attempts that were
** satisfied using lookaside memory. Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE]]
** ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to the amount of
** memory requested being larger than the lookaside slot size.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL]]
** ^(<dt>SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to all lookaside
** memory already being in use.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLITE_DBSTATUS_CACHE_USED]] ^(<dt>SQLITE_DBSTATUS_CACHE_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** memory used by all pager caches associated with the database connection.)^
** ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_USED is always 0.
**
** [[SQLITE_DBSTATUS_CACHE_USED_SHARED]]
** ^(<dt>SQLITE_DBSTATUS_CACHE_USED_SHARED</dt>
** <dd>This parameter is similar to DBSTATUS_CACHE_USED, except that if a
** pager cache is shared between two or more connections the bytes of heap
** memory used by that pager cache is divided evenly between the attached
** connections.)^  In other words, if none of the pager caches associated
** with the database connection are shared, this request returns the same
** value as DBSTATUS_CACHE_USED. Or, if one or more or the pager caches are
** shared, the value returned by this call will be smaller than that returned
** by DBSTATUS_CACHE_USED. ^The highwater mark associated with
** SQLITE_DBSTATUS_CACHE_USED_SHARED is always 0.
**
** [[SQLITE_DBSTATUS_SCHEMA_USED]] ^(<dt>SQLITE_DBSTATUS_SCHEMA_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** memory used to store the schema for all databases associated
** with the connection - main, temp, and any [ATTACH]-ed databases.)^
** ^The full amount of memory used by the schemas is reported, even if the
** schema memory is shared with other database connections due to
** [shared cache mode] being enabled.
** ^The highwater mark associated with SQLITE_DBSTATUS_SCHEMA_USED is always 0.
**
** [[SQLITE_DBSTATUS_STMT_USED]] ^(<dt>SQLITE_DBSTATUS_STMT_USED</dt>
** <dd>This parameter returns the approximate number of bytes of heap
** and lookaside memory used by all prepared statements associated with
** the database connection.)^
** ^The highwater mark associated with SQLITE_DBSTATUS_STMT_USED is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_HIT]] ^(<dt>SQLITE_DBSTATUS_CACHE_HIT</dt>
** <dd>This parameter returns the number of pager cache hits that have
** occurred.)^ ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_HIT
** is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_MISS]] ^(<dt>SQLITE_DBSTATUS_CACHE_MISS</dt>
** <dd>This parameter returns the number of pager cache misses that have
** occurred.)^ ^The highwater mark associated with SQLITE_DBSTATUS_CACHE_MISS
** is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_WRITE]] ^(<dt>SQLITE_DBSTATUS_CACHE_WRITE</dt>
** <dd>This parameter returns the number of dirty cache entries that have
** been written to disk. Specifically, the number of pages written to the
** wal file in wal mode databases, or the number of pages written to the
** database file in rollback mode databases. Any pages written as part of
** transaction rollback or database recovery operations are not included.
** If an IO or other error occurs while writing a page to disk, the effect
** on subsequent SQLITE_DBSTATUS_CACHE_WRITE requests is undefined.)^ ^The
** highwater mark associated with SQLITE_DBSTATUS_CACHE_WRITE is always 0.
** </dd>
**
** [[SQLITE_DBSTATUS_CACHE_SPILL]] ^(<dt>SQLITE_DBSTATUS_CACHE_SPILL</dt>
** <dd>This parameter returns the number of dirty cache entries that have
** been written to disk in the middle of a transaction due to the page
** cache overflowing. Transactions are more efficient if they are written
** to disk all at once. When pages spill mid-transaction, that introduces
** additional overhead. This parameter can be used help identify
** inefficiencies that can be resolved by increasing the cache size.
** </dd>
**
** [[SQLITE_DBSTATUS_DEFERRED_FKS]] ^(<dt>SQLITE_DBSTATUS_DEFERRED_FKS</dt>
** <dd>This parameter returns zero for the current value if and only if
** all foreign key constraints (deferred or immediate) have been
** resolved.)^  ^The highwater mark is always 0.
** </dd>
** </dl>
*/
/*line: 8591*/  SQLITE_DBSTATUS_LOOKASIDE_USED = 0x0,  // 0
/*line: 8592*/  SQLITE_DBSTATUS_CACHE_USED = 0x1,  // 1
/*line: 8593*/  SQLITE_DBSTATUS_SCHEMA_USED = 0x2,  // 2
/*line: 8594*/  SQLITE_DBSTATUS_STMT_USED = 0x3,  // 3
/*line: 8595*/  SQLITE_DBSTATUS_LOOKASIDE_HIT = 0x4,  // 4
/*line: 8596*/  SQLITE_DBSTATUS_LOOKASIDE_MISS_SIZE = 0x5,  // 5
/*line: 8597*/  SQLITE_DBSTATUS_LOOKASIDE_MISS_FULL = 0x6,  // 6
/*line: 8598*/  SQLITE_DBSTATUS_CACHE_HIT = 0x7,  // 7
/*line: 8599*/  SQLITE_DBSTATUS_CACHE_MISS = 0x8,  // 8
/*line: 8600*/  SQLITE_DBSTATUS_CACHE_WRITE = 0x9,  // 9
/*line: 8601*/  SQLITE_DBSTATUS_DEFERRED_FKS = 0xa,  // 10
/*line: 8602*/  SQLITE_DBSTATUS_CACHE_USED_SHARED = 0xb,  // 11
/*line: 8603*/  SQLITE_DBSTATUS_CACHE_SPILL = 0xc,  // 12
/*line: 8604*/  SQLITE_DBSTATUS_MAX = 0xc, /* Largest defined DBSTATUS */ // 12
};

enum macro_stmt_status {
/*
** CAPI3REF: Status Parameters for prepared statements
** KEYWORDS: {SQLITE_STMTSTATUS counter} {SQLITE_STMTSTATUS counters}
**
** These preprocessor macros define integer codes that name counter
** values associated with the [sqlite3_stmt_status()] interface.
** The meanings of the various counters are as follows:
**
** <dl>
** [[SQLITE_STMTSTATUS_FULLSCAN_STEP]] <dt>SQLITE_STMTSTATUS_FULLSCAN_STEP</dt>
** <dd>^This is the number of times that SQLite has stepped forward in
** a table as part of a full table scan.  Large numbers for this counter
** may indicate opportunities for performance improvement through
** careful use of indices.</dd>
**
** [[SQLITE_STMTSTATUS_SORT]] <dt>SQLITE_STMTSTATUS_SORT</dt>
** <dd>^This is the number of sort operations that have occurred.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance through careful use of indices.</dd>
**
** [[SQLITE_STMTSTATUS_AUTOINDEX]] <dt>SQLITE_STMTSTATUS_AUTOINDEX</dt>
** <dd>^This is the number of rows inserted into transient indices that
** were created automatically in order to help joins run faster.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance by adding permanent indices that do not
** need to be reinitialized each time the statement is run.</dd>
**
** [[SQLITE_STMTSTATUS_VM_STEP]] <dt>SQLITE_STMTSTATUS_VM_STEP</dt>
** <dd>^This is the number of virtual machine operations executed
** by the prepared statement if that number is less than or equal
** to 2147483647.  The number of virtual machine operations can be
** used as a proxy for the total work done by the prepared statement.
** If the number of virtual machine operations exceeds 2147483647
** then the value returned by this statement status code is undefined.
**
** [[SQLITE_STMTSTATUS_REPREPARE]] <dt>SQLITE_STMTSTATUS_REPREPARE</dt>
** <dd>^This is the number of times that the prepare statement has been
** automatically regenerated due to schema changes or changes to
** [bound parameters] that might affect the query plan.
**
** [[SQLITE_STMTSTATUS_RUN]] <dt>SQLITE_STMTSTATUS_RUN</dt>
** <dd>^This is the number of times that the prepared statement has
** been run.  A single "run" for the purposes of this counter is one
** or more calls to [sqlite3_step()] followed by a call to [sqlite3_reset()].
** The counter is incremented on the first [sqlite3_step()] call of each
** cycle.
**
** [[SQLITE_STMTSTATUS_FILTER_MISS]]
** [[SQLITE_STMTSTATUS_FILTER HIT]]
** <dt>SQLITE_STMTSTATUS_FILTER_HIT<br>
** SQLITE_STMTSTATUS_FILTER_MISS</dt>
** <dd>^SQLITE_STMTSTATUS_FILTER_HIT is the number of times that a join
** step was bypassed because a Bloom filter returned not-found.  The
** corresponding SQLITE_STMTSTATUS_FILTER_MISS value is the number of
** times that the Bloom filter returned a find, and thus the join step
** had to be processed as normal.
**
** [[SQLITE_STMTSTATUS_MEMUSED]] <dt>SQLITE_STMTSTATUS_MEMUSED</dt>
** <dd>^This is the approximate number of bytes of heap memory
** used to store the prepared statement.  ^This value is not actually
** a counter, and so the resetFlg parameter to sqlite3_stmt_status()
** is ignored when the opcode is SQLITE_STMTSTATUS_MEMUSED.
** </dd>
** </dl>
*/
/*line: 8698*/  SQLITE_STMTSTATUS_FULLSCAN_STEP = 0x1,  // 1
/*line: 8699*/  SQLITE_STMTSTATUS_SORT = 0x2,  // 2
/*line: 8700*/  SQLITE_STMTSTATUS_AUTOINDEX = 0x3,  // 3
/*line: 8701*/  SQLITE_STMTSTATUS_VM_STEP = 0x4,  // 4
/*line: 8702*/  SQLITE_STMTSTATUS_REPREPARE = 0x5,  // 5
/*line: 8703*/  SQLITE_STMTSTATUS_RUN = 0x6,  // 6
/*line: 8704*/  SQLITE_STMTSTATUS_FILTER_MISS = 0x7,  // 7
/*line: 8705*/  SQLITE_STMTSTATUS_FILTER_HIT = 0x8,  // 8
/*line: 8706*/  SQLITE_STMTSTATUS_MEMUSED = 0x63,  // 99
};

enum macro_checkpoint_mode {
/*
** CAPI3REF: Checkpoint Mode Values
** KEYWORDS: {checkpoint mode}
**
** These constants define all valid values for the "checkpoint mode" passed
** as the third parameter to the [sqlite3_wal_checkpoint_v2()] interface.
** See the [sqlite3_wal_checkpoint_v2()] documentation for details on the
** meaning of each of these checkpoint modes.
*/
/*line: 9434*/  SQLITE_CHECKPOINT_PASSIVE = 0x0, /* Do as much as possible w/o blocking */ // 0
/*line: 9435*/  SQLITE_CHECKPOINT_FULL = 0x1, /* Wait for writers, then checkpoint */ // 1
/*line: 9436*/  SQLITE_CHECKPOINT_RESTART = 0x2, /* Like FULL but wait for readers */ // 2
/*line: 9437*/  SQLITE_CHECKPOINT_TRUNCATE = 0x3, /* Like RESTART but also truncate WAL */ // 3
};

enum macro_vtab_config_options {
/*
** CAPI3REF: Virtual Table Configuration Options
** KEYWORDS: {virtual table configuration options}
** KEYWORDS: {virtual table configuration option}
**
** These macros define the various options to the
** [sqlite3_vtab_config()] interface that [virtual table] implementations
** can use to customize and optimize their behavior.
**
** <dl>
** [[SQLITE_VTAB_CONSTRAINT_SUPPORT]]
** <dt>SQLITE_VTAB_CONSTRAINT_SUPPORT</dt>
** <dd>Calls of the form
** [sqlite3_vtab_config](db,SQLITE_VTAB_CONSTRAINT_SUPPORT,X) are supported,
** where X is an integer.  If X is zero, then the [virtual table] whose
** [xCreate] or [xConnect] method invoked [sqlite3_vtab_config()] does not
** support constraints.  In this configuration (which is the default) if
** a call to the [xUpdate] method returns [SQLITE_CONSTRAINT], then the entire
** statement is rolled back as if [ON CONFLICT | OR ABORT] had been
** specified as part of the users SQL statement, regardless of the actual
** ON CONFLICT mode specified.
**
** If X is non-zero, then the virtual table implementation guarantees
** that if [xUpdate] returns [SQLITE_CONSTRAINT], it will do so before
** any modifications to internal or persistent data structures have been made.
** If the [ON CONFLICT] mode is ABORT, FAIL, IGNORE or ROLLBACK, SQLite
** is able to roll back a statement or database transaction, and abandon
** or continue processing the current SQL statement as appropriate.
** If the ON CONFLICT mode is REPLACE and the [xUpdate] method returns
** [SQLITE_CONSTRAINT], SQLite handles this as if the ON CONFLICT mode
** had been ABORT.
**
** Virtual table implementations that are required to handle OR REPLACE
** must do so within the [xUpdate] method. If a call to the
** [sqlite3_vtab_on_conflict()] function indicates that the current ON
** CONFLICT policy is REPLACE, the virtual table implementation should
** silently replace the appropriate rows within the xUpdate callback and
** return SQLITE_OK. Or, if this is not possible, it may return
** SQLITE_CONSTRAINT, in which case SQLite falls back to OR ABORT
** constraint handling.
** </dd>
**
** [[SQLITE_VTAB_DIRECTONLY]]<dt>SQLITE_VTAB_DIRECTONLY</dt>
** <dd>Calls of the form
** [sqlite3_vtab_config](db,SQLITE_VTAB_DIRECTONLY) from within the
** the [xConnect] or [xCreate] methods of a [virtual table] implementation
** prohibits that virtual table from being used from within triggers and
** views.
** </dd>
**
** [[SQLITE_VTAB_INNOCUOUS]]<dt>SQLITE_VTAB_INNOCUOUS</dt>
** <dd>Calls of the form
** [sqlite3_vtab_config](db,SQLITE_VTAB_INNOCUOUS) from within the
** the [xConnect] or [xCreate] methods of a [virtual table] implementation
** identify that virtual table as being safe to use from within triggers
** and views.  Conceptually, the SQLITE_VTAB_INNOCUOUS tag means that the
** virtual table can do no serious harm even if it is controlled by a
** malicious hacker.  Developers should avoid setting the SQLITE_VTAB_INNOCUOUS
** flag unless absolutely necessary.
** </dd>
**
** [[SQLITE_VTAB_USES_ALL_SCHEMAS]]<dt>SQLITE_VTAB_USES_ALL_SCHEMAS</dt>
** <dd>Calls of the form
** [sqlite3_vtab_config](db,SQLITE_VTAB_USES_ALL_SCHEMA) from within the
** the [xConnect] or [xCreate] methods of a [virtual table] implementation
** instruct the query planner to begin at least a read transaction on
** all schemas ("main", "temp", and any ATTACH-ed databases) whenever the
** virtual table is used.
** </dd>
** </dl>
*/
/*line: 9531*/  SQLITE_VTAB_CONSTRAINT_SUPPORT = 0x1,  // 1
/*line: 9532*/  SQLITE_VTAB_INNOCUOUS = 0x2,  // 2
/*line: 9533*/  SQLITE_VTAB_DIRECTONLY = 0x3,  // 3
/*line: 9534*/  SQLITE_VTAB_USES_ALL_SCHEMAS = 0x4,  // 4
};

enum macro_conflict_resolution {
/*
** CAPI3REF: Conflict resolution modes
** KEYWORDS: {conflict resolution mode}
**
** These constants are returned by [sqlite3_vtab_on_conflict()] to
** inform a [virtual table] implementation what the [ON CONFLICT] mode
** is for the SQL statement being evaluated.
**
** Note that the [SQLITE_IGNORE] constant is also used as a potential
** return value from the [sqlite3_set_authorizer()] callback and that
** [SQLITE_ABORT] is also a [result code].
*/
/*line: 9866*/  SQLITE_ROLLBACK = 0x1,  // 1
/* #define SQLITE_IGNORE 2 // Also used by sqlite3_authorizer() callback */
/*line: 9868*/  SQLITE_FAIL = 0x3,  // 3
/* #define SQLITE_ABORT 4  // Also an error code */
/*line: 9870*/  SQLITE_REPLACE = 0x5,  // 5
};

enum macro_scan_status_options {
/*
** CAPI3REF: Prepared Statement Scan Status Opcodes
** KEYWORDS: {scanstatus options}
**
** The following constants can be used for the T parameter to the
** [sqlite3_stmt_scanstatus(S,X,T,V)] interface.  Each constant designates a
** different metric for sqlite3_stmt_scanstatus() to return.
**
** When the value returned to V is a string, space to hold that string is
** managed by the prepared statement S and will be automatically freed when
** S is finalized.
**
** Not all values are available for all query elements. When a value is
** not available, the output variable is set to -1 if the value is numeric,
** or to NULL if it is a string (SQLITE_SCANSTAT_NAME).
**
** <dl>
** [[SQLITE_SCANSTAT_NLOOP]] <dt>SQLITE_SCANSTAT_NLOOP</dt>
** <dd>^The [sqlite3_int64] variable pointed to by the V parameter will be
** set to the total number of times that the X-th loop has run.</dd>
**
** [[SQLITE_SCANSTAT_NVISIT]] <dt>SQLITE_SCANSTAT_NVISIT</dt>
** <dd>^The [sqlite3_int64] variable pointed to by the V parameter will be set
** to the total number of rows examined by all iterations of the X-th loop.</dd>
**
** [[SQLITE_SCANSTAT_EST]] <dt>SQLITE_SCANSTAT_EST</dt>
** <dd>^The "double" variable pointed to by the V parameter will be set to the
** query planner's estimate for the average number of rows output from each
** iteration of the X-th loop.  If the query planner's estimates was accurate,
** then this value will approximate the quotient NVISIT/NLOOP and the
** product of this value for all prior loops with the same SELECTID will
** be the NLOOP value for the current loop.
**
** [[SQLITE_SCANSTAT_NAME]] <dt>SQLITE_SCANSTAT_NAME</dt>
** <dd>^The "const char *" variable pointed to by the V parameter will be set
** to a zero-terminated UTF-8 string containing the name of the index or table
** used for the X-th loop.
**
** [[SQLITE_SCANSTAT_EXPLAIN]] <dt>SQLITE_SCANSTAT_EXPLAIN</dt>
** <dd>^The "const char *" variable pointed to by the V parameter will be set
** to a zero-terminated UTF-8 string containing the [EXPLAIN QUERY PLAN]
** description for the X-th loop.
**
** [[SQLITE_SCANSTAT_SELECTID]] <dt>SQLITE_SCANSTAT_SELECTID</dt>
** <dd>^The "int" variable pointed to by the V parameter will be set to the
** id for the X-th query plan element. The id value is unique within the
** statement. The select-id is the same value as is output in the first
** column of an [EXPLAIN QUERY PLAN] query.
**
** [[SQLITE_SCANSTAT_PARENTID]] <dt>SQLITE_SCANSTAT_PARENTID</dt>
** <dd>The "int" variable pointed to by the V parameter will be set to the
** the id of the parent of the current query element, if applicable, or
** to zero if the query element has no parent. This is the same value as
** returned in the second column of an [EXPLAIN QUERY PLAN] query.
**
** [[SQLITE_SCANSTAT_NCYCLE]] <dt>SQLITE_SCANSTAT_NCYCLE</dt>
** <dd>The sqlite3_int64 output value is set to the number of cycles,
** according to the processor time-stamp counter, that elapsed while the
** query element was being processed. This value is not available for
** all query elements - if it is unavailable the output variable is
** set to -1.
** </dl>
*/
/*line: 9935*/  SQLITE_SCANSTAT_NLOOP = 0x0,  // 0
/*line: 9936*/  SQLITE_SCANSTAT_NVISIT = 0x1,  // 1
/*line: 9937*/  SQLITE_SCANSTAT_EST = 0x2,  // 2
/*line: 9938*/  SQLITE_SCANSTAT_NAME = 0x3,  // 3
/*line: 9939*/  SQLITE_SCANSTAT_EXPLAIN = 0x4,  // 4
/*line: 9940*/  SQLITE_SCANSTAT_SELECTID = 0x5,  // 5
/*line: 9941*/  SQLITE_SCANSTAT_PARENTID = 0x6,  // 6
/*line: 9942*/  SQLITE_SCANSTAT_NCYCLE = 0x7,  // 7
};

enum macro_scan_status_flags {
/*
** CAPI3REF: Prepared Statement Scan Status
** KEYWORDS: {scan status flags}
*/
/*line: 10002*/ SQLITE_SCANSTAT_COMPLEX = 0x1,  // 0x0001
};

enum macro_serialize_flags {
/*
** CAPI3REF: Flags for sqlite3_serialize
**
** Zero or more of the following constants can be OR-ed together for
** the F argument to [sqlite3_serialize(D,S,P,F)].
**
** SQLITE_SERIALIZE_NOCOPY means that [sqlite3_serialize()] will return
** a pointer to contiguous in-memory database that it is currently using,
** without making a copy of the database.  If SQLite is not currently using
** a contiguous in-memory database, then this option causes
** [sqlite3_serialize()] to return a NULL pointer.  SQLite will only be
** using a contiguous in-memory database if it has been initialized by a
** prior call to [sqlite3_deserialize()].
*/
/*line: 10302*/ SQLITE_SERIALIZE_NOCOPY = 0x1, /* Do no memory allocations */ // 0x001
};

enum macro_deserialize_flags {
/*
** CAPI3REF: Flags for sqlite3_deserialize()
**
** The following are allowed values for 6th argument (the F argument) to
** the [sqlite3_deserialize(D,S,P,N,M,F)] interface.
**
** The SQLITE_DESERIALIZE_FREEONCLOSE means that the database serialization
** in the P argument is held in memory obtained from [sqlite3_malloc64()]
** and that SQLite should take ownership of this memory and automatically
** free it when it has finished using it.  Without this flag, the caller
** is responsible for freeing any dynamically allocated memory.
**
** The SQLITE_DESERIALIZE_RESIZEABLE flag means that SQLite is allowed to
** grow the size of the database using calls to [sqlite3_realloc64()].  This
** flag should only be used if SQLITE_DESERIALIZE_FREEONCLOSE is also used.
** Without this flag, the deserialized database cannot increase in size beyond
** the number of bytes specified by the M parameter.
**
** The SQLITE_DESERIALIZE_READONLY flag means that the deserialized database
** should be treated as read-only.
*/
/*line: 10368*/ SQLITE_DESERIALIZE_FREEONCLOSE = 0x1, /* Call sqlite3_free() on close */ // 1
/*line: 10369*/ SQLITE_DESERIALIZE_RESIZEABLE = 0x2, /* Resize using sqlite3_realloc64() */ // 2
/*line: 10370*/ SQLITE_DESERIALIZE_READONLY = 0x4, /* Database is read-only */ // 4
};

enum macro_rtree_within {
/*
** Allowed values for sqlite3_rtree_query.eWithin and .eParentWithin.
*/
/*line: 10486*/ NOT_WITHIN = 0x0, /* Object completely outside of query region */ // 0
/*line: 10487*/ PARTLY_WITHIN = 0x1, /* Object partially overlaps query region */ // 1
/*line: 10488*/ FULLY_WITHIN = 0x2, /* Object fully contained within query region */ // 2
};

enum macro_fts5_tokenize_flags {
/* Flags that may be passed as the third argument to xTokenize() */
/*line: 11017*/ FTS5_TOKENIZE_QUERY = 0x1,  // 0x0001
/*line: 11018*/ FTS5_TOKENIZE_PREFIX = 0x2,  // 0x0002
/*line: 11019*/ FTS5_TOKENIZE_DOCUMENT = 0x4,  // 0x0004
/*line: 11020*/ FTS5_TOKENIZE_AUX = 0x8,  // 0x0008
};

enum macro_fts5_token_flags {
/* Flags that may be passed by the tokenizer implementation back to FTS5
** as the third argument to the supplied xToken callback. */
/*line: 11024*/ FTS5_TOKEN_COLOCATED = 0x1, /* Same position as prev. token */ // 0x0001
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 64
// #define SQLITE_EXTERN extern

// Line: 76
// #define SQLITE_STDCALL SQLITE_APICALL

// Line: 104
// #define SQLITE_AVAILABLE __API_AVAILABLE

// Line: 105
// #define SQLITE_DEPRECATED_NO_REPLACEMENT __API_DEPRECATED

// Line: 106
// #define SQLITE_DEPRECATED_WITH_REPLACEMENT __API_DEPRECATED_WITH_REPLACEMENT

