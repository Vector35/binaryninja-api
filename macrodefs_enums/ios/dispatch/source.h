// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dispatch/source.h

enum macro_dispatch_send_dead {
/*!
 * @typedef dispatch_source_mach_send_flags_t
 * Type of dispatch_source_mach_send flags
 *
 * @constant DISPATCH_MACH_SEND_DEAD
 * The receive right corresponding to the given send right was destroyed.
 */
/*line: 220*/   DISPATCH_MACH_SEND_DEAD = 0x1,  // 0x1
};

enum macro_dispatch_source_flags {
/*!
 * @typedef dispatch_source_memorypressure_flags_t
 * Type of dispatch_source_memorypressure flags
 *
 * @constant DISPATCH_MEMORYPRESSURE_NORMAL
 * The system memory pressure condition has returned to normal.
 *
 * @constant DISPATCH_MEMORYPRESSURE_WARN
 * The system memory pressure condition has changed to warning.
 *
 * @constant DISPATCH_MEMORYPRESSURE_CRITICAL
 * The system memory pressure condition has changed to critical.
 *
 * @discussion
 * Elevated memory pressure is a system-wide condition that applications
 * registered for this source should react to by changing their future memory
 * use behavior, e.g. by reducing cache sizes of newly initiated operations
 * until memory pressure returns back to normal.
 * NOTE: applications should NOT traverse and discard existing caches for past
 * operations when the system memory pressure enters an elevated state, as that
 * is likely to trigger VM operations that will further aggravate system memory
 * pressure.
 */
/*line: 255*/   DISPATCH_MEMORYPRESSURE_NORMAL = 0x1,  // 0x01
/*line: 256*/   DISPATCH_MEMORYPRESSURE_WARN = 0x2,  // 0x02
/*line: 257*/   DISPATCH_MEMORYPRESSURE_CRITICAL = 0x4,  // 0x04
/*!
 * @typedef dispatch_source_proc_flags_t
 * Type of dispatch_source_proc flags
 *
 * @constant DISPATCH_PROC_EXIT
 * The process has exited (perhaps cleanly, perhaps not).
 *
 * @constant DISPATCH_PROC_FORK
 * The process has created one or more child processes.
 *
 * @constant DISPATCH_PROC_EXEC
 * The process has become another executable image via
 * exec*() or posix_spawn*().
 *
 * @constant DISPATCH_PROC_SIGNAL
 * A Unix signal was delivered to the process.
 */
/*line: 279*/   DISPATCH_PROC_EXIT = 0x80000000,  // 0x80000000
/*line: 280*/   DISPATCH_PROC_FORK = 0x40000000,  // 0x40000000
/*line: 281*/   DISPATCH_PROC_EXEC = 0x20000000,  // 0x20000000
/*line: 282*/   DISPATCH_PROC_SIGNAL = 0x8000000,  // 0x08000000
};

enum macro_vnode_flags {
/*!
 * @typedef dispatch_source_vnode_flags_t
 * Type of dispatch_source_vnode flags
 *
 * @constant DISPATCH_VNODE_DELETE
 * The filesystem object was deleted from the namespace.
 *
 * @constant DISPATCH_VNODE_WRITE
 * The filesystem object data changed.
 *
 * @constant DISPATCH_VNODE_EXTEND
 * The filesystem object changed in size.
 *
 * @constant DISPATCH_VNODE_ATTRIB
 * The filesystem object metadata changed.
 *
 * @constant DISPATCH_VNODE_LINK
 * The filesystem object link count changed.
 *
 * @constant DISPATCH_VNODE_RENAME
 * The filesystem object was renamed in the namespace.
 *
 * @constant DISPATCH_VNODE_REVOKE
 * The filesystem object was revoked.
 *
 * @constant DISPATCH_VNODE_FUNLOCK
 * The filesystem object was unlocked.
 */
/*line: 316*/   DISPATCH_VNODE_DELETE = 0x1,  // 0x1
/*line: 317*/   DISPATCH_VNODE_WRITE = 0x2,  // 0x2
/*line: 318*/   DISPATCH_VNODE_EXTEND = 0x4,  // 0x4
/*line: 319*/   DISPATCH_VNODE_ATTRIB = 0x8,  // 0x8
/*line: 320*/   DISPATCH_VNODE_LINK = 0x10,  // 0x10
/*line: 321*/   DISPATCH_VNODE_RENAME = 0x20,  // 0x20
/*line: 322*/   DISPATCH_VNODE_REVOKE = 0x40,  // 0x40
/*line: 323*/   DISPATCH_VNODE_FUNLOCK = 0x100,  // 0x100
};

enum macro_dispatch_timer_strict {
/*!
 * @typedef dispatch_source_timer_flags_t
 * Type of dispatch_source_timer flags
 *
 * @constant DISPATCH_TIMER_STRICT
 * Specifies that the system should make a best effort to strictly observe the
 * leeway value specified for the timer via dispatch_source_set_timer(), even
 * if that value is smaller than the default leeway value that would be applied
 * to the timer otherwise. A minimal amount of leeway will be applied to the
 * timer even if this flag is specified.
 *
 * CAUTION: Use of this flag may override power-saving techniques employed by
 * the system and cause higher power consumption, so it must be used with care
 * and only when absolutely necessary.
 */
/*line: 344*/   DISPATCH_TIMER_STRICT = 0x1,  // 0x1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 83
// #define DISPATCH_SOURCE_TYPE_DATA_ADD (&_dispatch_source_type_data_add)

// Line: 94
// #define DISPATCH_SOURCE_TYPE_DATA_OR (&_dispatch_source_type_data_or)

// Line: 109
// #define DISPATCH_SOURCE_TYPE_DATA_REPLACE (&_dispatch_source_type_data_replace)

// Line: 120
// #define DISPATCH_SOURCE_TYPE_MACH_SEND (&_dispatch_source_type_mach_send)

// Line: 131
// #define DISPATCH_SOURCE_TYPE_MACH_RECV (&_dispatch_source_type_mach_recv)

// Line: 143
// #define DISPATCH_SOURCE_TYPE_MEMORYPRESSURE (&_dispatch_source_type_memorypressure)

// Line: 155
// #define DISPATCH_SOURCE_TYPE_PROC (&_dispatch_source_type_proc)

// Line: 166
// #define DISPATCH_SOURCE_TYPE_READ (&_dispatch_source_type_read)

// Line: 176
// #define DISPATCH_SOURCE_TYPE_SIGNAL (&_dispatch_source_type_signal)

// Line: 187
// #define DISPATCH_SOURCE_TYPE_TIMER (&_dispatch_source_type_timer)

// Line: 198
// #define DISPATCH_SOURCE_TYPE_VNODE (&_dispatch_source_type_vnode)

// Line: 209
// #define DISPATCH_SOURCE_TYPE_WRITE (&_dispatch_source_type_write)

