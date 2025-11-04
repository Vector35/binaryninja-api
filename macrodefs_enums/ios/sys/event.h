// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/event.h

// Depends on identifiers
enum macro_event_filter {
/*
 * Filter types
 */
/*line: 68*/    EVFILT_READ = -0x1,  // (-1)
/*line: 69*/    EVFILT_WRITE = -0x2,  // (-2)
/*line: 70*/    EVFILT_AIO = -0x3, /* attached to aio requests */ // (-3)
/*line: 71*/    EVFILT_VNODE = -0x4, /* attached to vnodes */ // (-4)
/*line: 72*/    EVFILT_PROC = -0x5, /* attached to struct proc */ // (-5)
/*line: 73*/    EVFILT_SIGNAL = -0x6, /* attached to struct proc */ // (-6)
/*line: 74*/    EVFILT_TIMER = -0x7, /* timers */ // (-7)
/*line: 75*/    EVFILT_MACHPORT = -0x8, /* Mach portsets */ // (-8)
/*line: 76*/    EVFILT_FS = -0x9, /* Filesystem events */ // (-9)
/*line: 77*/    EVFILT_USER = -0xa, /* User events */ // (-10)
/*line: 78*/    EVFILT_VM = -0xc, /* Virtual memory events */ // (-12)
/*line: 79*/    EVFILT_EXCEPT = -0xf, /* Exception events */ // (-15)
/*line: 81*/    EVFILT_SYSCOUNT = 0x12,  // 18
/*line: 82*/    EVFILT_THREADMARKER = 0x12, /* Internal use only */ // EVFILT_SYSCOUNT
};

enum macro_kevent_flags {
/* kevent system call flags */
/*line: 131*/   KEVENT_FLAG_NONE = 0x0, /* no flag value */ // 0x000000
/*line: 132*/   KEVENT_FLAG_IMMEDIATE = 0x1, /* immediate timeout */ // 0x000001
/*line: 133*/   KEVENT_FLAG_ERROR_EVENTS = 0x2, /* output events only include change errors */ // 0x000002
};

// Depends on identifiers
enum macro_event_action {
/* actions */
/*line: 136*/   EV_ADD = 0x1, /* add event to kq (implies enable) */ // 0x0001
/*line: 137*/   EV_DELETE = 0x2, /* delete event from kq */ // 0x0002
/*line: 138*/   EV_ENABLE = 0x4, /* enable event */ // 0x0004
/*line: 139*/   EV_DISABLE = 0x8, /* disable event (not reported) */ // 0x0008
/* flags */
/*line: 142*/   EV_ONESHOT = 0x10, /* only report one occurrence */ // 0x0010
/*line: 143*/   EV_CLEAR = 0x20, /* clear event state after reporting */ // 0x0020
/*line: 144*/   EV_RECEIPT = 0x40, /* force immediate event output */ // 0x0040
/*     on syscalls supporting flags */
/*line: 149*/   EV_DISPATCH = 0x80, /* disable event after reporting */ // 0x0080
/*line: 150*/   EV_UDATA_SPECIFIC = 0x100, /* unique kevent per udata value */ // 0x0100
/*line: 152*/   EV_DISPATCH2 = 0x180,  // (EV_DISPATCH|EV_UDATA_SPECIFIC)
/* returned to indicate the deferral */
/*line: 158*/   EV_VANISHED = 0x200, /* report that source has vanished  */ // 0x0200
/* ... only valid with EV_DISPATCH2 */
/*line: 161*/   EV_SYSFLAGS = 0xf000, /* reserved by system */ // 0xF000
/*line: 162*/   EV_FLAG0 = 0x1000, /* filter-specific flag */ // 0x1000
/*line: 163*/   EV_FLAG1 = 0x2000, /* filter-specific flag */ // 0x2000
};

enum macro_event_retval {
/* returned values */
/*line: 166*/   EV_EOF = 0x8000, /* EOF detected */ // 0x8000
/*line: 167*/   EV_ERROR = 0x4000, /* error, data contains errno */ // 0x4000
};

// Depends on identifiers
enum macro_read_flags {
/*
 * Filter specific flags for EVFILT_READ
 *
 * The default behavior for EVFILT_READ is to make the "read" determination
 * relative to the current file descriptor read pointer.
 *
 * The EV_POLL flag indicates the determination should be made via poll(2)
 * semantics. These semantics dictate always returning true for regular files,
 * regardless of the amount of unread data in the file.
 *
 * On input, EV_OOBAND specifies that filter should actively return in the
 * presence of OOB on the descriptor. It implies that filter will return
 * if there is OOB data available to read OR when any other condition
 * for the read are met (for example number of bytes regular data becomes >=
 * low-watermark).
 * If EV_OOBAND is not set on input, it implies that the filter should not actively
 * return for out of band data on the descriptor. The filter will then only return
 * when some other condition for read is met (ex: when number of regular data bytes
 * >=low-watermark OR when socket can't receive more data (SS_CANTRCVMORE)).
 *
 * On output, EV_OOBAND indicates the presence of OOB data on the descriptor.
 * If it was not specified as an input parameter, then the data count is the
 * number of bytes before the current OOB marker, else data count is the number
 * of bytes beyond OOB marker.
 */
/*line: 194*/   EV_POLL = 0x1000,  // EV_FLAG0
/*line: 195*/   EV_OOBAND = 0x2000,  // EV_FLAG1
};

enum macro_note_trigger {
/*
 * On input, NOTE_TRIGGER causes the event to be triggered for output.
 */
/*line: 204*/   NOTE_TRIGGER = 0x1000000,  // 0x01000000
};

enum macro_fflags_operation {
/*
 * On input, the top two bits of fflags specifies how the lower twenty four
 * bits should be applied to the stored value of fflags.
 *
 * On output, the top two bits will always be set to NOTE_FFNOP and the
 * remaining twenty four bits will contain the stored fflags value.
 */
/*line: 213*/   NOTE_FFNOP = 0x0, /* ignore input fflags */ // 0x00000000
/*line: 214*/   NOTE_FFAND = 0x40000000, /* and fflags */ // 0x40000000
/*line: 215*/   NOTE_FFOR = 0x80000000, /* or fflags */ // 0x80000000
/*line: 216*/   NOTE_FFCOPY = 0xc0000000, /* copy fflags */ // 0xc0000000
/*line: 217*/   NOTE_FFCTRLMASK = 0xc0000000, /* mask for operations */ // 0xc0000000
/*line: 218*/   NOTE_FFLAGSMASK = 0xffffff,  // 0x00ffffff
};

enum macro_event_io_fflags {
/*
 * data/hint fflags for EVFILT_{READ|WRITE}, shared with userspace
 *
 * The default behavior for EVFILT_READ is to make the determination
 * realtive to the current file descriptor read pointer.
 */
/*line: 226*/   NOTE_LOWAT = 0x1, /* low water mark */ // 0x00000001
/* data/hint flags for EVFILT_EXCEPT, shared with userspace */
/*line: 229*/   NOTE_OOB = 0x2, /* OOB data */ // 0x00000002
};

enum macro_vnode_event_flags {
/*
 * data/hint fflags for EVFILT_VNODE, shared with userspace
 */
/*line: 234*/   NOTE_DELETE = 0x1, /* vnode was removed */ // 0x00000001
/*line: 235*/   NOTE_WRITE = 0x2, /* data contents changed */ // 0x00000002
/*line: 236*/   NOTE_EXTEND = 0x4, /* size increased */ // 0x00000004
/*line: 237*/   NOTE_ATTRIB = 0x8, /* attributes changed */ // 0x00000008
/*line: 238*/   NOTE_LINK = 0x10, /* link count changed */ // 0x00000010
/*line: 239*/   NOTE_RENAME = 0x20, /* vnode was renamed */ // 0x00000020
/*line: 240*/   NOTE_REVOKE = 0x40, /* vnode access was revoked */ // 0x00000040
/*line: 241*/   NOTE_NONE = 0x80, /* No specific vnode event: to test for EVFILT_READ activation*/ // 0x00000080
/*line: 242*/   NOTE_FUNLOCK = 0x100, /* vnode was unlocked by flock(2) */ // 0x00000100
/*line: 243*/   NOTE_LEASE_DOWNGRADE = 0x200, /* lease downgrade requested */ // 0x00000200
/*line: 244*/   NOTE_LEASE_RELEASE = 0x400, /* lease release requested */ // 0x00000400
/*line: 260*/   NOTE_EXIT = 0x80000000, /* process exited */ // 0x80000000
/*line: 261*/   NOTE_FORK = 0x40000000, /* process forked */ // 0x40000000
/*line: 262*/   NOTE_EXEC = 0x20000000, /* process exec'd */ // 0x20000000
/*line: 264*/   NOTE_SIGNAL = 0x8000000, /* shared with EVFILT_SIGNAL */ // 0x08000000
/*line: 265*/   NOTE_EXITSTATUS = 0x4000000, /* exit status to be returned, valid for child process or when allowed to signal target pid */ // 0x04000000
/*line: 266*/   NOTE_EXIT_DETAIL = 0x2000000, /* provide details on reasons for exit */ // 0x02000000
};

// Depends on identifiers
enum macro_event_proc_fflags_masks {
/*line: 268*/   NOTE_PDATAMASK = 0xfffff, /* mask for signal & exit status */ // 0x000fffff
/*line: 269*/   NOTE_PCTRLMASK = -0x100000,  // (~NOTE_PDATAMASK)
};

enum macro_event_proc_vm_fflags {
/*
 * If NOTE_EXIT_DETAIL is present, these bits indicate specific reasons for exiting.
 */
/*line: 282*/   NOTE_EXIT_DETAIL_MASK = 0x70000,  // 0x00070000
/*line: 283*/   NOTE_EXIT_DECRYPTFAIL = 0x10000,  // 0x00010000
/*line: 284*/   NOTE_EXIT_MEMORY = 0x20000,  // 0x00020000
/*line: 285*/   NOTE_EXIT_CSERROR = 0x40000,  // 0x00040000
/*
 * data/hint fflags for EVFILT_VM, shared with userspace.
 */
/*line: 290*/   NOTE_VM_PRESSURE = 0x80000000, /* will react on memory pressure */ // 0x80000000
/*line: 291*/   NOTE_VM_PRESSURE_TERMINATE = 0x40000000, /* will quit on memory pressure, possibly after cleaning up dirty state */ // 0x40000000
/*line: 292*/   NOTE_VM_PRESSURE_SUDDEN_TERMINATE = 0x20000000, /* will quit immediately on memory pressure */ // 0x20000000
/*line: 293*/   NOTE_VM_ERROR = 0x10000000, /* there was an error */ // 0x10000000
};

enum macro_timer_flags {
/*
 * data/hint fflags for EVFILT_TIMER, shared with userspace.
 * The default is a (repeating) interval timer with the data
 * specifying the timeout interval in milliseconds.
 *
 * All timeouts are implicitly EV_CLEAR events.
 */
/*line: 302*/   NOTE_SECONDS = 0x1, /* data is seconds         */ // 0x00000001
/*line: 303*/   NOTE_USECONDS = 0x2, /* data is microseconds    */ // 0x00000002
/*line: 304*/   NOTE_NSECONDS = 0x4, /* data is nanoseconds     */ // 0x00000004
/*line: 305*/   NOTE_ABSOLUTE = 0x8, /* absolute timeout        */ // 0x00000008
/* ... implicit EV_ONESHOT, timeout uses the gettimeofday epoch */
/*line: 307*/   NOTE_LEEWAY = 0x10, /* ext[1] holds leeway for power aware timers */ // 0x00000010
/*line: 308*/   NOTE_CRITICAL = 0x20, /* system does minimal timer coalescing */ // 0x00000020
/*line: 309*/   NOTE_BACKGROUND = 0x40, /* system does maximum timer coalescing */ // 0x00000040
/*line: 310*/   NOTE_MACH_CONTINUOUS_TIME = 0x80,  // 0x00000080
/*
 * NOTE_MACH_CONTINUOUS_TIME:
 * with NOTE_ABSOLUTE: causes the timer to continue to tick across sleep,
 *      still uses gettimeofday epoch
 * with NOTE_MACHTIME and NOTE_ABSOLUTE: uses mach continuous time epoch
 * without NOTE_ABSOLUTE (interval timer mode): continues to tick across sleep
 */
/*line: 318*/   NOTE_MACHTIME = 0x100, /* data is mach absolute time units */ // 0x00000100
};

enum macro_process_flags {
/* additional flags for EVFILT_PROC */
/*line: 359*/   NOTE_TRACK = 0x1, /* follow across forks */ // 0x00000001
/*line: 360*/   NOTE_TRACKERR = 0x2, /* could not track child */ // 0x00000002
/*line: 361*/   NOTE_CHILD = 0x4, /* am a child process */ // 0x00000004
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 263
// #define NOTE_REAP ((unsigned int)eNoteReapDeprecated /* 0x10000000 */ )

// Line: 277
// #define NOTE_EXIT_REPARENTED ((unsigned int)eNoteExitReparentedDeprecated)

