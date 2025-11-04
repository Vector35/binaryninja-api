// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/port.h

// Depends on identifiers
enum macro_port_state {
/*
 *  MACH_PORT_NULL is a legal value that can be carried in messages.
 *  It indicates the absence of any port or port rights.  (A port
 *  argument keeps the message from being "simple", even if the
 *  value is MACH_PORT_NULL.)  The value MACH_PORT_DEAD is also a legal
 *  value that can be carried in messages.  It indicates
 *  that a port right was present, but it died.
 */
/*line: 141*/   MACH_PORT_NULL = 0x0, /* intentional loose typing */ // 0
/*line: 142*/   MACH_PORT_DEAD = -0x1,  // ((mach_port_name_t)~0)
};

// Depends on identifiers
enum macro_port_rights {
/*line: 190*/   MACH_PORT_RIGHT_SEND = 0x0,  // ((mach_port_right_t)0)
/*line: 191*/   MACH_PORT_RIGHT_RECEIVE = 0x1,  // ((mach_port_right_t)1)
/*line: 192*/   MACH_PORT_RIGHT_SEND_ONCE = 0x2,  // ((mach_port_right_t)2)
/*line: 193*/   MACH_PORT_RIGHT_PORT_SET = 0x3,  // ((mach_port_right_t)3)
/*line: 194*/   MACH_PORT_RIGHT_DEAD_NAME = 0x4,  // ((mach_port_right_t)4)
/*line: 195*/   MACH_PORT_RIGHT_LABELH = 0x5, /* obsolete right */ // ((mach_port_right_t)5)
/*line: 196*/   MACH_PORT_RIGHT_NUMBER = 0x6, /* right not implemented */ // ((mach_port_right_t)6)
};

// Depends on identifiers
enum macro_port_type {
/*line: 205*/   MACH_PORT_TYPE_NONE = 0x0,  // ((mach_port_type_t)0L)
/*line: 206*/   MACH_PORT_TYPE_SEND = 0x0,  // MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND)
/*line: 207*/   MACH_PORT_TYPE_RECEIVE = 0x1,  // MACH_PORT_TYPE(MACH_PORT_RIGHT_RECEIVE)
/*line: 208*/   MACH_PORT_TYPE_SEND_ONCE = 0x2,  // MACH_PORT_TYPE(MACH_PORT_RIGHT_SEND_ONCE)
/*line: 209*/   MACH_PORT_TYPE_PORT_SET = 0x3,  // MACH_PORT_TYPE(MACH_PORT_RIGHT_PORT_SET)
/*line: 210*/   MACH_PORT_TYPE_DEAD_NAME = 0x4,  // MACH_PORT_TYPE(MACH_PORT_RIGHT_DEAD_NAME)
/*line: 211*/   MACH_PORT_TYPE_LABELH = 0x5, /* obsolete */ // MACH_PORT_TYPE(MACH_PORT_RIGHT_LABELH)
/* Dummy type bits that mach_port_type/mach_port_names can return. */
/*line: 213*/   MACH_PORT_TYPE_DNREQUEST = 0x80000000,  // 0x80000000
/*line: 214*/   MACH_PORT_TYPE_SPREQUEST = 0x40000000,  // 0x40000000
/*line: 215*/   MACH_PORT_TYPE_SPREQUEST_DELAYED = 0x20000000,  // 0x20000000
/* Convenient combinations. */
/*line: 219*/   MACH_PORT_TYPE_SEND_RECEIVE = 0x1,  // (MACH_PORT_TYPE_SEND|MACH_PORT_TYPE_RECEIVE)
/*line: 221*/   MACH_PORT_TYPE_SEND_RIGHTS = 0x2,  // (MACH_PORT_TYPE_SEND|MACH_PORT_TYPE_SEND_ONCE)
/*line: 223*/   MACH_PORT_TYPE_PORT_RIGHTS = 0x3,  // (MACH_PORT_TYPE_SEND_RIGHTS|MACH_PORT_TYPE_RECEIVE)
/*line: 225*/   MACH_PORT_TYPE_PORT_OR_DEAD = 0x7,  // (MACH_PORT_TYPE_PORT_RIGHTS|MACH_PORT_TYPE_DEAD_NAME)
/*line: 227*/   MACH_PORT_TYPE_ALL_RIGHTS = 0x7,  // (MACH_PORT_TYPE_PORT_OR_DEAD|MACH_PORT_TYPE_PORT_SET)
};

enum macro_send_rights {
/*
 *	Are there outstanding send rights for a given port?
 */
/*line: 245*/   MACH_PORT_SRIGHTS_NONE = 0x0, /* no srights */ // 0
/*line: 246*/   MACH_PORT_SRIGHTS_PRESENT = 0x1, /* srights */ // 1
};

// Depends on identifiers
enum macro_port_queue_limit {
/* System-wide values for setting queue limits on a port */
/*line: 263*/   MACH_PORT_QLIMIT_ZERO = 0x0,  // (0)
/*line: 264*/   MACH_PORT_QLIMIT_BASIC = 0x5,  // (5)
/*line: 265*/   MACH_PORT_QLIMIT_SMALL = 0x10,  // (16)
/*line: 266*/   MACH_PORT_QLIMIT_LARGE = 0x400,  // (1024)
/*line: 267*/   MACH_PORT_QLIMIT_KERNEL = 0xfffe,  // (65534)
/*line: 268*/   MACH_PORT_QLIMIT_MIN = 0x0,  // MACH_PORT_QLIMIT_ZERO
/*line: 269*/   MACH_PORT_QLIMIT_DEFAULT = 0x5,  // MACH_PORT_QLIMIT_BASIC
/*line: 270*/   MACH_PORT_QLIMIT_MAX = 0x400,  // MACH_PORT_QLIMIT_LARGE
};

enum macro_port_status_flags {
/* Possible values for mps_flags (part of mach_port_status_t) */
/*line: 277*/   MACH_PORT_STATUS_FLAG_TEMPOWNER = 0x1,  // 0x01
/*line: 278*/   MACH_PORT_STATUS_FLAG_GUARDED = 0x2,  // 0x02
/*line: 279*/   MACH_PORT_STATUS_FLAG_STRICT_GUARD = 0x4,  // 0x04
/*line: 280*/   MACH_PORT_STATUS_FLAG_IMP_DONATION = 0x8,  // 0x08
/*line: 281*/   MACH_PORT_STATUS_FLAG_REVIVE = 0x10,  // 0x10
/*line: 282*/   MACH_PORT_STATUS_FLAG_TASKPTR = 0x20,  // 0x20
/*line: 283*/   MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE = 0x40,  // 0x40
/*line: 284*/   MACH_PORT_STATUS_FLAG_NO_GRANT = 0x80,  // 0x80
};

enum macro_port_flavor {
/*line: 300*/   MACH_PORT_LIMITS_INFO = 0x1, /* uses mach_port_limits_t */ // 1
/*line: 301*/   MACH_PORT_RECEIVE_STATUS = 0x2, /* uses mach_port_status_t */ // 2
/*line: 302*/   MACH_PORT_DNREQUESTS_SIZE = 0x3, /* info is int */ // 3
/*line: 303*/   MACH_PORT_TEMPOWNER = 0x4, /* indicates receive right will be reassigned to another task */ // 4
/*line: 304*/   MACH_PORT_IMPORTANCE_RECEIVER = 0x5, /* indicates recieve right accepts priority donation */ // 5
/*line: 305*/   MACH_PORT_DENAP_RECEIVER = 0x6, /* indicates receive right accepts de-nap donation */ // 6
/*line: 306*/   MACH_PORT_INFO_EXT = 0x7, /* uses mach_port_info_ext_t */ // 7
/*line: 307*/   MACH_PORT_GUARD_INFO = 0x8, /* asserts if the strict guard value is correct */ // 8
/*line: 308*/   MACH_PORT_SERVICE_THROTTLED = 0x9, /* info is an integer that indicates if service port is throttled or not */ // 9
/*line: 314*/   MACH_PORT_DNREQUESTS_SIZE_COUNT = 0x1,  // 1
/*line: 319*/   MACH_PORT_SERVICE_THROTTLED_COUNT = 0x1,  // 1
};

enum macro_port_name_length {
/*
 * Structure used to pass information about the service port
 */
/*line: 335*/   MACH_SERVICE_PORT_INFO_STRING_NAME_MAX_BUF_LEN = 0xff, /* Maximum length of the port string name buffer */ // 255
};

enum macro_port_options {
/*
 * Flags for mach_port_options (used for
 * invocation of mach_port_construct).
 * Indicates attributes to be set for the newly
 * allocated port.
 */
/*line: 353*/   MPO_CONTEXT_AS_GUARD = 0x1, /* Add guard to the port */ // 0x01
/*line: 354*/   MPO_QLIMIT = 0x2, /* Set qlimit for the port msg queue */ // 0x02
/*line: 355*/   MPO_TEMPOWNER = 0x4, /* Set the tempowner bit of the port */ // 0x04
/*line: 356*/   MPO_IMPORTANCE_RECEIVER = 0x8, /* Mark the port as importance receiver */ // 0x08
/*line: 357*/   MPO_INSERT_SEND_RIGHT = 0x10, /* Insert a send right for the port */ // 0x10
/*line: 358*/   MPO_STRICT = 0x20, /* Apply strict guarding for port */ // 0x20
/*line: 359*/   MPO_DENAP_RECEIVER = 0x40, /* Mark the port as App de-nap receiver */ // 0x40
/*line: 360*/   MPO_IMMOVABLE_RECEIVE = 0x80, /* Mark the port as immovable; protected by the guard context */ // 0x80
/*line: 361*/   MPO_FILTER_MSG = 0x100, /* Allow message filtering */ // 0x100
/*line: 362*/   MPO_TG_BLOCK_TRACKING = 0x200, /* Track blocking relationship for thread group during sync IPC */ // 0x200
/*line: 363*/   MPO_SERVICE_PORT = 0x400, /* Create a service port with the given name; should be used only by launchd */ // 0x400
/*line: 364*/   MPO_CONNECTION_PORT = 0x800, /* Derive new peer connection port from a given service port */ // 0x800
/*line: 365*/   MPO_REPLY_PORT = 0x1000, /* Designate port as a reply port. */ // 0x1000
/*line: 366*/   MPO_ENFORCE_REPLY_PORT_SEMANTICS = 0x2000, /* When talking to this port, local port of mach msg needs to follow reply port semantics.*/ // 0x2000
/*line: 367*/   MPO_PROVISIONAL_REPLY_PORT = 0x4000, /* Designate port as a provisional reply port. */ // 0x4000
/*line: 368*/   MPO_EXCEPTION_PORT = 0x8000, /* Used for hardened exceptions - immovable */ // 0x8000
};

enum macro_guard_type {
/*
 * EXC_GUARD represents a guard violation for both
 * mach ports and file descriptors. GUARD_TYPE_ is used
 * to differentiate among them.
 */
/*line: 395*/   GUARD_TYPE_MACH_PORT = 0x1,  // 0x1
};

enum macro_port_guard_flags {
/*
 * Flags for mach_port_guard_with_flags. These flags extend
 * the attributes associated with a guarded port.
 */
/*line: 476*/   MPG_STRICT = 0x1, /* Apply strict guarding for a port */ // 0x01
/*line: 477*/   MPG_IMMOVABLE_RECEIVE = 0x2, /* Receive right cannot be moved out of the space */ // 0x02
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 310
// #define MACH_PORT_LIMITS_INFO_COUNT ((natural_t) \
// 	(sizeof(mach_port_limits_t)/sizeof(natural_t)))

// Line: 312
// #define MACH_PORT_RECEIVE_STATUS_COUNT ((natural_t) \
// 	(sizeof(mach_port_status_t)/sizeof(natural_t)))

// Line: 315
// #define MACH_PORT_INFO_EXT_COUNT ((natural_t) \
// 	(sizeof(mach_port_info_ext_t)/sizeof(natural_t)))

// Line: 317
// #define MACH_PORT_GUARD_INFO_COUNT ((natural_t) \
// 	(sizeof(mach_port_guard_info_t)/sizeof(natural_t)))

// Line: 342
// #define MACH_SERVICE_PORT_INFO_COUNT ((char) \
// 	(sizeof(mach_service_port_info_data_t)/sizeof(char)))

// Line: 442
// #define MAX_FATAL_kGUARD_EXC_CODE kGUARD_EXC_MSG_FILTERED

// Line: 443
// #define MAX_OPTIONAL_kGUARD_EXC_CODE kGUARD_EXC_RCV_INVALID_NAME

// Line: 448
// #define MPG_FLAGS_NONE (0x00ull)

// Line: 453
// #define MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_DISP (0x01ull << 56)

// Line: 454
// #define MPG_FLAGS_STRICT_REPLY_INVALID_REPLY_PORT (0x02ull << 56)

// Line: 455
// #define MPG_FLAGS_STRICT_REPLY_INVALID_VOUCHER (0x04ull << 56)

// Line: 456
// #define MPG_FLAGS_STRICT_REPLY_NO_BANK_ATTR (0x08ull << 56)

// Line: 457
// #define MPG_FLAGS_STRICT_REPLY_MISMATCHED_PERSONA (0x10ull << 56)

// Line: 458
// #define MPG_FLAGS_STRICT_REPLY_MASK (0xffull << 56)

// Line: 463
// #define MPG_FLAGS_MOD_REFS_PINNED_DEALLOC (0x01ull << 56)

// Line: 464
// #define MPG_FLAGS_MOD_REFS_PINNED_DESTROY (0x02ull << 56)

// Line: 465
// #define MPG_FLAGS_MOD_REFS_PINNED_COPYIN (0x04ull << 56)

// Line: 470
// #define MPG_FLAGS_IMMOVABLE_PINNED (0x01ull << 56)

