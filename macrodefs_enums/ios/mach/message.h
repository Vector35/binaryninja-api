// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/message.h

// Depends on identifiers
enum macro_no_timeout {
/*
 *  The value to be used when there is no timeout.
 *  (No MACH_SEND_TIMEOUT/MACH_RCV_TIMEOUT option.)
 */
/*line: 104*/   MACH_MSG_TIMEOUT_NONE = 0x0,  // ((mach_msg_timeout_t)0)
};

// Depends on identifiers
enum macro_message_bits {
/*
 *  The kernel uses MACH_MSGH_BITS_COMPLEX as a hint.  If it isn't on, it
 *  assumes the body of the message doesn't contain port rights or OOL
 *  data.  The field is set in received messages.  A user task must
 *  use caution in interpreting the body of a message if the bit isn't
 *  on, because the mach_msg_type's in the body might "lie" about the
 *  contents.  If the bit isn't on, but the mach_msg_types
 *  in the body specify rights or OOL data, the behavior is undefined.
 *  (Ie, an error may or may not be produced.)
 *
 *  The value of MACH_MSGH_BITS_REMOTE determines the interpretation
 *  of the msgh_remote_port field.  It is handled like a msgt_name,
 *  but must result in a send or send-once type right.
 *
 *  The value of MACH_MSGH_BITS_LOCAL determines the interpretation
 *  of the msgh_local_port field.  It is handled like a msgt_name,
 *  and also must result in a send or send-once type right.
 *
 *  The value of MACH_MSGH_BITS_VOUCHER determines the interpretation
 *  of the msgh_voucher_port field.  It is handled like a msgt_name,
 *  but must result in a send right (and the msgh_voucher_port field
 *  must be the name of a send right to a Mach voucher kernel object.
 *
 *  MACH_MSGH_BITS() combines two MACH_MSG_TYPE_* values, for the remote
 *  and local fields, into a single value suitable for msgh_bits.
 *
 *  MACH_MSGH_BITS_CIRCULAR should be zero; is is used internally.
 *
 *  The unused bits should be zero and are reserved for the kernel
 *  or for future interface expansion.
 */
/*line: 138*/   MACH_MSGH_BITS_ZERO = 0x0,  // 0x00000000
/*line: 140*/   MACH_MSGH_BITS_REMOTE_MASK = 0x1f,  // 0x0000001f
/*line: 141*/   MACH_MSGH_BITS_LOCAL_MASK = 0x1f00,  // 0x00001f00
/*line: 142*/   MACH_MSGH_BITS_VOUCHER_MASK = 0x1f0000,  // 0x001f0000
/*line: 144*/   MACH_MSGH_BITS_PORTS_MASK = 0x1f1f1f,  // (MACH_MSGH_BITS_REMOTE_MASK|MACH_MSGH_BITS_LOCAL_MASK|MACH_MSGH_BITS_VOUCHER_MASK)
/*line: 149*/   MACH_MSGH_BITS_COMPLEX = 0x80000000, /* message is complex */ // 0x80000000U
/*line: 151*/   MACH_MSGH_BITS_USER = 0x801f1f1f, /* allowed bits user->kernel */ // 0x801f1f1fU
/*line: 153*/   MACH_MSGH_BITS_RAISEIMP = 0x20000000, /* importance raised due to msg */ // 0x20000000U
/*line: 154*/   MACH_MSGH_BITS_DENAP = 0x20000000,  // MACH_MSGH_BITS_RAISEIMP
/*line: 156*/   MACH_MSGH_BITS_IMPHOLDASRT = 0x10000000, /* assertion help, userland private */ // 0x10000000U
/*line: 157*/   MACH_MSGH_BITS_DENAPHOLDASRT = 0x10000000,  // MACH_MSGH_BITS_IMPHOLDASRT
/*line: 159*/   MACH_MSGH_BITS_CIRCULAR = 0x10000000, /* message circular, kernel private */ // 0x10000000U
/*line: 161*/   MACH_MSGH_BITS_USED = 0xb01f1f1f,  // 0xb01f1f1fU
};

// // Depends on identifiers
// enum macro_msg_size_null {
// /*line: 231*/   MACH_MSG_SIZE_NULL = 0x0,  // (mach_msg_size_t*)0
// };

// Depends on identifiers
enum macro_message_type {
/*line: 235*/   MACH_MSG_PRIORITY_UNSPECIFIED = 0x0,  // (mach_msg_priority_t)0
/*line: 240*/   MACH_MSG_TYPE_MOVE_RECEIVE = 0x10, /* Must hold receive right */ // 16
/*line: 241*/   MACH_MSG_TYPE_MOVE_SEND = 0x11, /* Must hold send right(s) */ // 17
/*line: 242*/   MACH_MSG_TYPE_MOVE_SEND_ONCE = 0x12, /* Must hold sendonce right */ // 18
/*line: 243*/   MACH_MSG_TYPE_COPY_SEND = 0x13, /* Must hold send right(s) */ // 19
/*line: 244*/   MACH_MSG_TYPE_MAKE_SEND = 0x14, /* Must hold receive right */ // 20
/*line: 245*/   MACH_MSG_TYPE_MAKE_SEND_ONCE = 0x15, /* Must hold receive right */ // 21
/*line: 246*/   MACH_MSG_TYPE_COPY_RECEIVE = 0x16, /* NOT VALID */ // 22
/*line: 247*/   MACH_MSG_TYPE_DISPOSE_RECEIVE = 0x18, /* must hold receive right */ // 24
/*line: 248*/   MACH_MSG_TYPE_DISPOSE_SEND = 0x19, /* must hold send right(s) */ // 25
/*line: 249*/   MACH_MSG_TYPE_DISPOSE_SEND_ONCE = 0x1a, /* must hold sendonce right */ // 26
};

enum macro_message_copy_cmd {
/*line: 253*/   MACH_MSG_PHYSICAL_COPY = 0x0,  // 0
/*line: 254*/   MACH_MSG_VIRTUAL_COPY = 0x1,  // 1
/*line: 255*/   MACH_MSG_ALLOCATE = 0x2,  // 2
/*line: 256*/   MACH_MSG_OVERWRITE = 0x3, /* deprecated */ // 3
};

enum macro_message_guard_flags {
/*line: 261*/   MACH_MSG_GUARD_FLAGS_NONE = 0x0,  // 0x0000
/*line: 262*/   MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE = 0x1, /* Move the receive right and mark it as immovable */ // 0x0001
/*line: 263*/   MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND = 0x2, /* Verify that the port is unguarded */ // 0x0002
/*line: 264*/   MACH_MSG_GUARD_FLAGS_MASK = 0x3, /* Valid flag bits */ // 0x0003
};

enum macro_message_descriptor_type {
/*line: 281*/   MACH_MSG_PORT_DESCRIPTOR = 0x0,  // 0
/*line: 282*/   MACH_MSG_OOL_DESCRIPTOR = 0x1,  // 1
/*line: 283*/   MACH_MSG_OOL_PORTS_DESCRIPTOR = 0x2,  // 2
/*line: 284*/   MACH_MSG_OOL_VOLATILE_DESCRIPTOR = 0x3,  // 3
/*line: 285*/   MACH_MSG_GUARDED_PORT_DESCRIPTOR = 0x4,  // 4
/*line: 287*/   MACH_MSG_DESCRIPTOR_MAX = 0x4,  // MACH_MSG_GUARDED_PORT_DESCRIPTOR
};

// Depends on identifiers
enum macro_null_ptr {
/*line: 419*/   MACH_MSG_BODY_NULL = 0x0,  // ((mach_msg_body_t*)0)
/*line: 420*/   MACH_MSG_DESCRIPTOR_NULL = 0x0,  // ((mach_msg_descriptor_t*)0)
/*line: 433*/   MACH_MSG_NULL = 0x0,  // ((mach_msg_header_t*)0)
};

enum macro_msg_trailer_format {
/*line: 443*/   MACH_MSG_TRAILER_FORMAT_0 = 0x0,  // 0
};

// Depends on identifiers
enum macro_mach_msg_filter_policy {
/*line: 532*/   MACH_MSG_FILTER_POLICY_ALLOW = 0x0,  // (mach_msg_filter_id)0
};

// Depends on identifiers
enum macro_mach_message_sizes {
/*
 *  There is no fixed upper bound to the size of Mach messages.
 */
/*line: 614*/   MACH_MSG_SIZE_MAX = -0x1,  // ((mach_msg_size_t)~0)
/*
 *  But architectural limits of a given implementation, or
 *  temporal conditions may cause unpredictable send failures
 *  for messages larger than MACH_MSG_SIZE_RELIABLE.
 *
 *  In either case, waiting for memory is [currently] outside
 *  the scope of send timeout values provided to IPC.
 */
/*line: 625*/   MACH_MSG_SIZE_RELIABLE = 0x40000,  // ((mach_msg_size_t)256*1024)
};

enum macro_mach_message_kind {
/*
 *  Compatibility definitions, for code written
 *  when there was a msgh_kind instead of msgh_seqno.
 */
/*line: 631*/   MACH_MSGH_KIND_NORMAL = 0x0,  // 0x00000000
/*line: 632*/   MACH_MSGH_KIND_NOTIFICATION = 0x1,  // 0x00000001
};

// Depends on identifiers
enum macro_port_type {
/*
 *  Values received/carried in messages.  Tells the receiver what
 *  sort of port right he now has.
 *
 *  MACH_MSG_TYPE_PORT_NAME is used to transfer a port name
 *  which should remain uninterpreted by the kernel.  (Port rights
 *  are not transferred, just the port name.)
 */
/*line: 648*/   MACH_MSG_TYPE_PORT_NONE = 0x0,  // 0
/*line: 650*/   MACH_MSG_TYPE_PORT_NAME = 0xf,  // 15
/*line: 651*/   MACH_MSG_TYPE_PORT_RECEIVE = 0x10,  // MACH_MSG_TYPE_MOVE_RECEIVE
/*line: 652*/   MACH_MSG_TYPE_PORT_SEND = 0x11,  // MACH_MSG_TYPE_MOVE_SEND
/*line: 653*/   MACH_MSG_TYPE_PORT_SEND_ONCE = 0x12,  // MACH_MSG_TYPE_MOVE_SEND_ONCE
/*line: 655*/   MACH_MSG_TYPE_LAST = 0x16, /* Last assigned */ // 22
};

// Depends on identifiers
enum macro_mach_message_options {
/*
 *  A dummy value.  Mostly used to indicate that the actual value
 *  will be filled in later, dynamically.
 */
/*line: 662*/   MACH_MSG_TYPE_POLYMORPHIC = -0x1,  // ((mach_msg_type_name_t)-1)
/*line: 686*/   MACH_MSG_OPTION_NONE = 0x0,  // 0x00000000
/*line: 688*/   MACH_SEND_MSG = 0x1,  // 0x00000001
/*line: 689*/   MACH_RCV_MSG = 0x2,  // 0x00000002
/*line: 691*/   MACH_RCV_LARGE = 0x4, /* report large message sizes */ // 0x00000004
/*line: 692*/   MACH_RCV_LARGE_IDENTITY = 0x8, /* identify source of large messages */ // 0x00000008
/*line: 694*/   MACH_SEND_TIMEOUT = 0x10, /* timeout value applies to send */ // 0x00000010
/*line: 695*/   MACH_SEND_OVERRIDE = 0x20, /* priority override for send */ // 0x00000020
/*line: 696*/   MACH_SEND_INTERRUPT = 0x40, /* don't restart interrupted sends */ // 0x00000040
/*line: 697*/   MACH_SEND_NOTIFY = 0x80, /* arm send-possible notify */ // 0x00000080
/*line: 698*/   MACH_SEND_ALWAYS = 0x10000, /* ignore qlimits - kernel only */ // 0x00010000
/*line: 699*/   MACH_SEND_FILTER_NONFATAL = 0x10000, /* rejection by message filter should return failure - user only */ // 0x00010000
/*line: 700*/   MACH_SEND_TRAILER = 0x20000, /* sender-provided trailer */ // 0x00020000
/*line: 701*/   MACH_SEND_NOIMPORTANCE = 0x40000, /* msg won't carry importance */ // 0x00040000
/*line: 702*/   MACH_SEND_NODENAP = 0x40000,  // MACH_SEND_NOIMPORTANCE
/*line: 703*/   MACH_SEND_IMPORTANCE = 0x80000, /* msg carries importance - kernel only */ // 0x00080000
/*line: 704*/   MACH_SEND_SYNC_OVERRIDE = 0x100000, /* msg should do sync IPC override (on legacy kernels) */ // 0x00100000
/*line: 705*/   MACH_SEND_PROPAGATE_QOS = 0x200000, /* IPC should propagate the caller's QoS */ // 0x00200000
/*line: 706*/   MACH_SEND_SYNC_USE_THRPRI = 0x200000, /* obsolete name */ // MACH_SEND_PROPAGATE_QOS
/*line: 707*/   MACH_SEND_KERNEL = 0x400000, /* full send from kernel space - kernel only */ // 0x00400000
/*line: 708*/   MACH_SEND_SYNC_BOOTSTRAP_CHECKIN = 0x800000, /* special reply port should boost thread doing sync bootstrap checkin */ // 0x00800000
};

enum macro_receive_flags {
/*line: 710*/   MACH_RCV_TIMEOUT = 0x100, /* timeout value applies to receive */ // 0x00000100
/*line: 711*/   MACH_RCV_NOTIFY = 0x0, /* legacy name (value was: 0x00000200) */ // 0x00000000
/*line: 712*/   MACH_RCV_INTERRUPT = 0x400, /* don't restart interrupted receive */ // 0x00000400
/*line: 713*/   MACH_RCV_VOUCHER = 0x800, /* willing to receive voucher port */ // 0x00000800
/*line: 714*/   MACH_RCV_OVERWRITE = 0x0, /* scatter receive (deprecated) */ // 0x00000000
/*line: 715*/   MACH_RCV_GUARDED_DESC = 0x1000, /* Can receive new guarded descriptor */ // 0x00001000
/*line: 716*/   MACH_RCV_SYNC_WAIT = 0x4000, /* sync waiter waiting for rcv */ // 0x00004000
/*line: 717*/   MACH_RCV_SYNC_PEEK = 0x8000, /* sync waiter waiting to peek */ // 0x00008000
};

enum macro_strict_reply {
/*line: 719*/   MACH_MSG_STRICT_REPLY = 0x200, /* Enforce specific properties about the reply port, and
	                                         * the context in which a thread replies to a message.
	                                         * This flag must be passed on both the SEND and RCV */ // 0x00000200
};

enum macro_rcv_trailer_flags {
/*
 * NOTE: a 0x00------ RCV mask implies to ask for
 * a MACH_MSG_TRAILER_FORMAT_0 with 0 Elements,
 * which is equivalent to a mach_msg_trailer_t.
 *
 * XXXMAC: unlike the rest of the MACH_RCV_* flags, MACH_RCV_TRAILER_LABELS
 * needs its own private bit since we only calculate its fields when absolutely
 * required.
 */
/*line: 733*/   MACH_RCV_TRAILER_NULL = 0x0,  // 0
/*line: 734*/   MACH_RCV_TRAILER_SEQNO = 0x1,  // 1
/*line: 735*/   MACH_RCV_TRAILER_SENDER = 0x2,  // 2
/*line: 736*/   MACH_RCV_TRAILER_AUDIT = 0x3,  // 3
/*line: 737*/   MACH_RCV_TRAILER_CTX = 0x4,  // 4
/*line: 738*/   MACH_RCV_TRAILER_AV = 0x7,  // 7
/*line: 739*/   MACH_RCV_TRAILER_LABELS = 0x8,  // 8
};

enum macro_rcv_trailer_mask {
/*line: 743*/   MACH_RCV_TRAILER_MASK = 0xf000000,  // ((0xf<<24))
};

enum macro_mach_message_errors {
/*line: 789*/   MACH_MSG_SUCCESS = 0x0,  // 0x00000000
/*line: 792*/   MACH_MSG_MASK = 0x3e00,  // 0x00003e00
/* All special error code bits defined below. */
/*line: 794*/   MACH_MSG_IPC_SPACE = 0x2000,  // 0x00002000
/* No room in IPC name space for another capability name. */
/*line: 796*/   MACH_MSG_VM_SPACE = 0x1000,  // 0x00001000
/* No room in VM address space for out-of-line memory. */
/*line: 798*/   MACH_MSG_IPC_KERNEL = 0x800,  // 0x00000800
/* Kernel resource shortage handling an IPC capability. */
/*line: 800*/   MACH_MSG_VM_KERNEL = 0x400,  // 0x00000400
/* Kernel resource shortage handling out-of-line memory. */
/*line: 803*/   MACH_SEND_IN_PROGRESS = 0x10000001,  // 0x10000001
/* Thread is waiting to send.  (Internal use only.) */
/*line: 805*/   MACH_SEND_INVALID_DATA = 0x10000002,  // 0x10000002
/* Bogus in-line data. */
/*line: 807*/   MACH_SEND_INVALID_DEST = 0x10000003,  // 0x10000003
/* Bogus destination port. */
/*line: 809*/   MACH_SEND_TIMED_OUT = 0x10000004,  // 0x10000004
/* Message not sent before timeout expired. */
/*line: 811*/   MACH_SEND_INVALID_VOUCHER = 0x10000005,  // 0x10000005
/* Bogus voucher port. */
/*line: 813*/   MACH_SEND_INTERRUPTED = 0x10000007,  // 0x10000007
/* Software interrupt. */
/*line: 815*/   MACH_SEND_MSG_TOO_SMALL = 0x10000008,  // 0x10000008
/* Data doesn't contain a complete message. */
/*line: 817*/   MACH_SEND_INVALID_REPLY = 0x10000009,  // 0x10000009
/* Bogus reply port. */
/*line: 819*/   MACH_SEND_INVALID_RIGHT = 0x1000000a,  // 0x1000000a
/* Bogus port rights in the message body. */
/*line: 821*/   MACH_SEND_INVALID_NOTIFY = 0x1000000b,  // 0x1000000b
/* Bogus notify port argument. */
/*line: 823*/   MACH_SEND_INVALID_MEMORY = 0x1000000c,  // 0x1000000c
/* Invalid out-of-line memory pointer. */
/*line: 825*/   MACH_SEND_NO_BUFFER = 0x1000000d,  // 0x1000000d
/* No message buffer is available. */
/*line: 827*/   MACH_SEND_TOO_LARGE = 0x1000000e,  // 0x1000000e
/* Send is too large for port */
/*line: 829*/   MACH_SEND_INVALID_TYPE = 0x1000000f,  // 0x1000000f
/* Invalid msg-type specification. */
/*line: 831*/   MACH_SEND_INVALID_HEADER = 0x10000010,  // 0x10000010
/* A field in the header had a bad value. */
/*line: 833*/   MACH_SEND_INVALID_TRAILER = 0x10000011,  // 0x10000011
/* The trailer to be sent does not match kernel format. */
/*line: 835*/   MACH_SEND_INVALID_CONTEXT = 0x10000012,  // 0x10000012
/* The sending thread context did not match the context on the dest port */
/*line: 837*/   MACH_SEND_INVALID_OPTIONS = 0x10000013,  // 0x10000013
/* Send options are invalid. */
/*line: 839*/   MACH_SEND_INVALID_RT_OOL_SIZE = 0x10000015,  // 0x10000015
/* compatibility: no longer a returned error */
/*line: 841*/   MACH_SEND_NO_GRANT_DEST = 0x10000016,  // 0x10000016
/* The destination port doesn't accept ports in body */
/*line: 843*/   MACH_SEND_MSG_FILTERED = 0x10000017,  // 0x10000017
/* Message send was rejected by message filter */
/*line: 845*/   MACH_SEND_AUX_TOO_SMALL = 0x10000018,  // 0x10000018
/* Message auxiliary data is too small */
/*line: 847*/   MACH_SEND_AUX_TOO_LARGE = 0x10000019,  // 0x10000019
/* Message auxiliary data is too large */
/*line: 850*/   MACH_RCV_IN_PROGRESS = 0x10004001,  // 0x10004001
/* Thread is waiting for receive.  (Internal use only.) */
/*line: 852*/   MACH_RCV_INVALID_NAME = 0x10004002,  // 0x10004002
/* Bogus name for receive port/port-set. */
/*line: 854*/   MACH_RCV_TIMED_OUT = 0x10004003,  // 0x10004003
/* Didn't get a message within the timeout value. */
/*line: 856*/   MACH_RCV_TOO_LARGE = 0x10004004,  // 0x10004004
/* Message buffer is not large enough for inline data. */
/*line: 858*/   MACH_RCV_INTERRUPTED = 0x10004005,  // 0x10004005
/* Software interrupt. */
/*line: 860*/   MACH_RCV_PORT_CHANGED = 0x10004006,  // 0x10004006
/* compatibility: no longer a returned error */
/*line: 862*/   MACH_RCV_INVALID_NOTIFY = 0x10004007,  // 0x10004007
/* Bogus notify port argument. */
/*line: 864*/   MACH_RCV_INVALID_DATA = 0x10004008,  // 0x10004008
/* Bogus message buffer for inline data. */
/*line: 866*/   MACH_RCV_PORT_DIED = 0x10004009,  // 0x10004009
/* Port/set was sent away/died during receive. */
/*line: 868*/   MACH_RCV_IN_SET = 0x1000400a,  // 0x1000400a
/* compatibility: no longer a returned error */
/*line: 870*/   MACH_RCV_HEADER_ERROR = 0x1000400b,  // 0x1000400b
/* Error receiving message header.  See special bits. */
/*line: 872*/   MACH_RCV_BODY_ERROR = 0x1000400c,  // 0x1000400c
/* Error receiving message body.  See special bits. */
/*line: 874*/   MACH_RCV_INVALID_TYPE = 0x1000400d,  // 0x1000400d
/* Invalid msg-type specification in scatter list. */
/*line: 876*/   MACH_RCV_SCATTER_SMALL = 0x1000400e,  // 0x1000400e
/* Out-of-line overwrite region is not large enough */
/*line: 878*/   MACH_RCV_INVALID_TRAILER = 0x1000400f,  // 0x1000400f
/* trailer type or number of trailer elements not supported */
/*line: 880*/   MACH_RCV_IN_PROGRESS_TIMED = 0x10004011,  // 0x10004011
/* Waiting for receive with timeout. (Internal use only.) */
/*line: 882*/   MACH_RCV_INVALID_REPLY = 0x10004012,  // 0x10004012
/* invalid reply port used in a STRICT_REPLY message */
/*line: 884*/   MACH_RCV_INVALID_ARGUMENTS = 0x10004013,  // 0x10004013
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 432
// #define msgh_reserved msgh_voucher_port

// Line: 504
// #define INVALID_AUDIT_TOKEN_VALUE {{ \
// 	UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX, \
// 	UINT_MAX, UINT_MAX, UINT_MAX, UINT_MAX }}

// Line: 551
// #define MACH_MSG_TRAILER_MINIMUM_SIZE sizeof(mach_msg_trailer_t)

// Line: 564
// #define MAX_TRAILER_SIZE ((mach_msg_size_t)sizeof(mach_msg_max_trailer_t))

// Line: 578
// #define MACH_MSG_TRAILER_FORMAT_0_SIZE sizeof(mach_msg_format_0_trailer_t)

// Line: 580
// #define KERNEL_SECURITY_TOKEN_VALUE { {0, 1} }

// Line: 583
// #define KERNEL_AUDIT_TOKEN_VALUE { {0, 0, 0, 0, 0, 0, 0, 0} }

// Line: 588
// #define MACH_MSG_HEADER_EMPTY (mach_msg_header_t){ }

// Line: 633
// #define msgh_kind msgh_seqno

// Line: 634
// #define mach_msg_kind_t mach_port_seqno_t

