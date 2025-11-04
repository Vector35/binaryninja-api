// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/kern_return.h

enum macro_kern_return {
/*line: 72*/    KERN_SUCCESS = 0x0,  // 0
/*line: 74*/    KERN_INVALID_ADDRESS = 0x1,  // 1
/* Specified address is not currently valid.
 */
/*line: 78*/    KERN_PROTECTION_FAILURE = 0x2,  // 2
/* Specified memory is valid, but does not permit the
 * required forms of access.
 */
/*line: 83*/    KERN_NO_SPACE = 0x3,  // 3
/* The address range specified is already in use, or
 * no address range of the size specified could be
 * found.
 */
/*line: 89*/    KERN_INVALID_ARGUMENT = 0x4,  // 4
/* The function requested was not applicable to this
 * type of argument, or an argument is invalid
 */
/*line: 94*/    KERN_FAILURE = 0x5,  // 5
/* The function could not be performed.  A catch-all.
 */
/*line: 98*/    KERN_RESOURCE_SHORTAGE = 0x6,  // 6
/* A system resource could not be allocated to fulfill
 * this request.  This failure may not be permanent.
 */
/*line: 103*/   KERN_NOT_RECEIVER = 0x7,  // 7
/* The task in question does not hold receive rights
 * for the port argument.
 */
/*line: 108*/   KERN_NO_ACCESS = 0x8,  // 8
/* Bogus access restriction.
 */
/*line: 112*/   KERN_MEMORY_FAILURE = 0x9,  // 9
/* During a page fault, the target address refers to a
 * memory object that has been destroyed.  This
 * failure is permanent.
 */
/*line: 118*/   KERN_MEMORY_ERROR = 0xa,  // 10
/* During a page fault, the memory object indicated
 * that the data could not be returned.  This failure
 * may be temporary; future attempts to access this
 * same data may succeed, as defined by the memory
 * object.
 */
/*line: 126*/   KERN_ALREADY_IN_SET = 0xb,  // 11
/* The receive right is already a member of the portset.
 */
/*line: 130*/   KERN_NOT_IN_SET = 0xc,  // 12
/* The receive right is not a member of a port set.
 */
/*line: 134*/   KERN_NAME_EXISTS = 0xd,  // 13
/* The name already denotes a right in the task.
 */
/*line: 138*/   KERN_ABORTED = 0xe,  // 14
/* The operation was aborted.  Ipc code will
 * catch this and reflect it as a message error.
 */
/*line: 143*/   KERN_INVALID_NAME = 0xf,  // 15
/* The name doesn't denote a right in the task.
 */
/*line: 147*/   KERN_INVALID_TASK = 0x10,  // 16
/* Target task isn't an active task.
 */
/*line: 151*/   KERN_INVALID_RIGHT = 0x11,  // 17
/* The name denotes a right, but not an appropriate right.
 */
/*line: 155*/   KERN_INVALID_VALUE = 0x12,  // 18
/* A blatant range error.
 */
/*line: 159*/   KERN_UREFS_OVERFLOW = 0x13,  // 19
/* Operation would overflow limit on user-references.
 */
/*line: 163*/   KERN_INVALID_CAPABILITY = 0x14,  // 20
/* The supplied (port) capability is improper.
 */
/*line: 167*/   KERN_RIGHT_EXISTS = 0x15,  // 21
/* The task already has send or receive rights
 * for the port under another name.
 */
/*line: 172*/   KERN_INVALID_HOST = 0x16,  // 22
/* Target host isn't actually a host.
 */
/*line: 176*/   KERN_MEMORY_PRESENT = 0x17,  // 23
/* An attempt was made to supply "precious" data
 * for memory that is already present in a
 * memory object.
 */
/*line: 182*/   KERN_MEMORY_DATA_MOVED = 0x18,  // 24
/* A page was requested of a memory manager via
 * memory_object_data_request for an object using
 * a MEMORY_OBJECT_COPY_CALL strategy, with the
 * VM_PROT_WANTS_COPY flag being used to specify
 * that the page desired is for a copy of the
 * object, and the memory manager has detected
 * the page was pushed into a copy of the object
 * while the kernel was walking the shadow chain
 * from the copy to the object. This error code
 * is delivered via memory_object_data_error
 * and is handled by the kernel (it forces the
 * kernel to restart the fault). It will not be
 * seen by users.
 */
/*line: 198*/   KERN_MEMORY_RESTART_COPY = 0x19,  // 25
/* A strategic copy was attempted of an object
 * upon which a quicker copy is now possible.
 * The caller should retry the copy using
 * vm_object_copy_quickly. This error code
 * is seen only by the kernel.
 */
/*line: 206*/   KERN_INVALID_PROCESSOR_SET = 0x1a,  // 26
/* An argument applied to assert processor set privilege
 * was not a processor set control port.
 */
/*line: 211*/   KERN_POLICY_LIMIT = 0x1b,  // 27
/* The specified scheduling attributes exceed the thread's
 * limits.
 */
/*line: 216*/   KERN_INVALID_POLICY = 0x1c,  // 28
/* The specified scheduling policy is not currently
 * enabled for the processor set.
 */
/*line: 221*/   KERN_INVALID_OBJECT = 0x1d,  // 29
/* The external memory manager failed to initialize the
 * memory object.
 */
/*line: 226*/   KERN_ALREADY_WAITING = 0x1e,  // 30
/* A thread is attempting to wait for an event for which
 * there is already a waiting thread.
 */
/*line: 231*/   KERN_DEFAULT_SET = 0x1f,  // 31
/* An attempt was made to destroy the default processor
 * set.
 */
/*line: 236*/   KERN_EXCEPTION_PROTECTED = 0x20,  // 32
/* An attempt was made to fetch an exception port that is
 * protected, or to abort a thread while processing a
 * protected exception.
 */
/*line: 242*/   KERN_INVALID_LEDGER = 0x21,  // 33
/* A ledger was required but not supplied.
 */
/*line: 246*/   KERN_INVALID_MEMORY_CONTROL = 0x22,  // 34
/* The port was not a memory cache control port.
 */
/*line: 250*/   KERN_INVALID_SECURITY = 0x23,  // 35
/* An argument supplied to assert security privilege
 * was not a host security port.
 */
/*line: 255*/   KERN_NOT_DEPRESSED = 0x24,  // 36
/* thread_depress_abort was called on a thread which
 * was not currently depressed.
 */
/*line: 260*/   KERN_TERMINATED = 0x25,  // 37
/* Object has been terminated and is no longer available
 */
/*line: 264*/   KERN_LOCK_SET_DESTROYED = 0x26,  // 38
/* Lock set has been destroyed and is no longer available.
 */
/*line: 268*/   KERN_LOCK_UNSTABLE = 0x27,  // 39
/* The thread holding the lock terminated before releasing
 * the lock
 */
/*line: 273*/   KERN_LOCK_OWNED = 0x28,  // 40
/* The lock is already owned by another thread
 */
/*line: 277*/   KERN_LOCK_OWNED_SELF = 0x29,  // 41
/* The lock is already owned by the calling thread
 */
/*line: 281*/   KERN_SEMAPHORE_DESTROYED = 0x2a,  // 42
/* Semaphore has been destroyed and is no longer available.
 */
/*line: 285*/   KERN_RPC_SERVER_TERMINATED = 0x2b,  // 43
/* Return from RPC indicating the target server was
 * terminated before it successfully replied
 */
/*line: 290*/   KERN_RPC_TERMINATE_ORPHAN = 0x2c,  // 44
/* Terminate an orphaned activation.
 */
/*line: 294*/   KERN_RPC_CONTINUE_ORPHAN = 0x2d,  // 45
/* Allow an orphaned activation to continue executing.
 */
/*line: 298*/   KERN_NOT_SUPPORTED = 0x2e,  // 46
/* Empty thread activation (No thread linked to it)
 */
/*line: 302*/   KERN_NODE_DOWN = 0x2f,  // 47
/* Remote node down or inaccessible.
 */
/*line: 306*/   KERN_NOT_WAITING = 0x30,  // 48
/* A signalled thread was not actually waiting. */
/*line: 309*/   KERN_OPERATION_TIMED_OUT = 0x31,  // 49
/* Some thread-oriented operation (semaphore_wait) timed out
 */
/*line: 313*/   KERN_CODESIGN_ERROR = 0x32,  // 50
/* During a page fault, indicates that the page was rejected
 * as a result of a signature check.
 */
/*line: 318*/   KERN_POLICY_STATIC = 0x33,  // 51
/* The requested property cannot be changed at this time.
 */
/*line: 322*/   KERN_INSUFFICIENT_BUFFER_SIZE = 0x34,  // 52
/* The provided buffer is of insufficient size for the requested data.
 */
/*line: 326*/   KERN_DENIED = 0x35,  // 53
/* Denied by security policy
 */
/*line: 330*/   KERN_MISSING_KC = 0x36,  // 54
/* The KC on which the function is operating is missing
 */
/*line: 334*/   KERN_INVALID_KC = 0x37,  // 55
/* The KC on which the function is operating is invalid
 */
/*line: 338*/   KERN_NOT_FOUND = 0x38,  // 56
};

enum macro_kern_return_max {
/* A search or query operation did not return a result
 */
/*line: 342*/   KERN_RETURN_MAX = 0x100,  // 0x100
};

