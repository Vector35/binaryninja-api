// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/xpc/connection.h

enum macro_xpc_connection_flags {
/*!
 * @constant XPC_CONNECTION_MACH_SERVICE_LISTENER
 * Passed to xpc_connection_create_mach_service(). This flag indicates that the
 * caller is the listener for the named service. This flag may only be passed
 * for services which are advertised in the process' launchd.plist(5). You may
 * not use this flag to dynamically add services to the Mach bootstrap
 * namespace.
 */
/*line: 104*/   XPC_CONNECTION_MACH_SERVICE_LISTENER = 0x1,  // (1<<0)
/*!
 * @constant XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
 * Passed to xpc_connection_create_mach_service(). This flag indicates that the
 * job advertising the service name in its launchd.plist(5) should be in the
 * privileged Mach bootstrap. This is typically accomplished by placing your
 * launchd.plist(5) in /Library/LaunchDaemons. If specified alongside the
 * XPC_CONNECTION_MACH_SERVICE_LISTENER flag, this flag is a no-op.
 */
/*line: 114*/   XPC_CONNECTION_MACH_SERVICE_PRIVILEGED = 0x2,  // (1<<1)
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 34
// #define XPC_ERROR_CONNECTION_INTERRUPTED XPC_GLOBAL_OBJECT(_xpc_error_connection_interrupted)

// Line: 53
// #define XPC_ERROR_CONNECTION_INVALID XPC_GLOBAL_OBJECT(_xpc_error_connection_invalid)

// Line: 76
// #define XPC_ERROR_TERMINATION_IMMINENT XPC_GLOBAL_OBJECT(_xpc_error_termination_imminent)

// Line: 90
// #define XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT XPC_GLOBAL_OBJECT(_xpc_error_peer_code_signing_requirement)

