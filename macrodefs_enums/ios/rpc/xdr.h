// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/rpc/xdr.h

enum macro_bytes_per_xdr_unit {
/*
 * This is the number of bytes per unit of external data.
 */
/*line: 112*/   BYTES_PER_XDR_UNIT = 0x4,  // (4)
};

// Depends on identifiers
enum macro_xdr_discriminant {
/*
 * Support struct for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * an entry with a null procedure pointer.  The xdr_union routine gets
 * the discriminant value and then searches the array of structures
 * for a matching value.  If a match is found the associated xdr routine
 * is called to handle that part of the union.  If there is
 * no match, then a default routine may be called.
 * If there is no match and no default routine it is an error.
 */
/*line: 316*/   NULL_xdrproc_t = 0x0,  // ((xdrproc_t)0)
};

enum macro_max_netobj_size {
/*
 * Common opaque bytes objects used by many rpc protocols;
 * declared here due to commonality.
 */
/*line: 417*/   MAX_NETOBJ_SZ = 0x400,  // 1024
};

