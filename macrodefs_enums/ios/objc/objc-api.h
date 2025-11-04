// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/objc/objc-api.h

// This is looks like conditional macros
// enum macro_objc_flags {
// /*line: 68*/    OBJC_API_VERSION = 0x2,  // 2
// /* GC is unsupported. GC API symbols are not exported. */
// /*line: 89*/    OBJC_NO_GC = 0x1,  // 1
// /*line: 90*/    OBJC_NO_GC_API = 0x1,  // 1
// };

// enum macro_ns_enforce_ns_object {
// /*line: 97*/    NS_ENFORCE_NSOBJECT_DESIGNATED_INITIALIZER = 0x1,  // 1
// };

// enum macro_objc_flags {
// /*line: 104*/   OBJC_OLD_DISPATCH_PROTOTYPES = 0x0,  // 0
// };

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 157
// #define OBJC_ISA_AVAILABILITY __attribute__((deprecated))

// Line: 214
// #define OBJC_EXTERN extern

// Line: 223
// #define OBJC_EXPORT OBJC_EXTERN OBJC_VISIBLE

// Line: 227
// #define OBJC_IMPORT extern

// Line: 232
// #define OBJC_ROOT_CLASS __attribute__((objc_root_class))

// Line: 243
// #define OBJC_INLINE __inline

// Line: 288
// #define OBJC_NOESCAPE __attribute__((noescape))

// Line: 298
// #define OBJC_REFINED_FOR_SWIFT __attribute__((swift_private))

// Line: 305
// #define OBJC_NOT_TAIL_CALLED __attribute__((not_tail_called))

