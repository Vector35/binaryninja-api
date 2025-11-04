// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/cdefs.h

// This whole file is mostly for compilation, so no reason to include in runtime headers
// enum macro_has_safe_buffers {
// /*line: 571*/   __has_safe_buffers = 0x1,  // 1
// };

// enum macro_darwin_flags {
// /* Platform: iPhoneOS */
// /*line: 624*/   __DARWIN_ONLY_64_BIT_INO_T = 0x1,  // 1
// /*line: 625*/   __DARWIN_ONLY_UNIX_CONFORMANCE = 0x1,  // 1
// /*line: 626*/   __DARWIN_ONLY_VERS_1050 = 0x1,  // 1
// };

// enum macro_darwin_unix03 {
// /*line: 651*/   __DARWIN_UNIX03 = 0x1,  // 1
// };

// enum macro_darwin_64_bit_ino_t {
// /*line: 683*/   __DARWIN_64_BIT_INO_T = 0x1,  // 1
// };

// enum macro_darwin_version {
// /*line: 694*/   __DARWIN_VERS_1050 = 0x1,  // 1
// };

// enum macro_darwin_non_cancelable {
// /*line: 703*/   __DARWIN_NON_CANCELABLE = 0x0,  // 0
// };

// enum macro_darwin_source {
// /*
//  * Set a single macro which will always be defined and can be used to determine
//  * the appropriate namespace.  For POSIX, these values will correspond to
//  * _POSIX_C_SOURCE value.  Currently there are two additional levels corresponding
//  * to ANSI (_ANSI_SOURCE) and Darwin extensions (_DARWIN_C_SOURCE)
//  */
// /*line: 848*/   __DARWIN_C_ANSI = 0x1000,  // 010000L
// /*line: 849*/   __DARWIN_C_FULL = 0xdbba0,  // 900000L
// };

// // Depends on identifiers
// enum macro_darwin_c_level {
// /*line: 856*/   __DARWIN_C_LEVEL = 0xdbba0,  // __DARWIN_C_FULL
// };

// enum macro_stdc_want_lib_ext1 {
// /*line: 864*/   __STDC_WANT_LIB_EXT1__ = 0x1,  // 1
// };

// enum macro_darwin_no_long_long {
// /*line: 875*/   __DARWIN_NO_LONG_LONG = 0x0,  // 0
// };

// enum macro_darwin_feature_64_bit_inode {
// /*line: 887*/   _DARWIN_FEATURE_64_BIT_INODE = 0x1,  // 1
// };

// enum macro_darwin_feature {
// /*line: 897*/   _DARWIN_FEATURE_ONLY_64_BIT_INODE = 0x1,  // 1
// };

// enum macro_darwin_feature {
// /*line: 905*/   _DARWIN_FEATURE_ONLY_VERS_1050 = 0x1,  // 1
// };

// enum macro_darwin_features {
// /*line: 913*/   _DARWIN_FEATURE_ONLY_UNIX_CONFORMANCE = 0x1,  // 1
// /*line: 921*/   _DARWIN_FEATURE_UNIX_CONFORMANCE = 0x3,  // 3
// };

// enum macro_abi_compatibility {
// /*
//  * We intentionally define to nothing pointer attributes which do not have an
//  * impact on the ABI. __indexable and __bidi_indexable are not defined because
//  * of the ABI incompatibility that makes the diagnostic preferable.
//  */
// /*line: 968*/   __has_ptrcheck = 0x0,  // 0
// };

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 119
// #define __const const

// Line: 120
// #define __signed signed

// Line: 121
// #define __volatile volatile

// Line: 165
// #define __dead2 __attribute__((__noreturn__))

// Line: 166
// #define __pure2 __attribute__((__const__))

// Line: 167
// #define __stateful_pure __attribute__((__pure__))

// Line: 172
// #define __unused __attribute__((__unused__))

// Line: 177
// #define __used __attribute__((__used__))

// Line: 183
// #define __cold __attribute__((__cold__))

// Line: 190
// #define __returns_nonnull __attribute((returns_nonnull))

// Line: 214
// #define __deprecated __attribute__((__deprecated__))

// Line: 235
// #define __unavailable __attribute__((__unavailable__))

// Line: 257
// #define __restrict restrict

// Line: 290
// #define __disable_tail_calls __attribute__((__disable_tail_calls__))

// Line: 302
// #define __not_tail_called __attribute__((__not_tail_called__))

// Line: 313
// #define __result_use_check __attribute__((__warn_unused_result__))

// Line: 347
// #define __abortlike __dead2 __cold __not_tail_called

// Line: 370
// #define __header_inline inline

// Line: 383
// #define __header_always_inline __header_inline __attribute__ ((__always_inline__))

// Line: 572
// #define __unsafe_buffer_usage __attribute__((__unsafe_buffer_usage__))

// Line: 1013
// #define __ASSUME_PTR_ABI_SINGLE_BEGIN __ptrcheck_abi_assume_single()

// Line: 1014
// #define __ASSUME_PTR_ABI_SINGLE_END __ptrcheck_abi_assume_unsafe_indexable()

// Line: 1038
// #define __enum_open __attribute__((__enum_extensibility__(open)))

// Line: 1039
// #define __enum_closed __attribute__((__enum_extensibility__(closed)))

// Line: 1046
// #define __enum_options __attribute__((__flag_enum__))

