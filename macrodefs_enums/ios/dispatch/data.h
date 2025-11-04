// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dispatch/data.h

// Depends on identifiers
enum macro_data_destructor {
/*!
 * @const DISPATCH_DATA_DESTRUCTOR_DEFAULT
 * @discussion The default destructor for dispatch data objects.
 * Used at data object creation to indicate that the supplied buffer should
 * be copied into internal storage managed by the system.
 */
/*line: 63*/    DISPATCH_DATA_DESTRUCTOR_DEFAULT = 0x0,  // NULL
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 52
// #define dispatch_data_empty DISPATCH_GLOBAL_OBJECT(dispatch_data_t, _dispatch_data_empty)

// Line: 81
// #define DISPATCH_DATA_DESTRUCTOR_FREE (_dispatch_data_destructor_free)

// Line: 91
// #define DISPATCH_DATA_DESTRUCTOR_MUNMAP (_dispatch_data_destructor_munmap)

