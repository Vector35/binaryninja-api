// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/uvernum.h

enum macro_icu_major_version {
/** The current ICU major version as an integer.
 *  This value will change in the subsequent releases of ICU
 *  @stable ICU 2.4
 */
/*line: 56*/    U_ICU_VERSION_MAJOR_NUM = 0x4c,  // 76
};

enum macro_icu_minor {
/** The current ICU minor version as an integer.
 *  This value will change in the subsequent releases of ICU
 *  @stable ICU 2.6
 */
/*line: 62*/    U_ICU_VERSION_MINOR_NUM = 0x1,  // 1
};

enum macro_icu_patchlevel {
/** The current ICU patchlevel version as an integer.
 *  This value will change in the subsequent releases of ICU
 *  @stable ICU 2.4
 */
/*line: 68*/    U_ICU_VERSION_PATCHLEVEL_NUM = 0x0,  // 0
};

enum macro_icu_buildlevel {
/*line: 75*/    U_ICU_VERSION_BUILDLEVEL_NUM = 0x0,  // 0
};

enum macro_disable_version_suffix {
/*line: 105*/   U_DISABLE_VERSION_SUFFIX = 0x0,  // 0
};

enum macro_collation_runtime_version {
/**
 * Collation runtime version (sort key generator, strcoll).
 * If the version is different, sort keys for the same string could be different.
 * This value may change in subsequent releases of ICU.
 * @stable ICU 2.4
 */
/*line: 170*/   UCOL_RUNTIME_VERSION = 0x9,  // 9
};

enum macro_ucol_builder_version {
/**
 * Collation builder code version.
 * When this is different, the same tailoring might result
 * in assigning different collation elements to code points.
 * This value may change in subsequent releases of ICU.
 * @stable ICU 2.4
 */
/*line: 179*/   UCOL_BUILDER_VERSION = 0x9,  // 9
};

enum macro_ucol_tailorings_version {
/**
 * Constant 1.
 * This was intended to be the version of collation tailorings,
 * but instead the tailoring data carries a version number.
 * @deprecated ICU 54
 */
/*line: 188*/   UCOL_TAILORINGS_VERSION = 0x1,  // 1
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 82
// #define U_ICU_VERSION_SUFFIX _76

