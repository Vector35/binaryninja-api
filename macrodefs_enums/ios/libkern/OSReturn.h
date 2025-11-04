// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libkern/OSReturn.h

// Depends on identifiers
enum macro_sys_libkern {
/*line: 83*/    sys_libkern = 0x37,  // err_system(0x37)
};

// Depends on identifiers
enum macro_error_subsystem {
/*line: 86*/    sub_libkern_common = 0x0,  // err_sub(0)
/*line: 87*/    sub_libkern_metaclass = 0x1,  // err_sub(1)
/*line: 88*/    sub_libkern_reserved = -0x1,  // err_sub(-1)
};

// Depends on identifiers
enum macro_os_return {
/*!
 * @define   kOSReturnSuccess
 * @abstract Operation successful.
 *           Equal to <code>@link //apple_ref/c/econst/KERN_SUCCESS
 *           KERN_SUCCESS@/link</code>.
 */
/*line: 104*/   kOSReturnSuccess = 0x0,  // KERN_SUCCESS
/*!
 * @define   kOSReturnError
 * @abstract Unspecified Libkern error.
 *           <b>Not equal</b> to
 *           <code>@link //apple_ref/c/econst/KERN_FAILURE
 *           KERN_FAILURE@/link</code>.
 */
/*line: 113*/   kOSReturnError = 0x1,  // libkern_common_err(1)
};

// Depends on identifiers
enum macro_metaclass_errors {
/*!
 * @define   kOSMetaClassInternal
 * @abstract Internal OSMetaClass run-time error.
 */
/*line: 119*/   kOSMetaClassInternal = 0x1,  // libkern_metaclass_err(1)
/*!
 * @define   kOSMetaClassHasInstances
 * @abstract A kext cannot be unloaded because there are instances
 *           derived from Libkern C++ classes that it defines.
 */
/*line: 126*/   kOSMetaClassHasInstances = 0x2,  // libkern_metaclass_err(2)
/*!
 * @define   kOSMetaClassNoInit
 * @abstract Internal error: The Libkern C++ class registration system
 *           was not properly initialized during kext loading.
 */
/*line: 133*/   kOSMetaClassNoInit = 0x3,  // libkern_metaclass_err(3)
/*!
 * @define   kOSMetaClassNoTempData
 * @abstract Internal error: An allocation failure occurred
 *           registering Libkern C++ classes during kext loading.
 */
/*line: 141*/   kOSMetaClassNoTempData = 0x4,  // libkern_metaclass_err(4)
/*!
 * @define   kOSMetaClassNoDicts
 * @abstract Internal error: An allocation failure occurred
 *           registering Libkern C++ classes during kext loading.
 */
/*line: 149*/   kOSMetaClassNoDicts = 0x5,  // libkern_metaclass_err(5)
/*!
 * @define   kOSMetaClassNoKModSet
 * @abstract Internal error: An allocation failure occurred
 *           registering Libkern C++ classes during kext loading.
 */
/*line: 157*/   kOSMetaClassNoKModSet = 0x6,  // libkern_metaclass_err(6)
/*!
 * @define   kOSMetaClassNoInsKModSet
 * @abstract Internal error: An error occurred registering
 *           a specific Libkern C++ class during kext loading.
 */
/*line: 165*/   kOSMetaClassNoInsKModSet = 0x7,  // libkern_metaclass_err(7)
/*!
 * @define   kOSMetaClassNoSuper
 * @abstract Internal error: No superclass can be found
 *           for a specific Libkern C++ class during kext loading.
 */
/*line: 173*/   kOSMetaClassNoSuper = 0x8,  // libkern_metaclass_err(8)
/*!
 * @define   kOSMetaClassInstNoSuper
 * @abstract Internal error: No superclass can be found when constructing
 *           an instance of a Libkern C++ class.
 */
/*line: 180*/   kOSMetaClassInstNoSuper = 0x9,  // libkern_metaclass_err(9)
/*!
 * @define   kOSMetaClassDuplicateClass
 * @abstract A duplicate Libkern C++ classname was encountered
 *           during kext loading.
 */
/*line: 187*/   kOSMetaClassDuplicateClass = 0xa,  // libkern_metaclass_err(10)
/*!
 * @define   kOSMetaClassNoKext
 * @abstract Internal error: The kext for a Libkern C++ class
 *           can't be found during kext loading.
 */
/*line: 194*/   kOSMetaClassNoKext = 0xb,  // libkern_metaclass_err(11)
};

