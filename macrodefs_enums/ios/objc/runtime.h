// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/objc/runtime.h

enum macro_objc_class_filter {
/**
 * Enumerates classes, filtering by image, name, protocol conformance and superclass.
 *
 * @param image The image to search.  Can be NULL (search the caller's image),
 *              OBJC_DYNAMIC_CLASSES (search dynamically registered classes),
 *              a handle returned by dlopen(3), or the Mach header of an image
 *              loaded into the current process.
 * @param namePrefix If non-NULL, a required prefix for the class name.
 * @param conformingTo If non-NULL, a protocol to which the enumerated classes
 *                     must conform.
 * @param subclassing If non-NULL, a class which the enumerated classes must
 *                    subclass.
 * @param block A block that is called for each matching class.  Can abort
 *              enumeration by setting *stop to YES.
 *
 */
/*line: 363*/   OBJC_DYNAMIC_CLASSES = -0x1,  // ((constvoid*)-1)
};

enum macro_objc_class_hook_defined {
/*line: 1738*/  OBJC_GETCLASSHOOK_DEFINED = 0x1,  // 1
};

enum macro_add_load_image_func {
/**
 * Add a function to be called when a new image is loaded. The function is
 * called after ObjC has scanned and fixed up the image. It is called
 * BEFORE +load methods are invoked.
 *
 * When adding a new function, that function is immediately called with all
 * images that are currently loaded. It is then called as needed for images
 * that are loaded afterwards.
 *
 * Note: the function is called with ObjC's internal runtime lock held.
 * Be VERY careful with what the function does to avoid deadlocks or
 * poor performance.
 *
 * @param func The function to add.
 */
/*line: 1766*/  OBJC_ADDLOADIMAGEFUNC_DEFINED = 0x1,  // 1
};

enum macro_objc_sethook_lazyclassnamer_defined {
/*line: 1795*/  OBJC_SETHOOK_LAZYCLASSNAMER_DEFINED = 0x1,  // 1
};

enum macro_objc_realizeclass {
/*line: 1817*/  OBJC_REALIZECLASSFROMSWIFT_DEFINED = 0x1,  // 1
};

enum macro_type_encoding {
// Type encoding characters
/*line: 1824*/  _C_ID = 0x40,  // '@'
/*line: 1825*/  _C_CLASS = 0x23,  // '#'
/*line: 1826*/  _C_SEL = 0x3a,  // ':'
/*line: 1827*/  _C_CHR = 0x63,  // 'c'
/*line: 1828*/  _C_UCHR = 0x43,  // 'C'
/*line: 1829*/  _C_SHT = 0x73,  // 's'
/*line: 1830*/  _C_USHT = 0x53,  // 'S'
/*line: 1831*/  _C_INT = 0x69,  // 'i'
/*line: 1832*/  _C_UINT = 0x49,  // 'I'
/*line: 1833*/  _C_LNG = 0x6c,  // 'l'
/*line: 1834*/  _C_ULNG = 0x4c,  // 'L'
/*line: 1835*/  _C_LNG_LNG = 0x71,  // 'q'
/*line: 1836*/  _C_ULNG_LNG = 0x51,  // 'Q'
/*line: 1837*/  _C_INT128 = 0x74,  // 't'
/*line: 1838*/  _C_UINT128 = 0x54,  // 'T'
/*line: 1839*/  _C_FLT = 0x66,  // 'f'
/*line: 1840*/  _C_DBL = 0x64,  // 'd'
/*line: 1841*/  _C_LNG_DBL = 0x44,  // 'D'
/*line: 1842*/  _C_BFLD = 0x62,  // 'b'
/*line: 1843*/  _C_BOOL = 0x42,  // 'B'
/*line: 1844*/  _C_VOID = 0x76,  // 'v'
/*line: 1845*/  _C_UNDEF = 0x3f,  // '?'
/*line: 1846*/  _C_PTR = 0x5e,  // '^'
/*line: 1847*/  _C_CHARPTR = 0x2a,  // '*'
/*line: 1848*/  _C_ATOM = 0x25,  // '%'
/*line: 1849*/  _C_ARY_B = 0x5b,  // '['
/*line: 1850*/  _C_ARY_E = 0x5d,  // ']'
/*line: 1851*/  _C_UNION_B = 0x28,  // '('
/*line: 1852*/  _C_UNION_E = 0x29,  // ')'
/*line: 1853*/  _C_STRUCT_B = 0x7b,  // '{'
/*line: 1854*/  _C_STRUCT_E = 0x7d,  // '}'
/*line: 1855*/  _C_VECTOR = 0x21,  // '!'
// Modifiers
/*line: 1858*/  _C_COMPLEX = 0x6a,  // 'j'
/*line: 1859*/  _C_ATOMIC = 0x41,  // 'A'
/*line: 1860*/  _C_CONST = 0x72,  // 'r'
/*line: 1861*/  _C_IN = 0x6e,  // 'n'
/*line: 1862*/  _C_INOUT = 0x4e,  // 'N'
/*line: 1863*/  _C_OUT = 0x6f,  // 'o'
/*line: 1864*/  _C_BYCOPY = 0x4f,  // 'O'
/*line: 1865*/  _C_BYREF = 0x52,  // 'R'
/*line: 1866*/  _C_ONEWAY = 0x56,  // 'V'
/*line: 1867*/  _C_GNUREGISTER = 0x2b,  // '+'
};

