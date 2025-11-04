// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/fat.h

enum macro_fat_magic {
/*line: 54*/    FAT_MAGIC = 0xcafebabe,  // 0xcafebabe
/*line: 55*/    FAT_CIGAM = 0xbebafeca, /* NXSwapLong(FAT_MAGIC) */ // 0xbebafeca
/*
 * The support for the 64-bit fat file format described here is a work in
 * progress and not yet fully supported in all the Apple Developer Tools.
 *
 * When a slice is greater than 4mb or an offset to a slice is greater than 4mb
 * then the 64-bit fat file format is used.
 */
/*line: 77*/    FAT_MAGIC_64 = 0xcafebabf,  // 0xcafebabf
/*line: 78*/    FAT_CIGAM_64 = 0xbfbafeca, /* NXSwapLong(FAT_MAGIC_64) */ // 0xbfbafeca
};

