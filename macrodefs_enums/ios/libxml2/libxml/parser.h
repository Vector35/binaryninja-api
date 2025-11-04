// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libxml/parser.h

enum macro_dtd_flags {
/**
 * XML_DETECT_IDS:
 *
 * Bit in the loadsubset context field to tell to do ID/REFs lookups.
 * Use it to initialize xmlLoadExtDtdDefaultValue.
 */
/*line: 139*/   XML_DETECT_IDS = 0x2,  // 2
/**
 * XML_COMPLETE_ATTRS:
 *
 * Bit in the loadsubset context field to tell to do complete the
 * elements attributes lists with the ones defaulted from the DTDs.
 * Use it to initialize xmlLoadExtDtdDefaultValue.
 */
/*line: 148*/   XML_COMPLETE_ATTRS = 0x4,  // 4
/**
 * XML_SKIP_IDS:
 *
 * Bit in the loadsubset context field to tell to not do ID/REFs registration.
 * Used to initialize xmlLoadExtDtdDefaultValue in some special cases.
 */
/*line: 156*/   XML_SKIP_IDS = 0x8,  // 8
};

enum macro_xml_magic {
/**
 * XML_SAX2_MAGIC:
 *
 * Special constant found in SAX2 blocks initialized fields
 */
/*line: 673*/   XML_SAX2_MAGIC = 0xdeedbeaf,  // 0xDEEDBEAF
};

