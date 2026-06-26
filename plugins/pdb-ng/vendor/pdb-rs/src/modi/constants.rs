//! Constants for all versions of the module info stream.
#![allow(unused)]

/// First explicit signature.
pub const CV_SIGNATURE_C7: u32 = 1;
/// Signature indicating a C11 (VC 5.x) module info stream. Uses 32-bit types.
pub const CV_SIGNATURE_C11: u32 = 2;
/// Signature indicating a C13 (VC 7.x) module info stream. Uses zero terminated names.
pub const CV_SIGNATURE_C13: u32 = 4;

/// Debug subsection kind for empty subsections. Should be skipped.
pub const DEBUG_S_IGNORE: u32 = 0x8000_0000;
/// Flag indicating that column information is present.
pub const CV_LINES_HAVE_COLUMNS: u16 = 0x1;

/// Flag indicating the default format of `DEBUG_S_INLINEELINEINFO`
pub const CV_INLINEE_SOURCE_LINE_SIGNATURE: u32 = 0x0;
/// Flag indicating the extended format of `DEBUG_S_INLINEELINEINFO`
pub const CV_INLINEE_SOURCE_LINE_SIGNATURE_EX: u32 = 0x1;
