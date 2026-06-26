// Copyright 2018 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Definitions for PE headers contained in PDBs.

// PDBs contain PE section headers in one or two streams. `pdb::pe` is responsible for parsing them.

use std::fmt;

use scroll::ctx::TryFromCtx;
use scroll::Endian;

use crate::common::*;

/// The section should not be padded to the next boundary. This flag is
/// obsolete and is replaced by `IMAGE_SCN_ALIGN_1BYTES`.
const IMAGE_SCN_TYPE_NO_PAD: u32 = 0x00000008;
/// The section contains executable code.
const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
/// The section contains initialized data.
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
/// The section contains uninitialized data.
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
/// Reserved.
const IMAGE_SCN_LNK_OTHER: u32 = 0x00000100;
/// The section contains comments or other information. This is valid only for object files.
const IMAGE_SCN_LNK_INFO: u32 = 0x00000200;
/// The section will not become part of the image. This is valid only for object files.
const IMAGE_SCN_LNK_REMOVE: u32 = 0x00000800;
/// The section contains COMDAT data. This is valid only for object files.
const IMAGE_SCN_LNK_COMDAT: u32 = 0x00001000;
/// Reset speculative exceptions handling bits in the TLB entries for this section.
const IMAGE_SCN_NO_DEFER_SPEC_EXC: u32 = 0x00004000;
/// The section contains data referenced through the global pointer.
const IMAGE_SCN_GPREL: u32 = 0x00008000;
/// Reserved.
const IMAGE_SCN_MEM_PURGEABLE: u32 = 0x00020000;
/// Reserved.
const IMAGE_SCN_MEM_LOCKED: u32 = 0x00040000;
/// Reserved.
const IMAGE_SCN_MEM_PRELOAD: u32 = 0x00080000;
/// Align data on a 1-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_1BYTES: u32 = 0x00100000;
/// Align data on a 2-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_2BYTES: u32 = 0x00200000;
/// Align data on a 4-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_4BYTES: u32 = 0x00300000;
/// Align data on a 8-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_8BYTES: u32 = 0x00400000;
/// Align data on a 16-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_16BYTES: u32 = 0x00500000;
/// Align data on a 32-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_32BYTES: u32 = 0x00600000;
/// Align data on a 64-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_64BYTES: u32 = 0x00700000;
/// Align data on a 128-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_128BYTES: u32 = 0x00800000;
/// Align data on a 256-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_256BYTES: u32 = 0x00900000;
/// Align data on a 512-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_512BYTES: u32 = 0x00A00000;
/// Align data on a 1024-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_1024BYTES: u32 = 0x00B00000;
/// Align data on a 2048-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_2048BYTES: u32 = 0x00C00000;
/// Align data on a 4096-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_4096BYTES: u32 = 0x00D00000;
/// Align data on a 8192-byte boundary. This is valid only for object files.
const IMAGE_SCN_ALIGN_8192BYTES: u32 = 0x00E00000;
/// The section contains extended relocations. The count of relocations for the
/// section exceeds the 16 bits that is reserved for it in the section header.
/// If the `number_of_relocations` field in the section header is `0xffff`, the
/// actual relocation count is stored in the `virtual_address` field of the first
/// relocation. It is an error if `IMAGE_SCN_LNK_NRELOC_OVFL` is set and there
/// are fewer than `0xffff` relocations in the section.
const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x01000000;
/// The section can be discarded as needed.
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x02000000;
/// The section cannot be cached.
const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x04000000;
/// The section cannot be paged.
const IMAGE_SCN_MEM_NOT_PAGED: u32 = 0x08000000;
/// The section can be shared in memory.
const IMAGE_SCN_MEM_SHARED: u32 = 0x10000000;
/// The section can be executed as code.
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
/// The section can be read.
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
/// The section can be written to.
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// Characteristic flags of an [`ImageSectionHeader`].
///
/// These are defined by Microsoft as [`IMAGE_SCN_`] constants.
///
/// [`IMAGE_SCN_`]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
#[derive(Clone, Copy, Eq, Default, PartialEq)]
pub struct SectionCharacteristics(pub u32);

impl SectionCharacteristics {
    /// The section contains executable code.
    pub fn executable(self) -> bool {
        (self.0 & IMAGE_SCN_CNT_CODE) > 0
    }

    /// The section contains initialized data.
    pub fn initialized_data(self) -> bool {
        (self.0 & IMAGE_SCN_CNT_INITIALIZED_DATA) > 0
    }

    /// The section contains uninitialized data.
    pub fn uninitialized_data(self) -> bool {
        (self.0 & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0
    }

    /// Reserved.
    pub fn other(self) -> bool {
        (self.0 & IMAGE_SCN_LNK_OTHER) > 0
    }

    /// The section contains comments or other information. This is valid only for object files.
    pub fn info(self) -> bool {
        (self.0 & IMAGE_SCN_LNK_INFO) > 0
    }

    /// The section will not become part of the image. This is valid only for object files.
    pub fn remove(self) -> bool {
        (self.0 & IMAGE_SCN_LNK_REMOVE) > 0
    }

    /// The section contains COMDAT data. This is valid only for object files.
    pub fn comdat(self) -> bool {
        (self.0 & IMAGE_SCN_LNK_COMDAT) > 0
    }

    /// Reset speculative exceptions handling bits in the TLB entries for this section.
    pub fn defer_speculative_exceptions(self) -> bool {
        (self.0 & IMAGE_SCN_NO_DEFER_SPEC_EXC) > 0
    }

    /// The section contains data referenced through the global pointer.
    pub fn global_pointer_relative(self) -> bool {
        (self.0 & IMAGE_SCN_GPREL) > 0
    }

    /// Reserved.
    pub fn purgeable(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_PURGEABLE) > 0
    }

    /// Reserved.
    pub fn locked(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_LOCKED) > 0
    }

    /// Reserved.
    pub fn preload(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_PRELOAD) > 0
    }

    /// Alignment for section data.
    ///
    /// This is valid only for object files. Returns `Some` if alignment is specified, and `None` if
    /// no alignment is specified. An alignment of `Some(1)` means that the section should not be
    /// padded to a boundary.
    pub fn alignment(self) -> Option<u16> {
        // Mask covering all align values and IMAGE_SCN_TYPE_NO_PAD.
        match self.0 & 0x00F00008 {
            self::IMAGE_SCN_ALIGN_1BYTES => Some(1),
            self::IMAGE_SCN_ALIGN_2BYTES => Some(2),
            self::IMAGE_SCN_ALIGN_4BYTES => Some(4),
            self::IMAGE_SCN_ALIGN_8BYTES => Some(8),
            self::IMAGE_SCN_ALIGN_16BYTES => Some(16),
            self::IMAGE_SCN_ALIGN_32BYTES => Some(32),
            self::IMAGE_SCN_ALIGN_64BYTES => Some(64),
            self::IMAGE_SCN_ALIGN_128BYTES => Some(128),
            self::IMAGE_SCN_ALIGN_256BYTES => Some(256),
            self::IMAGE_SCN_ALIGN_512BYTES => Some(512),
            self::IMAGE_SCN_ALIGN_1024BYTES => Some(1024),
            self::IMAGE_SCN_ALIGN_2048BYTES => Some(2048),
            self::IMAGE_SCN_ALIGN_4096BYTES => Some(4096),
            self::IMAGE_SCN_ALIGN_8192BYTES => Some(8192),
            self::IMAGE_SCN_TYPE_NO_PAD => Some(1),
            _ => None,
        }
    }

    /// The section contains extended relocations.
    ///
    /// The count of relocations for the section exceeds the 16 bits that is reserved for it in the
    /// section header. If the [`number_of_relocations`](ImageSectionHeader::number_of_relocations)
    /// field in the section header is `0xffff`, the actual relocation count is stored in the
    /// `virtual_address` field of the first relocation. It is an error if this flag is set and
    /// there are fewer than `0xffff` relocations in the section.
    pub fn lnk_nreloc_ovfl(self) -> bool {
        (self.0 & IMAGE_SCN_LNK_NRELOC_OVFL) > 0
    }

    /// The section can be discarded as needed.
    pub fn discardable(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_DISCARDABLE) > 0
    }

    /// The section cannot be cached.
    pub fn not_cached(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_NOT_CACHED) > 0
    }

    /// The section cannot be paged.
    pub fn not_paged(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_NOT_PAGED) > 0
    }

    /// The section can be shared in memory.
    pub fn shared(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_SHARED) > 0
    }

    /// The section can be executed as code.
    pub fn execute(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_EXECUTE) > 0
    }

    /// The section can be read.
    pub fn read(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_READ) > 0
    }

    /// The section can be written to.
    pub fn write(self) -> bool {
        (self.0 & IMAGE_SCN_MEM_WRITE) > 0
    }
}

impl fmt::Debug for SectionCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.debug_struct("ImageCharacteristics")
                .field("executable", &self.executable())
                .field("initialized_data", &self.initialized_data())
                .field("uninitialized_data", &self.uninitialized_data())
                .field("info", &self.info())
                .field("remove", &self.remove())
                .field("comdat", &self.comdat())
                .field(
                    "defer_speculative_exceptions",
                    &self.defer_speculative_exceptions(),
                )
                .field("global_pointer_relative", &self.global_pointer_relative())
                .field("purgeable", &self.purgeable())
                .field("locked", &self.locked())
                .field("preload", &self.preload())
                .field("alignment", &self.alignment())
                .field("lnk_nreloc_ovfl", &self.lnk_nreloc_ovfl())
                .field("discardable", &self.discardable())
                .field("not_cached", &self.not_cached())
                .field("not_paged", &self.not_paged())
                .field("shared", &self.shared())
                .field("execute", &self.execute())
                .field("read", &self.read())
                .field("write", &self.write())
                .finish()
        } else {
            f.debug_tuple("ImageCharacteristics")
                .field(&format_args!("{:#x}", self.0))
                .finish()
        }
    }
}

impl<'t> TryFromCtx<'t, Endian> for SectionCharacteristics {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let (value, size) = u32::try_from_ctx(this, le)?;
        Ok((SectionCharacteristics(value), size))
    }
}

/// A PE `IMAGE_SECTION_HEADER`, as described in [the Microsoft documentation](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx).
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct ImageSectionHeader {
    /// An 8-byte, null-padded UTF-8 string. There is no terminating null character if the string is
    /// exactly eight characters long. For longer names, this member contains a forward slash (`/`)
    /// followed by an ASCII representation of a decimal number that is an offset into the string
    /// table. Executable images do not use a string table and do not support section names longer
    /// than eight characters.
    pub name: [u8; 8],

    /// The total size of the section when loaded into memory, in bytes. If this value is greater
    /// than the [`size_of_raw_data`](Self::size_of_raw_data) member, the section is filled with
    /// zeroes. This field is valid only for executable images and should be set to `0` for object
    /// files.
    ///
    /// In object files, this field would be replaced with the physical file address. Such headers
    /// are never embedded in PDBs.
    pub virtual_size: u32,

    /// The address of the first byte of the section when loaded into memory, relative to the image
    /// base. For object files, this is the address of the first byte before relocation is applied.
    pub virtual_address: u32,

    /// The size of the initialized data on disk, in bytes. This value must be a multiple of the
    /// `FileAlignment` member of the [`IMAGE_OPTIONAL_HEADER`] structure. If this value is less than
    /// the [`virtual_size`](Self::virtual_size) member, the remainder of the section is filled with
    /// zeroes. If the section contains only uninitialized data, the member is zero.
    ///
    /// [`IMAGE_OPTIONAL_HEADER`]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
    pub size_of_raw_data: u32,

    /// A file pointer to the first page within the COFF file. This value must be a multiple of the
    /// `FileAlignment` member of the [`IMAGE_OPTIONAL_HEADER`] structure. If a section contains only
    /// uninitialized data, set this member is zero.
    ///
    /// [`IMAGE_OPTIONAL_HEADER`]: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32
    pub pointer_to_raw_data: u32,

    /// A file pointer to the beginning of the relocation entries for the section. If there are no
    /// relocations, this value is zero.
    pub pointer_to_relocations: u32,

    /// A file pointer to the beginning of the line-number entries for the section. If there are no
    /// COFF line numbers, this value is zero.
    pub pointer_to_line_numbers: u32,

    /// The number of relocation entries for the section. This value is zero for executable images.
    ///
    /// If the value is `0xffff`, the actual relocation count is stored in the `virtual_address`
    /// field of the first relocation. It is an error if this flag is set and there are fewer than
    /// `0xffff` relocations in the section.
    pub number_of_relocations: u16,

    /// The number of line-number entries for the section.
    pub number_of_line_numbers: u16,

    /// The characteristics of the image.
    pub characteristics: SectionCharacteristics,
}

impl ImageSectionHeader {
    pub(crate) fn parse(parse_buffer: &mut ParseBuffer<'_>) -> Result<Self> {
        let name_bytes = parse_buffer.take(8)?;

        Ok(Self {
            name: [
                name_bytes[0],
                name_bytes[1],
                name_bytes[2],
                name_bytes[3],
                name_bytes[4],
                name_bytes[5],
                name_bytes[6],
                name_bytes[7],
            ],
            virtual_size: parse_buffer.parse_u32()?,
            virtual_address: parse_buffer.parse_u32()?,
            size_of_raw_data: parse_buffer.parse_u32()?,
            pointer_to_raw_data: parse_buffer.parse_u32()?,
            pointer_to_relocations: parse_buffer.parse_u32()?,
            pointer_to_line_numbers: parse_buffer.parse_u32()?,
            number_of_relocations: parse_buffer.parse_u16()?,
            number_of_line_numbers: parse_buffer.parse_u16()?,
            characteristics: parse_buffer.parse()?,
        })
    }

    /// Returns the name of the section.
    pub fn name(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|ch| *ch == 0)
            .unwrap_or(self.name.len());

        // The spec guarantees that the name is a proper UTF-8 string.
        // TODO: Look up long names from the string table.
        std::str::from_utf8(&self.name[0..end]).unwrap_or("")
    }
}

impl fmt::Debug for ImageSectionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImageSectionHeader")
            .field("name()", &self.name())
            .field("virtual_size", &format_args!("{:#x}", self.virtual_size))
            .field(
                "virtual_address",
                &format_args!("{:#x}", self.virtual_address),
            )
            .field("size_of_raw_data", &self.size_of_raw_data)
            .field(
                "pointer_to_raw_data",
                &format_args!("{:#x}", self.pointer_to_raw_data),
            )
            .field(
                "pointer_to_relocations",
                &format_args!("{:#x}", self.pointer_to_relocations),
            )
            .field(
                "pointer_to_line_numbers",
                &format_args!("{:#x}", self.pointer_to_line_numbers),
            )
            .field("number_of_relocations", &self.number_of_relocations)
            .field("number_of_line_numbers", &self.number_of_line_numbers)
            .field("characteristics", &self.characteristics)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_section_characteristics() {
        let bytes: Vec<u8> = vec![0x40, 0x00, 0x00, 0xC8];
        let mut parse_buffer = ParseBuffer::from(bytes.as_slice());
        let characteristics = parse_buffer
            .parse::<SectionCharacteristics>()
            .expect("parse");

        assert_eq!(characteristics, SectionCharacteristics(0xc800_0040));

        assert!(characteristics.initialized_data());
        assert!(characteristics.not_paged());
        assert!(characteristics.read());
        assert!(characteristics.write());

        assert_eq!(characteristics.alignment(), None);
    }

    #[test]
    fn test_section_characteristics_nopad() {
        let characteristics = SectionCharacteristics(IMAGE_SCN_TYPE_NO_PAD);
        assert_eq!(characteristics.alignment(), Some(1));
    }

    #[test]
    fn test_section_characteristics_alignment() {
        let characteristics = SectionCharacteristics(IMAGE_SCN_ALIGN_64BYTES);
        assert_eq!(characteristics.alignment(), Some(64));
    }

    #[test]
    fn test_image_section_header() {
        let bytes: Vec<u8> = vec![
            0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x48, 0x35, 0x09, 0x00, 0x00, 0xD0,
            0x1E, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x00, 0xA2, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xC8,
        ];

        let mut parse_buffer = ParseBuffer::from(bytes.as_slice());

        let ish = ImageSectionHeader::parse(&mut parse_buffer).expect("parse");
        assert_eq!(&ish.name, b".data\0\0\0");
        assert_eq!(ish.name(), ".data");
        assert_eq!(ish.virtual_size, 0x93548);
        assert_eq!(ish.virtual_address, 0x001e_d000);
        assert_eq!(ish.size_of_raw_data, 0xfe00);
        assert_eq!(ish.pointer_to_raw_data, 0x001e_a200);
        assert_eq!(ish.pointer_to_relocations, 0);
        assert_eq!(ish.pointer_to_line_numbers, 0);
        assert_eq!(ish.number_of_relocations, 0);
        assert_eq!(ish.number_of_line_numbers, 0);
        assert_eq!(ish.characteristics, SectionCharacteristics(0xc800_0040));
    }
}
