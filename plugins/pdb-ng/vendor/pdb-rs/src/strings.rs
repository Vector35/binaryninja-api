use std::borrow::Cow;

use scroll::{ctx::TryFromCtx, Endian, Pread};

use crate::common::*;
use crate::msf::Stream;

/// Magic bytes identifying the string name table.
///
/// This value is declared as `NMT::verHdr` in `nmt.h`.
const PDB_NMT_HDR: u32 = 0xEFFE_EFFE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StringTableHashVersion {
    /// Default hash method used for reverse string lookups.
    ///
    /// The hash function has originally been defined in `LHashPbCb`.
    LongHash = 1,

    /// Revised hash method used for reverse string lookups.
    ///
    /// The hash function has originally been defined in `LHashPbCbV2`.
    LongHashV2 = 2,
}

impl StringTableHashVersion {
    fn parse_u32(value: u32) -> Result<Self> {
        match value {
            1 => Ok(Self::LongHash),
            2 => Ok(Self::LongHashV2),
            _ => Err(Error::UnimplementedFeature(
                "unknown string table hash version",
            )),
        }
    }
}

/// Raw header of the string table stream.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct StringTableHeader {
    /// Magic bytes of the string table.
    magic: u32,
    /// Version of the hash table after the names.
    hash_version: u32,
    /// The size of all names in bytes.
    names_size: u32,
}

impl<'t> TryFromCtx<'t, Endian> for StringTableHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            magic: this.gread_with(&mut offset, le)?,
            hash_version: this.gread_with(&mut offset, le)?,
            names_size: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl StringTableHeader {
    /// Start index of the names buffer in the string table stream.
    fn names_start(self) -> usize {
        std::mem::size_of::<Self>()
    }

    /// End index of the names buffer in the string table stream.
    fn names_end(self) -> usize {
        self.names_start() + self.names_size as usize
    }
}

/// The global string table of a PDB.
///
/// The string table is a two-way mapping from offset to string and back. It can be used to resolve
/// [`StringRef`] offsets to their string values. Sometimes, it is also referred to as "Name table".
/// The mapping from string to offset has not been implemented yet.
///
/// Use [`PDB::string_table`](crate::PDB::string_table) to obtain an instance.
#[derive(Debug)]
pub struct StringTable<'s> {
    header: StringTableHeader,
    #[allow(dead_code)] // reason = "reverse-lookups through hash table not implemented"
    hash_version: StringTableHashVersion,
    stream: Stream<'s>,
}

impl<'s> StringTable<'s> {
    pub(crate) fn parse(stream: Stream<'s>) -> Result<Self> {
        let mut buf = stream.parse_buffer();
        let header = buf.parse::<StringTableHeader>()?;

        if header.magic != PDB_NMT_HDR {
            return Err(Error::UnimplementedFeature(
                "invalid string table signature",
            ));
        }

        // The string table should at least contain all names as C-strings. Their combined size is
        // declared in the `names_size` header field.
        if buf.len() < header.names_end() {
            return Err(Error::UnexpectedEof);
        }

        let hash_version = StringTableHashVersion::parse_u32(header.hash_version)?;

        // After the name buffer, the stream contains a closed hash table for reverse mapping. From
        // the original header file (`nmi.h`):
        //
        //     Strings are mapped into name indices using a closed hash table of NIs.
        //     To find a string, we hash it and probe into the table, and compare the
        //     string against each successive ni's name until we hit or find an empty
        //     hash table entry.

        Ok(StringTable {
            header,
            hash_version,
            stream,
        })
    }
}

impl<'s> StringTable<'s> {
    /// Resolves a string value from this string table.
    ///
    /// Errors if the offset is out of bounds, otherwise returns the raw binary string value.
    pub fn get(&self, offset: StringRef) -> Result<RawString<'_>> {
        if offset.0 >= self.header.names_size {
            return Err(Error::UnexpectedEof);
        }

        let string_offset = self.header.names_start() + offset.0 as usize;
        let data = &self.stream.as_slice()[string_offset..self.header.names_end()];
        ParseBuffer::from(data).parse_cstring()
    }
}

impl StringRef {
    /// Resolves the raw string value of this reference.
    ///
    /// This method errors if the offset is out of bounds of the string table. Use
    /// [`PDB::string_table`](crate::PDB::string_table) to obtain an instance of the string table.
    pub fn to_raw_string<'s>(self, strings: &'s StringTable<'_>) -> Result<RawString<'s>> {
        strings.get(self)
    }

    /// Resolves and decodes the UTF-8 string value of this reference.
    ///
    /// This method errors if the offset is out of bounds of the string table. Use
    /// [`PDB::string_table`](crate::PDB::string_table) to obtain an instance of the string table.
    pub fn to_string_lossy<'s>(self, strings: &'s StringTable<'_>) -> Result<Cow<'s, str>> {
        strings.get(self).map(|r| r.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;

    #[test]
    fn test_string_table_header() {
        assert_eq!(mem::size_of::<StringTableHeader>(), 12);
        assert_eq!(mem::align_of::<StringTableHeader>(), 4);
    }
}
