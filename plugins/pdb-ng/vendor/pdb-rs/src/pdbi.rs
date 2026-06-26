// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryInto;
use std::mem;

use uuid::Uuid;

use crate::common::*;
use crate::dbi::HeaderVersion;
use crate::msf::*;

/// A PDB info stream header parsed from a stream.
///
/// The [PDB information stream] contains the GUID and age fields that can be used to
/// verify that a PDB file matches a specific binary, as well a list of named PDB streams
/// with their stream indices.
///
/// [PDB information stream]: http://llvm.org/docs/PDB/PdbStream.html
#[derive(Debug)]
pub struct PDBInformation<'s> {
    /// The version of the PDB format in use.
    pub version: HeaderVersion,
    /// A 32-bit timestamp.
    pub signature: u32,
    /// The number of times this PDB file has been written.
    ///
    /// This number is bumped by the linker and other tools every time the PDB is modified. It does
    /// not necessarily correspond to the age declared in the image. Consider using
    /// [`DebugInformation::age`](crate::DebugInformation::age) for a better match.
    ///
    /// This PDB matches an image, if the `guid` values match and the PDB age is equal or higher
    /// than the image's age.
    pub age: u32,
    /// A `Uuid` generated when this PDB file was created that should uniquely identify it.
    pub guid: Uuid,
    /// The offset of the start of the stream name data within the stream.
    pub names_offset: usize,
    /// The size of the stream name data, in bytes.
    pub names_size: usize,
    stream: Stream<'s>,
}

impl<'s> PDBInformation<'s> {
    /// Parses a `PDBInformation` from raw stream data.
    pub(crate) fn parse(stream: Stream<'s>) -> Result<Self> {
        let (version, signature, age, guid, names_size, names_offset) = {
            let mut buf = stream.parse_buffer();
            let version = From::from(buf.parse_u32()?);
            let signature = buf.parse_u32()?;
            let age = buf.parse_u32()?;
            let guid = Uuid::from_fields(
                buf.parse_u32()?,
                buf.parse_u16()?,
                buf.parse_u16()?,
                buf.take(8)?.try_into().unwrap(),
            );
            let names_size = buf.parse_u32()? as usize;
            let names_offset = buf.pos();
            (version, signature, age, guid, names_size, names_offset)
        };

        Ok(PDBInformation {
            version,
            signature,
            age,
            guid,
            names_size,
            names_offset,
            stream,
        })
    }

    /// Get a `StreamNames` object that can be used to iterate over named streams contained
    /// within the PDB file.
    ///
    /// This can be used to look up certain PDB streams by name.
    ///
    /// # Example
    ///
    /// ```
    /// # use pdb::FallibleIterator;
    /// #
    /// # fn test() -> pdb::Result<()> {
    /// let file = std::fs::File::open("fixtures/self/foo.pdb")?;
    /// let mut pdb = pdb::PDB::open(file)?;
    /// let info = pdb.pdb_information()?;
    /// let names = info.stream_names()?;
    /// let mut v: Vec<_> = names.iter().map(|n| n.name.to_string()).collect();
    /// v.sort();
    /// assert_eq!(&v, &["mystream", "/LinkInfo", "/names", "/src/headerblock"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn stream_names(&self) -> Result<StreamNames<'_>> {
        // The names map is part of the PDB info stream that provides a mapping from stream names to
        // stream indicies. Its [format on disk](1) is somewhat complicated, consisting of a block of
        // data comprising the names as null-terminated C strings, followed by a map of stream indices
        // to the offset of their names within the names block.
        //
        // [The map itself](2) is stored as a 32-bit count of the number of entries, followed by a
        // 32-bit value that gives the number of bytes taken up by the entries themselves, followed by
        // two sets: one for names that are present in this PDB, and one for names that have been
        // deleted, followed by the map entries, each of which is a pair of 32-bit values consisting of
        // an offset into the names block and a stream ID.
        //
        // [The two sets](3) are each stored as a [bit array](4), which consists of a 32-bit count, and
        // then that many 32-bit words containing the bits in the array.
        //
        // [1]: https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/nmtni.h#L76
        // [2]: https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/map.h#L474
        // [3]: https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/iset.h#L62
        // [4]: https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/PDB/include/array.h#L209

        let mut names = vec![];
        let mut buf = self.stream.parse_buffer();

        // Seek forward to the name map.
        buf.take(self.names_offset + self.names_size)?;
        let count = buf.parse_u32()?;
        // We don't actually use most of these.
        let _entries_size = buf.parse_u32()?;
        let ok_words = buf.parse_u32()?;
        let _ok_bits = buf.take(ok_words as usize * mem::size_of::<u32>())?;
        let deleted_words = buf.parse_u32()?;
        let _deleted_bits = buf.take(deleted_words as usize * mem::size_of::<u32>())?;

        // Skip over the header here.
        let mut names_reader = self.stream.parse_buffer();
        names_reader.take(self.names_offset)?;
        // And take just the name data.
        let names_buf = names_reader.take(self.names_size)?;
        for _ in 0..count {
            let name_offset = buf.parse_u32()? as usize;
            let stream_id = StreamIndex(buf.parse_u32()? as u16);
            let name = ParseBuffer::from(&names_buf[name_offset..]).parse_cstring()?;
            names.push(StreamName { name, stream_id });
        }

        Ok(StreamNames { names })
    }
}

/// A named stream contained within the PDB file.
#[derive(Debug)]
pub struct StreamName<'n> {
    /// The stream's name.
    pub name: RawString<'n>,
    /// The index of this stream.
    pub stream_id: StreamIndex,
}

/// A list of named streams contained within the PDB file.
///
/// Call [`StreamNames::iter`] to iterate over the names. The iterator produces [`StreamName`]
/// objects.
#[derive(Debug)]
pub struct StreamNames<'s> {
    /// The list of streams and their names.
    names: Vec<StreamName<'s>>,
}

/// An iterator over [`StreamName`]s.
pub type NameIter<'a, 'n> = std::slice::Iter<'a, StreamName<'n>>;

impl<'s> StreamNames<'s> {
    /// Return an iterator over named streams and their stream indices.
    #[inline]
    pub fn iter(&self) -> NameIter<'_, 's> {
        self.names.iter()
    }
}

impl<'a, 's> IntoIterator for &'a StreamNames<'s> {
    type Item = &'a StreamName<'s>;
    type IntoIter = NameIter<'a, 's>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.names.iter()
    }
}
