// Copyright 2018 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Utilities for translating addresses between PDB offsets and _Relative Virtual Addresses_ (RVAs).

use std::cmp::{self, Ordering};
use std::fmt;
use std::iter::FusedIterator;
use std::mem;
use std::ops::Range;

use crate::common::*;
use crate::msf::Stream;
use crate::pe::ImageSectionHeader;

/// A address translation record from an `OMAPTable`.
///
/// This record applies to the half-open interval [ `record.source_address`,
/// `next_record.source_address` ).
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct OMAPRecord {
    source_address: u32,
    target_address: u32,
}

impl OMAPRecord {
    /// Create a new OMAP record for the given mapping.
    pub fn new(source_address: u32, target_address: u32) -> Self {
        Self {
            source_address: source_address.to_le(),
            target_address: target_address.to_le(),
        }
    }

    /// Returns the address in the source space.
    #[inline]
    pub fn source_address(self) -> u32 {
        u32::from_le(self.source_address)
    }

    /// Returns the start of the mapped portion in the target address space.
    #[inline]
    pub fn target_address(self) -> u32 {
        u32::from_le(self.target_address)
    }

    /// Translate the given address into the target address space.
    #[inline]
    fn translate(self, address: u32) -> u32 {
        // This method is only to be used internally by the OMAP iterator and lookups. The caller
        // must verify that the record is valid to translate an address.
        debug_assert!(self.source_address() <= address);
        (address - self.source_address()) + self.target_address()
    }
}

impl fmt::Debug for OMAPRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OMAPRecord")
            .field(
                "source_address",
                &format_args!("{:#010x}", self.source_address()),
            )
            .field(
                "target_address",
                &format_args!("{:#010x}", self.target_address()),
            )
            .finish()
    }
}

impl PartialOrd for OMAPRecord {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.source_address().partial_cmp(&other.source_address())
    }
}

impl Ord for OMAPRecord {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.source_address().cmp(&other.source_address())
    }
}

/// PDBs can contain OMAP tables, which translate relative virtual addresses (RVAs) from one address
/// space into another.
///
/// For more information on the pratical use of OMAPs, see the [module level documentation] and
/// [`AddressMap`]. A PDB can contain two OMAPs:
///
///  - `omap_from_src`: A mapping from the original address space to the transformed address space
///    of an optimized binary. Use `PDB::omap_from_src` to obtain an instance of this OMAP. Also,
///    `PdbInternalRva::rva` performs this conversion in a safe manner.
///  - `omap_to_src`: A mapping from the transformed address space back into the original address
///    space of the unoptimized binary. Use `PDB::omap_to_src` to obtain an instace of this OMAP.
///    Also, `Rva::original_rva` performs this conversion in a safe manner.
///
/// # Structure
///
/// OMAP tables are dense arrays, sequentially storing `OMAPRecord` structs sorted by source
/// address.
///
/// Each record applies to a range of addresses: i.e. record N indicates that addresses in the
/// half-open interval [ `record[n].source_address`, `record[n+1].source_address` ) were relocated
/// to a starting address of `record[n].target_address`. If `target_address` is zero, the `lookup()`
/// will return None, since this indicates a non-existent location in the target address space.
///
/// Given that the table is sorted, lookups by source address can be efficiently serviced using a
/// binary search directly against the underlying data without secondary data structures. This is
/// not the most cache efficient data structure (especially given that half of each cache line is
/// storing target addresses), but given that OMAP tables are an uncommon PDBs feature, the obvious
/// binary search implementation seems appropriate.
///
/// [module level documentation]: self
pub(crate) struct OMAPTable<'s> {
    stream: Stream<'s>,
}

impl<'s> OMAPTable<'s> {
    pub(crate) fn parse(stream: Stream<'s>) -> Result<Self> {
        match cast_aligned::<OMAPRecord>(stream.as_slice()) {
            Some(_) => Ok(OMAPTable { stream }),
            None => Err(Error::InvalidStreamLength("OMAP")),
        }
    }

    /// Returns a direct view onto the records stored in this OMAP table.
    #[inline]
    pub fn records(&self) -> &[OMAPRecord] {
        // alignment is checked during parsing, unwrap is safe.
        cast_aligned(self.stream.as_slice()).unwrap()
    }

    /// Look up `source_address` to yield a target address.
    pub fn lookup(&self, source_address: u32) -> Option<u32> {
        let records = self.records();

        let index = match records.binary_search_by_key(&source_address, |r| r.source_address()) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let record = records[index];

        // As a special case, `target_address` can be zero, which indicates that the
        // `source_address` does not exist in the target address space.
        if record.target_address() == 0 {
            return None;
        }

        Some(record.translate(source_address))
    }

    /// Look up a the range `start..end` and iterate all mapped sub-ranges.
    pub fn lookup_range(&self, range: Range<u32>) -> RangeIter<'_> {
        let Range { start, end } = range;
        if end <= start {
            return RangeIter::empty();
        }

        let records = self.records();
        let (record, next) = match records.binary_search_by_key(&start, |r| r.source_address()) {
            Ok(i) => (records[i], &records[i + 1..]),
            // Insert a dummy record no indicate that the range before the first record is invalid.
            // The range might still overlap with the first record however, so attempt regular
            // iteration.
            Err(0) => (OMAPRecord::new(0, 0), records),
            Err(i) => (records[i - 1], &records[i..]),
        };

        RangeIter {
            records: next.iter(),
            record,
            addr: start,
            end,
        }
    }
}

impl fmt::Debug for OMAPTable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OMAPTable").field(&self.records()).finish()
    }
}

/// An iterator over mapped target ranges in an OMAP.
pub(crate) struct RangeIter<'t> {
    /// Iterator over subsequent OMAP records.
    records: std::slice::Iter<'t, OMAPRecord>,
    /// The record that spans the current start address.
    record: OMAPRecord,
    /// The start address of the current subrange.
    addr: u32,
    /// The final end address of the (last sub-)range.
    end: u32,
}

impl<'t> RangeIter<'t> {
    /// Creates a `RangeIter` that does not yield any ranges.
    pub fn empty() -> Self {
        RangeIter {
            records: [].iter(),
            record: OMAPRecord::new(0, 0),
            addr: 0,
            end: 0,
        }
    }

    /// Creates a `RangeIter` that only yields the specified range.
    pub fn identity(range: Range<u32>) -> Self {
        // Declare the range `start..` as valid with an identity mapping. We cannot use `0..` here
        // since the target must be a non-zero value to be recognized as valid mapping. Since there
        // are no further records, a single subrange `start..end` will be considered.
        RangeIter {
            records: [].iter(),
            record: OMAPRecord::new(range.start, range.start),
            addr: range.start,
            end: range.end,
        }
    }
}

impl Default for RangeIter<'_> {
    fn default() -> Self {
        Self::empty()
    }
}

impl Iterator for RangeIter<'_> {
    type Item = Range<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.addr < self.end {
            // Pull the next record from the list. Since the current record is only valid up to the
            // next one, this will determine the end of the current sub slice. If there are no more
            // records, create an unmapped dummy record starting at the end of the source range.
            let next_record = match self.records.next() {
                Some(record) => *record,
                None => OMAPRecord::new(self.end, 0),
            };

            // Calculate the bounds of the current subrange and write it back for the next
            // iteration. Likewise, remember the next record as address translation base.
            let subrange_end = cmp::min(next_record.source_address(), self.end);
            let subrange_start = mem::replace(&mut self.addr, subrange_end);
            let last_record = mem::replace(&mut self.record, next_record);

            // Check for the validity of this sub-range or skip it silently:
            //  2. The sub range covered by the last OMAP record might be empty. This can be an
            //     artifact of a dummy record used when creating a new iterator.
            //  3. A `target_address` of zero indicates an unmapped address range.
            if subrange_start >= subrange_end || last_record.target_address() == 0 {
                continue;
            }

            let translated_start = last_record.translate(subrange_start);
            let translated_end = last_record.translate(subrange_end);
            return Some(translated_start..translated_end);
        }

        None
    }
}

impl FusedIterator for RangeIter<'_> {}

/// Iterator over [`Rva`] ranges returned by [`AddressMap::rva_ranges`].
pub struct RvaRangeIter<'t>(RangeIter<'t>);

impl Iterator for RvaRangeIter<'_> {
    type Item = Range<Rva>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|range| Rva(range.start)..Rva(range.end))
    }
}

impl FusedIterator for RvaRangeIter<'_> {}

/// Iterator over [`PdbInternalRva`] ranges returned by [`AddressMap::internal_rva_ranges`].
pub struct PdbInternalRvaRangeIter<'t>(RangeIter<'t>);

impl Iterator for PdbInternalRvaRangeIter<'_> {
    type Item = Range<PdbInternalRva>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .next()
            .map(|range| PdbInternalRva(range.start)..PdbInternalRva(range.end))
    }
}

impl FusedIterator for PdbInternalRvaRangeIter<'_> {}

/// A mapping between addresses and offsets used in the PDB and PE file.
///
/// To obtain an instace of this address map, call `PDB::address_map`. It will determine the correct
/// translation mode and read all internal state from the PDB. Then use the conversion methods on
/// the address and offset types to translate addresses.
///
/// # Background
///
/// Addresses in PDBs are stored as offsets into sections of the PE file. The `AddressMap` contains
/// the PE's section headers to translate between the offsets and virtual addresses relative to the
/// image base (RVAs).
///
/// Additionally, Microsoft has been reordering the Windows system and application binaries to
/// optimize them for paging reduction, using a toolset reported to be derived from and/or built on
/// top of the [Vulcan research project]. Relatively little else is known about the tools or the
/// methods they use. Looking at Windows system binaries like `ntoskrnl.exe`, it is apparent that
/// their layout has been rearranged, and their respective symbol files contain _OMAP_ re-mapping
/// information. The [Microsoft Binary Technologies Projects] may be involved in this.
///
/// The internals of this transformation are not well understood. According to [1997 reference
/// material]:
///
/// > Yet another form of debug information is relatively new and undocumented, except for a few
/// > obscure references in `WINNT.H` and the Win32 SDK help. This type of information is known as
/// > OMAP. Apparently, as part of Microsoft's internal build procedure, small fragments of code in
/// > EXEs and DLLs are moved around to put the most commonly used code at the beginning of the code
/// > section. This presumably keeps the process memory working set as small as possible. However,
/// > when shifting around the blocks of code, the corresponding debug information isn't updated.
/// > Instead, OMAP information is created. It lets symbol table code translate between the original
/// > address in a symbol table and the modified address where the variable or line of code really
/// > exists in memory.
///
/// # Usage
///
/// To aid with translating addresses and offsets, this module exposes `AddressMap`, a helper that
/// contains all information to apply the correct translation of any kind of address or offset to
/// another. Due to the rearranging optimizations, there are four types involved:
///
///  - [`Rva`]: A _Relative Virtual Address_ in the actual binary. This address directly corresponds
///    to instruction pointers seen in stack traces and symbol addresses reported by debuggers.
///  - [`PdbInternalRva`]: An RVA as it would have appeared before the optimization. These RVAs are
///    used in some places and can be converted to an `Rva` in the actual address space.
///  - [`SectionOffset`]: An offset into a section of the actual binary. A `section` member of _n_
///    refers to section _n - 1_, which makes a section number of _0_ a null pointer.
///  - [`PdbInternalSectionOffset`]: An offset into a section of the original binary. These offsets
///    are used throughout the PDB and can be converted to either `SectionOffset`, or directly to
///    `Rva` in the actual address space.
///
/// For binaries that have not been optimized that way, the `PdbInternal*` values are effectively
/// equal to their regular counterparts and the conversion between the two are no-ops. Address
/// translation still has to assume different address spaces, which is why there is no direct
/// conversion without an `AddressMap`.
///
/// # Example
///
/// ```rust
/// # use pdb::{Rva, FallibleIterator};
/// #
/// # fn test() -> pdb::Result<()> {
/// # let source = std::fs::File::open("fixtures/self/foo.pdb")?;
/// let mut pdb = pdb::PDB::open(source)?;
///
/// // Compute the address map once and reuse it
/// let address_map = pdb.address_map()?;
///
/// # let symbol_table = pdb.global_symbols()?;
/// # let symbol = symbol_table.iter().next()?.unwrap();
/// # match symbol.parse() { Ok(pdb::SymbolData::Public(pubsym)) => {
/// // Obtain some section offset, eg from a symbol, and convert it
/// match pubsym.offset.to_rva(&address_map) {
///     Some(rva) => {
///         println!("symbol is at {}", rva);
/// #       assert_eq!(rva, Rva(26048));
///     }
///     None => {
///         println!("symbol refers to eliminated code");
/// #       panic!("symbol should exist");
///     }
/// }
/// # } _ => unreachable!() }
/// # Ok(())
/// # }
/// # test().unwrap()
/// ```
///
/// [Vulcan research project]: https://research.microsoft.com/pubs/69850/tr-2001-50.pdf
/// [Microsoft Binary Technologies Projects]: https://microsoft.com/windows/cse/bit_projects.mspx
/// [1997 reference material]: https://www.microsoft.com/msj/0597/hood0597.aspx
#[derive(Debug, Default)]
pub struct AddressMap<'s> {
    pub(crate) original_sections: Vec<ImageSectionHeader>,
    pub(crate) transformed_sections: Option<Vec<ImageSectionHeader>>,
    pub(crate) transformed_to_original: Option<OMAPTable<'s>>,
    pub(crate) original_to_transformed: Option<OMAPTable<'s>>,
}

impl<'s> AddressMap<'s> {
    /// Resolves actual ranges in the executable's address space.
    ///
    /// The given internal address range might be split up into multiple ranges in the executable.
    /// This iterator traverses all mapped ranges in the order of the PDB-internal mapping. All
    /// empty or eliminated ranges are skipped. Thus, the iterator might be empty even for non-empty
    /// ranges.
    pub fn rva_ranges(&self, range: Range<PdbInternalRva>) -> RvaRangeIter<'_> {
        RvaRangeIter(match self.original_to_transformed {
            Some(ref omap) => omap.lookup_range(range.start.0..range.end.0),
            None => RangeIter::identity(range.start.0..range.end.0),
        })
    }

    /// Resolves actual ranges in the executable's address space.
    ///
    /// The given address range might correspond to multiple ranges in the PDB-internal address
    /// space. This iterator traverses all mapped ranges in the order of the actual RVA mapping.
    /// This iterator might be empty even for non-empty ranges if no corresponding original range
    /// can be found.
    pub fn internal_rva_ranges(&self, range: Range<Rva>) -> PdbInternalRvaRangeIter<'_> {
        PdbInternalRvaRangeIter(match self.transformed_to_original {
            Some(ref omap) => omap.lookup_range(range.start.0..range.end.0),
            None => RangeIter::identity(range.start.0..range.end.0),
        })
    }
}

fn get_section_offset(sections: &[ImageSectionHeader], address: u32) -> Option<(u16, u32)> {
    // Section headers are sorted by virtual_address, so we only need to iterate until we exceed
    // the desired address. Since the number of section headers is relatively low, a sequential
    // search is the fastest option here.
    let (index, section) = sections
        .iter()
        .take_while(|s| s.virtual_address <= address)
        .enumerate()
        .find(|(_, s)| address < s.virtual_address + s.size_of_raw_data)?;

    Some((index as u16 + 1, address - section.virtual_address))
}

fn get_virtual_address(sections: &[ImageSectionHeader], section: u16, offset: u32) -> Option<u32> {
    (section as usize)
        .checked_sub(1)
        .and_then(|i| sections.get(i))
        .map(|section| section.virtual_address + offset)
}

impl Rva {
    /// Resolves a PDB-internal Relative Virtual Address.
    ///
    /// This address is not necessarily compatible with the executable's address space and should
    /// therefore not be used for debugging purposes.
    pub fn to_internal_rva(self, translator: &AddressMap<'_>) -> Option<PdbInternalRva> {
        match translator.transformed_to_original {
            Some(ref omap) => omap.lookup(self.0).map(PdbInternalRva),
            None => Some(PdbInternalRva(self.0)),
        }
    }

    /// Resolves the section offset in the PE headers.
    ///
    /// This is an offset into PE section headers of the executable. To retrieve section offsets
    /// used in the PDB, use [`to_internal_offset`](Self::to_internal_offset) instead.
    pub fn to_section_offset(self, translator: &AddressMap<'_>) -> Option<SectionOffset> {
        let (section, offset) = match translator.transformed_sections {
            Some(ref sections) => get_section_offset(sections, self.0)?,
            None => get_section_offset(&translator.original_sections, self.0)?,
        };

        Some(SectionOffset { section, offset })
    }

    /// Resolves the PDB internal section offset.
    ///
    /// This is the offset value used in the PDB file. To index into the actual PE section headers,
    /// use [`to_section_offset`](Self::to_section_offset) instead.
    pub fn to_internal_offset(
        self,
        translator: &AddressMap<'_>,
    ) -> Option<PdbInternalSectionOffset> {
        self.to_internal_rva(translator)?
            .to_internal_offset(translator)
    }
}

impl PdbInternalRva {
    /// Resolves an actual Relative Virtual Address in the executable's address space.
    pub fn to_rva(self, translator: &AddressMap<'_>) -> Option<Rva> {
        match translator.original_to_transformed {
            Some(ref omap) => omap.lookup(self.0).map(Rva),
            None => Some(Rva(self.0)),
        }
    }

    /// Resolves the section offset in the PE headers.
    ///
    /// This is an offset into PE section headers of the executable. To retrieve section offsets
    /// used in the PDB, use [`to_internal_offset`](Self::to_internal_offset) instead.
    pub fn to_section_offset(self, translator: &AddressMap<'_>) -> Option<SectionOffset> {
        self.to_rva(translator)?.to_section_offset(translator)
    }

    /// Resolves the PDB internal section offset.
    ///
    /// This is the offset value used in the PDB file. To index into the actual PE section headers,
    /// use [`to_section_offset`](Self::to_section_offset) instead.
    pub fn to_internal_offset(
        self,
        translator: &AddressMap<'_>,
    ) -> Option<PdbInternalSectionOffset> {
        let (section, offset) = get_section_offset(&translator.original_sections, self.0)?;
        Some(PdbInternalSectionOffset { section, offset })
    }
}

impl SectionOffset {
    /// Resolves an actual Relative Virtual Address in the executable's address space.
    pub fn to_rva(self, translator: &AddressMap<'_>) -> Option<Rva> {
        let address = match translator.transformed_sections {
            Some(ref sections) => get_virtual_address(sections, self.section, self.offset)?,
            None => get_virtual_address(&translator.original_sections, self.section, self.offset)?,
        };

        Some(Rva(address))
    }

    /// Resolves a PDB-internal Relative Virtual Address.
    ///
    /// This address is not necessarily compatible with the executable's address space and should
    /// therefore not be used for debugging purposes.
    pub fn to_internal_rva(self, translator: &AddressMap<'_>) -> Option<PdbInternalRva> {
        self.to_rva(translator)?.to_internal_rva(translator)
    }

    /// Resolves the PDB internal section offset.
    pub fn to_internal_offset(
        self,
        translator: &AddressMap<'_>,
    ) -> Option<PdbInternalSectionOffset> {
        if translator.transformed_sections.is_none() {
            // Fast path to avoid section table lookups
            let Self { section, offset } = self;
            return Some(PdbInternalSectionOffset { section, offset });
        }

        self.to_internal_rva(translator)?
            .to_internal_offset(translator)
    }
}

impl PdbInternalSectionOffset {
    /// Resolves an actual Relative Virtual Address in the executable's address space.
    pub fn to_rva(self, translator: &AddressMap<'_>) -> Option<Rva> {
        self.to_internal_rva(translator)?.to_rva(translator)
    }

    /// Resolves a PDB-internal Relative Virtual Address.
    ///
    /// This address is not necessarily compatible with the executable's address space and should
    /// therefore not be used for debugging purposes.
    pub fn to_internal_rva(self, translator: &AddressMap<'_>) -> Option<PdbInternalRva> {
        get_virtual_address(&translator.original_sections, self.section, self.offset)
            .map(PdbInternalRva)
    }

    /// Resolves the section offset in the PE headers.
    pub fn to_section_offset(self, translator: &AddressMap<'_>) -> Option<SectionOffset> {
        if translator.transformed_sections.is_none() {
            // Fast path to avoid section table lookups
            let Self { section, offset } = self;
            return Some(SectionOffset { section, offset });
        }

        self.to_rva(translator)?.to_section_offset(translator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;

    #[test]
    fn test_omap_record() {
        assert_eq!(mem::size_of::<OMAPRecord>(), 8);
        assert_eq!(mem::align_of::<OMAPRecord>(), 4);
    }

    #[test]
    fn test_get_virtual_address() {
        let sections = vec![ImageSectionHeader {
            virtual_address: 0x1000_0000,
            ..Default::default()
        }];

        assert_eq!(get_virtual_address(&sections, 1, 0x1234), Some(0x1000_1234));
        assert_eq!(get_virtual_address(&sections, 2, 0x1234), None);

        // https://github.com/willglynn/pdb/issues/87
        assert_eq!(get_virtual_address(&sections, 0, 0x1234), None);
    }
}
