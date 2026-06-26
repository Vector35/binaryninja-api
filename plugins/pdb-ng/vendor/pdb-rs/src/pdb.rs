// Copyright 2017 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::common::*;
use crate::dbi::{DBIExtraStreams, DBIHeader, DebugInformation, Module};
use crate::framedata::FrameTable;
use crate::modi::ModuleInfo;
use crate::msf::{self, Msf, Stream};
use crate::omap::{AddressMap, OMAPTable};
use crate::pdbi::PDBInformation;
use crate::pe::ImageSectionHeader;
use crate::source::Source;
use crate::strings::StringTable;
use crate::symbol::SymbolTable;
use crate::tpi::{IdInformation, TypeInformation};

// Some streams have a fixed stream index.
// http://llvm.org/docs/PDB/index.html

const PDB_STREAM: u32 = 1;
const TPI_STREAM: u32 = 2;
const DBI_STREAM: u32 = 3;
const IPI_STREAM: u32 = 4;

/// `PDB` provides access to the data within a PDB file.
///
/// A PDB file is internally a Multi-Stream File (MSF), composed of multiple independent
/// (and usually discontiguous) data streams on-disk. `PDB` provides lazy access to these data
/// structures, which means the `PDB` accessor methods usually cause disk accesses.
#[derive(Debug)]
pub struct PDB<'s, S> {
    /// `msf` provides access to the underlying data streams
    msf: Box<dyn Msf<'s, S> + 's>,

    /// Memoize the `dbi::Header`, since it contains stream numbers we sometimes need
    dbi_header: Option<DBIHeader>,

    /// Memoize the `dbi::DBIExtraStreams`, since it too contains stream numbers we sometimes need
    dbi_extra_streams: Option<DBIExtraStreams>,
}

impl<'s, S: Source<'s> + 's> PDB<'s, S> {
    /// Create a new `PDB` for a `Source`.
    ///
    /// `open()` accesses enough of the source file to find the MSF stream table. This usually
    /// involves reading the header, a block near the end of the file, and finally the stream table
    /// itself. It does not access or validate any of the contents of the rest of the PDB.
    ///
    /// # Errors
    ///
    /// * `Error::UnimplementedFeature` if the PDB file predates ~2002
    /// * `Error::UnrecognizedFileFormat` if the `Source` does not appear to be a PDB file
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange`, `Error::InvalidPageSize` if the PDB file seems corrupt
    pub fn open(source: S) -> Result<PDB<'s, S>> {
        Ok(PDB {
            msf: msf::open_msf(source)?,
            dbi_header: None,
            dbi_extra_streams: None,
        })
    }

    /// Retrieve the `PDBInformation` for this PDB.
    ///
    /// The `PDBInformation` object contains the GUID and age fields that can be used to verify
    /// that a PDB file matches a binary, as well as the stream indicies of named PDB streams.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain the PDB information stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    pub fn pdb_information(&mut self) -> Result<PDBInformation<'s>> {
        let stream = self.msf.get(PDB_STREAM, None)?;
        PDBInformation::parse(stream)
    }

    /// Retrieve the `TypeInformation` for this PDB.
    ///
    /// The `TypeInformation` object owns a `SourceView` for the type information ("TPI") stream.
    /// This is usually the single largest stream of the PDB file.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain the type information stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::InvalidTypeInformationHeader` if the type information stream header was not
    ///   understood
    pub fn type_information(&mut self) -> Result<TypeInformation<'s>> {
        let stream = self.msf.get(TPI_STREAM, None)?;
        TypeInformation::parse(stream)
    }

    /// Retrieve the `IdInformation` for this PDB.
    ///
    /// The `IdInformation` object owns a `SourceView` for the type information ("IPI") stream.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain the id information stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::InvalidTypeInformationHeader` if the id information stream header was not
    ///   understood
    pub fn id_information(&mut self) -> Result<IdInformation<'s>> {
        let stream = self.msf.get(IPI_STREAM, None)?;
        IdInformation::parse(stream)
    }

    /// Retrieve the `DebugInformation` for this PDB.
    ///
    /// The `DebugInformation` object owns a `SourceView` for the debug information ("DBI") stream.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain a symbol records stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::UnimplementedFeature` if the debug information header predates ~1995
    pub fn debug_information(&mut self) -> Result<DebugInformation<'s>> {
        let stream = self.msf.get(DBI_STREAM, None)?;
        let debug_info = DebugInformation::parse(stream)?;

        // Grab its header, since we need that for unrelated operations
        self.dbi_header = Some(debug_info.header());
        Ok(debug_info)
    }

    fn dbi_header(&mut self) -> Result<DBIHeader> {
        // see if we've already got a header
        if let Some(ref h) = self.dbi_header {
            return Ok(*h);
        }

        // get just the first little bit of the DBI stream
        let stream = self.msf.get(DBI_STREAM, Some(1024))?;
        let header = DBIHeader::parse(stream)?;

        self.dbi_header = Some(header);
        Ok(header)
    }

    /// Retrieve the global symbol table for this PDB.
    ///
    /// The `SymbolTable` object owns a `SourceView` for the symbol records stream. This is usually
    /// the second-largest stream of the PDB file.
    ///
    /// The debug information stream indicates which stream is the symbol records stream, so
    /// `global_symbols()` accesses the debug information stream to read the header unless
    /// `debug_information()` was called first.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain a symbol records stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    ///
    /// If `debug_information()` was not already called, `global_symbols()` will additionally read
    /// the debug information header, in which case it can also return:
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain a debug information stream
    /// * `Error::UnimplementedFeature` if the debug information header predates ~1995
    pub fn global_symbols(&mut self) -> Result<SymbolTable<'s>> {
        // the global symbol table is stored in a stream number described by the DBI header
        // so, start by getting the DBI header
        let dbi_header = self.dbi_header()?;

        // open the appropriate stream, assuming that it is always present.
        let stream = self
            .raw_stream(dbi_header.symbol_records_stream)?
            .ok_or(Error::GlobalSymbolsNotFound)?;

        Ok(SymbolTable::new(stream))
    }

    /// Retrieve the module info stream for a specific `Module`.
    ///
    /// Some information for each module is stored in a separate stream per-module. `Module`s can be
    /// retrieved from the `PDB` by first calling [`debug_information`](Self::debug_information) to
    /// get the debug information stream, and then calling [`modules`](DebugInformation::modules) on
    /// that.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain this module info stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::UnimplementedFeature` if the module information stream is an unsupported version
    ///
    /// # Example
    ///
    /// ```
    /// # use pdb::FallibleIterator;
    /// #
    /// # fn test() -> pdb::Result<()> {
    /// let file = std::fs::File::open("fixtures/self/foo.pdb")?;
    /// let mut pdb = pdb::PDB::open(file)?;
    /// let dbi = pdb.debug_information()?;
    /// let mut modules = dbi.modules()?;
    /// if let Some(module) = modules.next()? {
    ///     println!("module name: {}, object file name: {}",
    ///              module.module_name(), module.object_file_name());
    ///     match pdb.module_info(&module)? {
    ///         Some(info) => println!("contains {} symbols", info.symbols()?.count()?),
    ///         None => println!("module information not available"),
    ///     }
    /// }
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn module_info<'m>(&mut self, module: &Module<'m>) -> Result<Option<ModuleInfo<'s>>> {
        Ok(self
            .raw_stream(module.info().stream)?
            .map(|stream| ModuleInfo::parse(stream, module)))
    }

    /// Retrieve the executable's section headers, as stored inside this PDB.
    ///
    /// The debug information stream indicates which stream contains the section headers, so
    /// `sections()` accesses the debug information stream to read the header unless
    /// `debug_information()` was called first.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain section headers
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::UnexpectedEof` if the section headers are truncated mid-record
    ///
    /// If `debug_information()` was not already called, `sections()` will additionally read
    /// the debug information header, in which case it can also return:
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain a debug information stream
    /// * `Error::UnimplementedFeature` if the debug information header predates ~1995
    pub fn sections(&mut self) -> Result<Option<Vec<ImageSectionHeader>>> {
        let index = self.extra_streams()?.section_headers;
        let stream = match self.raw_stream(index)? {
            Some(stream) => stream,
            None => return Ok(None),
        };

        let mut buf = stream.parse_buffer();
        let mut headers = Vec::with_capacity(buf.len() / 40);
        while !buf.is_empty() {
            headers.push(ImageSectionHeader::parse(&mut buf)?);
        }

        Ok(Some(headers))
    }

    /// Retrieve the global frame data table.
    ///
    /// This table describes the stack frame layout for functions from all modules in the PDB. Not
    /// every function in the image file must have FPO information defined for it. Those functions
    /// that do not have FPO information are assumed to have normal stack frames.
    ///
    /// If this PDB does not contain frame data, the returned table is empty.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain the referenced streams
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    ///
    /// # Example
    ///
    /// ```rust
    /// # use pdb::{PDB, Rva, FallibleIterator};
    /// #
    /// # fn test() -> pdb::Result<()> {
    /// # let source = std::fs::File::open("fixtures/self/foo.pdb")?;
    /// let mut pdb = PDB::open(source)?;
    ///
    /// // Read the tables once and reuse them
    /// let address_map = pdb.address_map()?;
    /// let frame_table = pdb.frame_table()?;
    /// let mut frames = frame_table.iter();
    ///
    /// // Iterate frame data in internal RVA order
    /// while let Some(frame) = frames.next()? {
    ///     println!("{:#?}", frame);
    /// }
    /// # Ok(())
    /// # }
    /// # test().unwrap()
    /// ```
    pub fn frame_table(&mut self) -> Result<FrameTable<'s>> {
        let extra = self.extra_streams()?;
        let old_stream = self.raw_stream(extra.fpo)?;
        let new_stream = self.raw_stream(extra.framedata)?;
        FrameTable::parse(old_stream, new_stream)
    }

    pub(crate) fn original_sections(&mut self) -> Result<Option<Vec<ImageSectionHeader>>> {
        let index = self.extra_streams()?.original_section_headers;
        let stream = match self.raw_stream(index)? {
            Some(stream) => stream,
            None => return Ok(None),
        };

        let mut buf = stream.parse_buffer();
        let mut headers = Vec::with_capacity(buf.len() / 40);
        while !buf.is_empty() {
            headers.push(ImageSectionHeader::parse(&mut buf)?);
        }

        Ok(Some(headers))
    }

    pub(crate) fn omap_from_src(&mut self) -> Result<Option<OMAPTable<'s>>> {
        let index = self.extra_streams()?.omap_from_src;
        match self.raw_stream(index)? {
            Some(stream) => OMAPTable::parse(stream).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn omap_to_src(&mut self) -> Result<Option<OMAPTable<'s>>> {
        let index = self.extra_streams()?.omap_to_src;
        match self.raw_stream(index)? {
            Some(stream) => OMAPTable::parse(stream).map(Some),
            None => Ok(None),
        }
    }

    /// Build a map translating between different kinds of offsets and virtual addresses.
    ///
    /// For more information on address translation, see [`AddressMap`].
    ///
    /// This reads `omap_from_src` and either `original_sections` or `sections` from this PDB and
    /// chooses internally which strategy to use for resolving RVAs. Consider to reuse this instance
    /// for multiple translations.
    ///
    /// # Errors
    ///
    /// * `Error::OmapNotFound` if an OMAP is required for translation but missing
    /// * `Error::StreamNotFound` if the PDB somehow does not contain section headers
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::UnexpectedEof` if the section headers are truncated mid-record
    ///
    /// If `debug_information()` was not already called, `omap_table()` will additionally read the
    /// debug information header, in which case it can also return:
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain a debug information stream
    /// * `Error::UnimplementedFeature` if the debug information header predates ~1995
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
    pub fn address_map(&mut self) -> Result<AddressMap<'s>> {
        let sections = self.sections()?.unwrap_or_default();
        Ok(match self.original_sections()? {
            Some(original_sections) => {
                let omap_from_src = self.omap_from_src()?.ok_or(Error::AddressMapNotFound)?;
                let omap_to_src = self.omap_to_src()?.ok_or(Error::AddressMapNotFound)?;

                AddressMap {
                    original_sections,
                    transformed_sections: Some(sections),
                    original_to_transformed: Some(omap_from_src),
                    transformed_to_original: Some(omap_to_src),
                }
            }
            None => AddressMap {
                original_sections: sections,
                transformed_sections: None,
                original_to_transformed: None,
                transformed_to_original: None,
            },
        })
    }

    /// Retrieve the global string table of this PDB.
    ///
    /// Long strings, such as file names, are stored in a global deduplicated string table. They are
    /// referred to by the [`StringRef`] type, which contains an offset into that table. Strings in
    /// the table are stored as null-terminated C strings. Modern PDBs only store valid UTF-8 data
    /// in the string table, but for older types a decoding might be necessary.
    ///
    /// The string table offers cheap zero-copy access to the underlying string data. It is
    /// therefore cheap to build.
    ///
    /// # Example
    ///
    /// ```
    /// # use pdb::{FallibleIterator, StringRef, PDB};
    /// #
    /// # fn test() -> pdb::Result<()> {
    /// # let file = std::fs::File::open("fixtures/self/foo.pdb")?;
    /// let mut pdb = PDB::open(file)?;
    /// let strings = pdb.string_table()?;
    ///
    /// // obtain a string ref somehow
    /// # let string_ref = StringRef(0);
    /// let raw_string = strings.get(string_ref)?;
    /// println!("{}", raw_string.to_string());
    ///
    /// // alternatively, use convenience methods
    /// println!("{}", string_ref.to_string_lossy(&strings)?);
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB somehow does not contain section headers
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    /// * `Error::UnexpectedEof` if the string table ends prematurely
    pub fn string_table(&mut self) -> Result<StringTable<'s>> {
        let stream = self.named_stream(b"/names")?;
        StringTable::parse(stream)
    }

    /// Retrieve a stream by its index to read its contents as bytes.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain this stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    ///
    /// # Example
    ///
    /// ```
    /// # fn test() -> pdb::Result<()> {
    /// let file = std::fs::File::open("fixtures/self/foo.pdb")?;
    /// let mut pdb = pdb::PDB::open(file)?;
    /// // This is the index of the "mystream" stream that was added using pdbstr.exe.
    /// let s = pdb.raw_stream(pdb::StreamIndex(208))?.expect("stream exists");
    /// assert_eq!(s.as_slice(), b"hello world\n");
    /// # Ok(())
    /// # }
    /// ```
    pub fn raw_stream(&mut self, index: StreamIndex) -> Result<Option<Stream<'s>>> {
        match index.msf_number() {
            Some(number) => self.msf.get(number, None).map(Some),
            None => Ok(None),
        }
    }

    /// Retrieve a stream by its name, as declared in the PDB info stream.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNameNotFound` if the PDB does not specify a stream with that name
    /// * `Error::StreamNotFound` if the PDB does not contain the stream referred to
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    pub fn named_stream(&mut self, name: &[u8]) -> Result<Stream<'s>> {
        let info = self.pdb_information()?;
        let names = info.stream_names()?;
        for named_stream in &names {
            if named_stream.name.as_bytes() == name {
                return self
                    .raw_stream(named_stream.stream_id)?
                    .ok_or(Error::StreamNameNotFound);
            }
        }
        Err(Error::StreamNameNotFound)
    }

    /// Loads the Optional Debug Header Stream, which contains offsets into extra streams.
    ///
    /// this stream is always returned, but its members are all optional depending on the data
    /// present in the PDB.
    ///
    /// The optional header begins at offset 0 immediately after the EC Substream ends.
    fn extra_streams(&mut self) -> Result<DBIExtraStreams> {
        if let Some(extra) = self.dbi_extra_streams {
            return Ok(extra);
        }

        // Parse and grab information on extra streams, since we might also need that
        let debug_info = self.debug_information()?;
        let extra = DBIExtraStreams::new(&debug_info)?;
        self.dbi_extra_streams = Some(extra);

        Ok(extra)
    }
}

impl StreamIndex {
    /// Load the raw data of this stream from the PDB.
    ///
    /// Returns `None` if this index is none. Otherwise, this will try to read the stream from the
    /// PDB, which might fail if the stream is missing.
    ///
    /// # Errors
    ///
    /// * `Error::StreamNotFound` if the PDB does not contain this stream
    /// * `Error::IoError` if returned by the `Source`
    /// * `Error::PageReferenceOutOfRange` if the PDB file seems corrupt
    pub fn get<'s, S>(self, pdb: &mut PDB<'s, S>) -> Result<Option<Stream<'s>>>
    where
        S: Source<'s> + 's,
    {
        pdb.raw_stream(self)
    }
}
