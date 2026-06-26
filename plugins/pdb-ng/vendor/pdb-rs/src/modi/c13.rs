use std::fmt;
use std::mem;
use std::slice;

use scroll::{ctx::TryFromCtx, Endian, Pread};

use crate::common::*;
use crate::modi::{
    constants, CrossModuleExport, CrossModuleRef, FileChecksum, FileIndex, FileInfo, LineInfo,
    LineInfoKind, ModuleRef,
};
use crate::symbol::{BinaryAnnotation, BinaryAnnotationsIter, InlineSiteSymbol};
use crate::FallibleIterator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(unused)]
enum DebugSubsectionKind {
    // Native
    Symbols = 0xf1,
    Lines = 0xf2,
    StringTable = 0xf3,
    FileChecksums = 0xf4,
    FrameData = 0xf5,
    InlineeLines = 0xf6,
    CrossScopeImports = 0xf7,
    CrossScopeExports = 0xf8,

    // .NET
    ILLines = 0xf9,
    FuncMDTokenMap = 0xfa,
    TypeMDTokenMap = 0xfb,
    MergedAssemblyInput = 0xfc,

    CoffSymbolRva = 0xfd,
}

impl DebugSubsectionKind {
    fn parse(value: u32) -> Result<Option<Self>> {
        if (0xf1..=0xfd).contains(&value) {
            Ok(Some(unsafe { std::mem::transmute(value) }))
        } else if value == constants::DEBUG_S_IGNORE {
            Ok(None)
        } else {
            Err(Error::UnimplementedDebugSubsection(value))
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct DebugSubsectionHeader {
    /// The kind of this subsection.
    kind: u32,
    /// The length of this subsection in bytes, following the header.
    len: u32,
}

impl<'t> TryFromCtx<'t, Endian> for DebugSubsectionHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            kind: this.gread_with(&mut offset, le)?,
            len: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl DebugSubsectionHeader {
    fn kind(self) -> Result<Option<DebugSubsectionKind>> {
        DebugSubsectionKind::parse(self.kind)
    }

    fn len(self) -> usize {
        self.len as usize
    }
}

#[derive(Clone, Copy, Debug)]
struct DebugSubsection<'a> {
    pub kind: DebugSubsectionKind,
    pub data: &'a [u8],
}

#[derive(Clone, Debug, Default)]
struct DebugSubsectionIterator<'a> {
    buf: ParseBuffer<'a>,
}

impl<'a> DebugSubsectionIterator<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            buf: ParseBuffer::from(data),
        }
    }
}

impl<'a> FallibleIterator for DebugSubsectionIterator<'a> {
    type Item = DebugSubsection<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while !self.buf.is_empty() {
            let header = self.buf.parse::<DebugSubsectionHeader>()?;
            let data = self.buf.take(header.len())?;
            let kind = match header.kind()? {
                Some(kind) => kind,
                None => continue,
            };

            return Ok(Some(DebugSubsection { kind, data }));
        }

        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DebugInlineeLinesHeader {
    /// The signature of the inlinees
    signature: u32,
}

impl<'t> TryFromCtx<'t, Endian> for DebugInlineeLinesHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            signature: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl DebugInlineeLinesHeader {
    pub fn has_extra_files(self) -> bool {
        self.signature == constants::CV_INLINEE_SOURCE_LINE_SIGNATURE_EX
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct InlineeSourceLine<'a> {
    pub inlinee: IdIndex,
    pub file_id: FileIndex,
    pub line: u32,
    extra_files: &'a [u8],
}

impl<'a> InlineeSourceLine<'a> {
    // TODO: Implement extra files iterator when needed.
}

impl<'a> TryFromCtx<'a, DebugInlineeLinesHeader> for InlineeSourceLine<'a> {
    type Error = Error;

    fn try_from_ctx(this: &'a [u8], header: DebugInlineeLinesHeader) -> Result<(Self, usize)> {
        let mut buf = ParseBuffer::from(this);
        let inlinee = buf.parse()?;
        let file_id = buf.parse()?;
        let line = buf.parse()?;

        let extra_files = if header.has_extra_files() {
            let file_count = buf.parse::<u32>()? as usize;
            buf.take(file_count * std::mem::size_of::<u32>())?
        } else {
            &[]
        };

        let source_line = Self {
            inlinee,
            file_id,
            line,
            extra_files,
        };

        Ok((source_line, buf.pos()))
    }
}

#[derive(Debug, Clone, Default)]
struct DebugInlineeLinesIterator<'a> {
    header: DebugInlineeLinesHeader,
    buf: ParseBuffer<'a>,
}

impl<'a> FallibleIterator for DebugInlineeLinesIterator<'a> {
    type Item = InlineeSourceLine<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(self.buf.parse_with(self.header)?))
        }
    }
}

#[derive(Clone, Debug, Default)]
struct DebugInlineeLinesSubsection<'a> {
    header: DebugInlineeLinesHeader,
    data: &'a [u8],
}

impl<'a> DebugInlineeLinesSubsection<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut buf = ParseBuffer::from(data);
        let header = buf.parse::<DebugInlineeLinesHeader>()?;

        Ok(Self {
            header,
            data: &data[buf.pos()..],
        })
    }

    /// Iterate through all inlinees.
    fn lines(&self) -> DebugInlineeLinesIterator<'a> {
        DebugInlineeLinesIterator {
            header: self.header,
            buf: ParseBuffer::from(self.data),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DebugLinesHeader {
    /// Section offset of this line contribution.
    offset: PdbInternalSectionOffset,
    /// See LineFlags enumeration.
    flags: u16,
    /// Code size of this line contribution.
    code_size: u32,
}

impl<'t> TryFromCtx<'t, Endian> for DebugLinesHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            offset: this.gread_with(&mut offset, le)?,
            flags: this.gread_with(&mut offset, le)?,
            code_size: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl DebugLinesHeader {
    fn has_columns(self) -> bool {
        self.flags & constants::CV_LINES_HAVE_COLUMNS != 0
    }
}

#[derive(Clone, Copy, Debug)]
struct DebugLinesSubsection<'a> {
    header: DebugLinesHeader,
    data: &'a [u8],
}

impl<'a> DebugLinesSubsection<'a> {
    fn parse(data: &'a [u8]) -> Result<Self> {
        let mut buf = ParseBuffer::from(data);
        let header = buf.parse()?;
        let data = &data[buf.pos()..];
        Ok(Self { header, data })
    }

    fn blocks(&self) -> DebugLinesBlockIterator<'a> {
        DebugLinesBlockIterator {
            header: self.header,
            buf: ParseBuffer::from(self.data),
        }
    }
}

/// Marker instructions for a line offset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LineMarkerKind {
    /// A debugger should skip this address.
    DoNotStepOnto,
    /// A debugger should not step into this address.
    DoNotStepInto,
}

/// The raw line number entry in a PDB.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct LineNumberHeader {
    /// Offset to start of code bytes for line number.
    offset: u32,
    /// Combined information on the start line, end line and entry type:
    ///
    /// ```ignore
    /// unsigned long   linenumStart:24;  // line where statement/expression starts
    /// unsigned long   deltaLineEnd:7;   // delta to line where statement ends (optional)
    /// unsigned long   fStatement  :1;   // true if a statement line number, else an expression
    /// ```
    flags: u32,
}

impl<'t> TryFromCtx<'t, Endian> for LineNumberHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            offset: this.gread_with(&mut offset, le)?,
            flags: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

/// A mapping of code section offsets to source line numbers.
#[derive(Clone, Debug)]
struct LineNumberEntry {
    /// Delta offset to the start of this line contribution (debug lines subsection).
    pub offset: u32,
    /// Start line number of the statement or expression.
    pub start_line: u32,
    /// End line number of the statement or expression.
    pub end_line: u32,
    /// The type of code construct this line entry refers to.
    pub kind: LineInfoKind,
}

/// Marker for debugging purposes.
#[derive(Clone, Debug)]
struct LineMarkerEntry {
    /// Delta offset to the start of this line contribution (debug lines subsection).
    #[allow(dead_code)] // reason = "unused until TODO in LineIterator is resolved"
    pub offset: u32,
    /// The marker kind, hinting a debugger how to deal with code at this offset.
    #[allow(dead_code)] // reason = "debugger instructions are not exposed"
    pub kind: LineMarkerKind,
}

/// A parsed line entry.
#[derive(Clone, Debug)]
enum LineEntry {
    /// Declares a source line number.
    Number(LineNumberEntry),
    /// Declares a debugging marker.
    Marker(LineMarkerEntry),
}

impl LineNumberHeader {
    /// Parse this line number header into a line entry.
    pub fn parse(self) -> LineEntry {
        // The compiler generates special line numbers to hint the debugger. Separate these out so
        // that they are not confused with actual line number entries.
        let start_line = self.flags & 0x00ff_ffff;
        let marker = match start_line {
            0xfeefee => Some(LineMarkerKind::DoNotStepOnto),
            0xf00f00 => Some(LineMarkerKind::DoNotStepInto),
            _ => None,
        };

        if let Some(kind) = marker {
            return LineEntry::Marker(LineMarkerEntry {
                offset: self.offset,
                kind,
            });
        }

        // It has been observed in some PDBs that this does not store a delta to start_line but
        // actually just the truncated value of `end_line`. Therefore, prefer to use `end_line` and
        // compute the deta from `end_line` and `start_line`, if needed.
        let line_delta = self.flags & 0x7f00_0000 >> 24;

        // The line_delta contains the lower 7 bits of the end line number. We take all higher bits
        // from the start line and OR them with the lower delta bits. This combines to the full
        // original end line number.
        let high_start = start_line & !0x7f;
        let mut end_line = high_start | line_delta;

        // If the end line number is smaller than the start line, we have to assume an overflow.
        // The end line will most likely be within 128 lines from the start line. Thus, we account
        // for the overflow by adding 1 to the 8th bit.
        if end_line < start_line {
            end_line += 1 << 7;
        }

        let kind = if self.flags & 0x8000_0000 != 0 {
            LineInfoKind::Statement
        } else {
            LineInfoKind::Expression
        };

        LineEntry::Number(LineNumberEntry {
            offset: self.offset,
            start_line,
            end_line,
            kind,
        })
    }
}

#[derive(Clone, Debug, Default)]
struct DebugLinesIterator<'a> {
    block: DebugLinesBlockHeader,
    buf: ParseBuffer<'a>,
}

impl FallibleIterator for DebugLinesIterator<'_> {
    type Item = LineEntry;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        self.buf.parse().map(LineNumberHeader::parse).map(Some)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ColumnNumberEntry {
    start_column: u16,
    end_column: u16,
}

impl<'t> TryFromCtx<'t, Endian> for ColumnNumberEntry {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            start_column: this.gread_with(&mut offset, le)?,
            end_column: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

#[derive(Clone, Debug, Default)]
struct DebugColumnsIterator<'a> {
    buf: ParseBuffer<'a>,
}

impl FallibleIterator for DebugColumnsIterator<'_> {
    type Item = ColumnNumberEntry;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        self.buf.parse().map(Some)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct DebugLinesBlockHeader {
    /// Offset of the file checksum in the file checksums debug subsection.
    file_index: u32,

    /// Number of line entries in this block.
    ///
    /// If the debug lines subsection also contains column information (see `has_columns`), then the
    /// same number of column entries will be present after the line entries.
    num_lines: u32,

    /// Total byte size of this block, including following line and column entries.
    block_size: u32,
}

impl<'t> TryFromCtx<'t, Endian> for DebugLinesBlockHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            file_index: this.gread_with(&mut offset, le)?,
            num_lines: this.gread_with(&mut offset, le)?,
            block_size: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl DebugLinesBlockHeader {
    /// The byte size of all line and column records combined.
    fn data_size(&self) -> usize {
        self.block_size as usize - std::mem::size_of::<Self>()
    }

    /// The byte size of all line number entries combined.
    fn line_size(&self) -> usize {
        self.num_lines as usize * std::mem::size_of::<LineNumberHeader>()
    }

    /// The byte size of all column number entries combined.
    fn column_size(&self, subsection: DebugLinesHeader) -> usize {
        if subsection.has_columns() {
            self.num_lines as usize * std::mem::size_of::<ColumnNumberEntry>()
        } else {
            0
        }
    }
}

#[derive(Clone, Debug)]
struct DebugLinesBlock<'a> {
    header: DebugLinesBlockHeader,
    line_data: &'a [u8],
    column_data: &'a [u8],
}

impl<'a> DebugLinesBlock<'a> {
    #[allow(unused)]
    fn file_index(&self) -> FileIndex {
        FileIndex(self.header.file_index)
    }

    fn lines(&self) -> DebugLinesIterator<'a> {
        DebugLinesIterator {
            block: self.header,
            buf: ParseBuffer::from(self.line_data),
        }
    }

    fn columns(&self) -> DebugColumnsIterator<'a> {
        DebugColumnsIterator {
            buf: ParseBuffer::from(self.column_data),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct DebugLinesBlockIterator<'a> {
    header: DebugLinesHeader,
    buf: ParseBuffer<'a>,
}

impl<'a> FallibleIterator for DebugLinesBlockIterator<'a> {
    type Item = DebugLinesBlock<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        // The header is followed by a variable-size chunk of data, specified by `data_size`. Load
        // all of it at once to ensure we're not reading garbage in case there is more information
        // we do not yet understand.
        let header = self.buf.parse::<DebugLinesBlockHeader>()?;
        let data = self.buf.take(header.data_size())?;

        // The first data is a set of line entries, optionally followed by column entries. Load both
        // and discard eventual data that follows
        let (line_data, data) = data.split_at(header.line_size());
        let (column_data, remainder) = data.split_at(header.column_size(self.header));

        // In case the PDB format is extended with more information, we'd like to know here.
        debug_assert!(remainder.is_empty());

        Ok(Some(DebugLinesBlock {
            header,
            line_data,
            column_data,
        }))
    }
}

/// Possible representations of file checksums in the file checksums subsection.
#[repr(u8)]
#[allow(unused)]
#[derive(Clone, Copy, Debug, Eq, Ord, Hash, PartialEq, PartialOrd)]
enum FileChecksumKind {
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha256 = 3,
}

impl FileChecksumKind {
    /// Parses the checksum kind from its raw value.
    fn parse(value: u8) -> Result<Self> {
        if value <= 3 {
            Ok(unsafe { std::mem::transmute(value) })
        } else {
            Err(Error::UnimplementedFileChecksumKind(value))
        }
    }
}

/// Raw header of a single file checksum entry.
#[derive(Clone, Copy, Debug)]
struct FileChecksumHeader {
    name_offset: u32,
    checksum_size: u8,
    checksum_kind: u8,
}

impl<'t> TryFromCtx<'t, Endian> for FileChecksumHeader {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            name_offset: this.gread_with(&mut offset, le)?,
            checksum_size: this.gread_with(&mut offset, le)?,
            checksum_kind: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

/// A file checksum entry.
#[derive(Clone, Debug)]
struct FileChecksumEntry<'a> {
    /// Reference to the file name in the string table.
    name: StringRef,
    /// File checksum value.
    checksum: FileChecksum<'a>,
}

#[derive(Clone, Debug, Default)]
struct DebugFileChecksumsIterator<'a> {
    buf: ParseBuffer<'a>,
}

impl<'a> FallibleIterator for DebugFileChecksumsIterator<'a> {
    type Item = FileChecksumEntry<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        let header = self.buf.parse::<FileChecksumHeader>()?;
        let checksum_data = self.buf.take(header.checksum_size as usize)?;

        let checksum = match FileChecksumKind::parse(header.checksum_kind)? {
            FileChecksumKind::None => FileChecksum::None,
            FileChecksumKind::Md5 => FileChecksum::Md5(checksum_data),
            FileChecksumKind::Sha1 => FileChecksum::Sha1(checksum_data),
            FileChecksumKind::Sha256 => FileChecksum::Sha256(checksum_data),
        };

        self.buf.align(4)?;

        Ok(Some(FileChecksumEntry {
            name: StringRef(header.name_offset),
            checksum,
        }))
    }
}

#[derive(Clone, Debug, Default)]
struct DebugFileChecksumsSubsection<'a> {
    data: &'a [u8],
}

impl<'a> DebugFileChecksumsSubsection<'a> {
    /// Creates a new file checksums subsection.
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns an iterator over all file checksum entries.
    #[allow(unused)]
    fn entries(&self) -> Result<DebugFileChecksumsIterator<'a>> {
        self.entries_at_offset(FileIndex(0))
    }

    /// Returns an iterator over file checksum entries starting at the given offset.
    fn entries_at_offset(&self, offset: FileIndex) -> Result<DebugFileChecksumsIterator<'a>> {
        let mut buf = ParseBuffer::from(self.data);
        buf.take(offset.0 as usize)?;
        Ok(DebugFileChecksumsIterator { buf })
    }
}

#[derive(Clone, Copy, Debug)]
struct CrossScopeImportModule<'a> {
    name: ModuleRef,
    /// unparsed in LE byteorder
    imports: &'a [u32],
}

impl CrossScopeImportModule<'_> {
    /// Returns the local reference at the given offset.
    ///
    /// This function performs an "unsafe" conversion of the raw value into `Local<I>`. It is
    /// assumed that this function is only called from contexts where `I` can be statically
    /// inferred.
    fn get<I>(self, import: usize) -> Option<Local<I>>
    where
        I: ItemIndex,
    {
        let value = self.imports.get(import)?;
        let index = u32::from_le(*value).into();
        Some(Local(index))
    }
}

#[derive(Clone, Debug, Default)]
struct CrossScopeImportModuleIter<'a> {
    buf: ParseBuffer<'a>,
}

impl<'a> FallibleIterator for CrossScopeImportModuleIter<'a> {
    type Item = CrossScopeImportModule<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        let name = ModuleRef(self.buf.parse()?);
        let count = self.buf.parse::<u32>()? as usize;

        let data = self.buf.take(count * mem::size_of::<u32>())?;
        let imports = cast_aligned(data).ok_or(Error::InvalidStreamLength("CrossScopeImports"))?;

        Ok(Some(CrossScopeImportModule { name, imports }))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DebugCrossScopeImportsSubsection<'a> {
    data: &'a [u8],
}

impl<'a> DebugCrossScopeImportsSubsection<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn modules(self) -> CrossScopeImportModuleIter<'a> {
        let buf = ParseBuffer::from(self.data);
        CrossScopeImportModuleIter { buf }
    }
}

/// Provides efficient access to imported types and IDs from other modules.
///
/// This can be used to resolve cross module references. See [`ItemIndex::is_cross_module`] for more
/// information.
#[derive(Clone, Debug, Default)]
pub struct CrossModuleImports<'a> {
    modules: Vec<CrossScopeImportModule<'a>>,
}

impl<'a> CrossModuleImports<'a> {
    /// Creates `CrossModuleImports` from the imports debug subsection.
    fn from_section(section: DebugCrossScopeImportsSubsection<'a>) -> Result<Self> {
        let modules = section.modules().collect()?;
        Ok(Self { modules })
    }

    /// Loads `CrossModuleImports` from the debug subsections data.
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self> {
        let import_data = DebugSubsectionIterator::new(data)
            .find(|sec| Ok(sec.kind == DebugSubsectionKind::CrossScopeImports))?
            .map(|sec| sec.data);

        match import_data {
            Some(d) => Self::from_section(DebugCrossScopeImportsSubsection::new(d)),
            None => Ok(Self::default()),
        }
    }

    /// Resolves the referenced module and local index for the index.
    ///
    /// The given index **must** be a cross module reference. Use `ItemIndex::is_cross_module` to
    /// check this before invoking this function. If successful, this function returns a reference
    /// to the module that declares the type, as well as the local index of the type in that module.
    ///
    /// # Errors
    ///
    /// * `Error::NotACrossModuleRef` if the given index is already a global index and not a cross
    ///   module reference.
    /// * `Error::CrossModuleRefNotFound` if the cross module reference points to a module or local
    ///   index that is not indexed by this import table.
    pub fn resolve_import<I>(&self, index: I) -> Result<CrossModuleRef<I>>
    where
        I: ItemIndex,
    {
        let raw_index = index.into();
        if !index.is_cross_module() {
            return Err(Error::NotACrossModuleRef(raw_index));
        }

        let module_index = ((raw_index >> 20) & 0x7ff) as usize;
        let import_index = (raw_index & 0x000f_ffff) as usize;

        let module = self
            .modules
            .get(module_index)
            .ok_or(Error::CrossModuleRefNotFound(raw_index))?;

        let local_index = module
            .get(import_index)
            .ok_or(Error::CrossModuleRefNotFound(raw_index))?;

        Ok(CrossModuleRef(module.name, local_index))
    }
}

/// Raw representation of `CrossModuleExport`.
///
/// This type can directly be mapped onto a slice of binary data and exposes the underlying `local`
/// and `global` fields with correct endianness via getter methods. There are two ways to use this:
///
///  1. Binary search over a slice of exports to find the one matching a given local index
///  2. Enumerate all for debugging purposes
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawCrossScopeExport {
    /// The local index within the module.
    ///
    /// This maps to `Local<I: ItemIndex>` in the public type signature.
    local: u32,

    /// The index in the global type or id stream.
    ///
    /// This maps to `I: ItemIndex` in the public type signature.
    global: u32,
}

impl<'t> TryFromCtx<'t, Endian> for RawCrossScopeExport {
    type Error = scroll::Error;

    fn try_from_ctx(this: &'t [u8], le: Endian) -> scroll::Result<(Self, usize)> {
        let mut offset = 0;
        let data = Self {
            local: this.gread_with(&mut offset, le)?,
            global: this.gread_with(&mut offset, le)?,
        };
        Ok((data, offset))
    }
}

impl From<RawCrossScopeExport> for CrossModuleExport {
    fn from(raw: RawCrossScopeExport) -> Self {
        if (raw.local & 0x8000_0000) != 0 {
            Self::Id(Local(IdIndex(raw.local)), IdIndex(raw.global))
        } else {
            Self::Type(Local(TypeIndex(raw.local)), TypeIndex(raw.global))
        }
    }
}

struct RawCrossScopeExportsIter<'a> {
    buf: ParseBuffer<'a>,
}

impl FallibleIterator for RawCrossScopeExportsIter<'_> {
    type Item = RawCrossScopeExport;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.buf.is_empty() {
            return Ok(None);
        }

        self.buf.parse().map(Some)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DebugCrossScopeExportsSubsection<'a> {
    data: &'a [u8],
}

impl<'a> DebugCrossScopeExportsSubsection<'a> {
    /// Creates a new cross scope exports subsection.
    fn parse(data: &'a [u8]) -> Result<Self> {
        if cast_aligned::<RawCrossScopeExport>(data).is_none() {
            return Err(Error::InvalidStreamLength(
                "DebugCrossScopeExportsSubsection",
            ));
        }

        Ok(Self { data })
    }

    fn exports(self) -> RawCrossScopeExportsIter<'a> {
        let buf = ParseBuffer::from(self.data);
        RawCrossScopeExportsIter { buf }
    }
}

/// Iterator returned by [`CrossModuleExports::exports`].
#[derive(Clone, Debug)]
pub struct CrossModuleExportIter<'a> {
    exports: slice::Iter<'a, RawCrossScopeExport>,
}

impl Default for CrossModuleExportIter<'_> {
    fn default() -> Self {
        Self { exports: [].iter() }
    }
}

impl<'a> FallibleIterator for CrossModuleExportIter<'a> {
    type Item = CrossModuleExport;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        Ok(self.exports.next().map(|r| (*r).into()))
    }
}

/// A table of exports declared by this module.
///
/// Other modules can import types and ids from this module by using [cross module
/// references](ItemIndex::is_cross_module).
#[derive(Clone, Debug, Default)]
pub struct CrossModuleExports {
    raw_exports: Vec<RawCrossScopeExport>,
}

impl CrossModuleExports {
    fn from_section(section: DebugCrossScopeExportsSubsection<'_>) -> Result<Self> {
        let raw_exports = section.exports().collect()?;
        Ok(Self { raw_exports })
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        let export_data = DebugSubsectionIterator::new(data)
            .find(|sec| Ok(sec.kind == DebugSubsectionKind::CrossScopeExports))?
            .map(|sec| sec.data);

        match export_data {
            Some(d) => Self::from_section(DebugCrossScopeExportsSubsection::parse(d)?),
            None => Ok(Self::default()),
        }
    }

    /// Returns the number of exported types or ids from this module.
    #[inline]
    pub fn len(&self) -> usize {
        self.raw_exports.len()
    }

    /// Returns `true` if this module does not export types or ids.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.raw_exports.is_empty()
    }

    /// Returns an iterator over all cross scope exports.
    pub fn exports(&self) -> CrossModuleExportIter<'_> {
        CrossModuleExportIter {
            exports: self.raw_exports.iter(),
        }
    }

    /// Resolves the global index of the given cross module import's local index.
    ///
    /// The global index can be used to retrieve items from the
    /// [`TypeInformation`](crate::TypeInformation) or [`IdInformation`](crate::IdInformation)
    /// streams. If the given local index is not listed in the export list, this function returns
    /// `Ok(None)`.
    pub fn resolve_import<I>(&self, local_index: Local<I>) -> Result<Option<I>>
    where
        I: ItemIndex,
    {
        let local = local_index.0.into();
        let exports = &self.raw_exports;

        Ok(match exports.binary_search_by_key(&local, |r| r.local) {
            Ok(i) => Some(I::from(exports[i].global)),
            Err(_) => None,
        })
    }
}

#[derive(Clone)]
pub struct LineIterator<'a> {
    /// Iterator over all subsections in the current module.
    sections: std::slice::Iter<'a, DebugLinesSubsection<'a>>,
    /// Iterator over all blocks in the current lines subsection.
    blocks: DebugLinesBlockIterator<'a>,
    /// Iterator over lines in the current block.
    lines: DebugLinesIterator<'a>,
    /// Iterator over optional columns in the current block.
    columns: DebugColumnsIterator<'a>,
    /// Previous line info before length can be inferred.
    last_info: Option<LineInfo>,
}

impl<'a> FallibleIterator for LineIterator<'a> {
    type Item = LineInfo;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        loop {
            if let Some(entry) = self.lines.next()? {
                // A column entry is only returned if the debug lines subsection contains column
                // information. Otherwise, the columns iterator is empty. We can safely assume that
                // the number of line entries and column entries returned from the two iterators is
                // equivalent. If it were not, the creation of the block would already have failed.
                let column_entry = self.columns.next()?;

                // The high-level line iterator is only interested in actual line entries. It might
                // make sense to eventually fold markers at the same offset into the `LineInfo`
                // record.
                let line_entry = match entry {
                    LineEntry::Number(line_entry) => line_entry,
                    LineEntry::Marker(_) => continue,
                };

                let section_header = self.blocks.header;
                let block_header = self.lines.block;

                let offset = section_header.offset + line_entry.offset;

                let line_info = LineInfo {
                    offset,
                    length: None, // Length is inferred in the next iteration.
                    file_index: FileIndex(block_header.file_index),
                    line_start: line_entry.start_line,
                    line_end: line_entry.end_line,
                    column_start: column_entry.map(|e| e.start_column.into()),
                    column_end: column_entry.map(|e| e.end_column.into()),
                    kind: line_entry.kind,
                };

                let mut last_info = match std::mem::replace(&mut self.last_info, Some(line_info)) {
                    Some(last_info) => last_info,
                    None => continue,
                };

                last_info.set_end(offset);
                return Ok(Some(last_info));
            }

            if let Some(block) = self.blocks.next()? {
                self.lines = block.lines();
                self.columns = block.columns();
                continue;
            }

            // The current debug lines subsection ends. Fix up the length of the last line record
            // using the code size of the lines section, before continuing iteration. This ensures
            // the most accurate length of the line record, even if there are gaps between sections.
            if let Some(ref mut last_line) = self.last_info {
                let section_header = self.blocks.header;
                last_line.set_end(section_header.offset + section_header.code_size);
            }

            if let Some(lines_section) = self.sections.next() {
                self.blocks = lines_section.blocks();
                continue;
            }

            return Ok(self.last_info.take());
        }
    }
}

impl Default for LineIterator<'_> {
    fn default() -> Self {
        Self {
            sections: [].iter(),
            blocks: DebugLinesBlockIterator::default(),
            lines: DebugLinesIterator::default(),
            columns: DebugColumnsIterator::default(),
            last_info: None,
        }
    }
}

impl fmt::Debug for LineIterator<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LineIterator")
            .field("sections", &self.sections.as_slice())
            .field("blocks", &self.blocks)
            .field("lines", &self.lines)
            .field("columns", &self.columns)
            .field("last_info", &self.last_info)
            .finish()
    }
}

/// An iterator over line information records in a module.
#[derive(Clone, Debug, Default)]
pub struct InlineeLineIterator<'a> {
    annotations: BinaryAnnotationsIter<'a>,
    file_index: FileIndex,
    code_offset_base: u32,
    code_offset: PdbInternalSectionOffset,
    code_length: Option<u32>,
    line: u32,
    line_length: u32,
    col_start: Option<u32>,
    col_end: Option<u32>,
    line_kind: LineInfoKind,
    last_info: Option<LineInfo>,
}

impl<'a> InlineeLineIterator<'a> {
    fn new(
        parent_offset: PdbInternalSectionOffset,
        inline_site: &InlineSiteSymbol<'a>,
        inlinee_line: InlineeSourceLine<'a>,
    ) -> Self {
        Self {
            annotations: inline_site.annotations.iter(),
            file_index: inlinee_line.file_id,
            code_offset_base: 0,
            code_offset: parent_offset,
            code_length: None,
            line: inlinee_line.line,
            line_length: 1,
            col_start: None,
            col_end: None,
            line_kind: LineInfoKind::Statement,
            last_info: None,
        }
    }
}

impl<'a> FallibleIterator for InlineeLineIterator<'a> {
    type Item = LineInfo;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        while let Some(op) = self.annotations.next()? {
            match op {
                BinaryAnnotation::CodeOffset(code_offset) => {
                    self.code_offset.offset = code_offset;
                }
                BinaryAnnotation::ChangeCodeOffsetBase(code_offset_base) => {
                    self.code_offset_base = code_offset_base;
                }
                BinaryAnnotation::ChangeCodeOffset(delta) => {
                    self.code_offset = self.code_offset.wrapping_add(delta);
                }
                BinaryAnnotation::ChangeCodeLength(code_length) => {
                    if let Some(ref mut last_info) = self.last_info {
                        if last_info.length.is_none() && last_info.kind == self.line_kind {
                            last_info.length = Some(code_length);
                        }
                    }

                    self.code_offset = self.code_offset.wrapping_add(code_length);
                }
                BinaryAnnotation::ChangeFile(file_index) => {
                    // NOTE: There seems to be a bug in VS2015-VS2019 compilers that generates
                    // invalid binary annotations when file changes are involved. This can be
                    // triggered by #including files directly into inline functions. The
                    // `ChangeFile` annotations are generated in the wrong spot or missing
                    // completely. This renders information on the file effectively useless in a lot
                    // of cases.
                    self.file_index = file_index;
                }
                BinaryAnnotation::ChangeLineOffset(delta) => {
                    self.line = (i64::from(self.line) + i64::from(delta)) as u32;
                }
                BinaryAnnotation::ChangeLineEndDelta(line_length) => {
                    self.line_length = line_length;
                }
                BinaryAnnotation::ChangeRangeKind(kind) => {
                    self.line_kind = match kind {
                        0 => LineInfoKind::Expression,
                        1 => LineInfoKind::Statement,
                        _ => self.line_kind,
                    };
                }
                BinaryAnnotation::ChangeColumnStart(col_start) => {
                    self.col_start = Some(col_start);
                }
                BinaryAnnotation::ChangeColumnEndDelta(delta) => {
                    self.col_end = self
                        .col_end
                        .map(|col_end| (i64::from(col_end) + i64::from(delta)) as u32)
                }
                BinaryAnnotation::ChangeCodeOffsetAndLineOffset(code_delta, line_delta) => {
                    self.code_offset += code_delta;
                    self.line = (i64::from(self.line) + i64::from(line_delta)) as u32;
                }
                BinaryAnnotation::ChangeCodeLengthAndCodeOffset(code_length, code_delta) => {
                    self.code_length = Some(code_length);
                    self.code_offset += code_delta;
                }
                BinaryAnnotation::ChangeColumnEnd(col_end) => {
                    self.col_end = Some(col_end);
                }
            }

            if !op.emits_line_info() {
                continue;
            }

            let line_offset = self.code_offset + self.code_offset_base;
            if let Some(ref mut last_info) = self.last_info {
                if last_info.length.is_none() && last_info.kind == self.line_kind {
                    last_info.length = Some(line_offset.offset - last_info.offset.offset);
                }
            }

            let line_info = LineInfo {
                kind: self.line_kind,
                file_index: self.file_index,
                offset: line_offset,
                length: self.code_length,
                line_start: self.line,
                line_end: self.line + self.line_length,
                column_start: self.col_start,
                column_end: self.col_end,
            };

            // Code length resets with every line record.
            self.code_length = None;

            // Finish the previous record and emit it. The current record is stored so that the
            // length can be inferred from subsequent operators or the next line info.
            if let Some(last_info) = std::mem::replace(&mut self.last_info, Some(line_info)) {
                return Ok(Some(last_info));
            }
        }

        Ok(self.last_info.take())
    }
}

/// An inlined function that can evaluate to line information.
#[derive(Clone, Debug, Default)]
pub struct Inlinee<'a>(InlineeSourceLine<'a>);

impl<'a> Inlinee<'a> {
    /// The index of this inlinee in the `IdInformation` stream (IPI).
    pub fn index(&self) -> IdIndex {
        self.0.inlinee
    }

    /// Returns an iterator over line records for an inline site.
    ///
    /// Note that line records are not guaranteed to be ordered by source code offset. If a
    /// monotonic order by `PdbInternalSectionOffset` or `Rva` is required, the lines have to be
    /// sorted manually.
    pub fn lines(
        &self,
        parent_offset: PdbInternalSectionOffset,
        inline_site: &InlineSiteSymbol<'a>,
    ) -> InlineeLineIterator<'a> {
        InlineeLineIterator::new(parent_offset, inline_site, self.0)
    }
}

/// An iterator over line information records in a module.
#[derive(Clone, Debug, Default)]
pub struct InlineeIterator<'a> {
    inlinee_lines: DebugInlineeLinesIterator<'a>,
}

impl<'a> InlineeIterator<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self> {
        let inlinee_data = DebugSubsectionIterator::new(data)
            .find(|sec| Ok(sec.kind == DebugSubsectionKind::InlineeLines))?
            .map(|sec| sec.data);

        let inlinee_lines = match inlinee_data {
            Some(d) => DebugInlineeLinesSubsection::parse(d)?,
            None => DebugInlineeLinesSubsection::default(),
        };

        Ok(Self {
            inlinee_lines: inlinee_lines.lines(),
        })
    }
}

impl<'a> FallibleIterator for InlineeIterator<'a> {
    type Item = Inlinee<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        match self.inlinee_lines.next() {
            Ok(Some(inlinee_line)) => Ok(Some(Inlinee(inlinee_line))),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FileIterator<'a> {
    checksums: DebugFileChecksumsIterator<'a>,
}

impl<'a> FallibleIterator for FileIterator<'a> {
    type Item = FileInfo<'a>;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        match self.checksums.next() {
            Ok(Some(entry)) => Ok(Some(FileInfo {
                name: entry.name,
                checksum: entry.checksum,
            })),
            Ok(None) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

pub struct LineProgram<'a> {
    file_checksums: DebugFileChecksumsSubsection<'a>,
    line_sections: Vec<DebugLinesSubsection<'a>>,
}

impl<'a> LineProgram<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self> {
        let mut file_checksums = DebugFileChecksumsSubsection::default();
        let mut line_sections = Vec::new();

        let mut section_iter = DebugSubsectionIterator::new(data);
        while let Some(sec) = section_iter.next()? {
            match sec.kind {
                DebugSubsectionKind::FileChecksums => {
                    file_checksums = DebugFileChecksumsSubsection::new(sec.data);
                }
                DebugSubsectionKind::Lines => {
                    line_sections.push(DebugLinesSubsection::parse(sec.data)?);
                }
                _ => {}
            }
        }

        line_sections.sort_unstable_by_key(Self::lines_key);

        Ok(Self {
            file_checksums,
            line_sections,
        })
    }

    pub(crate) fn lines(&self) -> LineIterator<'_> {
        LineIterator {
            sections: self.line_sections.iter(),
            blocks: DebugLinesBlockIterator::default(),
            lines: DebugLinesIterator::default(),
            columns: DebugColumnsIterator::default(),
            last_info: None,
        }
    }

    pub(crate) fn lines_for_symbol(&self, offset: PdbInternalSectionOffset) -> LineIterator<'_> {
        // Search for the lines subsection that covers the given offset. They are non-overlapping
        // and not empty, so there will be at most one match. In most cases, there will be an exact
        // match for each symbol. However, ASM sometimes yields line records outside of the stated
        // symbol range `[offset, offset+len)`. In this case, search for the section covering the
        // offset.
        let key = Self::lines_offset_key(offset);
        let index_result = self
            .line_sections
            .binary_search_by_key(&key, Self::lines_key);

        let section = match index_result {
            Err(0) => return LineIterator::default(),
            Err(i) => self.line_sections[i - 1],
            Ok(i) => self.line_sections[i],
        };

        // In the `Err(i)` case, we might have chosen a lines subsection pointing into a different
        // section. In this case, bail out.
        if section.header.offset.section != offset.section {
            return LineIterator::default();
        }

        LineIterator {
            sections: [].iter(),
            blocks: section.blocks(),
            lines: DebugLinesIterator::default(),
            columns: DebugColumnsIterator::default(),
            last_info: None,
        }
    }

    pub(crate) fn files(&self) -> FileIterator<'a> {
        FileIterator {
            checksums: self.file_checksums.entries().unwrap_or_default(),
        }
    }

    pub(crate) fn get_file_info(&self, index: FileIndex) -> Result<FileInfo<'a>> {
        // The file index actually contains the byte offset value into the file_checksums
        // subsection. Therefore, treat it as the offset.
        let mut entries = self.file_checksums.entries_at_offset(index)?;
        let entry = entries
            .next()?
            .ok_or(Error::InvalidFileChecksumOffset(index.0))?;

        Ok(FileInfo {
            name: entry.name,
            checksum: entry.checksum,
        })
    }

    fn lines_offset_key(offset: PdbInternalSectionOffset) -> (u16, u32) {
        (offset.section, offset.offset)
    }

    fn lines_key(lines: &DebugLinesSubsection<'_>) -> (u16, u32) {
        Self::lines_offset_key(lines.header.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;

    use crate::symbol::BinaryAnnotations;

    #[test]
    fn test_line_number_header() {
        assert_eq!(mem::size_of::<LineNumberHeader>(), 8);
        assert_eq!(mem::align_of::<LineNumberHeader>(), 4);
    }

    #[test]
    fn test_column_number_header() {
        assert_eq!(mem::size_of::<ColumnNumberEntry>(), 4);
        assert_eq!(mem::align_of::<ColumnNumberEntry>(), 2);
    }

    #[test]
    fn test_debug_lines_block_header() {
        assert_eq!(mem::size_of::<DebugLinesBlockHeader>(), 12);
        assert_eq!(mem::align_of::<DebugLinesBlockHeader>(), 4);
    }

    #[test]
    fn test_raw_cross_scope_export() {
        assert_eq!(mem::size_of::<RawCrossScopeExport>(), 8);
        assert_eq!(mem::align_of::<RawCrossScopeExport>(), 4);
    }

    #[test]
    fn test_iter_lines() {
        let data = &[
            244, 0, 0, 0, 24, 0, 0, 0, 169, 49, 0, 0, 16, 1, 115, 121, 2, 198, 45, 116, 88, 98,
            157, 13, 221, 82, 225, 34, 192, 51, 0, 0, 242, 0, 0, 0, 48, 0, 0, 0, 132, 160, 0, 0, 1,
            0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 128,
            0, 0, 0, 0, 23, 0, 0, 128, 11, 0, 0, 0, 24, 0, 0, 128,
        ];

        let line_program = LineProgram::parse(data).expect("parse line program");
        let lines: Vec<_> = line_program.lines().collect().expect("collect lines");

        let expected = [
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0xa084,
                },
                length: Some(0),
                file_index: FileIndex(0x0),
                line_start: 22,
                line_end: 22,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0xa084,
                },
                length: Some(11),
                file_index: FileIndex(0x0),
                line_start: 23,
                line_end: 23,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0xa08f,
                },
                length: Some(1),
                file_index: FileIndex(0x0),
                line_start: 24,
                line_end: 24,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
        ];

        assert_eq!(lines, expected);
    }

    #[test]
    fn test_lines_for_symbol() {
        let data = &[
            244, 0, 0, 0, 24, 0, 0, 0, 169, 49, 0, 0, 16, 1, 115, 121, 2, 198, 45, 116, 88, 98,
            157, 13, 221, 82, 225, 34, 192, 51, 0, 0, 242, 0, 0, 0, 48, 0, 0, 0, 132, 160, 0, 0, 1,
            0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 36, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 128,
            0, 0, 0, 0, 23, 0, 0, 128, 11, 0, 0, 0, 24, 0, 0, 128,
        ];

        let offset = PdbInternalSectionOffset {
            section: 0x0001,
            offset: 0xa084,
        };

        let line_program = LineProgram::parse(data).expect("parse line program");
        let line = line_program
            .lines_for_symbol(offset)
            .next()
            .expect("get line");

        let expected = Some(LineInfo {
            offset: PdbInternalSectionOffset {
                section: 0x1,
                offset: 0xa084,
            },
            length: Some(0),
            file_index: FileIndex(0x0),
            line_start: 22,
            line_end: 22,
            column_start: None,
            column_end: None,
            kind: LineInfoKind::Statement,
        });

        assert_eq!(expected, line);
    }

    #[test]
    fn test_lines_for_symbol_asm() {
        // This test is similar to lines_for_symbol, but it tests with an offset that points beyond
        // the beginning of a lines subsection. This happens when dealing with MASM.

        let data = &[
            244, 0, 0, 0, 96, 0, 0, 0, 177, 44, 0, 0, 16, 1, 148, 43, 19, 100, 121, 95, 165, 113,
            45, 169, 112, 53, 233, 149, 174, 133, 0, 0, 248, 44, 0, 0, 16, 1, 54, 176, 28, 14, 163,
            149, 3, 189, 0, 215, 91, 24, 204, 45, 117, 241, 0, 0, 59, 45, 0, 0, 16, 1, 191, 40,
            129, 240, 15, 71, 114, 239, 184, 146, 206, 88, 119, 218, 136, 139, 0, 0, 126, 45, 0, 0,
            16, 1, 175, 252, 248, 34, 196, 152, 31, 107, 144, 61, 83, 41, 122, 95, 140, 123, 0, 0,
            242, 0, 0, 0, 96, 0, 0, 0, 112, 137, 0, 0, 1, 0, 0, 0, 49, 0, 0, 0, 0, 0, 0, 0, 9, 0,
            0, 0, 84, 0, 0, 0, 16, 0, 0, 0, 45, 0, 0, 128, 16, 0, 0, 0, 47, 0, 0, 128, 23, 0, 0, 0,
            48, 0, 0, 128, 26, 0, 0, 0, 49, 0, 0, 128, 30, 0, 0, 0, 50, 0, 0, 128, 35, 0, 0, 0, 51,
            0, 0, 128, 38, 0, 0, 0, 52, 0, 0, 128, 40, 0, 0, 0, 62, 0, 0, 128, 44, 0, 0, 0, 66, 0,
            0, 128,
        ];

        let offset = PdbInternalSectionOffset {
            section: 0x0001,
            offset: 0x8990, // XXX: section and first line record at 0x0980
        };

        let line_program = LineProgram::parse(data).expect("parse line program");
        let line = line_program
            .lines_for_symbol(offset)
            .next()
            .expect("get line");

        let expected = Some(LineInfo {
            offset: PdbInternalSectionOffset {
                section: 0x1,
                offset: 0x8980,
            },
            length: Some(0),
            file_index: FileIndex(0x0),
            line_start: 45,
            line_end: 45,
            column_start: None,
            column_end: None,
            kind: LineInfoKind::Statement,
        });

        assert_eq!(expected, line);
    }

    #[test]
    fn test_parse_inlinee_lines() {
        let data = &[
            0, 0, 0, 0, 254, 18, 0, 0, 104, 1, 0, 0, 24, 0, 0, 0, 253, 18, 0, 0, 104, 1, 0, 0, 28,
            0, 0, 0,
        ];

        let inlinee_lines = DebugInlineeLinesSubsection::parse(data).expect("parse inlinee lines");
        assert!(!inlinee_lines.header.has_extra_files());

        let lines: Vec<_> = inlinee_lines
            .lines()
            .collect()
            .expect("collect inlinee lines");

        let expected = [
            InlineeSourceLine {
                inlinee: IdIndex(0x12FE),
                file_id: FileIndex(0x168),
                line: 24,
                extra_files: &[],
            },
            InlineeSourceLine {
                inlinee: IdIndex(0x12FD),
                file_id: FileIndex(0x168),
                line: 28,
                extra_files: &[],
            },
        ];

        assert_eq!(lines, expected);
    }

    #[test]
    fn test_parse_inlinee_lines_with_files() {
        let data = &[
            1, 0, 0, 0, 235, 102, 9, 0, 232, 37, 0, 0, 19, 0, 0, 0, 1, 0, 0, 0, 216, 26, 0, 0, 240,
            163, 7, 0, 176, 44, 0, 0, 120, 0, 0, 0, 1, 0, 0, 0, 120, 3, 0, 0,
        ];

        let inlinee_lines = DebugInlineeLinesSubsection::parse(data).expect("parse inlinee lines");
        assert!(inlinee_lines.header.has_extra_files());

        let lines: Vec<_> = inlinee_lines
            .lines()
            .collect()
            .expect("collect inlinee lines");

        let expected = [
            InlineeSourceLine {
                inlinee: IdIndex(0x966EB),
                file_id: FileIndex(0x25e8),
                line: 19,
                extra_files: &[216, 26, 0, 0],
            },
            InlineeSourceLine {
                inlinee: IdIndex(0x7A3F0),
                file_id: FileIndex(0x2cb0),
                line: 120,
                extra_files: &[120, 3, 0, 0],
            },
        ];

        assert_eq!(lines, expected)
    }

    #[test]
    fn test_inlinee_lines() {
        // Obtained from a PDB compiling Breakpad's crash_generation_client.obj

        // S_GPROC32: [0001:00000120], Cb: 00000054
        //   S_INLINESITE: Parent: 0000009C, End: 00000318, Inlinee:             0x1173
        //     S_INLINESITE: Parent: 00000190, End: 000001EC, Inlinee:             0x1180
        //     BinaryAnnotations:    CodeLengthAndCodeOffset 2 3f  CodeLengthAndCodeOffset 3 9
        let inline_site = InlineSiteSymbol {
            parent: Some(SymbolIndex(0x190)),
            end: SymbolIndex(0x1ec),
            inlinee: IdIndex(0x1180),
            invocations: None,
            annotations: BinaryAnnotations::new(&[12, 2, 63, 12, 3, 9, 0, 0]),
        };

        // Inline site from corresponding DEBUG_S_INLINEELINES subsection:
        let inlinee_line = InlineeSourceLine {
            inlinee: IdIndex(0x1180),
            file_id: FileIndex(0x270),
            line: 341,
            extra_files: &[],
        };

        // Parent offset from procedure root:
        // S_GPROC32: [0001:00000120]
        let parent_offset = PdbInternalSectionOffset {
            offset: 0x120,
            section: 0x1,
        };

        let iter = InlineeLineIterator::new(parent_offset, &inline_site, inlinee_line);
        let lines: Vec<_> = iter.collect().expect("collect inlinee lines");

        let expected = [
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0x015f,
                },
                length: Some(2),
                file_index: FileIndex(0x270),
                line_start: 341,
                line_end: 342,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0x0168,
                },
                length: Some(3),
                file_index: FileIndex(0x270),
                line_start: 341,
                line_end: 342,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
        ];

        assert_eq!(lines, expected);
    }

    #[test]
    fn test_inlinee_lines_length() {
        // Obtained from xul.pdb:
        // https://symbols.mozilla.org/xul.pdb/5DCA9FFE1E8BC7FE4C4C44205044422E1/xul.pd_
        //
        // 1. Rename to `xul.pdb.cab` and extract with `cabextract`
        // 2. Get procedure at SymbolIndex(0x3e3c7f4)
        // 3. Get inlinee   at SymbolIndex(0x3e51b04)

        let inline_site = InlineSiteSymbol {
            parent: Some(SymbolIndex(0x03e5_14dc)),
            end: SymbolIndex(0x03e5_1bd0),
            inlinee: IdIndex(0xeb476),
            invocations: None,
            annotations: BinaryAnnotations::new(&[6, 38, 3, 186, 32, 11, 71, 11, 36, 4, 5, 0]),
        };

        // Binary annotations:
        //   ChangeLineOffset(19),
        //   ChangeCodeOffset(14880),
        //   ChangeCodeOffsetAndLineOffset(7, 2),
        //   ChangeCodeOffsetAndLineOffset(4, 1),
        //   ChangeCodeLength(5),

        let inlinee_line = InlineeSourceLine {
            inlinee: IdIndex(0xeb476),
            file_id: FileIndex(0x590),
            line: 499,
            extra_files: &[],
        };

        let parent_offset = PdbInternalSectionOffset {
            section: 0x1,
            offset: 0x0453_f100,
        };

        let iter = InlineeLineIterator::new(parent_offset, &inline_site, inlinee_line);
        let lines: Vec<_> = iter.collect().expect("collect inlinee lines");

        let expected = [
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0x0454_2b20,
                },
                length: Some(7),
                file_index: FileIndex(0x590),
                line_start: 518,
                line_end: 519,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0x0454_2b27,
                },
                length: Some(4),
                file_index: FileIndex(0x590),
                line_start: 520,
                line_end: 521,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
            LineInfo {
                offset: PdbInternalSectionOffset {
                    section: 0x1,
                    offset: 0x0454_2b2b,
                },
                length: Some(5),
                file_index: FileIndex(0x590),
                line_start: 521,
                line_end: 522,
                column_start: None,
                column_end: None,
                kind: LineInfoKind::Statement,
            },
        ];

        assert_eq!(lines, expected);
    }

    #[repr(align(4))]
    struct Align4<T>(T);

    /// Aligned data for parsing cross module imports.
    ///
    /// When parsing them from the file, alignment is validated during ruintime using
    /// `cast_aligned`. If alignment is validated, it throws an error.
    const CROSS_MODULE_IMPORT_DATA: Align4<[u8; 76]> = Align4([
        // module 0
        189, 44, 0, 0, // module name 2CBD
        14, 0, 0, 0, // 14 imports (all IDs, no Types)
        171, 19, 0, 128, // 800013AB
        37, 20, 0, 128, // 80001425
        161, 19, 0, 128, // 800013A1
        90, 20, 0, 128, // 8000145A
        159, 19, 0, 128, // 8000139F
        55, 20, 0, 128, // 80001437
        109, 17, 0, 128, // 8000116D
        238, 17, 0, 128, // 800011EE
        246, 19, 0, 128, // 800013F6
        69, 20, 0, 128, // 80001445
        104, 19, 0, 128, // 80001368
        148, 20, 0, 128, // 80001494
        195, 20, 0, 128, // 800014C3
        219, 20, 0, 128, // 800014DB
        // module 1
        21, 222, 0, 0, // module name DE15
        1, 0, 0, 0, // 1 import (id)
        96, 22, 0, 128, // 80001660
    ]);

    #[test]
    fn test_parse_cross_section_imports() {
        let sec = DebugCrossScopeImportsSubsection::new(&CROSS_MODULE_IMPORT_DATA.0);

        let modules: Vec<_> = sec.modules().collect().expect("collect imports");
        assert_eq!(modules.len(), 2);

        let module = modules[0];
        assert_eq!(module.get(0), Some(Local(IdIndex(0x8000_13AB))));
        assert_eq!(module.get(13), Some(Local(IdIndex(0x8000_14DB))));
        assert_eq!(module.get::<IdIndex>(14), None);
    }

    #[test]
    fn test_resolve_cross_module_import() {
        let sec = DebugCrossScopeImportsSubsection::new(&CROSS_MODULE_IMPORT_DATA.0);

        let imports = CrossModuleImports::from_section(sec).expect("parse section");
        let cross_ref = imports
            .resolve_import(IdIndex(0x8000_000A))
            .expect("resolve import");

        let expected = CrossModuleRef(
            // The module index is 0x000 = 1st module.
            ModuleRef(StringRef(0x2CBD)),
            // The import index is 0x0000A = 11th element.
            Local(IdIndex(0x8000_1368)),
        );

        assert_eq!(cross_ref, expected);
    }

    #[test]
    fn test_resolve_cross_module_import2() {
        let sec = DebugCrossScopeImportsSubsection::new(&CROSS_MODULE_IMPORT_DATA.0);

        let imports = CrossModuleImports::from_section(sec).expect("parse section");
        let cross_ref = imports
            .resolve_import(IdIndex(0x8010_0000))
            .expect("resolve import");

        let expected = CrossModuleRef(
            // The module index is 0x001 = 2nd module.
            ModuleRef(StringRef(0xDE15)),
            // The import index is 0x00001 = 1st element.
            Local(IdIndex(0x8000_1660)),
        );

        assert_eq!(cross_ref, expected);
    }

    const CROSS_MODULE_EXPORT_DATA: Align4<[u8; 32]> = Align4([
        31, 16, 0, 0, 12, 16, 0, 0, // 101F -> 100C
        32, 16, 0, 0, 79, 34, 0, 0, // 1020 -> 224F
        92, 17, 0, 128, 97, 17, 0, 0, // 8000115C -> 1161
        109, 17, 0, 128, 98, 17, 0, 0, // 8000116D -> 1162
    ]);

    #[test]
    fn test_iter_cross_module_exports() {
        let section = DebugCrossScopeExportsSubsection::parse(&CROSS_MODULE_EXPORT_DATA.0)
            .expect("parse exports");
        let exports = CrossModuleExports::from_section(section).expect("parse section");

        let exports: Vec<_> = exports.exports().collect().expect("collect exports");

        let expected = [
            CrossModuleExport::Type(Local(TypeIndex(0x101F)), TypeIndex(0x100C)),
            CrossModuleExport::Type(Local(TypeIndex(0x1020)), TypeIndex(0x224F)),
            CrossModuleExport::Id(Local(IdIndex(0x8000_115C)), IdIndex(0x1161)),
            CrossModuleExport::Id(Local(IdIndex(0x8000_116D)), IdIndex(0x1162)),
        ];

        assert_eq!(exports, expected);
    }

    #[test]
    fn test_resolve_cross_module_ref() {
        let section = DebugCrossScopeExportsSubsection::parse(&CROSS_MODULE_EXPORT_DATA.0)
            .expect("parse exports");
        let exports = CrossModuleExports::from_section(section).expect("parse section");

        let type_index = exports
            .resolve_import(Local(TypeIndex(0x101F)))
            .expect("resolve type");
        assert_eq!(type_index, Some(TypeIndex(0x100C)));

        let id_index = exports
            .resolve_import(Local(IdIndex(0x8000_115C)))
            .expect("resolve id");
        assert_eq!(id_index, Some(IdIndex(0x1161)));

        let missing_index = exports
            .resolve_import(Local(TypeIndex(0xFEED)))
            .expect("resolve missing");
        assert_eq!(missing_index, None);
    }
}
