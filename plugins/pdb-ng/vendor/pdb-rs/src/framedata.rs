// Copyright 2018 pdb Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Facilities for parsing legacy FPO and FrameData streams.

use std::cmp::Ordering;
use std::fmt;

use crate::common::*;
use crate::msf::Stream;
use crate::FallibleIterator;

/// A compiler specific frame type.
///
/// This frame type is used by the old FPO data and has been superseeded by program strings. Its
/// values are originally specified in [`enum StackFrameTypeEnum`].
///
/// [`enum StackFrameTypeEnum`]: https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/stackframetypeenum?view=vs-2017
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FrameType {
    /// Frame which does not have any debug info.
    Unknown = 0xff,

    /// Frame pointer omitted, FPO info available.
    FPO = 0,

    /// Kernel Trap frame.
    Trap = 1,

    /// Kernel Trap frame.
    TSS = 2,

    /// Standard EBP stackframe.
    Standard = 3,

    /// Frame pointer omitted, FrameData info available.
    FrameData = 4,
}

impl fmt::Display for FrameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::FPO => write!(f, "fpo"),
            Self::Trap => write!(f, "trap"),
            Self::TSS => write!(f, "tss"),
            Self::Standard => write!(f, "std"),
            Self::FrameData => write!(f, "fdata"),
        }
    }
}

/// New frame data format.
///
/// This format is used in the `DEBUG_S_FRAMEDATA` subsection in C13 module information, as well as
/// in the `dbgFRAMEDATA` stream defined in the optional debug header. Effectively, all recent PDBs
/// contain frame infos in this format.
///
/// The definition corresponds to [`struct tagFRAMEDATA`].
///
/// ```c
/// struct tagFRAMEDATA {
///     unsigned long   ulRvaStart;
///     unsigned long   cbBlock;
///     unsigned long   cbLocals;
///     unsigned long   cbParams;
///     unsigned long   cbStkMax;
///     unsigned long   frameFunc;
///     unsigned short  cbProlog;
///     unsigned short  cbSavedRegs;
///
///     unsigned long   fHasSEH          : 1;
///     unsigned long   fHasEH           : 1;
///     unsigned long   fIsFunctionStart : 1;
///     unsigned long   reserved         : 29;
/// };
/// ```
///
/// [`struct tagFRAMEDATA`]: https://github.com/Microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L4635
#[repr(C)]
struct NewFrameData {
    code_start: u32,
    code_size: u32,
    locals_size: u32,
    params_size: u32,
    max_stack_size: u32,
    frame_func: u32,
    prolog_size: u16,
    saved_regs_size: u16,
    flags: u32,
}

impl NewFrameData {
    pub fn code_start(&self) -> PdbInternalRva {
        PdbInternalRva(u32::from_le(self.code_start))
    }

    pub fn code_size(&self) -> u32 {
        u32::from_le(self.code_size)
    }

    pub fn locals_size(&self) -> u32 {
        u32::from_le(self.locals_size)
    }

    pub fn params_size(&self) -> u32 {
        u32::from_le(self.params_size)
    }

    pub fn max_stack_size(&self) -> u32 {
        u32::from_le(self.max_stack_size)
    }

    pub fn frame_func(&self) -> StringRef {
        StringRef(u32::from_le(self.frame_func))
    }

    pub fn prolog_size(&self) -> u16 {
        u16::from_le(self.prolog_size)
    }

    pub fn saved_regs_size(&self) -> u16 {
        u16::from_le(self.saved_regs_size)
    }

    pub fn has_seh(&self) -> bool {
        self.flags() & 1 != 0
    }

    pub fn has_eh(&self) -> bool {
        self.flags() & 2 != 0
    }

    pub fn is_function_start(&self) -> bool {
        self.flags() & 4 != 0
    }

    fn flags(&self) -> u32 {
        u32::from_le(self.flags)
    }
}

impl fmt::Debug for NewFrameData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewFrameData")
            .field("code_start", &self.code_start())
            .field("code_size", &self.code_size())
            .field("locals_size", &self.locals_size())
            .field("params_size", &self.params_size())
            .field("max_stack_size", &self.max_stack_size())
            .field("frame_func", &self.frame_func())
            .field("prolog_size", &self.prolog_size())
            .field("saved_regs_size", &self.saved_regs_size())
            .field("has_seh", &self.has_seh())
            .field("has_eh", &self.has_eh())
            .field("is_function_start", &self.is_function_start())
            .finish()
    }
}

/// Initial structure used for describing stack frames.
///
/// This structure corresponds to [`struct _FPO_DATA`] in the PE/COFF spec. It was used to describe
/// the layout of stack frames in the `dbgFPO` stream defined in the optional debug header. Since,
/// it has been superseeded by the `tagFRAMEDATA` structure (see [`NewFrameData`]).
///
/// Even if the newer FrameData stream is present, a PDB might still contain an additional FPO
/// stream. This is due to the fact that the linker simply copies over the stream. As a result, both
/// stream might describe the same RVA.
///
/// [`struct _FPO_DATA`]: https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format#debug-type
///
/// ```c
/// typedef struct _FPO_DATA {
///     DWORD  ulOffStart;      // offset 1st byte of function code
///     DWORD  cbProcSize;      // # bytes in function
///     DWORD  cdwLocals;       // # bytes in locals/4
///     WORD   cdwParams;       // # bytes in params/4
///
///     WORD   cbProlog : 8;    // # bytes in prolog
///     WORD   cbRegs   : 3;    // # regs saved
///     WORD   fHasSEH  : 1;    // TRUE if SEH in func
///     WORD   fUseBP   : 1;    // TRUE if EBP has been allocated
///     WORD   reserved : 1;    // reserved for future use
///     WORD   cbFrame  : 2;    // frame type
/// } FPO_DATA;
/// ```
#[repr(C)]
struct OldFrameData {
    code_start: u32,
    code_size: u32,
    locals_size: u32,
    params_size: u16,
    attributes: u16,
}

impl OldFrameData {
    pub fn code_start(&self) -> PdbInternalRva {
        PdbInternalRva(u32::from_le(self.code_start))
    }

    pub fn code_size(&self) -> u32 {
        u32::from_le(self.code_size)
    }

    pub fn locals_size(&self) -> u32 {
        u32::from_le(self.locals_size)
    }

    pub fn params_size(&self) -> u16 {
        u16::from_le(self.params_size)
    }

    pub fn prolog_size(&self) -> u16 {
        self.attributes() & 0xf
    }

    pub fn saved_regs_size(&self) -> u16 {
        (self.attributes() >> 8) & 0x7
    }

    pub fn has_seh(&self) -> bool {
        self.attributes() & 0x200 != 0
    }

    pub fn uses_base_pointer(&self) -> bool {
        self.attributes() & 0x400 != 0
    }

    pub fn frame_type(&self) -> FrameType {
        match self.attributes() >> 14 {
            0x00 => FrameType::FPO,
            0x01 => FrameType::Trap,
            0x02 => FrameType::TSS,
            0x03 => FrameType::Standard,
            0x04 => FrameType::FrameData,
            _ => FrameType::Unknown,
        }
    }

    fn attributes(&self) -> u16 {
        u16::from_le(self.attributes)
    }
}

impl fmt::Debug for OldFrameData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OldFrameData")
            .field("code_start", &self.code_start())
            .field("code_size", &self.code_size())
            .field("locals_size", &self.locals_size())
            .field("params_size", &self.params_size())
            .field("prolog_size", &self.prolog_size())
            .field("saved_regs_size", &self.saved_regs_size())
            .field("has_seh", &self.has_seh())
            .field("uses_base_pointer", &self.uses_base_pointer())
            .field("frame_type", &self.frame_type())
            .finish()
    }
}

/// Frame data for a code block.
#[derive(Clone, Debug)]
pub struct FrameData {
    /// Compiler-specific frame type.
    pub ty: FrameType,

    /// Relative virtual address of the start of the code block.
    ///
    /// Note that this address is internal to the PDB. To convert this to an actual [`Rva`], use
    /// [`PdbInternalRva::to_rva`].
    pub code_start: PdbInternalRva,

    /// Size of the code block covered by this frame data in bytes.
    pub code_size: u32,

    /// Size of local variables pushed on the stack in bytes.
    pub locals_size: u32,

    /// Size of parameters pushed on the stack in bytes.
    pub params_size: u32,

    /// Number of bytes of prologue code in the block.
    pub prolog_size: u16,

    /// Size of saved registers pushed on the stack in bytes.
    pub saved_regs_size: u16,

    /// The maximum number of bytes pushed on the stack.
    pub max_stack_size: Option<u32>,

    /// Indicates that structured exception handling is in effect.
    pub has_structured_eh: bool,

    /// Indicates that C++ exception handling is in effect.
    pub has_cpp_eh: bool,

    /// Indicates that this frame is the start of a function.
    pub is_function_start: bool,

    /// Indicates that this function uses the EBP register.
    pub uses_base_pointer: bool,

    /// A program string allowing to reconstruct register values for this frame.
    ///
    /// The program string is a sequence of macros that is interpreted in order to establish the
    /// prologue. For example, a typical stack frame might use the program string `"$T0 $ebp = $eip
    /// $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + ="`. The format is reverse polish notation, where the
    /// operators follow the operands. `T0` represents a temporary variable on the stack.
    ///
    /// Note that the program string is specific to the CPU and to the calling convention set up for
    /// the function represented by the current stack frame.
    pub program: Option<StringRef>,
}

impl From<&'_ OldFrameData> for FrameData {
    fn from(data: &OldFrameData) -> Self {
        Self {
            ty: data.frame_type(),
            code_start: data.code_start(),
            code_size: data.code_size(),
            prolog_size: data.prolog_size(),
            locals_size: data.locals_size() * 4,
            params_size: u32::from(data.params_size()) * 4,
            saved_regs_size: data.saved_regs_size() * 4,
            max_stack_size: None,
            has_structured_eh: data.has_seh(),
            has_cpp_eh: false,
            is_function_start: false,
            uses_base_pointer: data.uses_base_pointer(),
            program: None,
        }
    }
}

impl From<&'_ NewFrameData> for FrameData {
    fn from(data: &NewFrameData) -> Self {
        Self {
            ty: FrameType::FrameData,
            code_start: data.code_start(),
            code_size: data.code_size(),
            prolog_size: data.prolog_size(),
            locals_size: data.locals_size(),
            params_size: data.params_size(),
            saved_regs_size: data.saved_regs_size(),
            max_stack_size: Some(data.max_stack_size()),
            has_structured_eh: data.has_seh(),
            has_cpp_eh: data.has_eh(),
            is_function_start: data.is_function_start(),
            uses_base_pointer: false,
            program: Some(data.frame_func()),
        }
    }
}

/// Iterator over entries in a [`FrameTable`].
#[derive(Debug, Default)]
pub struct FrameDataIter<'t> {
    old_frames: &'t [OldFrameData],
    new_frames: &'t [NewFrameData],
    old_index: usize,
    new_index: usize,
}

impl FallibleIterator for FrameDataIter<'_> {
    type Item = FrameData;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        let old_opt = self.old_frames.get(self.old_index);
        let new_opt = self.new_frames.get(self.new_index);

        Ok(Some(match (old_opt, new_opt) {
            (Some(old_frame), Some(new_frame)) => {
                match new_frame.code_start().cmp(&old_frame.code_start()) {
                    Ordering::Less => {
                        self.new_index += 1;
                        new_frame.into()
                    }
                    Ordering::Equal => {
                        self.new_index += 1;
                        self.old_index += 1;
                        new_frame.into()
                    }
                    Ordering::Greater => {
                        self.old_index += 1;
                        old_frame.into()
                    }
                }
            }
            (Some(old_frame), None) => {
                self.old_index += 1;
                old_frame.into()
            }
            (None, Some(new_frame)) => {
                self.new_index += 1;
                new_frame.into()
            }
            (None, None) => return Ok(None),
        }))
    }
}

/// An object that spans a code range.
trait AddrRange {
    /// The start RVA of the block.
    fn start(&self) -> PdbInternalRva;

    /// The size of the block in bytes.
    fn size(&self) -> u32;

    /// The non-inclusive end of the block.
    #[inline]
    fn end(&self) -> PdbInternalRva {
        self.start() + self.size()
    }

    /// Returns whether this item includes the given Rva.
    #[inline]
    fn contains(&self, rva: PdbInternalRva) -> bool {
        rva >= self.start() && rva < self.end()
    }
}

impl AddrRange for OldFrameData {
    fn start(&self) -> PdbInternalRva {
        self.code_start()
    }

    fn size(&self) -> u32 {
        self.code_size()
    }
}

impl AddrRange for NewFrameData {
    fn start(&self) -> PdbInternalRva {
        self.code_start()
    }

    fn size(&self) -> u32 {
        self.code_size()
    }
}

/// Searches for a frame data entry covering the given `PdbInternalRva`.
fn binary_search_by_rva<R: AddrRange>(frames: &[R], rva: PdbInternalRva) -> usize {
    match frames.binary_search_by_key(&rva, |f| f.start()) {
        Ok(index) => index,
        Err(index) => {
            if index > 0 && frames[index - 1].contains(rva) {
                index - 1
            } else {
                index
            }
        }
    }
}

/// Describes stack frame layout of functions.
///
/// The table contains [`FrameData`] entries ordered by [`PdbInternalRva`]. Each entry describes a
/// range of instructions starting at `code_rva` for `code_size` bytes.
///
/// A procedure/function might be described by multiple entries, with the first one declaring
/// `is_function_start`. To retrieve frame information for a specific function, use
/// [`FrameTable::iter_at_rva`].
///
/// Not every function in the image file must have frame data defined for it. Those functions that
/// do not have frame data are assumed to have normal stack frames.
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
/// // Read the frame table once and reuse it
/// let frame_table = pdb.frame_table()?;
/// let mut frames = frame_table.iter();
///
/// // Iterate frame data in RVA order
/// while let Some(frame) = frames.next()? {
///     println!("{:#?}", frame);
/// }
/// # Ok(())
/// # }
/// # test().unwrap()
/// ```
pub struct FrameTable<'s> {
    old_stream: Option<Stream<'s>>,
    new_stream: Option<Stream<'s>>,
}

impl<'s> FrameTable<'s> {
    /// Parses frame data from raw streams.
    pub(crate) fn parse(
        old_stream: Option<Stream<'s>>,
        new_stream: Option<Stream<'s>>,
    ) -> Result<Self> {
        if let Some(ref stream) = old_stream {
            if cast_aligned::<OldFrameData>(stream.as_slice()).is_none() {
                return Err(Error::InvalidStreamLength("FrameData"));
            }
        }

        if let Some(ref stream) = new_stream {
            if cast_aligned::<NewFrameData>(stream.as_slice()).is_none() {
                return Err(Error::InvalidStreamLength("FPO"));
            }
        }

        Ok(FrameTable {
            old_stream,
            new_stream,
        })
    }

    /// Returns an iterator over all frame data in this table, ordered by `code_rva`.
    pub fn iter(&self) -> FrameDataIter<'_> {
        FrameDataIter {
            old_frames: self.old_frames(),
            new_frames: self.new_frames(),
            old_index: 0,
            new_index: 0,
        }
    }

    /// Returns an iterator over frame data starting at the given `PdbInternalRva`.
    ///
    /// The first item returned by this iterator covers the given RVA. If the address is not a
    /// direct start of a function or block, this is the closest element preceding the block. If no
    /// frame data covers the given RVA, the iterator starts at the first item **after** the RVA.
    /// Therefore, check for the desired RVA range when iterating frame data.
    ///
    /// To obtain a `PdbInternalRva`, use [`PdbInternalSectionOffset::to_internal_rva`] or
    /// [`Rva::to_internal_rva`].
    pub fn iter_at_rva(&self, rva: PdbInternalRva) -> FrameDataIter<'_> {
        let old_frames = self.old_frames();
        let old_index = binary_search_by_rva(old_frames, rva);

        let new_frames = self.new_frames();
        let new_index = binary_search_by_rva(new_frames, rva);

        FrameDataIter {
            old_frames,
            new_frames,
            old_index,
            new_index,
        }
    }

    /// Indicates whether any frame data is available.
    pub fn is_empty(&self) -> bool {
        self.new_frames().is_empty() && self.old_frames().is_empty()
    }

    fn old_frames(&self) -> &[OldFrameData] {
        match self.old_stream {
            // alignment checked during parsing
            Some(ref stream) => cast_aligned(stream.as_slice()).unwrap(),
            None => &[],
        }
    }

    fn new_frames(&self) -> &[NewFrameData] {
        match self.new_stream {
            // alignment checked during parsing
            Some(ref stream) => cast_aligned(stream.as_slice()).unwrap(),
            None => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::mem;

    #[test]
    fn test_new_frame_data() {
        assert_eq!(mem::size_of::<NewFrameData>(), 32);
        assert_eq!(mem::align_of::<NewFrameData>(), 4);
    }

    #[test]
    fn test_old_frame_data() {
        assert_eq!(mem::size_of::<OldFrameData>(), 16);
        assert_eq!(mem::align_of::<OldFrameData>(), 4);
    }
}
