// Copyright 2021-2026 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use gimli::{EndianRcSlice, Endianity, RunTimeEndian, SectionId};
use object::{elf, Object, ObjectSection, ObjectSymbol, RelocationTarget};

use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase},
    settings::Settings,
    Endianness,
};

use binaryninja::settings::QueryOptions;
use std::collections::HashMap;
use std::rc::Rc;
//////////////////////
// Dwarf Validation

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("unknown section compression method {0:#x}")]
    UnknownCompressionMethod(u32),

    #[error("{0}")]
    GimliError(#[from] gimli::Error),

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    ObjectError(#[from] object::Error),

    #[error("relocation at {0:#x} is outside its section")]
    RelocationOutOfBounds(u64),

    #[error("invalid relocation at {offset:#x}: {reason}")]
    InvalidRelocation { offset: u64, reason: &'static str },
}

pub fn is_non_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info").is_some() || view.section_by_name("__debug_info").is_some()
}

pub fn is_dwo_dwarf(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info.dwo").is_some()
}

pub fn is_raw_non_dwo_dwarf(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info").is_some()
            || view.section_by_name("__debug_info").is_some()
    } else {
        false
    }
}

pub fn is_raw_dwo_dwarf(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        raw_view.section_by_name(".debug_info.dwo").is_some()
    } else {
        false
    }
}

pub fn can_use_debuginfod(view: &BinaryView) -> bool {
    let mut query_options = QueryOptions::new_with_view(view);
    has_build_id_section(view)
        && Settings::global().get_bool_with_opts("network.enableDebuginfod", &mut query_options)
}

pub fn has_build_id_section(view: &BinaryView) -> bool {
    if let Some(raw_view) = view.raw_view() {
        return raw_view.section_by_name(".note.gnu.build-id").is_some();
    }
    false
}

pub fn is_valid(view: &BinaryView) -> bool {
    is_non_dwo_dwarf(view)
        || is_raw_non_dwo_dwarf(view)
        || is_dwo_dwarf(view)
        || is_raw_dwo_dwarf(view)
}

pub fn get_endian(view: &BinaryView) -> RunTimeEndian {
    match view.default_endianness() {
        Endianness::LittleEndian => RunTimeEndian::Little,
        Endianness::BigEndian => RunTimeEndian::Big,
    }
}

pub fn create_section_reader<Endian: Endianity>(
    section_id: SectionId,
    view: &BinaryView,
    endian: Endian,
    is_dwo: bool,
) -> Result<RelocateOwned<gimli::EndianRcSlice<Endian>>, Error> {
    let raw_view = view.raw_view().unwrap();
    let view_data = raw_view.read_vec(0, raw_view.len() as usize);
    let file = object::File::parse(&*view_data)?;
    create_section_reader_object(section_id, &file, endian, is_dwo, &SectionAddresses::new())
}

/// The addresses to place the sections of a relocatable object at, by section index.
///
/// Every section of a relocatable object is at address 0, so an address in its debug info is
/// an offset into the section that the relocation's symbol is defined in. Adding the address
/// the section was placed at turns it into an address in the view.
pub type SectionAddresses = HashMap<object::SectionIndex, u64>;

#[derive(Debug, Clone)]
pub struct RelocationMap(Rc<object::read::RelocationMap>);

impl Default for RelocationMap {
    fn default() -> Self {
        Self(Rc::new(object::read::RelocationMap::default()))
    }
}

impl RelocationMap {
    /// Adds the relocations of `section`, whose uncompressed contents are `data`. Relocations
    /// that can't be expressed as an entry in the map are applied to `data` instead.
    ///
    /// Relocations that go in the map and refer into a section in `section_addresses` are moved
    /// to where that section was placed. The ones applied to `data` aren't: they compute
    /// differences between labels in the same section, which don't depend on where it is.
    fn add(
        &mut self,
        file: &object::File,
        section: &object::Section,
        data: &mut [u8],
        section_addresses: &SectionAddresses,
    ) -> Result<(), Error> {
        let map =
            Rc::get_mut(&mut self.0).expect("Failed to get mutable reference to RelocationMap");
        let mut riscv = RiscvRelocations::default();
        for (offset, mut relocation) in section.relocations() {
            let keep = match file.architecture() {
                object::Architecture::Riscv32 | object::Architecture::Riscv64 => {
                    riscv.apply(file, offset, &relocation, data)?
                }
                _ => true,
            };
            if !keep {
                continue;
            }
            if let Some(address) = target_section_address(file, &relocation, section_addresses) {
                relocation.set_addend(relocation.addend().wrapping_add(address as i64));
            }
            map.add(file, offset, relocation)?
        }
        riscv.finish()
    }
}

/// The address in `section_addresses` of the section that `relocation` refers into.
fn target_section_address(
    file: &object::File,
    relocation: &object::Relocation,
    section_addresses: &SectionAddresses,
) -> Option<u64> {
    if section_addresses.is_empty() {
        return None;
    }
    let section_index = match relocation.target() {
        RelocationTarget::Symbol(index) => file.symbol_by_index(index).ok()?.section_index()?,
        RelocationTarget::Section(index) => index,
        _ => return None,
    };
    section_addresses.get(&section_index).copied()
}

/// Applies the RISC-V relocations that `object::read::RelocationMap` can't represent.
///
/// With linker relaxation enabled, the assembler can't resolve differences between labels in
/// code, so it emits `R_RISCV_ADD*`/`R_RISCV_SUB*`, `R_RISCV_SET*`/`R_RISCV_SUB6` and
/// `R_RISCV_SET_ULEB128`/`R_RISCV_SUB_ULEB128` pairs at the same offset for the linker to
/// evaluate (e.g. `DW_AT_high_pc`, line table advances, CFA advances and location list ranges).
/// They are applied to the section data in order, as `perform_relocation` in binutils'
/// `bfd/elfnn-riscv.c` does; since the file isn't relaxed, this gives the unrelaxed difference.
#[derive(Default)]
struct RiscvRelocations {
    /// The offset and value of an `R_RISCV_SET_ULEB128` waiting for its `R_RISCV_SUB_ULEB128`.
    pending_set_uleb128: Option<(u64, u64)>,
}

impl RiscvRelocations {
    /// Applies `relocation` to `data` if needed. Returns `false` if the relocation has been
    /// handled and shouldn't be added to the relocation map.
    fn apply(
        &mut self,
        file: &object::File,
        offset: u64,
        relocation: &object::Relocation,
        data: &mut [u8],
    ) -> Result<bool, Error> {
        let object::RelocationFlags::Elf { r_type } = relocation.flags() else {
            return Ok(true);
        };
        // The psABI requires `R_RISCV_SUB_ULEB128` to immediately follow its `R_RISCV_SET_ULEB128`.
        if let Some((set_offset, set_value)) = self.pending_set_uleb128.take() {
            if r_type != elf::R_RISCV_SUB_ULEB128 || offset != set_offset {
                return Err(Error::InvalidRelocation {
                    offset: set_offset,
                    reason: "R_RISCV_SET_ULEB128 without a matching R_RISCV_SUB_ULEB128",
                });
            }
            // Like binutils, ignore the addend: older assemblers emitted a bogus non-zero one.
            let value = set_value.wrapping_sub(riscv_symbol_value(file, offset, relocation)?);
            write_uleb128_in_place(data, offset, value)?;
            return Ok(false);
        }

        let (size, apply): (usize, fn(u64, u64) -> u64) = match r_type {
            elf::R_RISCV_NONE | elf::R_RISCV_RELAX => return Ok(false),
            elf::R_RISCV_ADD8 => (1, u64::wrapping_add),
            elf::R_RISCV_ADD16 => (2, u64::wrapping_add),
            elf::R_RISCV_ADD32 => (4, u64::wrapping_add),
            elf::R_RISCV_ADD64 => (8, u64::wrapping_add),
            elf::R_RISCV_SUB6 => (1, |old, value| {
                (old & !0x3f) | (old.wrapping_sub(value) & 0x3f)
            }),
            elf::R_RISCV_SUB8 => (1, u64::wrapping_sub),
            elf::R_RISCV_SUB16 => (2, u64::wrapping_sub),
            elf::R_RISCV_SUB32 => (4, u64::wrapping_sub),
            elf::R_RISCV_SUB64 => (8, u64::wrapping_sub),
            elf::R_RISCV_SET6 => (1, |old, value| (old & !0x3f) | (value & 0x3f)),
            elf::R_RISCV_SET8 => (1, |_, value| value),
            elf::R_RISCV_SET16 => (2, |_, value| value),
            elf::R_RISCV_SET32 => (4, |_, value| value),
            elf::R_RISCV_SET_ULEB128 => {
                let value = riscv_symbol_value(file, offset, relocation)?
                    .wrapping_add(relocation.addend() as u64);
                self.pending_set_uleb128 = Some((offset, value));
                return Ok(false);
            }
            elf::R_RISCV_SUB_ULEB128 => {
                return Err(Error::InvalidRelocation {
                    offset,
                    reason: "R_RISCV_SUB_ULEB128 without a preceding R_RISCV_SET_ULEB128",
                })
            }
            // Leave the rest (`R_RISCV_32` and `R_RISCV_64` in particular) to the map.
            _ => return Ok(true),
        };
        let value =
            riscv_symbol_value(file, offset, relocation)?.wrapping_add(relocation.addend() as u64);
        update_word_in_place(data, offset, size, file.is_little_endian(), |old| {
            apply(old, value)
        })?;
        Ok(false)
    }

    /// Checks that no relocation pair was left incomplete.
    fn finish(self) -> Result<(), Error> {
        match self.pending_set_uleb128 {
            Some((offset, _)) => Err(Error::InvalidRelocation {
                offset,
                reason: "R_RISCV_SET_ULEB128 without a matching R_RISCV_SUB_ULEB128",
            }),
            None => Ok(()),
        }
    }
}

/// Returns `S`, the value of the symbol or section that `relocation` refers to.
///
/// In a relocatable object this is the offset into the symbol's section, not where the view
/// placed it, which is fine for the label differences it's used for.
fn riscv_symbol_value(
    file: &object::File,
    offset: u64,
    relocation: &object::Relocation,
) -> Result<u64, Error> {
    match relocation.target() {
        RelocationTarget::Symbol(index) => Ok(file.symbol_by_index(index)?.address()),
        RelocationTarget::Section(index) => Ok(file.section_by_index(index)?.address()),
        RelocationTarget::Absolute => Ok(0),
        _ => Err(Error::InvalidRelocation {
            offset,
            reason: "unsupported relocation target",
        }),
    }
}

/// Replaces the `size`-byte word at `offset` in `data` with `update` applied to it, truncated.
fn update_word_in_place(
    data: &mut [u8],
    offset: u64,
    size: usize,
    little_endian: bool,
    update: impl FnOnce(u64) -> u64,
) -> Result<(), Error> {
    let bytes = usize::try_from(offset)
        .ok()
        .and_then(|start| data.get_mut(start..)?.get_mut(..size))
        .ok_or(Error::RelocationOutOfBounds(offset))?;
    let mut word = [0; 8];
    let old = if little_endian {
        word[..size].copy_from_slice(bytes);
        u64::from_le_bytes(word)
    } else {
        word[8 - size..].copy_from_slice(bytes);
        u64::from_be_bytes(word)
    };
    let new = update(old);
    if little_endian {
        bytes.copy_from_slice(&new.to_le_bytes()[..size]);
    } else {
        bytes.copy_from_slice(&new.to_be_bytes()[8 - size..]);
    }
    Ok(())
}

/// Replaces the ULEB128 at `offset` in `data` with `value`, keeping its encoded length: the
/// data that follows can't move, and the assembler leaves enough room for the final value.
fn write_uleb128_in_place(data: &mut [u8], offset: u64, mut value: u64) -> Result<(), Error> {
    let bytes = usize::try_from(offset)
        .ok()
        .and_then(|start| {
            let bytes = data.get_mut(start..)?;
            let len = bytes.iter().position(|byte| byte & 0x80 == 0)? + 1;
            bytes.get_mut(..len)
        })
        .ok_or(Error::RelocationOutOfBounds(offset))?;
    let last = bytes.len() - 1;
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = (value & 0x7f) as u8 | if i < last { 0x80 } else { 0 };
        value >>= 7;
    }
    if value != 0 {
        return Err(Error::InvalidRelocation {
            offset,
            reason: "ULEB128 value doesn't fit in the space the assembler left",
        });
    }
    Ok(())
}

impl gimli::read::Relocate for RelocationMap {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        <usize as gimli::ReaderOffset>::from_u64(self.0.relocate(offset as u64, value as u64))
    }
}

type RelocateOwned<R> = gimli::RelocateReader<R, RelocationMap>;

pub fn create_section_reader_object<Endian: gimli::Endianity>(
    id: gimli::SectionId,
    file: &object::File,
    endian: Endian,
    is_dwo: bool,
    section_addresses: &SectionAddresses,
) -> Result<RelocateOwned<gimli::EndianRcSlice<Endian>>, Error> {
    let mut relocations = RelocationMap::default();
    let name = if is_dwo {
        id.dwo_name()
    } else if file.format() == object::BinaryFormat::Xcoff {
        id.xcoff_name()
    } else {
        Some(id.name())
    };
    let data = match name.and_then(|name| file.section_by_name(name)) {
        Some(ref section) => {
            let mut data = section.uncompressed_data()?.into_owned();
            // DWO sections never have relocations, so don't bother.
            if !is_dwo {
                relocations.add(file, section, &mut data, section_addresses)?;
            }
            data
        }
        // Use a non-zero capacity so that `ReaderOffsetId`s are unique.
        None => Vec::with_capacity(1),
    };
    let section = EndianRcSlice::new(Rc::from(data.into_boxed_slice()), endian);
    Ok(gimli::RelocateReader::new(section, relocations))
}
