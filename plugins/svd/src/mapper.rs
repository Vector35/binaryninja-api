use crate::settings::LoadSettings;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::confidence::{Conf, MAX_CONFIDENCE};
use binaryninja::data_buffer::DataBuffer;
use binaryninja::rc::Ref;
use binaryninja::section::{SectionBuilder, Semantics};
use binaryninja::segment::{SegmentBuilder, SegmentFlags};
use binaryninja::symbol::{SymbolBuilder, SymbolType};
use binaryninja::types::{
    BaseStructure, EnumerationBuilder, MemberAccess, MemberScope, NamedTypeReference,
    NamedTypeReferenceClass, StructureBuilder, StructureMember, StructureType, Type, TypeBuilder,
};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use svd_parser::svd::{
    Access, AddressBlock, AddressBlockUsage, DataType, Device, EnumeratedValues, Field, FieldInfo,
    Peripheral, PeripheralInfo, Register, RegisterCluster, RegisterInfo, Usage,
};

pub fn byte_aligned(bit_width: u32) -> bool {
    bit_width % 8 == 0
}

/// Byte aligned width for bit-width
pub fn byte_width(bit_width: u32) -> u32 {
    if byte_aligned(bit_width) {
        bit_width / 8
    } else {
        (bit_width / 8) + 1
    }
}

#[derive(Clone, Debug)]
pub struct AddressBlockMemoryInfo {
    pub segment: SegmentBuilder,
    pub segment_flags: SegmentFlags,
    pub section: SectionBuilder,
}

pub struct DeviceMapper {
    settings: LoadSettings,
    device: Device,
    address_size: usize,
}

impl DeviceMapper {
    pub fn new(settings: LoadSettings, address_size: usize, mut device: Device) -> Self {
        svd_parser::expand_properties(&mut device);

        // TODO: Until https://github.com/rust-embedded/svd/issues/288 is fixed
        let mut new_device = device.clone();
        new_device.peripherals.clear();
        for peripheral in &device.peripherals {
            let mut new_peripheral = peripheral.clone();
            if let Some(derived_periph_name) = &peripheral.derived_from {
                // Add derived address blocks.
                // TODO: Should this not be done by svd_parser::expand?
                // TODO: Should this be recursive?
                if let Some(derived_peripheral) = device.get_peripheral(derived_periph_name) {
                    if let Some(address_blocks) = &derived_peripheral.address_block {
                        new_peripheral
                            .address_block
                            .get_or_insert_with(Vec::new)
                            .extend(address_blocks.to_owned());
                    }
                }
            }
            new_device.peripherals.push(new_peripheral);
        }

        // TODO: Return error instead.
        let expanded_device = svd_parser::expand(&new_device).expect("Failed to expand device!");
        Self {
            settings,
            device: expanded_device,
            address_size,
        }
    }

    pub fn map_to_view(&self, view: &BinaryView) {
        log::info!("Mapping device... {}", self.device.name);
        for peripheral in &self.device.peripherals {
            match peripheral {
                Peripheral::Single(info) => {
                    self.map_peripheral_to_view(view, info);
                }
                Peripheral::Array(_info, _elem) => {
                    // TODO: How do we handle this?
                    // TODO: I guess we will need to update the base address?
                    // TODO: expand feature solves this.
                }
            }
        }
    }

    // TODO: Add address blocks from derived peripherals?
    pub fn map_peripheral_to_view(&self, view: &BinaryView, peripheral: &PeripheralInfo) {
        // Get the size to extend the current block by.
        let extend_block_size = |current_block: &AddressBlock, new_block: &AddressBlock| {
            (new_block.offset + new_block.size - current_block.offset).max(current_block.size)
        };

        let merge_blocks = |mut coalesced_blocks: Vec<AddressBlock>,
                            new_block: AddressBlock|
         -> Vec<AddressBlock> {
            if let Some(current_block) = coalesced_blocks.last_mut() {
                // Check if the new block can be merged with the last block.
                // TODO: We don't account for the offset between the blocks
                // TODO: Because we dont that means a register block 0x1000 away from another register block
                // TODO: will still be merged, which is undesirable considering that SVD address blocks
                // TODO: are suppose to be distinct memory regions!
                if current_block.usage == new_block.usage {
                    current_block.size = extend_block_size(current_block, &new_block);
                    return coalesced_blocks;
                }
            }
            // Push as a new block if not mergeable.
            coalesced_blocks.push(new_block);
            coalesced_blocks
        };

        if let Some(address_blocks) = &peripheral.address_block {
            // Because some SVD authors decided to create address blocks for sub-regions
            // we must first coalesce all contiguous register address blocks.
            let mut sorted_blocks = address_blocks.clone();
            sorted_blocks.sort_by_key(|block| block.offset);
            let merged_blocks: Vec<AddressBlock> =
                sorted_blocks.into_iter().fold(Vec::new(), merge_blocks);
            // Update the peripheral so downstream usage sees only merged blocks.
            let mut updated_peripheral = peripheral.clone();
            updated_peripheral.address_block = Some(merged_blocks.clone());

            for address_block in merged_blocks {
                self.map_peripheral_block_to_view(view, &updated_peripheral, &address_block);
            }
        }
    }

    pub fn map_peripheral_block_to_view(
        &self,
        view: &BinaryView,
        peripheral: &PeripheralInfo,
        address_block: &AddressBlock,
    ) {
        let block_addr = peripheral.base_address + address_block.offset as u64;
        log::info!(
            "Mapping peripheral block @ 0x{:x} for {}",
            block_addr,
            peripheral.name
        );

        // We don't postfix the block offset in case we only have a single peripheral address block
        // as it is unnecessary to talk about a unique block in that case.
        let periph_block_len = peripheral.address_block.as_ref().unwrap().len();
        let block_name = if address_block.offset == 0 || periph_block_len == 1 {
            // Block name: "PERIPH"
            peripheral.name.to_owned()
        } else {
            // Block name: "PERIPH_0x40"
            format!("{}_0x{:x}", peripheral.name, address_block.offset)
        };

        let memory_info =
            self.peripheral_block_memory_info(peripheral, address_block, block_name.clone());

        // Add the block segment, section and backing memory (optional).
        if self.settings.add_backing_regions {
            // Because adding a memory region will add a possibly large memory buffer in the BNDB, this
            // is optional. if a user disables this, they cannot write to the segment until they add a backing memory region.
            let data_memory = DataBuffer::new(&vec![0; address_block.size as usize]);
            let added_memory = view.memory_map().add_data_memory_region(
                &block_name,
                block_addr,
                &data_memory,
                Some(memory_info.segment_flags),
            );

            if !added_memory {
                log::error!(
                    "Failed to add memory for peripheral block! {} @ 0x{:x}",
                    block_name,
                    block_addr
                );
            }
        }

        view.add_segment(memory_info.segment);
        view.add_section(memory_info.section);

        // Handle usage specific stuff like adding registers.
        match address_block.usage {
            AddressBlockUsage::Registers => {
                // Registers get comments
                if self.settings.add_comments {
                    if let Some(periph_desc) = &peripheral.description {
                        // Add peripheral description
                        view.set_comment_at(block_addr, periph_desc);
                    }
                    // Add register descriptions
                    self.add_comments_for_registers(view, peripheral);
                }

                // Registers will get the peripheral type.
                let peripheral_ty = self.peripheral_type(peripheral, address_block);
                let peripheral_ty_id = format!("SVD:{}", peripheral.name);
                let id = view.define_auto_type_with_id(
                    &peripheral.name,
                    &peripheral_ty_id,
                    &peripheral_ty,
                );
                let ntr =
                    NamedTypeReference::new(NamedTypeReferenceClass::StructNamedTypeClass, id);
                view.define_auto_data_var(block_addr, &Type::named_type(&ntr));
                let symbol =
                    SymbolBuilder::new(SymbolType::Data, peripheral.name.to_owned(), block_addr)
                        .create();
                view.define_auto_symbol(&symbol);
            }
            AddressBlockUsage::Buffer => {
                let array_ty = Type::array(&Type::int(1, false), address_block.size as u64);
                view.define_auto_data_var(block_addr, &array_ty);
                let symbol_name = format!("buffer_0x{:x}", block_addr);
                let symbol = SymbolBuilder::new(SymbolType::Data, symbol_name, block_addr).create();
                view.define_auto_symbol(&symbol);
                view.set_comment_at(
                    block_addr,
                    &format!("Buffer block with size {}", address_block.size),
                );
            }
            AddressBlockUsage::Reserved => {
                // TODO: What to do for reserved blocks?
                view.set_comment_at(
                    block_addr,
                    &format!("Reserved block with size {}", address_block.size),
                );
            }
        }
    }

    pub fn add_comments_for_registers(&self, view: &BinaryView, peripheral: &PeripheralInfo) {
        // Adding comments will add a bunch of undo actions.
        let undo_id = view.file().begin_undo_actions(true);
        for register in peripheral.all_registers() {
            // Turns out the "enclosing element" seems to always be the peripheral base address?
            let register_addr = peripheral.base_address + register.address_offset as u64;
            if let Some(description) = &register.description {
                view.set_comment_at(register_addr, description);
            }

            // TODO: Add a setting to disable field comments
            if let Some(fields) = &register.fields {
                let (aligned, unaligned): (Vec<_>, Vec<_>) = fields.iter().partition(|f| {
                    byte_aligned(f.bit_range.width) && byte_aligned(f.bit_range.offset)
                });

                for field in aligned {
                    let field_byte_offset = field.bit_range.offset / 8;
                    let field_addr = register_addr + field_byte_offset as u64;
                    if let Some(description) = &field.description {
                        view.set_comment_at(field_addr, description);
                    }
                }

                let mut unaligned_comments = HashMap::new();
                for field in unaligned {
                    // For unaligned fields we want to provide more information such as the bit offset and width.
                    let field_byte_offset = field.bit_range.offset / 8;
                    let field_bit_width = field.bit_range.width;
                    let field_addr = register_addr + field_byte_offset as u64;
                    let mut field_comment = format!(
                        "{}-{} {}",
                        field.bit_range.offset,
                        field.bit_range.offset + field_bit_width - 1,
                        field.name
                    );

                    if let Some(description) = &field.description {
                        field_comment.push_str(&format!(": {}", description));
                    }

                    unaligned_comments
                        .entry(field_addr)
                        .or_insert_with(Vec::new)
                        .push(field_comment);
                }

                for (field_addr, comments) in unaligned_comments {
                    let comment = comments.join("\n");
                    view.set_comment_at(field_addr, &comment);
                }
            }
        }
        view.file().commit_undo_actions(&undo_id);
    }

    pub fn peripheral_block_memory_info(
        &self,
        peripheral: &PeripheralInfo,
        address_block: &AddressBlock,
        block_name: String,
    ) -> AddressBlockMemoryInfo {
        let block_addr = peripheral.base_address + address_block.offset as u64;
        let block_range = block_addr..(block_addr + address_block.size as u64);

        let block_access = peripheral.default_register_properties.access;
        let semantics = match block_access {
            Some(Access::ReadOnly) => Semantics::ReadOnlyData,
            Some(Access::ReadWrite | Access::ReadWriteOnce) => Semantics::ReadWriteData,
            // NOTE: Binary Ninja has no concept of write-only section semantics.
            Some(Access::WriteOnce | Access::WriteOnly) => Semantics::ReadWriteData,
            // TODO: This should never happen. We use the expand feature of svd_parser
            None => Semantics::ReadWriteData,
        };

        let (readable, writable) = match block_access {
            Some(Access::ReadOnly) => (true, false),
            Some(Access::ReadWrite | Access::ReadWriteOnce) => (true, true),
            Some(Access::WriteOnce | Access::WriteOnly) => (false, true),
            None => (true, true),
        };

        let section_type_str = match address_block.protection {
            Some(protection) => {
                // Section type: "peripheral:s"
                format!("peripheral:{}", protection.as_str())
            }
            None => {
                // Section type: "peripheral"
                "peripheral".to_string()
            }
        };

        let section = SectionBuilder::new(block_name, block_range.clone())
            .section_type(section_type_str)
            .semantics(semantics);
        let segment_flags = SegmentFlags::new()
            .contains_code(false)
            .contains_data(true)
            .deny_execute(true)
            .readable(readable)
            .writable(writable);
        let segment = SegmentBuilder::new(block_range).flags(segment_flags);

        AddressBlockMemoryInfo {
            segment,
            segment_flags,
            section,
        }
    }

    // TODO: In the future we might need to have partial types for each [`AddressBlock`]
    // TODO: Support using header name, this requires we define the peripheral type id as the real peripheral name.
    // TODO: cont. the reason is so that we can resolve the derived peripheral.
    pub fn peripheral_type(
        &self,
        peripheral: &PeripheralInfo,
        address_block: &AddressBlock,
    ) -> Ref<Type> {
        let mut peripheral_struct = StructureBuilder::new();

        if let Some(derived_periph_name) = &peripheral.derived_from {
            // We will create an NTR to ref the derived peripheral type.
            let ntr = NamedTypeReference::new(
                NamedTypeReferenceClass::StructNamedTypeClass,
                derived_periph_name,
            );
            let base_struct = BaseStructure::new(ntr, 0, 0);
            peripheral_struct.base_structures(&[base_struct]);
        }

        // Take the address block size and use it as the structure width.
        // TODO: Support non-contiguous register address blocks (i.e. partial types).
        peripheral_struct.width(address_block.size as u64);

        if let Some(register_clusters) = &peripheral.registers {
            for register_cluster in register_clusters {
                match register_cluster {
                    RegisterCluster::Register(register) => {
                        let mut register_member = self.register_member(register);
                        // TODO: If we want registers to be relative to the peripheral than we must
                        // TODO: assert that we create the peripheral type at offset 0 from the base address.
                        // Make the register member relative to the address block, not the peripheral.
                        register_member.offset -= address_block.offset as u64;
                        let overwrite = false; // TODO: Handle overwrites?
                        peripheral_struct.insert_member(register_member, overwrite);
                    }
                    RegisterCluster::Cluster(_cluster) => {
                        // TODO: Support clusters
                    }
                }
            }
        }

        Type::structure(&peripheral_struct.finalize())
    }

    pub fn register_member(&self, register: &Register) -> StructureMember {
        let register_ty = self.register_type(register);
        let conf_register_ty = Conf::new(register_ty, MAX_CONFIDENCE);
        StructureMember::new(
            conf_register_ty,
            register.name.to_owned(),
            register.address_offset as u64,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
    }

    pub fn register_type(&self, register: &Register) -> Ref<Type> {
        match register {
            Register::Single(info) => self.single_register_type(info),
            Register::Array(info, elem) => {
                // TODO: dimIncrement tells us the stride. We should consult that to
                // TODO: make sure that the accesses are aligned.
                Type::array(&self.single_register_type(info), elem.dim as u64)
            }
        }
    }

    pub fn single_register_type(&self, register: &RegisterInfo) -> Ref<Type> {
        match register.datatype {
            Some(data_type) => self.data_type(&data_type),
            None => {
                // No data type means we have a structure!
                let mut register_struct = StructureBuilder::new();

                // Constrain the width of the struct to the register size if available.
                if let Some(register_size) = register.properties.size {
                    let register_byte_size = byte_width(register_size);
                    register_struct.width(register_byte_size as u64);
                }

                if let Some(derived_register_name) = &register.derived_from {
                    // We will create an NTR to ref the derived register type.
                    let ntr = NamedTypeReference::new(
                        NamedTypeReferenceClass::StructNamedTypeClass,
                        derived_register_name,
                    );
                    let base_struct = BaseStructure::new(ntr, 0, 0);
                    register_struct.base_structures(&[base_struct]);
                }

                let type_builder = match &register.fields {
                    Some(fields) => {
                        // Separate bitfields from regular fields.
                        let (fields, bitfield_items): (Vec<_>, Vec<_>) =
                            fields.iter().partition(|f| {
                                byte_aligned(f.bit_range.width) && byte_aligned(f.bit_range.offset)
                            });

                        for field in fields {
                            let field_member = self.field_member(field);
                            let overwrites = true; // TODO: Handle overwrites?
                            register_struct.insert_member(field_member, overwrites);
                        }

                        if self.settings.add_bitfields {
                            // The bitfield items need to be coalesced to a map of byte offset to vec of fields.
                            let mut bitfield_map: HashMap<u64, Vec<&Field>> = HashMap::new();

                            // Sort bitfields by their offset
                            let mut sorted_bitfields = bitfield_items.iter().collect::<Vec<_>>();
                            sorted_bitfields.sort_by_key(|f| f.bit_range.offset);

                            // Group bitfields by overlapping bit offsets
                            let mut current_bit_start = 0;
                            let mut current_bit_end = 0;
                            for field in sorted_bitfields {
                                let bit_start = field.bit_range.offset;
                                let byte_start = bit_start / 8;
                                let current_byte_start = current_bit_start / 8;
                                if current_byte_start != byte_start && current_bit_end < bit_start {
                                    // Make a new bitfield, only if the current field is in a new byte.
                                    current_bit_start = bit_start;
                                }
                                current_bit_end = bit_start + field.bit_range.width;
                                bitfield_map
                                    .entry(current_bit_start as u64)
                                    .or_insert_with(Vec::new)
                                    .push(field);
                            }

                            for (bit_start, fields) in bitfield_map {
                                // Add each bitfield to the structure!
                                let byte_start = bit_start / 8;
                                let bitfield_member = self.bitfield_member(byte_start, fields);
                                let overwrites = true; // TODO: Handle overwrites?
                                register_struct.insert_member(bitfield_member, overwrites);
                            }
                        }

                        TypeBuilder::structure(&register_struct.finalize())
                    }
                    None if register.derived_from.is_some() => {
                        // Use the structure so that we get the base fields.
                        TypeBuilder::structure(&register_struct.finalize())
                    }
                    None => {
                        // We don't have any fields, or a derived register, attempt to construct type ourselves.
                        match register.properties.size {
                            Some(bit_width) => {
                                // We have a sized register, convert to byte aligned int.
                                let byte_aligned_width = byte_width(bit_width);
                                TypeBuilder::int(byte_aligned_width as usize, false)
                            }
                            None => {
                                // TODO: How can we construct a type here?
                                panic!("Register {} has no size!", register.name);
                            }
                        }
                    }
                };

                if let Some(Access::ReadOnly) = register.properties.access {
                    type_builder.set_const(true);
                }

                type_builder.finalize()
            }
        }
    }

    // TODO: Register access should be consulted to see if we should set as const.
    pub fn data_type(&self, data_type: &DataType) -> Ref<Type> {
        match data_type {
            DataType::U8 => Type::int(1, false),
            DataType::U16 => Type::int(2, false),
            DataType::U32 => Type::int(4, false),
            DataType::U64 => Type::int(8, false),
            DataType::I8 => Type::int(1, true),
            DataType::I16 => Type::int(2, true),
            DataType::I32 => Type::int(4, true),
            DataType::I64 => Type::int(8, true),
            // TODO: This can be cleaned up...
            DataType::U8Ptr => {
                Type::pointer_of_width(&Type::int(1, false), self.address_size, false, false, None)
            }
            DataType::U16Ptr => {
                Type::pointer_of_width(&Type::int(2, false), self.address_size, false, false, None)
            }
            DataType::U32Ptr => {
                Type::pointer_of_width(&Type::int(4, false), self.address_size, false, false, None)
            }
            DataType::U64Ptr => {
                Type::pointer_of_width(&Type::int(8, false), self.address_size, false, false, None)
            }
            DataType::I8Ptr => {
                Type::pointer_of_width(&Type::int(1, true), self.address_size, false, false, None)
            }
            DataType::I16Ptr => {
                Type::pointer_of_width(&Type::int(2, true), self.address_size, false, false, None)
            }
            DataType::I32Ptr => {
                Type::pointer_of_width(&Type::int(4, true), self.address_size, false, false, None)
            }
            DataType::I64Ptr => {
                Type::pointer_of_width(&Type::int(8, true), self.address_size, false, false, None)
            }
        }
    }

    pub fn bitfield_member(&self, byte_offset: u64, fields: Vec<&Field>) -> StructureMember {
        let field_ty = self.bitfield_type(byte_offset, fields);
        // TODO: Create bitfield name from the fields?
        let field_name = format!("bitfield_0x{:x}", byte_offset);
        // TODO: This should be like 120 confidence?
        let conf_field_ty = Conf::new(field_ty, MAX_CONFIDENCE);
        StructureMember::new(
            conf_field_ty,
            field_name,
            byte_offset,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
    }

    pub fn bitfield_type(&self, byte_offset: u64, fields: Vec<&Field>) -> Ref<Type> {
        let mut union_builder = StructureBuilder::new();
        union_builder.structure_type(StructureType::UnionStructureType);
        for field in fields {
            let mut field_member = self.field_member(field);
            // Field members are relative to the union member, so we must remove the union member offset
            // from the field member offset to make it relative to the union member.
            field_member.offset -= byte_offset;
            let overwrites = false; // TODO: Handle overwrites?
            union_builder.insert_member(field_member, overwrites);
        }
        Type::structure(&union_builder.finalize())
    }

    pub fn field_member(&self, field: &Field) -> StructureMember {
        let field_ty = self.field_type(field);
        let conf_field_ty = Conf::new(field_ty, MAX_CONFIDENCE);
        let byte_offset = field.bit_offset() / 8;
        StructureMember::new(
            conf_field_ty,
            field.name.to_owned(),
            byte_offset as u64,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        )
    }

    pub fn field_type(&self, field: &Field) -> Ref<Type> {
        match field {
            Field::Single(info) => self.single_field_type(info),
            Field::Array(info, elem) => {
                // TODO: dimIncrement tells us the stride. We should consult that to
                // TODO: make sure that the accesses are aligned.
                Type::array(&self.single_field_type(info), elem.dim as u64)
            }
        }
    }

    // TODO: Handle enum type.
    // TODO: Fields can derive from one another.
    pub fn single_field_type(&self, field: &FieldInfo) -> Ref<Type> {
        match field.enumerated_values.len() {
            0 => self.single_field_int_type(field),
            1 => {
                // Unlike normal fields, enums must be registered with the view separately.
                // If you do not register the enum with the view than you cannot view the enum type!
                // TODO: Register enum type so they can be viewed.
                self.single_field_enumerated_type(field, &field.enumerated_values[0])
            }
            arr_len => {
                // TODO: Untested, I guess this works?
                let enum_value_ty =
                    self.single_field_enumerated_type(field, &field.enumerated_values[0]);
                Type::array(&enum_value_ty, arr_len as u64)
            }
        }
    }

    pub fn single_field_int_type(&self, field: &FieldInfo) -> Ref<Type> {
        // TODO: Binary Ninja is unable to handle bit fields, so we abuse unions.
        // Get the closest 8-bit aligned integer and use that.
        let width = field.bit_width();
        let byte_aligned_width = byte_width(width);
        let type_builder = TypeBuilder::int(byte_aligned_width as usize, false);
        if let Some(Access::ReadOnly) = field.access {
            // We set fields to volatile as well to prevent constant value propagation.
            type_builder.set_volatile(true);
            type_builder.set_const(true);
        }
        type_builder.finalize()
    }

    // TODO: EnumeratedValues can derive from one another.
    pub fn single_field_enumerated_type(
        &self,
        field: &FieldInfo,
        enumerated_values: &EnumeratedValues,
    ) -> Ref<Type> {
        // Get the closest 8-bit aligned integer and use that.
        let width = field.bit_width();
        let byte_aligned_width = byte_width(width);
        let mut enum_builder = EnumerationBuilder::new();

        let mut current_value = 0;
        for enumerated_value in &enumerated_values.values {
            current_value = enumerated_value.value.unwrap_or(current_value + 1);
            // TODO: The Rust API needs to expose this...
            let _is_default = enumerated_value.is_default.unwrap_or(false);
            enum_builder.insert(&enumerated_value.name, current_value);
        }

        let enum_width = NonZeroUsize::new(byte_aligned_width as usize).unwrap();
        let type_builder = TypeBuilder::enumeration(&enum_builder.finalize(), enum_width, false);

        if let Some(Usage::Read) = enumerated_values.usage {
            // We set fields to volatile as well to prevent constant value propagation.
            type_builder.set_volatile(true);
            type_builder.set_const(true);
        }

        type_builder.finalize()
    }
}
