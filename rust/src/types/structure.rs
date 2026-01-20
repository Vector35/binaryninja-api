use crate::confidence::Conf;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};
use crate::types::{
    MemberAccess, MemberScope, NamedTypeReference, StructureType, Type, TypeContainer,
};
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

// Needed for doc comments
#[allow(unused)]
use crate::binary_view::BinaryViewExt;

#[derive(PartialEq, Eq, Hash)]
pub struct StructureBuilder {
    pub(crate) handle: *mut BNStructureBuilder,
}

/// ```no_run
/// // Includes
/// # use binaryninja::binary_view::BinaryViewExt;
/// use binaryninja::types::{MemberAccess, MemberScope, Structure, StructureBuilder, Type};
///
/// // Types to use in the members
/// let field_1_ty = Type::named_int(5, false, "my_weird_int_type");
/// let field_2_ty = Type::int(4, false);
/// let field_3_ty = Type::int(8, false);
///
/// // Assign those fields
/// let mut my_custom_struct = StructureBuilder::new();
/// my_custom_struct
///     .insert(
///         &field_1_ty,
///         "field_1",
///         0,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .insert(
///         &field_2_ty,
///         "field_2",
///         5,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .insert(
///         &field_3_ty,
///         "field_3",
///         9,
///         false,
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     )
///     .append(
///         &field_1_ty,
///         "field_4",
///         MemberAccess::PublicAccess,
///         MemberScope::NoScope,
///     );
///
/// // Convert structure to type
/// let my_custom_structure_type = Type::structure(&my_custom_struct.finalize());
///
/// // Add the struct to the binary view to use in analysis
/// let bv = binaryninja::load("example").unwrap();
/// bv.define_user_type("my_custom_struct", &my_custom_structure_type);
/// ```
impl StructureBuilder {
    pub fn new() -> Self {
        Self {
            handle: unsafe { BNCreateStructureBuilder() },
        }
    }

    pub(crate) unsafe fn from_raw(handle: *mut BNStructureBuilder) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    // TODO: Document the width adjustment with alignment.
    pub fn finalize(&self) -> Ref<Structure> {
        let raw_struct_ptr = unsafe { BNFinalizeStructureBuilder(self.handle) };
        unsafe { Structure::ref_from_raw(raw_struct_ptr) }
    }

    /// Sets the width of the [`StructureBuilder`] to the new width.
    ///
    /// This will remove all previously inserted members outside the new width. This is done by computing
    /// the member access range (member offset + member width) and if it is larger than the new width
    /// it will be removed.
    pub fn width(&mut self, width: u64) -> &mut Self {
        unsafe {
            BNSetStructureBuilderWidth(self.handle, width);
        }
        self
    }

    pub fn alignment(&mut self, alignment: usize) -> &mut Self {
        unsafe {
            BNSetStructureBuilderAlignment(self.handle, alignment);
        }
        self
    }

    /// Sets whether the [`StructureBuilder`] is packed.
    ///
    /// If set the alignment of the structure will be `1`. You do not need to set the alignment to `1`.
    pub fn packed(&mut self, packed: bool) -> &mut Self {
        unsafe {
            BNSetStructureBuilderPacked(self.handle, packed);
        }
        self
    }

    pub fn structure_type(&mut self, t: StructureType) -> &mut Self {
        unsafe { BNSetStructureBuilderType(self.handle, t) };
        self
    }

    pub fn pointer_offset(&mut self, offset: i64) -> &mut Self {
        unsafe { BNSetStructureBuilderPointerOffset(self.handle, offset) };
        self
    }

    pub fn propagates_data_var_refs(&mut self, propagates: bool) -> &mut Self {
        unsafe { BNSetStructureBuilderPropagatesDataVariableReferences(self.handle, propagates) };
        self
    }

    pub fn base_structures(&mut self, bases: &[BaseStructure]) -> &mut Self {
        let raw_base_structs: Vec<BNBaseStructure> =
            bases.iter().map(BaseStructure::into_owned_raw).collect();
        unsafe {
            BNSetBaseStructuresForStructureBuilder(
                self.handle,
                raw_base_structs.as_ptr() as *mut _,
                raw_base_structs.len(),
            )
        };
        self
    }

    /// Append a member at the next available byte offset.
    ///
    /// Otherwise, consider using:
    ///
    /// - [`StructureBuilder::insert_member`]
    /// - [`StructureBuilder::insert`]
    /// - [`StructureBuilder::insert_bitwise`]
    pub fn append<'a, T: Into<Conf<&'a Type>>>(
        &mut self,
        ty: T,
        name: &str,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        let name = name.to_cstr();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNAddStructureBuilderMember(
                self.handle,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                access,
                scope,
            );
        }
        self
    }

    /// Insert an already constructed [`StructureMember`].
    ///
    /// Otherwise, consider using:
    ///
    /// - [`StructureBuilder::append`]
    /// - [`StructureBuilder::insert`]
    /// - [`StructureBuilder::insert_bitwise`]
    pub fn insert_member(
        &mut self,
        member: StructureMember,
        overwrite_existing: bool,
    ) -> &mut Self {
        self.insert_bitwise(
            &member.ty,
            &member.name,
            member.bit_offset(),
            member.bit_width,
            overwrite_existing,
            member.access,
            member.scope,
        );
        self
    }

    /// Inserts a member at the `offset` (in bytes).
    ///
    /// If you need to insert a member at a specific bit within a given byte (like a bitfield), you
    /// can use [`StructureBuilder::insert_bitwise`].
    pub fn insert<'a, T: Into<Conf<&'a Type>>>(
        &mut self,
        ty: T,
        name: &str,
        offset: u64,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        self.insert_bitwise(
            ty,
            name,
            offset * 8,
            None,
            overwrite_existing,
            access,
            scope,
        )
    }

    /// Inserts a member at `bit_offset` with an optional `bit_width`.
    ///
    /// NOTE: The `bit_offset` is relative to the start of the structure, for example, passing `8` will place
    /// the field at the start of the byte `0x1`.
    pub fn insert_bitwise<'a, T: Into<Conf<&'a Type>>>(
        &mut self,
        ty: T,
        name: &str,
        bit_offset: u64,
        bit_width: Option<u8>,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        let name = name.to_cstr();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        let byte_offset = bit_offset / 8;
        let bit_position = bit_offset % 8;
        unsafe {
            BNAddStructureBuilderMemberAtOffset(
                self.handle,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                byte_offset,
                overwrite_existing,
                access,
                scope,
                bit_position as u8,
                bit_width.unwrap_or(0),
            );
        }
        self
    }

    pub fn replace<'a, T: Into<Conf<&'a Type>>>(
        &mut self,
        index: usize,
        ty: T,
        name: &str,
        overwrite_existing: bool,
    ) -> &mut Self {
        let name = name.to_cstr();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNReplaceStructureBuilderMember(
                self.handle,
                index,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                overwrite_existing,
            )
        }
        self
    }

    /// Removes the member at a given index.
    pub fn remove(&mut self, index: usize) -> &mut Self {
        unsafe { BNRemoveStructureBuilderMember(self.handle, index) };
        self
    }

    // TODO: We should add BNGetStructureBuilderAlignedWidth
    /// Gets the current **unaligned** width of the structure.
    ///
    /// This cannot be used to accurately get the width of a non-packed structure.
    pub fn current_width(&self) -> u64 {
        unsafe { BNGetStructureBuilderWidth(self.handle) }
    }
}

impl From<&Structure> for StructureBuilder {
    fn from(structure: &Structure) -> StructureBuilder {
        unsafe { Self::from_raw(BNCreateStructureBuilderFromStructure(structure.handle)) }
    }
}

impl From<Vec<StructureMember>> for StructureBuilder {
    fn from(members: Vec<StructureMember>) -> StructureBuilder {
        let mut builder = StructureBuilder::new();
        for member in members {
            builder.insert_member(member, false);
        }
        builder
    }
}

impl Drop for StructureBuilder {
    fn drop(&mut self) {
        unsafe { BNFreeStructureBuilder(self.handle) };
    }
}

impl Default for StructureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Structure {
    pub(crate) handle: *mut BNStructure,
}

impl Structure {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNStructure) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn builder() -> StructureBuilder {
        StructureBuilder::new()
    }

    pub fn width(&self) -> u64 {
        unsafe { BNGetStructureWidth(self.handle) }
    }

    pub fn structure_type(&self) -> StructureType {
        unsafe { BNGetStructureType(self.handle) }
    }

    /// Retrieve the members that are accessible at a given offset.
    ///
    /// The reason for this being plural is that members may overlap and the offset is in bytes
    /// where a bitfield may contain multiple members at the given byte.
    ///
    /// Unions are also represented as structures and will cause this function to return
    /// **all** members that can reach that offset.
    ///
    /// We must pass a [`TypeContainer`] here so that we can resolve base structure members, as they
    /// are treated as members through this function. Typically, you get the [`TypeContainer`]
    /// through the binary view with [`BinaryViewExt::type_container`].
    pub fn members_at_offset(
        &self,
        container: &TypeContainer,
        offset: u64,
    ) -> Vec<StructureMember> {
        self.members_including_inherited(container)
            .into_iter()
            .filter(|m| m.member.is_offset_valid(offset))
            .map(|m| m.member)
            .collect()
    }

    /// Return the list of non-inherited structure members.
    ///
    /// If you want to get all members, including ones inherited from base structures,
    /// use [`Structure::members_including_inherited`] instead.
    pub fn members(&self) -> Vec<StructureMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr: *mut BNStructureMember =
                BNGetStructureMembers(self.handle, &mut count);
            debug_assert!(!members_raw_ptr.is_null());
            let members_raw = std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw.iter().map(StructureMember::from_raw).collect();
            BNFreeStructureMemberList(members_raw_ptr, count);
            members
        }
    }

    /// Returns the list of all structure members, including inherited ones.
    ///
    /// Because we must traverse through base structures, we have to provide the [`TypeContainer`];
    /// in most cases it is ok to provide the binary views container via [`BinaryViewExt::type_container`].
    pub fn members_including_inherited(
        &self,
        container: &TypeContainer,
    ) -> Vec<InheritedStructureMember> {
        unsafe {
            let mut count = 0;
            let members_raw_ptr: *mut BNInheritedStructureMember =
                BNGetStructureMembersIncludingInherited(
                    self.handle,
                    container.handle.as_ptr(),
                    &mut count,
                );
            debug_assert!(!members_raw_ptr.is_null());
            let members_raw = std::slice::from_raw_parts(members_raw_ptr, count);
            let members = members_raw
                .iter()
                .map(InheritedStructureMember::from_raw)
                .collect();
            BNFreeInheritedStructureMemberList(members_raw_ptr, count);
            members
        }
    }

    /// Retrieve the list of base structures for the structure. These base structures are what give
    /// a structure inherited members.
    pub fn base_structures(&self) -> Vec<BaseStructure> {
        let mut count = 0;
        let bases_raw_ptr = unsafe { BNGetBaseStructuresForStructure(self.handle, &mut count) };
        debug_assert!(!bases_raw_ptr.is_null());
        let bases_raw = unsafe { std::slice::from_raw_parts(bases_raw_ptr, count) };
        let bases = bases_raw.iter().map(BaseStructure::from_raw).collect();
        unsafe { BNFreeBaseStructureList(bases_raw_ptr, count) };
        bases
    }

    /// Whether the structure is packed or not.
    pub fn is_packed(&self) -> bool {
        unsafe { BNIsStructurePacked(self.handle) }
    }

    pub fn alignment(&self) -> usize {
        unsafe { BNGetStructureAlignment(self.handle) }
    }
}

impl Debug for Structure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Structure")
            .field("width", &self.width())
            .field("alignment", &self.alignment())
            .field("packed", &self.is_packed())
            .field("structure_type", &self.structure_type())
            .field("base_structures", &self.base_structures())
            .field("members", &self.members())
            .finish()
    }
}

unsafe impl RefCountable for Structure {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Self::ref_from_raw(BNNewStructureReference(handle.handle))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeStructure(handle.handle);
    }
}

impl ToOwned for Structure {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StructureMember {
    pub ty: Conf<Ref<Type>>,
    // TODO: Shouldnt this be a QualifiedName? The ffi says no...
    pub name: String,
    /// The byte offset of the member.
    pub offset: u64,
    pub access: MemberAccess,
    pub scope: MemberScope,
    /// The bit position relative to the byte offset.
    pub bit_position: Option<u8>,
    pub bit_width: Option<u8>,
}

impl StructureMember {
    pub(crate) fn from_raw(value: &BNStructureMember) -> Self {
        Self {
            ty: Conf::new(
                unsafe { Type::from_raw(value.type_) }.to_owned(),
                value.typeConfidence,
            ),
            // TODO: I dislike using this function here.
            name: raw_to_string(value.name as *mut _).unwrap(),
            offset: value.offset,
            access: value.access,
            scope: value.scope,
            bit_position: match value.bitPosition {
                0 => None,
                _ => Some(value.bitPosition),
            },
            bit_width: match value.bitWidth {
                0 => None,
                _ => Some(value.bitWidth),
            },
        }
    }

    #[allow(unused)]
    pub(crate) fn from_owned_raw(value: BNStructureMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    #[allow(unused)]
    pub(crate) fn into_raw(value: Self) -> BNStructureMember {
        let bn_name = BnString::new(value.name);
        BNStructureMember {
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            name: BnString::into_raw(bn_name),
            offset: value.offset,
            typeConfidence: value.ty.confidence,
            access: value.access,
            scope: value.scope,
            bitPosition: value.bit_position.unwrap_or(0),
            bitWidth: value.bit_width.unwrap_or(0),
        }
    }

    #[allow(unused)]
    pub(crate) fn free_raw(value: BNStructureMember) {
        let _ = unsafe { Type::ref_from_raw(value.type_) };
        unsafe { BnString::free_raw(value.name) };
    }

    pub fn new(
        ty: Conf<Ref<Type>>,
        name: String,
        offset: u64,
        access: MemberAccess,
        scope: MemberScope,
    ) -> Self {
        Self {
            ty,
            name,
            offset,
            access,
            scope,
            bit_position: None,
            bit_width: None,
        }
    }

    pub fn new_bitfield(
        ty: Conf<Ref<Type>>,
        name: String,
        bit_offset: u64,
        bit_width: u8,
        access: MemberAccess,
        scope: MemberScope,
    ) -> Self {
        Self {
            ty,
            name,
            offset: bit_offset / 8,
            access,
            scope,
            bit_position: Some((bit_offset % 8) as u8),
            bit_width: Some(bit_width),
        }
    }

    // TODO: Do we count bitwidth here?
    /// Whether the offset within the accessible range of the member.
    pub fn is_offset_valid(&self, offset: u64) -> bool {
        self.offset <= offset && offset < self.offset + self.ty.contents.width()
    }

    /// Member offset in bits.
    pub fn bit_offset(&self) -> u64 {
        (self.offset * 8) + self.bit_position.unwrap_or(0) as u64
    }

    /// Member width in bits.
    ///
    /// NOTE: This is a helper to calculate the bit width of the member, even for non-bitfield members.
    /// This is not to be confused with the field `bit_width`, which is set for only bitfield members.
    pub fn width_in_bits(&self) -> u64 {
        self.bit_width
            .map(|w| w as u64)
            .unwrap_or(self.ty.contents.width() * 8)
    }
}

impl CoreArrayProvider for StructureMember {
    type Raw = BNStructureMember;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for StructureMember {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStructureMemberList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct InheritedStructureMember {
    pub base: Ref<NamedTypeReference>,
    pub base_offset: u64,
    pub member: StructureMember,
    pub member_index: usize,
}

impl InheritedStructureMember {
    pub(crate) fn from_raw(value: &BNInheritedStructureMember) -> Self {
        Self {
            base: unsafe { NamedTypeReference::from_raw(value.base) }.to_owned(),
            base_offset: value.baseOffset,
            member: StructureMember::from_raw(&value.member),
            member_index: value.memberIndex,
        }
    }

    #[allow(unused)]
    pub(crate) fn from_owned_raw(value: BNInheritedStructureMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    #[allow(unused)]
    pub(crate) fn into_raw(value: Self) -> BNInheritedStructureMember {
        BNInheritedStructureMember {
            base: unsafe { Ref::into_raw(value.base) }.handle,
            baseOffset: value.base_offset,
            member: StructureMember::into_raw(value.member),
            memberIndex: value.member_index,
        }
    }

    #[allow(unused)]
    pub(crate) fn free_raw(value: BNInheritedStructureMember) {
        let _ = unsafe { NamedTypeReference::ref_from_raw(value.base) };
        StructureMember::free_raw(value.member);
    }

    pub fn new(
        base: Ref<NamedTypeReference>,
        base_offset: u64,
        member: StructureMember,
        member_index: usize,
    ) -> Self {
        Self {
            base,
            base_offset,
            member,
            member_index,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BaseStructure {
    pub ty: Ref<NamedTypeReference>,
    pub offset: u64,
    pub width: u64,
}

impl BaseStructure {
    pub(crate) fn from_raw(value: &BNBaseStructure) -> Self {
        Self {
            ty: unsafe { NamedTypeReference::from_raw(value.type_) }.to_owned(),
            offset: value.offset,
            width: value.width,
        }
    }

    #[allow(unused)]
    pub(crate) fn from_owned_raw(value: BNBaseStructure) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    #[allow(unused)]
    pub(crate) fn into_raw(value: Self) -> BNBaseStructure {
        BNBaseStructure {
            type_: unsafe { Ref::into_raw(value.ty) }.handle,
            offset: value.offset,
            width: value.width,
        }
    }

    pub(crate) fn into_owned_raw(value: &Self) -> BNBaseStructure {
        BNBaseStructure {
            type_: value.ty.handle,
            offset: value.offset,
            width: value.width,
        }
    }

    #[allow(unused)]
    pub(crate) fn free_raw(value: BNBaseStructure) {
        let _ = unsafe { NamedTypeReference::ref_from_raw(value.type_) };
    }

    pub fn new(ty: Ref<NamedTypeReference>, offset: u64, width: u64) -> Self {
        Self { ty, offset, width }
    }
}
