use std::fmt::{Debug, Formatter};

use binaryninjacore_sys::*;

use crate::confidence::Conf;
use crate::rc::{CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{raw_to_string, BnString, IntoCStr};
use crate::types::{NamedTypeReference, Type};

pub type StructureType = BNStructureVariant;
pub type MemberAccess = BNMemberAccess;
pub type MemberScope = BNMemberScope;

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

    pub fn insert_member(
        &mut self,
        member: StructureMember,
        overwrite_existing: bool,
    ) -> &mut Self {
        self.insert(
            &member.ty,
            &member.name,
            member.offset,
            overwrite_existing,
            member.access,
            member.scope,
        );
        self
    }

    pub fn insert<'a, T: Into<Conf<&'a Type>>>(
        &mut self,
        ty: T,
        name: &str,
        offset: u64,
        overwrite_existing: bool,
        access: MemberAccess,
        scope: MemberScope,
    ) -> &mut Self {
        let name = name.to_cstr();
        let owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNAddStructureBuilderMemberAtOffset(
                self.handle,
                &owned_raw_ty,
                name.as_ref().as_ptr() as _,
                offset,
                overwrite_existing,
                access,
                scope,
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

    pub fn base_structures(&self) -> Vec<BaseStructure> {
        let mut count = 0;
        let bases_raw_ptr = unsafe { BNGetBaseStructuresForStructure(self.handle, &mut count) };
        debug_assert!(!bases_raw_ptr.is_null());
        let bases_raw = unsafe { std::slice::from_raw_parts(bases_raw_ptr, count) };
        let bases = bases_raw.iter().map(BaseStructure::from_raw).collect();
        unsafe { BNFreeBaseStructureList(bases_raw_ptr, count) };
        bases
    }

    // TODO : The other methods in the python version (alignment, packed, type, members, remove, replace, etc)
}

impl Debug for Structure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Structure")
            .field("width", &self.width())
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
    pub offset: u64,
    pub access: MemberAccess,
    pub scope: MemberScope,
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
        }
    }

    pub(crate) fn from_owned_raw(value: BNStructureMember) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNStructureMember {
        let bn_name = BnString::new(value.name);
        BNStructureMember {
            type_: unsafe { Ref::into_raw(value.ty.contents) }.handle,
            name: BnString::into_raw(bn_name),
            offset: value.offset,
            typeConfidence: value.ty.confidence,
            access: value.access,
            scope: value.scope,
        }
    }

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
        }
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

    pub(crate) fn from_owned_raw(value: BNBaseStructure) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

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

    pub(crate) fn free_raw(value: BNBaseStructure) {
        let _ = unsafe { NamedTypeReference::ref_from_raw(value.type_) };
    }

    pub fn new(ty: Ref<NamedTypeReference>, offset: u64, width: u64) -> Self {
        Self { ty, offset, width }
    }
}
