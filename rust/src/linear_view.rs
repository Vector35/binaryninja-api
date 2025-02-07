// Copyright 2022-2024 Vector 35 Inc.
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

//! APIs for accessing Binary Ninja's linear view

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::disassembly::{DisassemblySettings, DisassemblyTextLine};
use crate::function::{Function, NativeBlock};

use crate::basic_block::BasicBlock;
use crate::rc::*;
use crate::render_layer::CoreRenderLayer;
use crate::string::{raw_to_string, BnString};
use std::ops::Deref;

pub type LinearDisassemblyLineType = BNLinearDisassemblyLineType;
pub type LinearViewObjectIdentifierType = BNLinearViewObjectIdentifierType;

pub struct LinearViewObject {
    pub(crate) handle: *mut BNLinearViewObject,
}

impl LinearViewObject {
    pub(crate) unsafe fn from_raw(handle: *mut BNLinearViewObject) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNLinearViewObject) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn identifier(&self) -> LinearViewObjectIdentifier {
        let raw = unsafe { BNGetLinearViewObjectIdentifier(self.handle) };
        LinearViewObjectIdentifier::from_owned_raw(raw)
    }

    pub fn data_only(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewDataOnly(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn disassembly(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewDisassembly(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn lifted_il(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewLiftedIL(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn mlil(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewMediumLevelIL(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn mlil_ssa(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewMediumLevelILSSAForm(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn hlil(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewHighLevelIL(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn hlil_ssa(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewHighLevelILSSAForm(view.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn language_representation(
        view: &BinaryView,
        settings: &DisassemblySettings,
        language: &str,
    ) -> Ref<Self> {
        unsafe {
            let language = std::ffi::CString::new(language).unwrap();
            let handle = BNCreateLinearViewLanguageRepresentation(
                view.handle,
                settings.handle,
                language.as_ptr(),
            );

            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_disassembly(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle =
                BNCreateLinearViewSingleFunctionDisassembly(function.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_lifted_il(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewSingleFunctionLiftedIL(function.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_mlil(function: &Function, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                BNCreateLinearViewSingleFunctionMediumLevelIL(function.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_mlil_ssa(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
                function.handle,
                settings.handle,
            );
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_hlil(function: &Function, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                BNCreateLinearViewSingleFunctionHighLevelIL(function.handle, settings.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_hlil_ssa(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
                function.handle,
                settings.handle,
            );
            Self::ref_from_raw(handle)
        }
    }

    pub fn single_function_language_representation(
        function: &Function,
        settings: &DisassemblySettings,
        language: &str,
    ) -> Ref<Self> {
        unsafe {
            let language = std::ffi::CString::new(language).unwrap();
            let handle = BNCreateLinearViewSingleFunctionLanguageRepresentation(
                function.handle,
                settings.handle,
                language.as_ptr(),
            );
            Self::ref_from_raw(handle)
        }
    }

    pub fn create_cursor(&self) -> Ref<LinearViewCursor> {
        unsafe {
            let handle = BNCreateLinearViewCursor(self.handle);
            LinearViewCursor::ref_from_raw(handle)
        }
    }
}

unsafe impl RefCountable for LinearViewObject {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewLinearViewObjectReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLinearViewObject(handle.handle);
    }
}

impl ToOwned for LinearViewObject {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for LinearViewObject {}
unsafe impl Sync for LinearViewObject {}

#[derive(Clone, PartialEq, Debug)]
pub struct LinearViewObjectIdentifier {
    pub name: String,
    pub ty: LinearViewObjectIdentifierType,
    pub start: u64,
    pub end: u64,
}

impl LinearViewObjectIdentifier {
    pub fn from_raw(value: &BNLinearViewObjectIdentifier) -> Self {
        Self {
            name: raw_to_string(value.name).unwrap(),
            ty: value.type_,
            start: value.start,
            end: value.end,
        }
    }

    pub fn from_owned_raw(value: BNLinearViewObjectIdentifier) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub fn into_raw(value: Self) -> BNLinearViewObjectIdentifier {
        let bn_name = BnString::new(value.name);
        BNLinearViewObjectIdentifier {
            name: BnString::into_raw(bn_name),
            type_: value.ty,
            start: value.start,
            end: value.end,
        }
    }

    pub fn free_raw(value: BNLinearViewObjectIdentifier) {
        let _ = unsafe { BnString::from_raw(value.name) };
    }
}

// TODO: Impl iterator?
#[derive(Eq)]
pub struct LinearViewCursor {
    pub(crate) handle: *mut BNLinearViewCursor,
}

impl LinearViewCursor {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNLinearViewCursor) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// Gets the current [`LinearViewObject`] associated with this cursor.
    pub fn current_object(&self) -> Ref<LinearViewObject> {
        unsafe {
            let handle = BNGetLinearViewCursorCurrentObject(self.handle);
            LinearViewObject::ref_from_raw(handle)
        }
    }

    pub fn duplicate(&self) -> Ref<Self> {
        unsafe {
            let handle = BNDuplicateLinearViewCursor(self.handle);
            Self::ref_from_raw(handle)
        }
    }

    pub fn before_begin(&self) -> bool {
        unsafe { BNIsLinearViewCursorBeforeBegin(self.handle) }
    }

    pub fn after_end(&self) -> bool {
        unsafe { BNIsLinearViewCursorAfterEnd(self.handle) }
    }

    pub fn valid(&self) -> bool {
        !(self.before_begin() || self.after_end())
    }

    pub fn seek_to_start(&mut self) {
        unsafe { BNSeekLinearViewCursorToBegin(self.handle) }
    }

    pub fn seek_to_end(&mut self) {
        unsafe { BNSeekLinearViewCursorToEnd(self.handle) }
    }

    pub fn seek_to_address(&mut self, address: u64) {
        unsafe { BNSeekLinearViewCursorToAddress(self.handle, address) }
    }

    pub fn ordering_index(&self) -> std::ops::Range<u64> {
        unsafe {
            let range = BNGetLinearViewCursorOrderingIndex(self.handle);
            range.start..range.end
        }
    }

    pub fn ordering_index_total(&self) -> u64 {
        unsafe { BNGetLinearViewCursorOrderingIndexTotal(self.handle) }
    }

    pub fn seek_to_ordering_index(&mut self, idx: u64) {
        unsafe { BNSeekLinearViewCursorToAddress(self.handle, idx) }
    }

    pub fn previous(&mut self) -> bool {
        unsafe { BNLinearViewCursorPrevious(self.handle) }
    }

    // TODO: This clippy lint is probably right? Just a lot of work and it would
    // TODO: make this API different from the python and C++ implementations.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        unsafe { BNLinearViewCursorNext(self.handle) }
    }

    pub fn lines(&self) -> Array<LinearDisassemblyLine> {
        let mut count: usize = 0;
        unsafe {
            let handles = BNGetLinearViewCursorLines(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    /// A list of the currently applied [`CoreRenderLayer`]'s
    pub fn render_layers(&self) -> Array<CoreRenderLayer> {
        let mut count: usize = 0;
        unsafe {
            let handles = BNGetLinearViewCursorRenderLayers(self.handle, &mut count);
            Array::new(handles, count, ())
        }
    }

    /// Add a Render Layer to be applied to this [`LinearViewCursor`].
    ///
    /// NOTE: Layers will be applied in the order in which they are added.
    pub fn add_render_layer(&self, layer: &CoreRenderLayer) {
        unsafe { BNAddLinearViewCursorRenderLayer(self.handle, layer.handle.as_ptr()) };
    }

    /// Remove a Render Layer from being applied to this [`LinearViewCursor`].
    pub fn remove_render_layer(&self, layer: &CoreRenderLayer) {
        unsafe { BNRemoveLinearViewCursorRenderLayer(self.handle, layer.handle.as_ptr()) };
    }
}

impl PartialEq for LinearViewCursor {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNCompareLinearViewCursors(self.handle, other.handle) == 0 }
    }
}

impl PartialOrd for LinearViewCursor {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LinearViewCursor {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match unsafe { BNCompareLinearViewCursors(self.handle, other.handle) } {
            i if i < 0 => std::cmp::Ordering::Less,
            i if i > 0 => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        }
    }
}

unsafe impl RefCountable for LinearViewCursor {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewLinearViewCursorReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeLinearViewCursor(handle.handle);
    }
}

impl ToOwned for LinearViewCursor {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for LinearViewCursor {}
unsafe impl Sync for LinearViewCursor {}

#[derive(Clone, PartialEq, Debug, Eq)]
pub struct LinearDisassemblyLine {
    pub ty: LinearDisassemblyLineType,
    pub function: Option<Ref<Function>>,
    pub basic_block: Option<Ref<BasicBlock<NativeBlock>>>,
    pub contents: DisassemblyTextLine,
}

impl LinearDisassemblyLine {
    pub(crate) unsafe fn from_raw(value: &BNLinearDisassemblyLine) -> Self {
        let function = if !value.function.is_null() {
            Some(unsafe { Function::from_raw(value.function).to_owned() })
        } else {
            None
        };
        let basic_block = if !value.block.is_null() {
            Some(unsafe { BasicBlock::from_raw(value.block, NativeBlock::new()).to_owned() })
        } else {
            None
        };
        Self {
            ty: value.type_,
            function,
            basic_block,
            contents: DisassemblyTextLine::from_raw(&value.contents),
        }
    }

    #[allow(unused)]
    pub(crate) unsafe fn from_owned_raw(value: BNLinearDisassemblyLine) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNLinearDisassemblyLine {
        let function_ptr = value
            .function
            .map(|f| unsafe { Ref::into_raw(f) }.handle)
            .unwrap_or(std::ptr::null_mut());
        let block_ptr = value
            .basic_block
            .map(|b| unsafe { Ref::into_raw(b) }.handle)
            .unwrap_or(std::ptr::null_mut());
        BNLinearDisassemblyLine {
            type_: value.ty,
            function: function_ptr,
            block: block_ptr,
            contents: DisassemblyTextLine::into_raw(value.contents),
        }
    }

    pub(crate) fn free_raw(value: BNLinearDisassemblyLine) {
        if !value.function.is_null() {
            let _ = unsafe { Function::ref_from_raw(value.function) };
        }
        if !value.block.is_null() {
            let _ = unsafe { BasicBlock::ref_from_raw(value.block, NativeBlock::new()) };
        }
        DisassemblyTextLine::free_raw(value.contents);
    }
}

impl Deref for LinearDisassemblyLine {
    type Target = DisassemblyTextLine;
    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

impl std::fmt::Display for LinearDisassemblyLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.contents)
    }
}

impl CoreArrayProvider for LinearDisassemblyLine {
    type Raw = BNLinearDisassemblyLine;
    type Context = ();
    type Wrapped<'a> = LinearDisassemblyLine;
}

unsafe impl CoreArrayProviderInner for LinearDisassemblyLine {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeLinearDisassemblyLines(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(raw)
    }
}
