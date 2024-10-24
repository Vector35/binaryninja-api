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

use crate::binaryview::BinaryView;
use crate::disassembly::{DisassemblySettings, DisassemblyTextLine};
use crate::function::Function;

use crate::rc::*;
use std::ops::Deref;

use std::mem;

pub struct LinearViewObject {
    pub(crate) handle: *mut BNLinearViewObject,
}

impl LinearViewObject {
    pub(crate) unsafe fn from_raw(handle: *mut BNLinearViewObject) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn data_only(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                binaryninjacore_sys::BNCreateLinearViewDataOnly(view.handle, settings.handle);

            Self::from_raw(handle)
        }
    }

    pub fn disassembly(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                binaryninjacore_sys::BNCreateLinearViewDisassembly(view.handle, settings.handle);

            Self::from_raw(handle)
        }
    }

    pub fn lifted_il(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                binaryninjacore_sys::BNCreateLinearViewLiftedIL(view.handle, settings.handle);

            Self::from_raw(handle)
        }
    }

    pub fn mlil(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                binaryninjacore_sys::BNCreateLinearViewMediumLevelIL(view.handle, settings.handle);

            Self::from_raw(handle)
        }
    }

    pub fn mlil_ssa(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewMediumLevelILSSAForm(
                view.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn hlil(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle =
                binaryninjacore_sys::BNCreateLinearViewHighLevelIL(view.handle, settings.handle);

            Self::from_raw(handle)
        }
    }

    pub fn hlil_ssa(view: &BinaryView, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewHighLevelILSSAForm(
                view.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn language_representation(
        view: &BinaryView,
        settings: &DisassemblySettings,
        language: &str,
    ) -> Ref<Self> {
        unsafe {
            let language = std::ffi::CString::new(language).unwrap();
            let handle = binaryninjacore_sys::BNCreateLinearViewLanguageRepresentation(
                view.handle,
                settings.handle,
                language.as_ptr(),
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_disassembly(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionDisassembly(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_lifted_il(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionLiftedIL(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_mlil(function: &Function, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionMediumLevelIL(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_mlil_ssa(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionMediumLevelILSSAForm(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_hlil(function: &Function, settings: &DisassemblySettings) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionHighLevelIL(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_hlil_ssa(
        function: &Function,
        settings: &DisassemblySettings,
    ) -> Ref<Self> {
        unsafe {
            let handle = binaryninjacore_sys::BNCreateLinearViewSingleFunctionHighLevelILSSAForm(
                function.handle,
                settings.handle,
            );

            Self::from_raw(handle)
        }
    }

    pub fn single_function_language_representation(
        function: &Function,
        settings: &DisassemblySettings,
        language: &str,
    ) -> Ref<Self> {
        unsafe {
            let language = std::ffi::CString::new(language).unwrap();
            let handle =
                binaryninjacore_sys::BNCreateLinearViewSingleFunctionLanguageRepresentation(
                    function.handle,
                    settings.handle,
                    language.as_ptr(),
                );

            Self::from_raw(handle)
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

#[derive(Eq)]
pub struct LinearViewCursor {
    pub(crate) handle: *mut binaryninjacore_sys::BNLinearViewCursor,
}

impl LinearViewCursor {
    pub(crate) unsafe fn from_raw(handle: *mut BNLinearViewCursor) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn new(root: &LinearViewObject) -> Ref<Self> {
        unsafe {
            let handle = BNCreateLinearViewCursor(root.handle);
            Self::from_raw(handle)
        }
    }

    /// Gets the current [LinearViewObject] associated with this cursor.
    pub fn current_object(&self) -> Ref<LinearViewObject> {
        unsafe {
            let handle = BNGetLinearViewCursorCurrentObject(self.handle);
            LinearViewObject::from_raw(handle)
        }
    }

    // FIXME: can we implement clone without shadowing ToOwned?
    pub fn duplicate(&self) -> Ref<Self> {
        unsafe {
            let handle = BNDuplicateLinearViewCursor(self.handle);
            Self::from_raw(handle)
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

    pub fn seek_to_start(&self) {
        unsafe { BNSeekLinearViewCursorToBegin(self.handle) }
    }

    pub fn seek_to_end(&self) {
        unsafe { BNSeekLinearViewCursorToEnd(self.handle) }
    }

    pub fn seek_to_address(&self, address: u64) {
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

    pub fn seek_to_ordering_index(&self, idx: u64) {
        unsafe { BNSeekLinearViewCursorToAddress(self.handle, idx) }
    }

    pub fn previous(&self) -> bool {
        unsafe { BNLinearViewCursorPrevious(self.handle) }
    }

    pub fn next(&self) -> bool {
        unsafe { BNLinearViewCursorNext(self.handle) }
    }

    pub fn lines(&self) -> Array<LinearDisassemblyLine> {
        let mut count: usize = 0;
        unsafe {
            let handles = BNGetLinearViewCursorLines(self.handle, &mut count);
            Array::new(handles, count, ())
        }
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

pub type LinearDisassemblyLineType = BNLinearDisassemblyLineType;

pub struct LinearDisassemblyLine {
    t: LinearDisassemblyLineType,

    // These will be cleaned up by BNFreeLinearDisassemblyLines, so we
    // don't drop them in the relevant deconstructors.
    function: mem::ManuallyDrop<Ref<Function>>,
    contents: mem::ManuallyDrop<DisassemblyTextLine>,
}

impl LinearDisassemblyLine {
    pub(crate) unsafe fn from_raw(raw: &BNLinearDisassemblyLine) -> Self {
        let linetype = raw.type_;
        let function = mem::ManuallyDrop::new(Function::from_raw(raw.function));
        let contents = mem::ManuallyDrop::new(DisassemblyTextLine(raw.contents));
        Self {
            t: linetype,
            function,
            contents,
        }
    }

    pub fn function(&self) -> &Function {
        self.function.as_ref()
    }

    pub fn line_type(&self) -> LinearDisassemblyLineType {
        self.t
    }
}

impl Deref for LinearDisassemblyLine {
    type Target = DisassemblyTextLine;
    fn deref(&self) -> &Self::Target {
        self.contents.deref()
    }
}

impl std::fmt::Display for LinearDisassemblyLine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.deref())
    }
}

impl CoreArrayProvider for LinearDisassemblyLine {
    type Raw = BNLinearDisassemblyLine;
    type Context = ();
    type Wrapped<'a> = Guard<'a, LinearDisassemblyLine>;
}

unsafe impl CoreArrayProviderInner for LinearDisassemblyLine {
    unsafe fn free(raw: *mut BNLinearDisassemblyLine, count: usize, _context: &()) {
        BNFreeLinearDisassemblyLines(raw, count);
    }
    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(LinearDisassemblyLine::from_raw(raw), _context)
    }
}
