// Copyright 2021-2024 Vector 35 Inc.
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

//! Provides commands for registering plugins and plugin actions.
//!
//! All plugins need to provide one of the following functions for Binary Ninja to call:
//!
//! ```no_run
//! pub extern "C" fn CorePluginInit() -> bool {
//!     todo!();
//! }
//! ```
//!
//! ```no_run
//! pub extern "C" fn UIPluginInit() -> bool {
//!     todo!();
//! }
//! ```
//!
//! Both of these functions can call any of the following registration functions, though `CorePluginInit` is called during Binary Ninja core initialization, and `UIPluginInit` is called during Binary Ninja UI initialization.
//!
//! The return value of these functions should indicate whether they successfully initialized themselves.

use binaryninjacore_sys::{
    BNBinaryView, BNFunction, BNRegisterPluginCommand, BNRegisterPluginCommandForAddress,
    BNRegisterPluginCommandForFunction, BNRegisterPluginCommandForRange,
};

use std::ops::Range;
use std::os::raw::c_void;

use crate::binary_view::BinaryView;
use crate::function::Function;
use crate::string::BnStrCompatible;

/// The trait required for generic commands.  See [register_command] for example usage.
pub trait Command: 'static + Sync {
    fn action(&self, view: &BinaryView);
    fn valid(&self, view: &BinaryView) -> bool;
}

impl<T> Command for T
where
    T: 'static + Sync + Fn(&BinaryView),
{
    fn action(&self, view: &BinaryView) {
        self(view);
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}

/// The function call required for generic commands; commands added in this way will be in the `Plugins` submenu of the menu bar.
///
/// # Example
/// ```no_run
/// # use binaryninja::command::Command;
/// # use binaryninja::binary_view::BinaryView;
/// struct MyCommand;
///
/// impl Command for MyCommand {
///     fn action(&self, view: &BinaryView) {
///         // Your code here
///     }
///
///     fn valid(&self, view: &BinaryView) -> bool {
///         // Your code here
///         true
///     }
/// }
///
/// # use binaryninja::command::register_command;
/// #[no_mangle]
/// pub extern "C" fn CorePluginInit() -> bool {
///     register_command(
///         "My Plugin Command",
///         "A description of my command",
///         MyCommand {},
///     );
///     true
/// }
/// ```
pub fn register_command<S, C>(name: S, desc: S, command: C)
where
    S: BnStrCompatible,
    C: Command,
{
    extern "C" fn cb_action<C>(ctxt: *mut c_void, view: *mut BNBinaryView)
    where
        C: Command,
    {
        ffi_wrap!("Command::action", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.action(&view);
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView) -> bool
    where
        C: Command,
    {
        ffi_wrap!("Command::valid", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.valid(&view)
        })
    }

    let name = name.into_bytes_with_nul();
    let desc = desc.into_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommand(
            name_ptr,
            desc_ptr,
            Some(cb_action::<C>),
            Some(cb_valid::<C>),
            ctxt as *mut _,
        );
    }
}

/// The trait required for address-associated commands.  See [register_command_for_address] for example usage.
pub trait AddressCommand: 'static + Sync {
    fn action(&self, view: &BinaryView, addr: u64);
    fn valid(&self, view: &BinaryView, addr: u64) -> bool;
}

impl<T> AddressCommand for T
where
    T: 'static + Sync + Fn(&BinaryView, u64),
{
    fn action(&self, view: &BinaryView, addr: u64) {
        self(view, addr);
    }

    fn valid(&self, _view: &BinaryView, _addr: u64) -> bool {
        true
    }
}

/// The function call required for generic commands; commands added in this way will be in the `Plugins` submenu of the menu bar.
///
/// # Example
/// ```no_run
/// # use binaryninja::command::AddressCommand;
/// # use binaryninja::binary_view::BinaryView;
/// struct MyCommand;
///
/// impl AddressCommand for MyCommand {
///     fn action(&self, view: &BinaryView, addr: u64) {
///         // Your code here
///     }
///
///     fn valid(&self, view: &BinaryView, addr: u64) -> bool {
///         // Your code here
///         true
///     }
/// }
///
/// # use binaryninja::command::register_command_for_address;
/// #[no_mangle]
/// pub extern "C" fn CorePluginInit() -> bool {
///     register_command_for_address(
///         "My Plugin Command",
///         "A description of my command",
///         MyCommand {},
///     );
///     true
/// }
/// ```
pub fn register_command_for_address<S, C>(name: S, desc: S, command: C)
where
    S: BnStrCompatible,
    C: AddressCommand,
{
    extern "C" fn cb_action<C>(ctxt: *mut c_void, view: *mut BNBinaryView, addr: u64)
    where
        C: AddressCommand,
    {
        ffi_wrap!("AddressCommand::action", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.action(&view, addr);
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView, addr: u64) -> bool
    where
        C: AddressCommand,
    {
        ffi_wrap!("AddressCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.valid(&view, addr)
        })
    }

    let name = name.into_bytes_with_nul();
    let desc = desc.into_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForAddress(
            name_ptr,
            desc_ptr,
            Some(cb_action::<C>),
            Some(cb_valid::<C>),
            ctxt as *mut _,
        );
    }
}

/// The trait required for range-associated commands.  See [register_command_for_range] for example usage.
pub trait RangeCommand: 'static + Sync {
    fn action(&self, view: &BinaryView, range: Range<u64>);
    fn valid(&self, view: &BinaryView, range: Range<u64>) -> bool;
}

impl<T> RangeCommand for T
where
    T: 'static + Sync + Fn(&BinaryView, Range<u64>),
{
    fn action(&self, view: &BinaryView, range: Range<u64>) {
        self(view, range);
    }

    fn valid(&self, _view: &BinaryView, _range: Range<u64>) -> bool {
        true
    }
}

/// The function call required for generic commands; commands added in this way will be in the `Plugins` submenu of the menu bar.
///
/// # Example
/// ```no_run
/// # use std::ops::Range;
/// # use binaryninja::command::RangeCommand;
/// # use binaryninja::binary_view::BinaryView;
/// struct MyCommand;
///
/// impl RangeCommand for MyCommand {
///     fn action(&self, view: &BinaryView, range: Range<u64>) {
///         // Your code here
///     }
///
///     fn valid(&self, view: &BinaryView, range: Range<u64>) -> bool {
///         // Your code here
///         true
///     }
/// }
///
/// # use binaryninja::command::register_command_for_range;
/// #[no_mangle]
/// pub extern "C" fn CorePluginInit() -> bool {
///     register_command_for_range(
///         "My Plugin Command",
///         "A description of my command",
///         MyCommand {},
///     );
///     true
/// }
/// ```
pub fn register_command_for_range<S, C>(name: S, desc: S, command: C)
where
    S: BnStrCompatible,
    C: RangeCommand,
{
    extern "C" fn cb_action<C>(ctxt: *mut c_void, view: *mut BNBinaryView, addr: u64, len: u64)
    where
        C: RangeCommand,
    {
        ffi_wrap!("RangeCommand::action", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.action(&view, addr..addr.wrapping_add(len));
        })
    }

    extern "C" fn cb_valid<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        addr: u64,
        len: u64,
    ) -> bool
    where
        C: RangeCommand,
    {
        ffi_wrap!("RangeCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            cmd.valid(&view, addr..addr.wrapping_add(len))
        })
    }

    let name = name.into_bytes_with_nul();
    let desc = desc.into_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForRange(
            name_ptr,
            desc_ptr,
            Some(cb_action::<C>),
            Some(cb_valid::<C>),
            ctxt as *mut _,
        );
    }
}

/// The trait required for function-associated commands.  See [register_command_for_function] for example usage.
pub trait FunctionCommand: 'static + Sync {
    fn action(&self, view: &BinaryView, func: &Function);
    fn valid(&self, view: &BinaryView, func: &Function) -> bool;
}

impl<T> FunctionCommand for T
where
    T: 'static + Sync + Fn(&BinaryView, &Function),
{
    fn action(&self, view: &BinaryView, func: &Function) {
        self(view, func);
    }

    fn valid(&self, _view: &BinaryView, _func: &Function) -> bool {
        true
    }
}

/// The function call required for generic commands; commands added in this way will be in the `Plugins` submenu of the menu bar.
///
/// # Example
/// ```no_run
/// # use binaryninja::command::FunctionCommand;
/// # use binaryninja::binary_view::BinaryView;
/// # use binaryninja::function::Function;
/// # use binaryninja::command::register_command_for_function;
/// struct MyCommand;
///
/// impl FunctionCommand for MyCommand {
///     fn action(&self, view: &BinaryView, func: &Function) {
///         // Your code here
///     }
///
///     fn valid(&self, view: &BinaryView, func: &Function) -> bool {
///         // Your code here
///         true
///     }
/// }
///
/// #[no_mangle]
/// pub extern "C" fn CorePluginInit() -> bool {
///     register_command_for_function(
///         "My Plugin Command",
///         "A description of my command",
///         MyCommand {},
///     );
///     true
/// }
/// ```
pub fn register_command_for_function<S, C>(name: S, desc: S, command: C)
where
    S: BnStrCompatible,
    C: FunctionCommand,
{
    extern "C" fn cb_action<C>(ctxt: *mut c_void, view: *mut BNBinaryView, func: *mut BNFunction)
    where
        C: FunctionCommand,
    {
        ffi_wrap!("FunctionCommand::action", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            debug_assert!(!func.is_null());
            let func = Function { handle: func };

            cmd.action(&view, &func);
        })
    }

    extern "C" fn cb_valid<C>(
        ctxt: *mut c_void,
        view: *mut BNBinaryView,
        func: *mut BNFunction,
    ) -> bool
    where
        C: FunctionCommand,
    {
        ffi_wrap!("FunctionCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);

            debug_assert!(!view.is_null());
            let view = BinaryView { handle: view };

            debug_assert!(!func.is_null());
            let func = Function { handle: func };

            cmd.valid(&view, &func)
        })
    }

    let name = name.into_bytes_with_nul();
    let desc = desc.into_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForFunction(
            name_ptr,
            desc_ptr,
            Some(cb_action::<C>),
            Some(cb_valid::<C>),
            ctxt as *mut _,
        );
    }
}
