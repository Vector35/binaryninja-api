use binaryninjacore_sys::{BNRegisterPluginCommand,
                          BNRegisterPluginCommandForAddress,
                          BNRegisterPluginCommandForRange,
                          BNRegisterPluginCommandForFunction,
                          BNBinaryView,
                          BNFunction};

use std::ops::Range;
use std::os::raw::c_void;

use crate::binaryview::BinaryView;
use crate::function::Function;
use crate::string::BnStrCompatible;

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

pub fn register<S, C>(name: S, desc: S, command: C)
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
            let view = BinaryView::from_raw(view);

            cmd.action(&view);
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView) -> bool
    where
        C: Command,
    {
        ffi_wrap!("Command::valid", unsafe {
            let cmd = &*(ctxt as *const C);
            let view = BinaryView::from_raw(view);

            cmd.valid(&view)
        })
    }

    let name = name.as_bytes_with_nul();
    let desc = desc.as_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommand(name_ptr, desc_ptr,
                                Some(cb_action::<C>), Some(cb_valid::<C>),
                                ctxt as *mut _);
    }
}

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

pub fn register_for_address<S, C>(name: S, desc: S, command: C)
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
            let view = BinaryView::from_raw(view);

            cmd.action(&view, addr);
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView, addr: u64) -> bool
    where
        C: AddressCommand,
    {
        ffi_wrap!("AddressCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);
            let view = BinaryView::from_raw(view);

            cmd.valid(&view, addr)
        })
    }

    let name = name.as_bytes_with_nul();
    let desc = desc.as_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForAddress(name_ptr, desc_ptr,
                                          Some(cb_action::<C>), Some(cb_valid::<C>),
                                          ctxt as *mut _);
    }
}

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

pub fn register_for_range<S, C>(name: S, desc: S, command: C)
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
            let view = BinaryView::from_raw(view);

            cmd.action(&view, addr .. addr.wrapping_add(len));
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView, addr: u64, len: u64) -> bool
    where
        C: RangeCommand,
    {
        ffi_wrap!("RangeCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);
            let view = BinaryView::from_raw(view);

            cmd.valid(&view, addr .. addr.wrapping_add(len))
        })
    }

    let name = name.as_bytes_with_nul();
    let desc = desc.as_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForRange(name_ptr, desc_ptr,
                                        Some(cb_action::<C>), Some(cb_valid::<C>),
                                        ctxt as *mut _);
    }
}

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

pub fn register_for_function<S, C>(name: S, desc: S, command: C)
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
            let view = BinaryView::from_raw(view);
            let func = Function::from_raw(func);

            cmd.action(&view, &func);
        })
    }

    extern "C" fn cb_valid<C>(ctxt: *mut c_void, view: *mut BNBinaryView, func: *mut BNFunction) -> bool
    where
        C: FunctionCommand,
    {
        ffi_wrap!("FunctionCommand::valid", unsafe {
            let cmd = &*(ctxt as *const C);
            let view = BinaryView::from_raw(view);
            let func = Function::from_raw(func);

            cmd.valid(&view, &func)
        })
    }

    let name = name.as_bytes_with_nul();
    let desc = desc.as_bytes_with_nul();

    let name_ptr = name.as_ref().as_ptr() as *mut _;
    let desc_ptr = desc.as_ref().as_ptr() as *mut _;

    let ctxt = Box::into_raw(Box::new(command));

    unsafe {
        BNRegisterPluginCommandForFunction(name_ptr, desc_ptr,
                                           Some(cb_action::<C>), Some(cb_valid::<C>),
                                           ctxt as *mut _);
    }
}
