use core::ffi;
use std::ffi::CStr;

use binaryninjacore_sys::*;

use crate::architecture::CoreArchitecture;
use crate::binary_view::BinaryViewExt;
use crate::high_level_il::HighLevelILFunction;
use crate::low_level_il::function::{Finalized, LowLevelILFunction, NonSSA, RegularNonSSA};
use crate::medium_level_il::MediumLevelILFunction;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::BnStrCompatible;
use crate::{BinaryView, Function};

type PluginCommandType = BNPluginCommandType;

#[repr(transparent)]
#[derive(Debug)]
pub struct PluginCommand<T> {
    handle: BNPluginCommand,
    _kind: core::marker::PhantomData<T>,
}

impl<T> PluginCommand<T> {
    pub fn type_(&self) -> PluginCommandType {
        self.handle.type_
    }
    pub fn name(&self) -> &str {
        unsafe { CStr::from_ptr(self.handle.name) }
            .to_str()
            .unwrap()
    }
    pub fn description(&self) -> &str {
        unsafe { CStr::from_ptr(self.handle.description) }
            .to_str()
            .unwrap()
    }
}

impl<T> CoreArrayProvider for PluginCommand<T> {
    type Raw = BNPluginCommand;
    type Context = ();
    type Wrapped<'a>
        = &'a PluginCommand<T>
    where
        T: 'a;
}

unsafe impl<T> CoreArrayProviderInner for PluginCommand<T> {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreePluginCommandList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        // SAFETY BNPluginCommand and PluginCommand are transparent
        core::mem::transmute::<&'a BNPluginCommand, &'a PluginCommand<T>>(raw)
    }
}

macro_rules! define_enum {
    (
        $bv_name:ident,
        $($get_all:ident, $register_name:ident, $enum_name:ident, $trait_name:ident {
            $fun_run:ident :: $fun_is_valid:ident(
                $(
                    $arg_name:ident:
                    $raw_arg_type:ty:
                    $arg_type:ty =
                    $rust2ffi:expr =>
                    $ffi2rust:expr
                ),* $(,)?
            ) $(,)?
        }),* $(,)?
    ) => {
        impl PluginCommand<PluginCommandAll> {
            pub fn valid_plugin_commands() -> Array<Self> {
                let mut count = 0;
                let array = unsafe { BNGetAllPluginCommands(&mut count) };
                unsafe { Array::new(array, count, ()) }
            }
            pub fn execution(&self) -> PluginCommandAll {
                match self.type_() {
                    $(PluginCommandType::$enum_name => {
                        PluginCommandAll::$enum_name($enum_name {
                            context: self.handle.context,
                            is_valid: self.handle.$fun_is_valid,
                            run: self.handle.$fun_run.unwrap(),
                        })
                    }),*
                }
            }
        }

        pub enum PluginCommandAll {
            $($enum_name($enum_name)),*
        }

        $(
        pub struct $enum_name {
            context: *mut ffi::c_void,
            is_valid: Option<unsafe extern "C" fn (
                ctxt: *mut ffi::c_void,
                $bv_name: *mut BNBinaryView,
                $($raw_arg_type),*
            ) -> bool>,
            run: unsafe extern "C" fn (
                ctxt: *mut ffi::c_void,
                $bv_name: *mut BNBinaryView,
                $($raw_arg_type),*
            ),
        }

        impl $enum_name {
            pub fn is_valid(
                &mut self,
                $bv_name: &BinaryView,
                $($arg_name: $arg_type),*
            ) -> bool {
                // TODO I'm assuming is_valid be null means it's always valid
                let Some(fun) = self.is_valid else {
                    return true
                };
                unsafe{ fun(self.context, $bv_name.handle, $($rust2ffi),*) }
            }

            pub fn run(
                &mut self,
                $bv_name: &BinaryView,
                $($arg_name: $arg_type),*
            ) {
                unsafe{ (self.run)(self.context, $bv_name.handle, $($rust2ffi),*) }
            }
        }
        )*

        $(
        pub trait $trait_name: Send + Sync + 'static {
            fn is_valid(
                &mut self,
                $bv_name: &BinaryView,
                $($arg_name: $arg_type),*
            ) -> bool;
            fn run(
                &mut self,
                $bv_name: &BinaryView,
                $($arg_name: $arg_type),*
            );
            fn register(self, name: impl BnStrCompatible, description: impl BnStrCompatible) where Self: Sized {
                unsafe extern "C" fn ffi_action<T: $trait_name>(
                    ctxt: *mut ffi::c_void,
                    $bv_name: *mut BNBinaryView,
                    $($arg_name: $raw_arg_type),*
                ) {
                    let slf = ctxt as *mut T;
                    (*slf).run(&BinaryView::from_raw($bv_name), $($ffi2rust),*)
                }
                unsafe extern "C" fn ffi_is_valid<T: $trait_name>(
                    ctxt: *mut ffi::c_void,
                    $bv_name: *mut BNBinaryView,
                    $($arg_name: $raw_arg_type),*
                ) -> bool {
                    let slf = ctxt as *mut T;
                    (*slf).is_valid(&BinaryView::from_raw($bv_name), $($ffi2rust),*)
                }
                let name = name.into_bytes_with_nul();
                let description = description.into_bytes_with_nul();
                unsafe{ $register_name(
                    name.as_ref().as_ptr() as *const ffi::c_char,
                    description.as_ref().as_ptr() as *const ffi::c_char,
                    Some(ffi_action::<Self>),
                    Some(ffi_is_valid::<Self>),
                    Box::leak(Box::new(self)) as *mut Self as *mut ffi::c_void,
                ) }
            }
        }

        impl PluginCommand<$enum_name> {
            pub fn valid_plugin_commands(view: &BinaryView, $($arg_name: $arg_type),*) -> Array<Self> {
                let mut count = 0;
                let array = unsafe { $get_all(view.handle, $($rust2ffi, )* &mut count) };
                unsafe { Array::new(array, count, ()) }
            }

            pub fn execution(&self) -> $enum_name {
                assert_eq!(self.type_(), PluginCommandType::$enum_name);
                $enum_name {
                    context: self.handle.context,
                    is_valid: self.handle.$fun_is_valid,
                    run: self.handle.$fun_run.unwrap(),
                }
            }
        }
        )*
    };
}

define_enum! {
    view,
    BNGetValidPluginCommands, BNRegisterPluginCommand, DefaultPluginCommand, CustomDefaultPluginCommand {
        defaultCommand::defaultIsValid(),
    },
    BNGetValidPluginCommandsForAddress, BNRegisterPluginCommandForAddress, AddressPluginCommand, CustomAddressPluginCommand {
        addressCommand::addressIsValid(
            addr: u64: u64 = addr => addr,
        ),
    },
    BNGetValidPluginCommandsForRange, BNRegisterPluginCommandForRange, RangePluginCommand, CustomRangePluginCommand {
        rangeCommand::rangeIsValid(
            addr: u64: u64 = addr => addr,
            len: u64: u64 = len => len,
        ),
    },
    BNGetValidPluginCommandsForFunction, BNRegisterPluginCommandForFunction, FunctionPluginCommand, CustomFunctionPluginCommand {
        functionCommand::functionIsValid(
            func: *mut BNFunction: &Function = func.handle => &Function::from_raw(func),
        ),
    },
    BNGetValidPluginCommandsForLowLevelILFunction, BNRegisterPluginCommandForLowLevelILFunction, LowLevelILFunctionPluginCommand, CustomLowLevelILFunctionPluginCommand {
        lowLevelILFunctionCommand::lowLevelILFunctionIsValid(
            // TODO I don't know what Generics should be used here
            func: *mut BNLowLevelILFunction: &LowLevelILFunction<CoreArchitecture, Finalized, NonSSA<RegularNonSSA>> =
            func.handle => &LowLevelILFunction::from_raw(
                BinaryView::from_raw(view).default_arch().unwrap(),
                func,
            ),
        ),
    },
    BNGetValidPluginCommandsForLowLevelILInstruction, BNRegisterPluginCommandForLowLevelILInstruction, LowLevelILInstructionPluginCommand, CustomLowLevelILInstructionPluginCommand {
        lowLevelILInstructionCommand::lowLevelILInstructionIsValid(
            func: *mut BNLowLevelILFunction: &LowLevelILFunction<CoreArchitecture, Finalized, NonSSA<RegularNonSSA>> =
            func.handle => &LowLevelILFunction::from_raw(
                BinaryView::from_raw(view).default_arch().unwrap(),
                func,
            ),
            instr: usize: usize = instr => instr,
        ),
    },
    BNGetValidPluginCommandsForMediumLevelILFunction, BNRegisterPluginCommandForMediumLevelILFunction, MediumLevelILFunctionPluginCommand, CustomMediumLevelILFunctionPluginCommand {
        mediumLevelILFunctionCommand::mediumLevelILFunctionIsValid(
            func: *mut BNMediumLevelILFunction: &MediumLevelILFunction = func.handle => &MediumLevelILFunction::from_raw(func),
        ),
    },
    BNGetValidPluginCommandsForMediumLevelILInstruction, BNRegisterPluginCommandForMediumLevelILInstruction, MediumLevelILInstructionPluginCommand, CustomMediumLevelILInstructionPluginCommand {
        mediumLevelILInstructionCommand::mediumLevelILInstructionIsValid(
            func: *mut BNMediumLevelILFunction: &MediumLevelILFunction = func.handle => &MediumLevelILFunction::from_raw(func),
            instr: usize: usize = instr => instr,
        ),
    },
    BNGetValidPluginCommandsForHighLevelILFunction, BNRegisterPluginCommandForHighLevelILFunction, HighLevelILFunctionPluginCommand, CustomHighLevelILFunctionPluginCommand {
        // TODO I don't know if the value is full_ast or not
        highLevelILFunctionCommand::highLevelILFunctionIsValid(
            func: *mut BNHighLevelILFunction: &HighLevelILFunction = func.handle => &HighLevelILFunction{full_ast: false, handle: func},
        ),
    },
    BNGetValidPluginCommandsForHighLevelILInstruction, BNRegisterPluginCommandForHighLevelILInstruction, HighLevelILInstructionPluginCommand, CustomHighLevelILInstructionPluginCommand {
        highLevelILInstructionCommand::highLevelILInstructionIsValid(
            func: *mut BNHighLevelILFunction: &HighLevelILFunction = func.handle => &HighLevelILFunction{full_ast: false, handle: func},
            instr: usize: usize = instr => instr,
        ),
    },
}
