use binaryninja::architecture::register::RegisterId;
use binaryninja::architecture::{ArchitectureExt, CoreArchitecture, Register};
use binaryninja::calling_convention::{
    CallingConvention, CoreCallingConvention, register_calling_convention,
};

/// Registers the Go calling conventions (`go-abiinternal` and `go-stack`) on the
/// supported architectures.
///
/// TODO: decide whether these belong on the architecture itself instead of here.
pub struct GoCallingConventions {}

impl GoCallingConventions {
    /// Resolves register names to ids; returns None if any name is missing.
    fn ids(arch: &CoreArchitecture, names: &[&str]) -> Option<Vec<RegisterId>> {
        names.iter().map(|n| Self::reg_id(arch, n)).collect()
    }

    fn reg_id(arch: &CoreArchitecture, name: &str) -> Option<RegisterId> {
        let r = arch.register_by_name(name).map(|r| r.id());
        if r.is_none() {
            tracing::warn!("go-cc: register '{name}' not found on {}", arch.name());
        }
        r
    }

    /// Register the calling convention for x86
    pub fn for_x86() -> Option<()> {
        let arch = CoreArchitecture::by_name("x86_64")?;

        let int_args = Self::ids(
            &arch,
            &["rax", "rbx", "rcx", "rdi", "rsi", "r8", "r9", "r10", "r11"],
        )?;
        let float_args: Vec<RegisterId> = (0..15)
            .map(|i| Self::reg_id(&arch, &format!("xmm{i}")))
            .collect::<Option<_>>()?;
        let callee = Self::ids(&arch, &["rbp", "r14"])?;
        let caller = Self::ids(
            &arch,
            &[
                "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13",
                "r15",
            ],
        )?;
        let ret_int = Self::reg_id(&arch, "rax")?;
        let ret_hi = Self::reg_id(&arch, "rbx")?;
        let ret_float = Self::reg_id(&arch, "xmm0")?;

        register_calling_convention(&arch, "go-abiinternal", move |core| GoAbiInternal {
            core,
            int_args,
            float_args,
            callee,
            caller,
            ret_int,
            ret_hi,
            ret_float,
        });

        let s_callee = Self::ids(&arch, &["rbp", "r14"])?;
        let s_caller = Self::ids(
            &arch,
            &[
                "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13",
                "r15",
            ],
        )?;
        let s_ret = Self::reg_id(&arch, "rax")?;
        register_calling_convention(&arch, "go-stack", move |core| GoStack {
            core,
            callee: s_callee,
            caller: s_caller,
            ret_int: s_ret,
        });

        Some(())
    }

    /// Register the calling convention for arm64
    pub fn for_arm64() -> Option<()> {
        let arch = CoreArchitecture::by_name("aarch64")?;

        let int_args: Vec<RegisterId> = (0..16)
            .map(|i| Self::reg_id(&arch, &format!("x{i}")))
            .collect::<Option<_>>()?;
        let float_args: Vec<RegisterId> = (0..16)
            .map(|i| Self::reg_id(&arch, &format!("v{i}")))
            .collect::<Option<_>>()?;
        let callee = Self::ids(&arch, &["fp", "x28"])?;

        let mut caller_names: Vec<String> = Vec::new();
        caller_names.extend((0..=17).map(|i| format!("x{i}")));
        caller_names.extend((19..=27).map(|i| format!("x{i}")));
        caller_names.push("lr".into());
        caller_names.extend((0..32).map(|i| format!("v{i}")));
        let caller: Vec<RegisterId> = caller_names
            .iter()
            .map(|n| Self::reg_id(&arch, n))
            .collect::<Option<_>>()?;

        let ret_int = Self::reg_id(&arch, "x0")?;
        let ret_hi = Self::reg_id(&arch, "x1")?;
        let ret_float = Self::reg_id(&arch, "v0")?;

        register_calling_convention(&arch, "go-abiinternal", move |core| GoAbiInternal {
            core,
            int_args,
            float_args,
            callee,
            caller,
            ret_int,
            ret_hi,
            ret_float,
        });

        let s_callee = Self::ids(&arch, &["fp", "x28"])?;
        let mut s_caller_names: Vec<String> = Vec::new();
        s_caller_names.extend((0..=17).map(|i| format!("x{i}")));
        s_caller_names.extend((19..=27).map(|i| format!("x{i}")));
        s_caller_names.push("lr".into());
        let s_caller: Vec<RegisterId> = s_caller_names
            .iter()
            .map(|n| Self::reg_id(&arch, n))
            .collect::<Option<_>>()?;
        let s_ret = Self::reg_id(&arch, "x0")?;

        register_calling_convention(&arch, "go-stack", move |core| GoStack {
            core,
            callee: s_callee,
            caller: s_caller,
            ret_int: s_ret,
        });

        Some(())
    }
}

/// Go `ABIInternal` calling convention (go1.17+), register-based.
///
/// Go uses a common register-based ABI across all architectures: integer and
/// floating-point arguments and results are passed in fixed register sequences,
/// which do not share an index. There are no callee-save registers except those
/// with a fixed runtime meaning (frame pointer and the goroutine pointer); a call
/// may clobber anything else.
///
/// Source: <https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md>
pub struct GoAbiInternal {
    /// Handle to the registered core convention, returned via `AsRef`.
    core: CoreCallingConvention,
    /// Integer argument/result registers.
    int_args: Vec<RegisterId>,
    /// Floating-point argument/result registers.
    float_args: Vec<RegisterId>,
    /// Callee-saved (fixed-meaning) registers.
    callee: Vec<RegisterId>,
    /// Caller-saved (clobbered) registers.
    caller: Vec<RegisterId>,
    /// First integer return register.
    ret_int: RegisterId,
    /// Second integer return register.
    ret_hi: RegisterId,
    /// Floating-point return register.
    ret_float: RegisterId,
}

impl AsRef<CoreCallingConvention> for GoAbiInternal {
    fn as_ref(&self) -> &CoreCallingConvention {
        &self.core
    }
}

impl CallingConvention for GoAbiInternal {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        self.caller.clone()
    }
    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        self.callee.clone()
    }
    fn int_arg_registers(&self) -> Vec<RegisterId> {
        self.int_args.clone()
    }
    fn float_arg_registers(&self) -> Vec<RegisterId> {
        self.float_args.clone()
    }
    fn arg_registers_shared_index(&self) -> bool {
        false
    }
    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        false
    }
    fn stack_adjusted_on_return(&self) -> bool {
        false
    }
    fn is_eligible_for_heuristics(&self) -> bool {
        true
    }
    fn return_int_reg(&self) -> Option<RegisterId> {
        Some(self.ret_int)
    }
    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        Some(self.ret_hi)
    }
    fn return_float_reg(&self) -> Option<RegisterId> {
        Some(self.ret_float)
    }
    fn global_pointer_reg(&self) -> Option<RegisterId> {
        None
    }
    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        vec![]
    }
    fn are_argument_registers_used_for_var_args(&self) -> bool {
        false
    }
}

/// Go `ABI0` calling convention, stack-based.
///
/// The stable ABI used by assembly functions and `.abi0` wrappers. All arguments
/// and results are passed on the stack, so there are no argument registers. It is
/// equivalent to ABIInternal with zero available argument registers. The
/// fixed-meaning registers (frame pointer, goroutine pointer) stay callee-saved,
/// everything else is caller-saved, and the stack is caller-cleaned.
///
/// Source: <https://go.googlesource.com/go/+/refs/heads/master/src/cmd/compile/abi-internal.md>
pub struct GoStack {
    /// Handle to the registered core convention, returned via `AsRef`
    core: CoreCallingConvention,
    /// Callee-saved (fixed-meaning) registers
    callee: Vec<RegisterId>,
    /// Caller-saved (clobbered) registers
    caller: Vec<RegisterId>,
    /// Integer return register, but ABI0 returns on the stack
    ret_int: RegisterId,
}

impl AsRef<CoreCallingConvention> for GoStack {
    fn as_ref(&self) -> &CoreCallingConvention {
        &self.core
    }
}

impl CallingConvention for GoStack {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        self.caller.clone()
    }
    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        self.callee.clone()
    }
    fn int_arg_registers(&self) -> Vec<RegisterId> {
        vec![]
    }
    fn float_arg_registers(&self) -> Vec<RegisterId> {
        vec![]
    }
    fn arg_registers_shared_index(&self) -> bool {
        false
    }
    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        false
    }
    fn stack_adjusted_on_return(&self) -> bool {
        false
    }
    fn is_eligible_for_heuristics(&self) -> bool {
        false
    }
    fn return_int_reg(&self) -> Option<RegisterId> {
        Some(self.ret_int)
    }
    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        None
    }
    fn return_float_reg(&self) -> Option<RegisterId> {
        None
    }
    fn global_pointer_reg(&self) -> Option<RegisterId> {
        None
    }
    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        vec![]
    }
    fn are_argument_registers_used_for_var_args(&self) -> bool {
        false
    }
}
