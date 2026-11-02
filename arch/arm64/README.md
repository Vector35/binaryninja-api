# arch-arm64

This is the AArch64 plugin that ships with Binary Ninja.

## What's What

- [arch_arm64.cpp](./arch_arm64.cpp) implements the Architecture class
- [il.cpp](./il.cpp) contains the lifter, the translator from disassembly to intermediate language
- [operands.cpp](./operands.cpp) reads the operands exarmo decodes the way the lifter needs them
- [registers.cpp](./registers.cpp) and [system_registers.cpp](./system_registers.cpp) are the two register namespaces, and map exarmo's registers into them
- [acle_intrinsics.cpp](./acle_intrinsics.cpp) lifts an instruction as the ACLE intrinsic exarmo says it implements
- [system_operations.cpp](./system_operations.cpp) names the intrinsics for AT, DC, TLBI and the other SYS aliases
- [apple_vendor.cpp](./apple_vendor.cpp) covers the Apple instructions and system registers ARM does not define

Disassembly comes from [exarmo](https://crates.io/crates/exarmo-aarch64-capi), through its C API.

## Modeled exceptions and SMCCC

SVC, HVC, SMC, and BRK emit modeled exceptions. Their discriminator is
`(kind << 32) | immediate`, with kinds SVC=1, HVC=2, SMC=3, and BRK=4.
Instruction information reports the same discriminator so platform continuation
rules control both native basic blocks and IL. Bare AArch64 treats SVC, HVC,
and SMC as opaque, continuing exceptions; BRK terminates by default.

The available SMCCC conventions use the current SMCCC 1.2+ register profile:

| Convention | Eligible instruction | Function ID | Payload | Possible results |
|---|---|---|---|---|
| `smccc32` | `hvc #0`, `smc #0` | W0 | W1-W7 | W0-W7 |
| `smccc64` | `hvc #0`, `smc #0` | W0 | X1-X17 | X0-X17 |

Function Identifier bit 30 distinguishes the 32-bit and 64-bit forms. No
convention is inferred solely from the opcode or immediate. Select a convention
on an instruction, or configure a platform service namespace and exception
model. Nonzero HVC/SMC immediates do not offer these SMCCC conventions.

Argument and result layouts use register storage only, without stack arguments,
SIMD arguments, or an implicit result pointer. The convention API names backing
X registers; layouts describe the low 32 bits for W-register values. Without a
service definition, registers that can contain optional results are conservatively
considered modified, including X4-X7 or X4-X17. The other general-purpose registers,
SP, and vector/predicate registers are preserved. The older SMCCC 1.0 rules differ;
these conventions should not be used to infer preservation for that version.

Linux, macOS/iOS, and Windows supply explicit SVC models using their existing
syscall conventions. SVC #0 is named `syscall` on those platforms. Immediate zero
is omitted from IL call text when an effective convention is present. Other
immediates remain visible. The lifter retains the existing `syscall_info`
metadata register for compatibility with Windows' immediate-based syscall ABI.

Reference: [Arm SMC Calling Convention, DEN0028](https://developer.arm.com/documentation/den0028/latest),
sections 2.6, 2.7, and the SMC/HVC immediate-value rules.

## Samsung uH / RKP

`samsung-uh` is an explicit AArch64 convention for the six-argument Samsung uH
interface: X0 is the application ID, X1 is the command, and X2-X5 are four 64-bit
arguments. It returns a scalar in X0, with no floating-point or stack arguments
and no implicit result pointer. It is eligible only for `hvc #0`, is not selected
automatically, and is excluded from ordinary function-convention heuristics.
For example, the RKP application ID is `0xc300c002`.

The public interface declaration does not establish a complete preservation
contract for every Samsung firmware. This convention uses conservative
AAPCS64 scratch clobbers (X0-X18, V0-V7, V16-V31), preserving X19-X30 and SP.
LR is preserved because the HVC wrapper returns directly with `ret`. These are
modeling assumptions, not a claim that all of those scratch registers are
modified by the hypervisor. Firmware with a verified, narrower preservation
contract can register a more specific convention.

Selecting this convention supplies argument and register-effect information;
it does not automatically resolve `(application ID, command)` to command names.
The default `hvc` display name and platform continuation policy still apply.

Sources: [Samsung kernel uH declaration](https://raw.githubusercontent.com/Impalabs/resources/master/SM-G973F_QQ_Opensource/include/linux/uh.h),
[Samsung RKP Compendium](https://blog.impalabs.com/2101_samsung-rkp-compendium.html).

## Testing

- [./arm64test.py](./arm64test.py) runs a very basic "lift to string and compare" test

Personal Binary Ninja users can test via the built in console:

```
>>> sys.path.append('C:/users/x/onedrive/documents/binja/binaryninja-api/arch/arm64') # Path directory containing arm64test.py
>>> from importlib import reload
>>> import arm64test
>>> arm64test.run_all()
success!
>>> # Add or fix any testcases
>>> reload(arm64test).run_all()
success!
```

And, of course, you can open a test binary in Binary Ninja with this architecture built and activated to see if results are as expected.

## Requirements for Pull Requesters

1. **TEST!** If you're making an architecture or lifter change, add a test case to [arm64test.py](./arm64test.py) that fails before your change and succeeds after your change.

2. Disassembly comes from exarmo, so report disassembly bugs as issues rather than changing the plugin.
3. Compile with warnings enabled. Do this cmake invocation: `ARM64_WARNINGS=1 cmake .`

Please follow whatever formatting conventions are present in the file you edit. Pay attention to curly brackets, spacing, tabs vs. spaces, etc.

When you submit your first PR to one of Vector 35's repositories, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online.


## Building

Building the architecture plugin requires `cmake` 3.9 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api). You also need `rustup` and
Python 3 to build exarmo. Cargo fetches exarmo from crates.io at the version [Cargo.toml](./Cargo.toml)
pins. The build uses the Rust toolchain named by `CARGO_STABLE_VERSION` in
[RustBuild.cmake](../../cmake/RustBuild.cmake).

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libarch_arm64.so`,
`libarch_arm64.dylib` or `arch_arm64.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "Aarch64 architecture plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**

## Build Example

### acquire repositories

```
mkdir ~/repos/vector35
cd ~/repos/vector35
git clone git@github.com:Vector35/binaryninja-api.git
git clone git@github.com:Vector35/arch-arm64.git
```

### environment variables

`export BN_API_PATH=~/repos/vector35/binaryninja-api`

### cmake, make

```
cd arch-arm64
cmake -DBN_INSTALL_DIR=/Applications/Binary\ Ninja\ DEV.app/ .
make
```

## Build Troubleshooting

### example

    CMake Error at CMakeLists.txt:8 (message):
      Provide path to Binary Ninja API source in BN_API_PATH
    resolution:
    ensure BN_API_PATH is in your environment

### example

    CMake Error at /Users/andrewl/repos/vector35/binaryninja-api/CMakeLists.txt:53 (message):
      Binary Ninja Core Not Found
    resolution:
    ensure BN_INSTALL_DIR is supplied at command line invocation of cmake
    ensure some bad directory is not cached in CMakeCache.txt

### example

    cmake seems to ignore your setting of BN_INSTALL_DIR and other cmake variables
    resolution:
    rm CMakeCache.txt

### example

    undefined symbols at link time, like:
    Undefined symbols for architecture x86_64:
      "_BNClearUserVariableValue", referenced from:
      BinaryNinja::Function::ClearUserVariableValue(BinaryNinja::Variable const&, unsigned long long) in libbinaryninjaapi.a(function.cpp.o)
    resolution:
    ensure that your api repo is on the same channel and at the same commit as the libbinaryninjacore you're linking against
    eg: binaryninja is on dev update channel and is up-to-date and binaryninja-api repo is on branch dev with latest pulled
