# Recompiling Pseudo C

[`pseudoc_helpers.h`](pseudoc_helpers.h) is a standalone, MIT-licensed header for
the scalar helper expressions emitted by Binary Ninja's Pseudo C renderer. Copy
it alongside your exported source and include it before the function definitions:

```c
#include "pseudoc_helpers.h"

uint32_t float_bits(float value)
{
    return BIT_CAST(uint32_t, value);
}

uint32_t rotate_word(uint32_t value, uint64_t count)
{
    return ROLD(value, count);
}
```

Compile this example as an object file with either command:

```sh
clang -std=c11 -Wall -Wextra -O2 -c example.c
clang++ -x c++ -std=c++11 -Wall -Wextra -O2 -c example.c
```

For Clang-CL, use a Visual Studio Native Tools command prompt with LLVM on
`PATH`. These commands compile the same example against the Microsoft headers:

```bat
clang-cl /TC /std:c11 /W4 /O2 /c example.c
clang-cl /TP /std:c++14 /EHsc /W4 /O2 /c example.c
```

Add `-I/path/to/api/lang/c` if the header is elsewhere. GCC/G++ use the same
command-line options. When linking an executable, provide a `main` and link
`-lm` on platforms that require a separate math library. Avoid `-ffast-math`
when signed zero, NaNs, infinities, or ordered comparisons matter.

**Export does not insert this include automatically.** The header requires no
Binary Ninja runtime or libraries. It supplies helper definitions, not missing
program types, globals, external functions, or architecture-specific intrinsics.

## Compilers and types

The C implementation requires C11 with GCC/Clang extensions (`__auto_type`,
`__typeof__`, and statement expressions), which Clang-CL also supports. The C++
implementation uses C++11 templates and `memcpy`, without those C extensions.
Use C++14 or later with Clang-CL and Microsoft's C++ standard library.

| Compiler | Language modes checked | Validation |
| --- | --- | --- |
| Clang 21 | C11, C++11, C++17 | Compiled and executed on ARM64 macOS at `-O0`/`-O2`, including UBSan. |
| GCC 16 | C11, C++11, C++17 | Compiled and executed on ARM64 macOS at `-O0`/`-O2`, including UBSan. |
| Clang-CL 21 | C11, C++14, C++17 | Cross-compiled and linked Windows x86, x64, and ARM64 programs at `/Od`/`/O2` with Microsoft's CRT 14.44 and Windows SDK 10.0.26100. |

The Windows programs were not executed on the macOS host. The repository's
`Pseudo C helpers` workflow runs the Clang-CL checks on Windows x64 and the
Clang/GCC checks on Linux. It needs no Binary Ninja build or license.

Microsoft's `cl.exe` is a different compiler: its C mode does not support the
extensions used here, and its C++ mode has not been validated. Clang-CL is
supported without replacing Microsoft's runtime or supplying extra half-float
conversion routines for the representation-copy helpers. A numeric `_Float16`
conversion or other extended arithmetic in the exported program can still need
compiler runtime support, depending on the target.

Standard integer, boolean, and math declarations are included. When the compiler
has native support, the header also defines `int128_t`, `uint128_t`, `float16`,
and `float16_t`. `BN_PSEUDOC_HAS_INT128` and `BN_PSEUDOC_HAS_FLOAT16` report these
capabilities as `0` or `1`. There is no inaccurate substitute for an unavailable
extended type. Set `BN_PSEUDOC_NO_EXTENDED_TYPES` before inclusion if your SDK or
program already defines these names; for example, ARM SDKs can define
`float16_t` as `__fp16` instead of `_Float16`.

Use a compiler target with the original program's integer sizes, pointer size,
floating representations, and byte order. In particular, partial object offsets
are byte offsets in the target's representation. Cross-compiling may be necessary.

## Provided helpers

Suffixes `B`, `W`, `D`, `Q`, and `O` mean 8, 16, 32, 64, and 128 bits. The `O`
helpers and joins producing 128 bits require native 128-bit integers. The
renderer can also emit 80-bit (`T`) operations, which this header does not cover.

| Helper | Meaning |
| --- | --- |
| `BIT_CAST(type, value)` | Copy the same number of representation bytes into `type`. |
| `READ_PART(type, value, offset)` | Read bytes within a scalar or trivially copyable object. |
| `WRITE_PART(type, destination, offset, value)` | Replace exactly those bytes; retain the rest. |
| `ROLB/W/D/Q/O(value, count)`, `RORB/W/D/Q/O(value, count)` | Rotate an unsigned bit vector; count is reduced modulo its width. |
| `RLCB/W/D/Q/O(value, count, carry)`, `RRCB/W/D/Q/O(value, count, carry)` | Rotate through an extra carry bit; count is reduced modulo width + 1. Return the value, not the updated carry. |
| `TEST_BITB/W/D/Q/O(value, index)` | Test a bit **index**, not a mask. Out-of-range indices return false. |
| `LOWB/W/D/Q/O(value)` | Keep the low bits at the suffix's width. |
| `HIGHB/W/D/Q(value)` | Take the high half of an input twice the suffix's width. |
| `COMBINE(high, low)` | Join equally sized integer halves into an unsigned value twice as wide. |
| `__rbit(value)` | Reverse all bits at the operand's integer width. |
| `__cls(value)` | Count leading bits equal to the sign bit, excluding that sign bit. |
| `min(a, b)`, `max(a, b)` | Ordinary C comparison and conversion rules, with single evaluation. |
| `FCMP_UO(a, b)`, `FCMP_O(a, b)` | Legacy unordered/ordered predicates using `isunordered`. |

Helper arguments are evaluated once. Partial offsets must be compile-time
constants; invalid bounds or representation sizes are rejected during compilation.
Writes require an addressable, non-const, non-volatile destination. `WRITE_PART`
evaluates the destination before the source. Other helpers do not promise a
particular order between separate arguments. These are value/object helpers,
not atomic operations or volatile device-memory accessors.

`COMBINE`, `__rbit`, and `__cls` use the operand's C type to determine its width.
Keep width casts from the export, including on constants; for example,
`COMBINE((uint32_t)1, (uint32_t)2)`. Ordinary C integer promotion still applies
to expressions you pass as arguments.

Define `BN_PSEUDOC_NO_MINMAX` to omit the short `min`/`max` names, and
`BN_PSEUDOC_NO_BIT_INTRINSICS` to omit `__rbit`/`__cls` when integrating platform
headers. In C++, prefer qualified standard-library calls such as `std::min` to
avoid ambiguity with these global helpers. Existing macro definitions for
`BIT_CAST`, `READ_PART`, `WRITE_PART`, `COMBINE`, `min`, `max`, `__rbit`, `__cls`,
`FCMP_UO`, and `FCMP_O` take precedence.

## Representation transfers

`BIT_CAST(type, value)` copies an expression's representation into an equally
sized type. Pseudo C uses it when a 16-, 32-, or 64-bit floating value and an integer
exchange bits, such as `FMOV` or a source-level `memcpy`. Numeric conversions
continue to use ordinary casts.

```c
#include <stdint.h>
#include "pseudoc_helpers.h"

uint64_t double_bits(double value)
{
    return BIT_CAST(uint64_t, value);
}
```

The helper checks that the sizes match and uses `memcpy` without violating
aliasing rules. The copy preserves signed zero and NaN payloads. A caller can
supply its own `BIT_CAST` definition before including the header. In C, the
destination type is determined without evaluating a numeric initializer, so a
half-float bit copy does not unnecessarily require a conversion routine from
the compiler runtime.

Copies into a narrower integer first reinterpret the complete floating value,
then narrow its integer representation. For example,
`(uint32_t)BIT_CAST(uint64_t, value)` keeps the low 32 bits of a double; it does
not convert the double's numeric value to an integer.

The header also includes `<math.h>` for standard rounding functions,
`INFINITY`, and NaN predicates. Legacy `FCMP_UO` and `FCMP_O` expressions
use `isunordered` through the helper definitions. To preserve a NaN
payload or signaling bit, use `BIT_CAST` of its exact integer representation;
the standard `NAN` macro cannot guarantee those bits.

When two integer halves form a floating value, Pseudo C joins their unsigned
bits at the full width before applying `BIT_CAST`. Widening before the shift
avoids discarding the high half or relying on signed-shift behavior.

Partial reads and writes of floating variables use `READ_PART(type, value,
offset)` and `WRITE_PART(type, destination, offset, value)`. These helpers copy
object bytes with `memcpy`, preserve untouched bytes, and evaluate each value
or destination once. Offsets are constant byte offsets within the object.
The helpers check both bounds and the write's source width at compile time;
they do not numerically convert the floating value or use an integer pointer
alias to access it.

## Remaining work when recompiling

Pseudo C is a readable representation of analyzed code, and is not always a
complete C translation unit. Supply missing declarations and implementations,
resolve architecture-specific intrinsics and custom calling conventions, and
review unresolved or unimplemented IL. This header does not silently erase
`__convention`, `__offset`, or `ADJ` expressions because doing so can change
meaning. It supplies empty fallbacks for the metadata annotations `__pure` and
`__noreturn` only when they are not already defined.

Compiler builtins such as `__builtin_bswap32` remain compiler-dependent. C++
mode also does not make every exported C expression valid C++ automatically.
Code with signed overflow, invalid numeric conversions, or floating exception
requirements can need further work to preserve the original machine behavior.

## Test the header

The tests need Python 3 and a C/C++ compiler, but no Binary Ninja installation:

```sh
python3 tests/test_helpers.py
python3 tests/test_helpers.py --optimization O0
python3 tests/test_helpers.py --sanitize
CC=gcc CXX=g++ python3 tests/test_helpers.py
```

For Windows, run this in the Native Tools command prompt with LLVM on `PATH`:

```bat
python tests/test_helpers.py --compiler clang-cl
python tests/test_helpers.py --compiler clang-cl --optimization O0
```

Run from this directory. Use `--standard c11`, `--standard c++11`,
`--standard c++14`, or `--standard c++17` to select one mode. Clang-CL defaults
to C11/C++14/C++17; other compilers default to C11/C++11/C++17. `CC`/`CXX`,
`CFLAGS`/`CXXFLAGS`, and `LDFLAGS` can configure a toolchain. For cross builds,
`--no-run` compiles and links without executing; `--compile-only` checks object
compilation only. `--output-dir path` retains source, commands, diagnostics,
programs, and a JSON report in a subdirectory for each language mode. The runner
reports skipped execution explicitly. `--sanitize` requires the GNU-style
driver and its UBSan runtime.

Tests compare rotations and
integer helpers against independently generated bit-vector results, check
representation copies including NaN payloads, exercise single evaluation and
opt-outs, and verify that invalid helper uses fail compilation.

For toolchain setup, see the [Clang-CL documentation](https://clang.llvm.org/docs/UsersManual.html#clang-cl).
