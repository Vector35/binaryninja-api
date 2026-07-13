# BNIL Emulator

A standalone Binary Ninja plugin that emulates Binary Ninja's Low Level Intermediate
Language (LLIL). It is structured like the [debugger](https://github.com/Vector35/debugger):
the engine builds into its own plugin (`emulatorcore`) against the public Binary Ninja
API, exposes a C ABI, and ships C++ (`emulatorapi`) and Python bindings.

> **Experimental.** This plugin is experimental and under active development; its API and
> behavior may change.

The [Python API guide](../../docs/guide/emulator.md) walks through the `LLILEmulator`
class with examples; runnable tests live in [`test/emulator_test.py`](test/emulator_test.py).

## Scope & accuracy

This plugin emulates the given BNIL instructions — it is **not** meant to match the accuracy
of full CPU emulators like [Unicorn](https://www.unicorn-engine.org/) or
[QEMU](https://www.qemu.org/). Because emulation runs on Binary Ninja's *lifted* IL rather
than the raw machine instructions, the emulated state may deviate from the actual state of
the program during real execution.

In practice it is aimed at focused tasks — decrypting strings, resolving API hashes, and
similar snippet-level emulation. It is **not** intended for full-program or whole-system
emulation.

## Layout

- `core/` — the emulator engine (`ilemulator`, `llilemulator`) and plugin entry point,
  built as the `emulatorcore` plugin. Exposes the emulator C ABI (`api/ffi.h`).
- `api/` — C++ wrapper (`emulatorapi`, `BinaryNinja::LLILEmulator`) over the C ABI, plus
  Python bindings under `api/python/`.

## Building

```sh
export BN_API_PATH=/path/to/binaryninja-api
cmake -S . -B build           # -GNinja optional
cmake --build build
```

The resulting `emulatorcore` plugin is written to `build/out/plugins/`.

## Testing

The Python test suite is self-contained — it assembles tiny `BinaryView`s from raw
machine code rather than shipping test binaries — so it runs headless against any
Binary Ninja install that has the emulator plugin:

```sh
PYTHONPATH=<bn install>/python python3 -m pytest test/emulator_test.py
# or, without pytest:
PYTHONPATH=<bn install>/python python3 test/emulator_test.py
```

Inside the Binary Ninja source tree these same tests also run as part of the main
Binary Ninja test suite (`tests/python/test_emulator.py` loads this module), so
`cd tests && pytest python` exercises them alongside everything else.

## Support status

Only **LLIL** emulation is supported today. **MLIL and HLIL emulation are planned** for the
future.

Emulating an unsupported instruction stops the emulator with an `Unimplemented` stop reason.

### Supported LLIL instructions

- **Constants:** `CONST`, `CONST_PTR`, `EXTERN_PTR`, `FLOAT_CONST`
- **Registers:** `REG`, `SET_REG`, `REG_SPLIT`, `SET_REG_SPLIT`, `LOW_PART`
- **Memory:** `LOAD`, `STORE`, `PUSH`, `POP`
- **Arithmetic:** `ADD`, `ADC`, `SUB`, `SBB`, `MUL`, `MULU_DP`, `MULS_DP`, `DIVU`, `DIVS`,
  `DIVU_DP`, `DIVS_DP`, `MODU`, `MODS`, `MODU_DP`, `MODS_DP`, `NEG`, `ADD_OVERFLOW`
- **Bitwise / shifts:** `AND`, `OR`, `XOR`, `NOT`, `LSL`, `LSR`, `ASR`, `ROL`, `ROR`, `RLC`,
  `RRC`, `SX`, `ZX`, `LOW_PART`, `TEST_BIT`, `BOOL_TO_INT`
- **Comparisons:** `CMP_E`, `CMP_NE`, `CMP_SLT`, `CMP_SLE`, `CMP_SGE`, `CMP_SGT`, `CMP_ULT`,
  `CMP_ULE`, `CMP_UGE`, `CMP_UGT`
- **Flags:** `FLAG`, `SET_FLAG`, `FLAG_BIT`, `FLAG_COND`, `FLAG_GROUP`
- **Control flow:** `JUMP`, `JUMP_TO`, `GOTO`, `IF`, `CALL`, `CALL_STACK_ADJUST`, `TAILCALL`,
  `RET`, `NORET`
- **Other:** `NOP`

### Not yet supported

- **Floating point:** `FADD`, `FSUB`, `FMUL`, `FDIV`, `FSQRT`, `FABS`, `FNEG`, `FCMP_*`,
  `FLOAT_CONV`, `FLOAT_TO_INT`, `INT_TO_FLOAT`, `ROUND_TO_INT`, `CEIL`, `FLOOR`, `FTRUNC`
  (float *constants* are read, but float arithmetic is not evaluated)
- **Register stacks (x87/FPU-style):** `REG_STACK_REL`, `SET_REG_STACK_REL`, `REG_STACK_PUSH`,
  `REG_STACK_POP`, `REG_STACK_FREE_REG`, `REG_STACK_FREE_REL`
- **Bit operations:** `BSWAP`, `CLZ`, `CTZ`, `CLS`, `POPCNT`, `RBIT`, `ABS`, `MINS`, `MAXS`,
  `MINU`, `MAXU`
- **System / hooks** (no built-in semantics — stop unless the embedding code registers a
  hook): `SYSCALL`, `INTRINSIC`
- **Halting / non-representable** (stop the emulator): `BP`, `TRAP`, `UNDEF`, `UNIMPL`,
  `UNIMPL_MEM`
- **Other:** `ASSERT`, `FORCE_VER`, `CALL_PARAM`
