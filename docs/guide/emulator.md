# BNIL Emulator — Python API Guide

The emulator plugin executes Binary Ninja's Low Level IL (LLIL) with full register,
flag, and memory state. It is aimed at focused, snippet-level tasks — decrypting
strings, resolving API hashes, evaluating a slice of a function — rather than
full-program or whole-system emulation. See the
[plugin README](https://github.com/Vector35/binaryninja-api/blob/dev/plugins/emulator/README.md)
for the scope, accuracy notes, and the list of supported LLIL instructions.

> **Experimental.** The API and behavior may change.

Today the emulator works on **LLIL**; we intend to expand it to **MLIL** and **HLIL**
as well.

## Contents

- [Getting the class](#getting-the-class)
- [Creating an emulator](#creating-an-emulator)
- [Setting the entry point](#setting-the-entry-point)
- [Running and stepping](#running-and-stepping)
- [Stop reasons](#stop-reasons)
- [Registers, flags, and temporaries](#registers-flags-and-temporaries)
- [Memory](#memory)
- [Function arguments](#function-arguments)
- [Breakpoints](#breakpoints)
- [Hooks](#hooks)
- [Built-in libc stubs](#built-in-libc-stubs)
- [Call stack](#call-stack)
- [State serialization](#state-serialization)
- [Full example: cross-function emulation](#full-example-cross-function-emulation)
- [API reference](#api-reference)

## Getting the class

The emulator is a normal importable class — there is no auto-injected console
variable. In the Python console or a headless script:

```python
from binaryninja.emulator import LLILEmulator, ILEmulatorStopReason
```

In the interactive console, `bv` (current view) and `here` (current address) are
already available as built-in magic variables, so the two lines below are all you
need to get going:

```python
emu = LLILEmulator(bv)
emu.set_entry_point(here)
```

If you use the emulator often and want `LLILEmulator` available without importing
each session, add the import to `~/.binaryninja/startup.py`.

## Creating an emulator

`LLILEmulator` can be constructed three ways:

```python
# 1. For a whole view — resolve addresses to functions on demand (most common).
emu = LLILEmulator(bv)

# 2. For a specific LLIL function.
emu = LLILEmulator(bv, il=func.llil)

# 3. Wrap an existing core handle (advanced / internal).
emu = LLILEmulator(bv, handle=raw_handle)
```

A view can have as many independent emulators as you like; each keeps its own
registers, memory, and breakpoints.

## Setting the entry point

`set_entry_point` accepts two forms:

```python
# Address form: resolve an address to its function and start at its first LLIL
# instruction. Returns False if the address is not inside an analyzed function.
if not emu.set_entry_point(0x401000):
    raise ValueError("address is not in an analyzed function")

# IL form: start at a specific LLIL instruction index of a given LLIL function.
emu.set_entry_point(func.llil, 5)
```

## Running and stepping

```python
emu.set_max_instructions(100000)     # safety limit against runaway loops
reason = emu.run()                   # run until a stop condition

emu.step()                           # execute a single instruction
emu.step_n(10)                       # execute up to 10 instructions
emu.step_over()                      # step over a call (run through the callee)

emu.request_stop()                   # ask a running emulator to stop (thread-safe)
```

Progress and position:

```python
emu.instructions_executed            # count since the last reset
emu.current_address                  # address of the current instruction
emu.instruction_index                # LLIL index within the current function (settable)
```

## Stop reasons

`run`, `step`, `step_n`, and `step_over` all return an `ILEmulatorStopReason`, also
available afterward via `emu.stop_reason` with a human-readable `emu.stop_message`:

| Reason | Meaning |
| --- | --- |
| `ILEmulatorRunning` | Still running (not a terminal state) |
| `ILEmulatorBreakpoint` | Hit a breakpoint |
| `ILEmulatorInstructionLimit` | Reached `set_max_instructions` |
| `ILEmulatorHalt` | Returned from the top-level function / halted normally |
| `ILEmulatorError` | Internal error |
| `ILEmulatorCallHook` | Stopped by a call hook |
| `ILEmulatorSyscallHook` | Stopped by a syscall hook |
| `ILEmulatorUndefinedBehavior` | Executed undefined behavior |
| `ILEmulatorUnimplemented` | Hit an unimplemented LLIL instruction |
| `ILEmulatorUserRequestedStop` | Stopped via `request_stop` |

```python
reason = emu.run()
if reason != ILEmulatorStopReason.ILEmulatorHalt:
    print(f"stopped early: {reason.name} — {emu.stop_message}")
```

## Registers, flags, and temporaries

Registers accept either a name (`'rax'`) or a numeric register ID:

```python
emu.set_register('rsp', 0x7fff0000)
rax = emu.get_register('rax')

emu.regs                 # snapshot dict of every named register -> value

emu.set_flag('z', 1)     # flag by name or ID
emu.get_flag('z')

emu.set_temp_register(0, 0x1234)   # LLIL temporary registers, by index
emu.get_temp_register(0)
```

## Memory

> **The emulator does not inherit memory from the BinaryView.** It starts with an
> empty address space of its own. Execution works because the emulator runs on the
> lifted LLIL, not by fetching bytes from its memory — but any data the code *reads*
> (globals, `.rodata`, strings, tables, the stack) is **not** present unless you put
> it there. Reading an address that holds data in the view returns zeroes in the
> emulator. If you want the view's bytes, copy them in explicitly.

Map regions before accessing them, then read and write raw bytes:

```python
emu.map_memory(0x1000, b'\x00' * 0x1000)       # map with data
emu.map_memory(0x2000, 0x1000)                 # map zero-filled
emu.map_memory(0x3000, 0x1000, "stack")        # map a named region

emu.write_memory(0x1000, b'hello')             # returns bytes written
emu.read_memory(0x1000, 5)                      # -> b'hello'

emu.get_mapped_regions()   # [{'start':..., 'size':..., 'name':...}, ...]
```

### Copying BinaryView memory into the emulator

To emulate code that reads existing program data, copy the relevant bytes from the
view into the emulator at the same addresses. Copy whole segments:

```python
for seg in bv.segments:
    data = bv.read(seg.start, seg.length)      # bytes actually backed by the file
    if data:
        emu.map_memory(seg.start, data)
```

...or just the region you need (cheaper for large binaries):

```python
emu.map_memory(table_addr, bv.read(table_addr, table_size))
```

Alternatively, serve reads on demand with a memory-read hook that pulls from the view
(see [Hooks](#hooks)):

```python
emu.set_memory_read_hook(
    lambda emu, addr, size: int.from_bytes(bv.read(addr, size), 'little')
                            if bv.read(addr, size) else None)
```

## Function arguments

Arguments are placed using the function's default calling convention:

```python
emu.set_argument(0, 0x1000)          # a single argument by index
emu.set_arguments([0x1000, 16, 42])  # several at once
```

## Breakpoints

```python
emu.add_breakpoint(0x401234)         # stops *before* executing that address
emu.remove_breakpoint(0x401234)
emu.clear_breakpoints()
```

A breakpoint stops the emulator before the target instruction executes, so on stop
`emu.current_address` equals the breakpoint address and its side effects have not yet
occurred.

## Hooks

Hooks let embedding code intercept emulation. Pass a callable to install a hook and
`None` to remove it. Exceptions raised inside a hook are swallowed and treated as
"not handled".

```python
# CALL: return True if handled (advance past the call), False to let the emulator
# try cross-function emulation.
emu.set_call_hook(lambda emu, target: True)      # skip all calls

# SYSCALL: return True if handled, False to stop.
emu.set_syscall_hook(lambda emu: True)

# Memory read: return the value to use, or None to fall through to real memory.
emu.set_memory_read_hook(lambda emu, addr, size: 0 if addr in mmio else None)

# Memory write: return True if handled, False to let the write proceed.
emu.set_memory_write_hook(lambda emu, addr, size, value: False)

# Before each instruction: return True to continue, False to stop.
emu.set_pre_instruction_hook(lambda emu, index: True)

# INTRINSIC: return a list of (register_id, value) pairs if handled, else None.
emu.set_intrinsic_hook(lambda emu, intrinsic, params: None)

# stdout from emulated printf/puts/putchar; data is bytes.
emu.set_stdout_callback(lambda emu, data: print(data.decode('latin1'), end=''))

# stdin for emulated getchar/fgets/fread; return up to max_len bytes, b'' for EOF.
emu.set_stdin_callback(lambda emu, max_len: b'')
```

The memory-read hook fires on **every** load, including implicit reads such as the
stack pop performed by a `ret`, so filter by address when you only want to intercept
specific regions.

## Built-in libc stubs

The emulator ships simple stubs for common libc functions so snippets that call
`printf`, `malloc`, etc. can run without a real libc:

```python
emu.builtin_libc_stubs      # bool, default True — enable the built-in stubs
emu.log_libc_calls          # bool, default True — log stub calls to the console
emu.nop_unknown_externals   # bool, default False — treat unknown external calls
                            #   as no-ops returning 0 instead of stopping
```

## Call stack

While stopped inside a called function:

```python
emu.call_stack_depth        # number of nested calls
emu.get_call_stack()        # [{'function_address':..., 'return_address':...}, ...]
```

Frame 0 is the current function; later frames are its callers.

## State serialization

Emulator state (registers, flags, memory, call stack) can be snapshotted to JSON and
restored — useful for save/restore points or reproducing a state across runs:

```python
snapshot = emu.save_state()          # -> JSON string
emu.load_state(snapshot)             # restore, returns True on success

emu.save_state_to_file("state.json")
emu.load_state_from_file("state.json")

emu.reset()                          # clear all state back to initial
```

## Full example: cross-function emulation

Decrypt a string by emulating a decryption routine, letting the emulator run through
the called functions and skipping anything it can't resolve:

```python
from binaryninja.emulator import LLILEmulator, ILEmulatorStopReason

emu = LLILEmulator(bv)
emu.nop_unknown_externals = True          # don't stop on unresolved externals
emu.set_max_instructions(1_000_000)

# Give the routine a scratch output buffer and the encrypted input.
emu.map_memory(0x100000, 0x1000, "out")
emu.map_memory(0x101000, encrypted, "in")

emu.set_entry_point(decrypt_func.start)
emu.set_arguments([0x100000, 0x101000, len(encrypted)])

reason = emu.run()
if reason == ILEmulatorStopReason.ILEmulatorHalt:
    print(emu.read_memory(0x100000, 0x100).split(b'\x00', 1)[0])
else:
    print(f"stopped: {reason.name} — {emu.stop_message}")
```

## API reference

Everything is on the `LLILEmulator` class.

**Construction:** `LLILEmulator(view, il=None, handle=None)`

**Execution:** `run`, `step`, `step_n`, `step_over`, `request_stop`,
`set_max_instructions`, `reset`

**Entry / arguments:** `set_entry_point`, `set_argument`, `set_arguments`

**State (properties):** `instruction_index`, `current_address`, `stop_reason`,
`stop_message`, `instructions_executed`, `call_stack_depth`, `regs`

**Registers / flags:** `get_register`, `set_register`, `get_temp_register`,
`set_temp_register`, `get_flag`, `set_flag`

**Memory:** `map_memory`, `read_memory`, `write_memory`, `get_mapped_regions`

**Breakpoints:** `add_breakpoint`, `remove_breakpoint`, `clear_breakpoints`

**Hooks:** `set_call_hook`, `set_syscall_hook`, `set_memory_read_hook`,
`set_memory_write_hook`, `set_pre_instruction_hook`, `set_intrinsic_hook`,
`set_stdout_callback`, `set_stdin_callback`

**libc stubs (properties):** `builtin_libc_stubs`, `log_libc_calls`,
`nop_unknown_externals`

**Call stack:** `get_call_stack`

**Serialization:** `save_state`, `load_state`, `save_state_to_file`,
`load_state_from_file`

For runnable, self-contained examples of every feature above, see the
[test suite](https://github.com/Vector35/binaryninja-api/blob/dev/plugins/emulator/test/emulator_test.py).
