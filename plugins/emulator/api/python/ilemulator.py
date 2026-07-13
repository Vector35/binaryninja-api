# Copyright (c) 2015-2026 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import ctypes
from typing import Callable, Dict, List, Optional, Tuple

import binaryninja
from . import _emulatorcore as core
from .emulator_enums import ILEmulatorStopReason
from binaryninja import binaryview
from binaryninja import lowlevelil


class LLILEmulator:
    """Concrete emulator for Low Level IL.

    Executes LLIL instructions with full register, flag, and memory state.
    Supports cross-function emulation and user-defined hooks for calls,
    syscalls, memory access, and intrinsics.

    Example usage::

        >>> emu = LLILEmulator(bv)
        >>> emu.set_entry_point(here)
        >>> emu.set_register("rsp", 0x7fff0000)
        >>> emu.set_call_hook(lambda emu, target: True)  # skip all calls
        >>> emu.set_max_instructions(1000)
        >>> reason = emu.run()
        >>> print(f"Stopped: {reason.name}, rax = {hex(emu.get_register('rax'))}")
    """

    def __init__(
        self,
        view: 'binaryview.BinaryView',
        il: Optional['lowlevelil.LowLevelILFunction'] = None,
        handle: Optional[core.BNLLILEmulator] = None,
    ):
        if handle is not None:
            LLILHandle = ctypes.POINTER(core.BNLLILEmulator)
            self.handle = ctypes.cast(handle, LLILHandle)
        elif il is not None:
            self.handle = core.BNCreateLLILEmulator(
                ctypes.cast(il.handle, ctypes.POINTER(core.BNLowLevelILFunction)),
                ctypes.cast(view.handle, ctypes.POINTER(core.BNBinaryView)))
            assert self.handle is not None, "Failed to create LLILEmulator"
        else:
            self.handle = core.BNCreateLLILEmulatorForView(ctypes.cast(view.handle, ctypes.POINTER(core.BNBinaryView)))
            assert self.handle is not None, "Failed to create LLILEmulator"

        self._arch = il.arch if il is not None else view.arch
        self._view = view

        # Store callback wrappers to prevent garbage collection
        self._call_hook_cb = None
        self._syscall_hook_cb = None
        self._memory_read_hook_cb = None
        self._memory_write_hook_cb = None
        self._pre_instruction_hook_cb = None
        self._intrinsic_hook_cb = None
        self._stdout_cb = None
        self._stdin_cb = None

        # Store user callbacks
        self._call_hook = None
        self._syscall_hook = None
        self._memory_read_hook = None
        self._memory_write_hook = None
        self._pre_instruction_hook = None
        self._intrinsic_hook = None
        self._stdout_callback = None
        self._stdin_callback = None

    def __del__(self):
        if core is not None and hasattr(self, 'handle') and self.handle is not None:
            core.BNFreeLLILEmulator(self.handle)

    def _get_base(self):
        return core.BNLLILEmulatorGetBase(self.handle)

    # ── Execution ─────────────────────────────────────────────────────────

    def run(self) -> ILEmulatorStopReason:
        """Run until a stop condition is hit."""
        return ILEmulatorStopReason(core.BNILEmulatorRun(self._get_base()))

    def step(self) -> ILEmulatorStopReason:
        """Execute a single instruction."""
        return ILEmulatorStopReason(core.BNILEmulatorStep(self._get_base()))

    def step_n(self, n: int) -> ILEmulatorStopReason:
        """Execute up to *n* instructions."""
        return ILEmulatorStopReason(core.BNILEmulatorStepN(self._get_base(), n))

    def step_over(self) -> ILEmulatorStopReason:
        """Step over the current instruction (runs through called functions)."""
        return ILEmulatorStopReason(core.BNLLILEmulatorStepOver(self.handle))

    def request_stop(self):
        """Request the emulator to stop at the next opportunity. Thread-safe."""
        core.BNILEmulatorRequestStop(self._get_base())

    # ── State ─────────────────────────────────────────────────────────────

    @property
    def instruction_index(self) -> int:
        return core.BNILEmulatorGetInstructionIndex(self._get_base())

    @instruction_index.setter
    def instruction_index(self, index: int):
        core.BNILEmulatorSetInstructionIndex(self._get_base(), index)

    @property
    def current_address(self) -> int:
        return core.BNILEmulatorGetCurrentAddress(self._get_base())

    @property
    def stop_reason(self) -> ILEmulatorStopReason:
        return ILEmulatorStopReason(core.BNILEmulatorGetStopReason(self._get_base()))

    @property
    def stop_message(self) -> str:
        return core.BNILEmulatorGetStopMessage(self._get_base())

    @property
    def instructions_executed(self) -> int:
        return core.BNILEmulatorGetInstructionsExecuted(self._get_base())

    @property
    def call_stack_depth(self) -> int:
        return core.BNLLILEmulatorGetCallStackDepth(self.handle)

    def get_call_stack(self) -> List[Dict[str, int]]:
        """Return the call stack as a list of dicts with 'function_address' and 'return_address'.

        Frame 0 is the current function; subsequent frames are callers.
        For frame 0, 'return_address' is the current PC.
        """
        count = ctypes.c_ulonglong(0)
        entries = core.BNLLILEmulatorGetCallStack(self.handle, count)
        result = []
        if entries:
            for i in range(count.value):
                result.append({
                    'function_address': entries[i].functionAddress,
                    'return_address': entries[i].returnAddress,
                })
            core.BNLLILEmulatorFreeCallStack(entries)
        return result

    def get_mapped_regions(self) -> List[Dict]:
        """Return all mapped memory regions as a list of dicts with 'start', 'size', and 'name'."""
        count = ctypes.c_ulonglong(0)
        regions = core.BNILEmulatorGetMappedRegions(self._get_base(), count)
        result = []
        if regions:
            for i in range(count.value):
                result.append({
                    'start': regions[i].start,
                    'size': regions[i].size,
                    'name': regions[i].name,
                })
            core.BNFreeEmulatorMemoryRegions(regions, count.value)
        return result

    # ── Entry point ───────────────────────────────────────────────────────

    def set_entry_point(self, addr_or_il, instr_index: Optional[int] = None) -> bool:
        """Set the emulation entry point.

        Two forms:

        - ``set_entry_point(0x401000)`` — resolve address to a function and
          start at its first LLIL instruction.  Returns ``False`` if the
          address does not belong to an analyzed function.

        - ``set_entry_point(func.llil, 5)`` — start at LLIL instruction
          index 5 of the given LLIL function.  Always succeeds.
        """
        if instr_index is not None:
            # (LowLevelILFunction, index) form
            il = addr_or_il
            core.BNLLILEmulatorSetEntryPointForIL(self.handle, ctypes.cast(il.handle, ctypes.POINTER(core.BNLowLevelILFunction)), instr_index)
            self._arch = il.arch
            return True
        else:
            # address form
            result = core.BNLLILEmulatorSetEntryPoint(self.handle, addr_or_il)
            return result

    # ── Arguments ─────────────────────────────────────────────────────────

    def set_argument(self, index: int, value: int):
        """Set a single function argument by index using the default calling convention."""
        raw = value.to_bytes(64, 'little', signed=(value < 0))
        buf = (ctypes.c_ubyte * 64)(*raw)
        core.BNLLILEmulatorSetArgument(self.handle, index, buf, 64)

    def set_arguments(self, values: list):
        """Set multiple function arguments using the default calling convention."""
        count = len(values)
        arr = (ctypes.c_uint64 * count)(*values)
        core.BNLLILEmulatorSetArguments(self.handle, arr, count)

    # ── Memory ────────────────────────────────────────────────────────────

    def read_memory(self, addr: int, length: int) -> bytes:
        """Read *length* bytes from emulator memory at *addr*."""
        buf = (ctypes.c_ubyte * length)()
        n = core.BNILEmulatorReadMemory(self._get_base(), buf, addr, length)
        return bytes(buf[:n])

    def write_memory(self, addr: int, data: bytes) -> int:
        """Write *data* to emulator memory at *addr*.  Returns bytes written."""
        buf = (ctypes.c_ubyte * len(data))(*data)
        return core.BNILEmulatorWriteMemory(self._get_base(), addr, buf, len(data))

    def map_memory(self, addr: int, data_or_size, name: str = ""):
        """Map a memory region into the emulator.

        - ``map_memory(0x1000, b'\\x00' * 0x1000)`` — map with data
        - ``map_memory(0x1000, 0x1000)`` — map zero-filled
        - ``map_memory(0x1000, 0x1000, "my_region")`` — map with a name
        """
        base = self._get_base()
        if isinstance(data_or_size, (bytes, bytearray)):
            buf = (ctypes.c_ubyte * len(data_or_size))(*data_or_size)
            if name:
                core.BNILEmulatorMapMemoryNamed(base, addr, buf, len(data_or_size), name.encode())
            else:
                core.BNILEmulatorMapMemory(base, addr, buf, len(data_or_size))
        else:
            size = data_or_size
            if name:
                core.BNILEmulatorMapMemoryZeroNamed(base, addr, size, name.encode())
            else:
                core.BNILEmulatorMapMemoryZero(base, addr, size)

    # ── Breakpoints ───────────────────────────────────────────────────────

    def add_breakpoint(self, addr: int):
        core.BNILEmulatorAddBreakpoint(self._get_base(), addr)

    def remove_breakpoint(self, addr: int):
        core.BNILEmulatorRemoveBreakpoint(self._get_base(), addr)

    def clear_breakpoints(self):
        core.BNILEmulatorClearBreakpoints(self._get_base())

    # ── Limits ────────────────────────────────────────────────────────────

    def set_max_instructions(self, max_count: int):
        core.BNILEmulatorSetMaxInstructions(self._get_base(), max_count)

    # ── Register / flag access ────────────────────────────────────────────

    def _resolve_reg(self, reg) -> int:
        """Accept register name (str) or numeric register ID (int)."""
        if isinstance(reg, str):
            return self._arch.regs[reg].index
        return reg

    def get_register(self, reg) -> int:
        """Get register value.  *reg* can be a name (``'rax'``) or numeric ID."""
        buf = (ctypes.c_ubyte * 64)()
        core.BNLLILEmulatorGetRegister(self.handle, self._resolve_reg(reg), buf, 64)
        return int.from_bytes(bytes(buf), 'little')

    def set_register(self, reg, value: int):
        """Set register value.  *reg* can be a name (``'rax'``) or numeric ID."""
        raw = value.to_bytes(64, 'little', signed=(value < 0))
        buf = (ctypes.c_ubyte * 64)(*raw)
        core.BNLLILEmulatorSetRegister(self.handle, self._resolve_reg(reg), buf, 64)

    def get_temp_register(self, index: int) -> int:
        buf = (ctypes.c_ubyte * 64)()
        core.BNLLILEmulatorGetTempRegister(self.handle, index, buf, 64)
        return int.from_bytes(bytes(buf), 'little')

    def set_temp_register(self, index: int, value: int):
        raw = value.to_bytes(64, 'little', signed=(value < 0))
        buf = (ctypes.c_ubyte * 64)(*raw)
        core.BNLLILEmulatorSetTempRegister(self.handle, index, buf, 64)

    def get_flag(self, flag) -> int:
        """Get flag value.  *flag* can be a name (``'z'``) or numeric ID."""
        if isinstance(flag, str):
            flag = self._arch._flags[flag]
        return core.BNLLILEmulatorGetFlag(self.handle, flag)

    def set_flag(self, flag, value: int):
        """Set flag value.  *flag* can be a name (``'z'``) or numeric ID."""
        if isinstance(flag, str):
            flag = self._arch._flags[flag]
        core.BNLLILEmulatorSetFlag(self.handle, flag, value)

    @property
    def regs(self) -> Dict[str, int]:
        """Snapshot of all named registers as ``{name: value}``."""
        result = {}
        for name in self._arch.regs:
            result[name] = self.get_register(name)
        return result

    # ── Hooks ─────────────────────────────────────────────────────────────

    def set_call_hook(self, callback: Optional[Callable[['LLILEmulator', int], bool]]):
        """Set a hook called on CALL instructions.

        The callback receives ``(emulator, target_address)`` and should return
        ``True`` to indicate the call was handled (emulator advances past the
        call) or ``False`` to let the emulator try cross-function emulation.
        Pass ``None`` to remove the hook.
        """
        self._call_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator), ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetCallHook(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._call_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, target):
            try:
                return self._call_hook(self, target)
            except:
                return False

        self._call_hook_cb = _cb
        core.BNILEmulatorSetCallHook(self._get_base(), None, _cb)

    def set_syscall_hook(self, callback: Optional[Callable[['LLILEmulator'], bool]]):
        """Set a hook called on SYSCALL instructions.

        Return ``True`` if handled, ``False`` to stop.
        """
        self._syscall_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator))
        if callback is None:
            core.BNILEmulatorSetSyscallHook(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._syscall_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu):
            try:
                return self._syscall_hook(self)
            except:
                return False

        self._syscall_hook_cb = _cb
        core.BNILEmulatorSetSyscallHook(self._get_base(), None, _cb)

    def set_memory_read_hook(
        self,
        callback: Optional[Callable[['LLILEmulator', int, int], Optional[int]]],
    ):
        """Set a hook called on every memory read.

        The callback receives ``(emulator, address, size)`` and should return
        the value to use, or ``None`` to fall through to normal memory.
        """
        self._memory_read_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator),
            ctypes.c_ulonglong, ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetMemoryReadHook(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._memory_read_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, addr, size, out_buf, buf_len):
            try:
                result = self._memory_read_hook(self, addr, size)
                if result is not None:
                    raw = result.to_bytes(buf_len, 'little', signed=(result < 0))
                    for i in range(buf_len):
                        out_buf[i] = raw[i]
                    return True
                return False
            except:
                return False

        self._memory_read_hook_cb = _cb
        core.BNILEmulatorSetMemoryReadHook(self._get_base(), None, _cb)

    def set_memory_write_hook(
        self,
        callback: Optional[Callable[['LLILEmulator', int, int, int], bool]],
    ):
        """Set a hook called on every memory write.

        The callback receives ``(emulator, address, size, value)`` and should
        return ``True`` if handled, ``False`` to let the write proceed normally.
        """
        self._memory_write_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator),
            ctypes.c_ulonglong, ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetMemoryWriteHook(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._memory_write_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, addr, size, buf, buf_len):
            try:
                raw = bytes(buf[:buf_len])
                value = int.from_bytes(raw, 'little')
                return self._memory_write_hook(self, addr, size, value)
            except:
                return False

        self._memory_write_hook_cb = _cb
        core.BNILEmulatorSetMemoryWriteHook(self._get_base(), None, _cb)

    def set_pre_instruction_hook(
        self,
        callback: Optional[Callable[['LLILEmulator', int], bool]],
    ):
        """Set a hook called before each instruction executes.

        The callback receives ``(emulator, instruction_index)`` and should
        return ``True`` to continue or ``False`` to stop.
        """
        self._pre_instruction_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator), ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetPreInstructionHook(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._pre_instruction_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, instr_index):
            try:
                return self._pre_instruction_hook(self, instr_index)
            except:
                return False

        self._pre_instruction_hook_cb = _cb
        core.BNILEmulatorSetPreInstructionHook(self._get_base(), None, _cb)

    def set_intrinsic_hook(
        self,
        callback: Optional[Callable[
            ['LLILEmulator', int, List[int]],
            Optional[List[Tuple[int, int]]],
        ]],
    ):
        """Set a hook called on INTRINSIC instructions.

        The callback receives ``(emulator, intrinsic_id, params)`` and should
        return a list of ``(register_id, value)`` pairs if handled, or ``None``
        to stop with Unimplemented.
        """
        self._intrinsic_hook = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
            ctypes.POINTER(core.BNLLILEmulator), ctypes.c_uint,
            ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_ulonglong,
            ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_ulonglong))
        if callback is None:
            core.BNLLILEmulatorSetIntrinsicHook(self.handle, None, ctypes.cast(None, _CB_T))
            self._intrinsic_hook_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, intrinsic, params, param_count, out_values, out_regs, out_count):
            try:
                param_list = [params[i] for i in range(param_count)]
                result = self._intrinsic_hook(self, intrinsic, param_list)
                if result is not None:
                    out_count[0] = len(result)
                    for i, (reg, val) in enumerate(result):
                        out_regs[i] = reg
                        out_values[i] = val
                    return True
                return False
            except:
                return False

        self._intrinsic_hook_cb = _cb
        core.BNLLILEmulatorSetIntrinsicHook(self.handle, None, _cb)

    def set_stdout_callback(
        self,
        callback: Optional[Callable[['LLILEmulator', bytes], None]],
    ):
        """Set a callback for stdout output from emulated printf/puts/putchar.

        The callback receives ``(emulator, data)`` where *data* is a ``bytes``
        object containing the raw output. Pass ``None`` to remove the callback.
        """
        self._stdout_callback = callback
        _CB_T = ctypes.CFUNCTYPE(None, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator),
            ctypes.c_char_p, ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetStdoutCallback(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._stdout_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, data, length):
            try:
                self._stdout_callback(self, data[:length])
            except:
                pass

        self._stdout_cb = _cb
        core.BNILEmulatorSetStdoutCallback(self._get_base(), None, _cb)

    def set_stdin_callback(
        self,
        callback: Optional[Callable[['LLILEmulator', int], bytes]],
    ):
        """Set a callback for stdin reads from emulated getchar/fgets/fread.

        The callback receives ``(emulator, max_len)`` and should return a
        ``bytes`` object with the input data (up to *max_len* bytes).
        Return ``b''`` for EOF. Pass ``None`` to remove the callback.
        """
        self._stdin_callback = callback
        _CB_T = ctypes.CFUNCTYPE(ctypes.c_ulonglong, ctypes.c_void_p,
            ctypes.POINTER(core.BNILEmulator),
            ctypes.c_char_p, ctypes.c_ulonglong)
        if callback is None:
            core.BNILEmulatorSetStdinCallback(self._get_base(), None, ctypes.cast(None, _CB_T))
            self._stdin_cb = None
            return

        @_CB_T
        def _cb(ctxt, emu, buf, max_len):
            try:
                data = self._stdin_callback(self, max_len)
                if data:
                    n = min(len(data), max_len)
                    ctypes.memmove(buf, data[:n], n)
                    return n
                return 0
            except:
                return 0

        self._stdin_cb = _cb
        core.BNILEmulatorSetStdinCallback(self._get_base(), None, _cb)

    # ── Built-in libc stub settings ──────────────────────────────────────

    @property
    def builtin_libc_stubs(self) -> bool:
        """Whether built-in libc stub emulation is enabled (default: True)."""
        return core.BNLLILEmulatorIsBuiltinLibcStubsEnabled(self.handle)

    @builtin_libc_stubs.setter
    def builtin_libc_stubs(self, value: bool):
        core.BNLLILEmulatorSetBuiltinLibcStubsEnabled(self.handle, value)

    @property
    def log_libc_calls(self) -> bool:
        """Whether libc stub calls are logged to the console (default: True)."""
        return core.BNLLILEmulatorIsLogLibcCalls(self.handle)

    @log_libc_calls.setter
    def log_libc_calls(self, value: bool):
        core.BNLLILEmulatorSetLogLibcCalls(self.handle, value)

    @property
    def nop_unknown_externals(self) -> bool:
        """Whether unhandled external calls are treated as no-ops returning 0 (default: False)."""
        return core.BNLLILEmulatorIsNopUnknownExternals(self.handle)

    @nop_unknown_externals.setter
    def nop_unknown_externals(self, value: bool):
        core.BNLLILEmulatorSetNopUnknownExternals(self.handle, value)

    # ── Reset ─────────────────────────────────────────────────────────────

    def reset(self):
        """Reset all emulator state (registers, memory, flags, call stack)."""
        core.BNILEmulatorReset(self._get_base())

    # ── State serialization ──────────────────────────────────────────────

    def save_state(self) -> str:
        """Serialize emulator state to a JSON string."""
        result = core.BNLLILEmulatorSaveState(self.handle)
        if result is None:
            return ""
        return result

    def load_state(self, json_str: str) -> bool:
        """Restore emulator state from a JSON string."""
        return core.BNLLILEmulatorLoadState(self.handle, json_str.encode('utf-8'))

    def save_state_to_file(self, path: str):
        """Save emulator state to a file."""
        state = self.save_state()
        with open(path, 'w') as f:
            f.write(state)

    def load_state_from_file(self, path: str) -> bool:
        """Load emulator state from a file."""
        with open(path, 'r') as f:
            return self.load_state(f.read())
