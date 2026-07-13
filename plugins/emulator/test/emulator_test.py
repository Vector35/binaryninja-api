#!/usr/bin/env python3
#
# Unit tests for the BNIL (LLIL) emulator plugin.
#
# These tests are self-contained: instead of shipping test binaries, each test
# assembles a tiny BinaryView from raw x86-64 machine code, lets Binary Ninja
# lift it to LLIL, and emulates the result. Run headless with, e.g.:
#
#     PYTHONPATH=<bn>/python python3 -m pytest emulator_test.py
#     PYTHONPATH=<bn>/python python3 emulator_test.py
#
# Requires the `emulator` core plugin to be present in the Binary Ninja install.

import os
import tempfile
import unittest

from binaryninja import BinaryView, Architecture

try:
    from emulator import LLILEmulator, ILEmulatorStopReason
except ImportError:
    from binaryninja.emulator import LLILEmulator, ILEmulatorStopReason


def make_bv(code: bytes, entries=(0,), arch: str = 'x86_64') -> BinaryView:
    """Build an analyzed BinaryView from raw machine code with a function at each entry."""
    bv = BinaryView.new(code)
    bv.platform = Architecture[arch].standalone_platform
    for entry in entries:
        bv.add_function(entry)
    bv.update_analysis_and_wait()
    return bv


# Common x86-64 snippets used across tests.
#   mov eax, 5 (0..4); mov ebx, 3 (5..9); add eax, ebx (0xa..0xb); ret (0xc)
ADD_CONSTS = b'\xb8\x05\x00\x00\x00\xbb\x03\x00\x00\x00\x01\xd8\xc3'
#   mov eax, edi; add eax, esi; ret          -> returns arg0 + arg1
ADD_ARGS = b'\x89\xf8\x01\xf0\xc3'
#   mov ecx, 0x100000; dec ecx; jnz -3; ret  -> long-running loop
BUSY_LOOP = b'\xb9\x00\x00\x10\x00\xff\xc9\x75\xfc\xc3'
#   call +6 (target 0xb); ret; <pad>; ret@0xb
CALL_SNIPPET = b'\xe8\x06\x00\x00\x00\xc3\x90\x90\x90\x90\x90\xc3'
#   mov eax, [rdi]; ret
LOAD_RDI = b'\x8b\x07\xc3'
#   mov [rdi], eax; ret
STORE_RDI = b'\x89\x07\xc3'


class EmulatorTestBase(unittest.TestCase):
    def emulator_for(self, code: bytes, entries=(0,), entry_point=0, max_instructions=1000):
        bv = make_bv(code, entries=entries)
        emu = LLILEmulator(bv)
        self.assertTrue(emu.set_entry_point(entry_point))
        emu.set_max_instructions(max_instructions)
        # Keep the view alive for the lifetime of the test.
        emu._test_bv = bv
        return emu


class ExecutionTests(EmulatorTestBase):
    def test_basic_arithmetic(self):
        emu = self.emulator_for(ADD_CONSTS)
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorHalt)
        self.assertEqual(emu.get_register('rax'), 8)

    def test_step_advances_one_instruction(self):
        emu = self.emulator_for(ADD_CONSTS)
        self.assertEqual(emu.instructions_executed, 0)
        emu.step()
        self.assertEqual(emu.instructions_executed, 1)
        self.assertEqual(emu.get_register('rax'), 5)

    def test_step_n(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.step_n(2)
        self.assertEqual(emu.instructions_executed, 2)
        self.assertEqual(emu.get_register('rax'), 5)
        self.assertEqual(emu.get_register('rbx'), 3)

    def test_instruction_index_property(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.step()
        self.assertGreater(emu.instruction_index, 0)
        emu.instruction_index = 0
        self.assertEqual(emu.instruction_index, 0)

    def test_current_address_and_stop_message(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.step()
        self.assertIsInstance(emu.current_address, int)
        emu.run()
        self.assertIsInstance(emu.stop_message, str)
        self.assertEqual(emu.stop_reason, ILEmulatorStopReason.ILEmulatorHalt)

    def test_instruction_limit(self):
        emu = self.emulator_for(BUSY_LOOP, max_instructions=50)
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorInstructionLimit)
        self.assertEqual(emu.instructions_executed, 50)

    def test_reset_clears_state(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 8)
        emu.reset()
        self.assertEqual(emu.get_register('rax'), 0)
        self.assertEqual(emu.instructions_executed, 0)


class EntryPointTests(EmulatorTestBase):
    def test_entry_point_by_address(self):
        bv = make_bv(ADD_CONSTS)
        emu = LLILEmulator(bv)
        self.assertTrue(emu.set_entry_point(0))

    def test_entry_point_invalid_address(self):
        bv = make_bv(ADD_CONSTS)
        emu = LLILEmulator(bv)
        self.assertFalse(emu.set_entry_point(0xdeadbeef))

    def test_entry_point_by_il_index(self):
        bv = make_bv(ADD_CONSTS)
        llil = bv.get_function_at(0).llil
        emu = LLILEmulator(bv, il=llil)
        self.assertTrue(emu.set_entry_point(llil, 0))
        emu.set_max_instructions(100)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 8)


class RegisterFlagTests(EmulatorTestBase):
    def test_register_get_set_by_name(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.set_register('rax', 0x1122334455667788)
        self.assertEqual(emu.get_register('rax'), 0x1122334455667788)

    def test_register_get_set_by_id(self):
        emu = self.emulator_for(ADD_CONSTS)
        reg_id = emu._arch.regs['rax'].index
        emu.set_register(reg_id, 0xabcd)
        self.assertEqual(emu.get_register(reg_id), 0xabcd)
        self.assertEqual(emu.get_register('rax'), 0xabcd)

    def test_regs_snapshot(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.set_register('rax', 0x42)
        regs = emu.regs
        self.assertIn('rax', regs)
        self.assertEqual(regs['rax'], 0x42)

    def test_temp_registers(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.set_temp_register(0, 0x1234)
        self.assertEqual(emu.get_temp_register(0), 0x1234)

    def test_flags(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.set_flag('z', 1)
        self.assertEqual(emu.get_flag('z'), 1)
        emu.set_flag('z', 0)
        self.assertEqual(emu.get_flag('z'), 0)


class MemoryTests(EmulatorTestBase):
    def test_map_write_read(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.map_memory(0x200000, 0x1000)
        n = emu.write_memory(0x200000, b'\xde\xad\xbe\xef')
        self.assertEqual(n, 4)
        self.assertEqual(emu.read_memory(0x200000, 4), b'\xde\xad\xbe\xef')

    def test_map_with_data(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.map_memory(0x300000, b'\x01\x02\x03\x04')
        self.assertEqual(emu.read_memory(0x300000, 4), b'\x01\x02\x03\x04')

    def test_map_named_region_listed(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.map_memory(0x400000, 0x1000, "scratch")
        regions = emu.get_mapped_regions()
        self.assertTrue(any(r['name'] == 'scratch' for r in regions))
        scratch = next(r for r in regions if r['name'] == 'scratch')
        self.assertEqual(scratch['start'], 0x400000)
        self.assertEqual(scratch['size'], 0x1000)

    def test_memory_not_inherited_from_view(self):
        # The emulator has its own empty address space; it does not read the
        # BinaryView's bytes. Data must be copied in explicitly.
        code = ADD_CONSTS + b'\xAA\xBB\xCC\xDD'  # data appended after the code
        data_addr = len(ADD_CONSTS)
        bv = make_bv(code)
        self.assertEqual(bv.read(data_addr, 4), b'\xAA\xBB\xCC\xDD')
        emu = LLILEmulator(bv)
        # Not present in the emulator until mapped.
        self.assertEqual(emu.read_memory(data_addr, 4), b'\x00\x00\x00\x00')
        # After copying it in, the emulator sees it.
        emu.map_memory(data_addr, bv.read(data_addr, 4))
        self.assertEqual(emu.read_memory(data_addr, 4), b'\xAA\xBB\xCC\xDD')


class BreakpointTests(EmulatorTestBase):
    def test_breakpoint_stops_before_instruction(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.add_breakpoint(0xa)  # the `add eax, ebx` instruction
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorBreakpoint)
        self.assertEqual(emu.current_address, 0xa)
        self.assertEqual(emu.get_register('rax'), 5)  # add has not executed yet

    def test_remove_breakpoint(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.add_breakpoint(0xa)
        emu.remove_breakpoint(0xa)
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorHalt)
        self.assertEqual(emu.get_register('rax'), 8)

    def test_clear_breakpoints(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.add_breakpoint(0x5)
        emu.add_breakpoint(0xa)
        emu.clear_breakpoints()
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorHalt)


class ArgumentTests(EmulatorTestBase):
    def test_set_arguments(self):
        emu = self.emulator_for(ADD_ARGS)
        emu.set_arguments([10, 20])
        emu.run()
        self.assertEqual(emu.get_register('rax'), 30)

    def test_set_single_argument(self):
        emu = self.emulator_for(ADD_ARGS)
        emu.set_argument(0, 7)
        emu.set_argument(1, 35)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 42)


class CallStackTests(EmulatorTestBase):
    def test_call_stack_inside_callee(self):
        emu = self.emulator_for(CALL_SNIPPET, entries=(0, 0xb))
        emu.add_breakpoint(0xb)
        emu.run()
        self.assertEqual(emu.call_stack_depth, 1)
        stack = emu.get_call_stack()
        self.assertEqual(len(stack), 2)
        # The caller frame returns to the instruction after the call (offset 5).
        self.assertEqual(stack[-1]['return_address'], 0x5)


class HookTests(EmulatorTestBase):
    def test_call_hook_receives_target_and_skips(self):
        emu = self.emulator_for(CALL_SNIPPET, entries=(0, 0xb))
        seen = []
        emu.set_call_hook(lambda e, target: (seen.append(target), True)[1])
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorHalt)
        self.assertIn(0xb, seen)

    def test_memory_read_hook_overrides_value(self):
        emu = self.emulator_for(LOAD_RDI)
        emu.set_register('rdi', 0x400000)
        seen = []
        emu.set_memory_read_hook(lambda e, addr, size: (seen.append((addr, size)), 0xcafe)[1])
        emu.run()
        self.assertEqual(emu.get_register('rax'), 0xcafe)
        self.assertIn((0x400000, 4), seen)

    def test_memory_write_hook_intercepts(self):
        emu = self.emulator_for(STORE_RDI)
        emu.set_register('rdi', 0x400000)
        emu.set_register('rax', 0x11223344)
        writes = []
        emu.set_memory_write_hook(
            lambda e, addr, size, value: (writes.append((addr, size, value)), True)[1])
        emu.run()
        self.assertIn((0x400000, 4, 0x11223344), writes)

    def test_pre_instruction_hook_stops_early(self):
        emu = self.emulator_for(ADD_CONSTS)
        calls = {'n': 0}

        def pre(e, idx):
            calls['n'] += 1
            return calls['n'] < 2  # allow one instruction, then stop

        emu.set_pre_instruction_hook(pre)
        emu.run()
        self.assertEqual(emu.instructions_executed, 1)
        self.assertEqual(calls['n'], 2)

    def test_all_hooks_can_be_removed(self):
        # Regression test: removing a hook must pass a NULL callback to the core
        # binding rather than Python None (which raised ctypes.ArgumentError).
        emu = self.emulator_for(ADD_CONSTS)
        setters = [
            (emu.set_call_hook, lambda *a: True),
            (emu.set_syscall_hook, lambda *a: True),
            (emu.set_memory_read_hook, lambda *a: None),
            (emu.set_memory_write_hook, lambda *a: False),
            (emu.set_pre_instruction_hook, lambda *a: True),
            (emu.set_intrinsic_hook, lambda *a: None),
            (emu.set_stdout_callback, lambda *a: None),
            (emu.set_stdin_callback, lambda *a: b''),
        ]
        for setter, fn in setters:
            setter(fn)
            setter(None)  # must not raise


class StateSerializationTests(EmulatorTestBase):
    def test_save_load_round_trip(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.step()
        emu.step()
        rax_mid = emu.get_register('rax')
        snapshot = emu.save_state()
        self.assertIsInstance(snapshot, str)
        self.assertTrue(snapshot)
        emu.run()  # mutate state
        self.assertTrue(emu.load_state(snapshot))
        self.assertEqual(emu.get_register('rax'), rax_mid)

    def test_save_load_file_round_trip(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.step()
        rax_mid = emu.get_register('rax')
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        try:
            emu.save_state_to_file(path)
            emu.run()
            self.assertTrue(emu.load_state_from_file(path))
            self.assertEqual(emu.get_register('rax'), rax_mid)
        finally:
            os.remove(path)


class LibcStubSettingTests(EmulatorTestBase):
    def test_toggle_settings(self):
        emu = self.emulator_for(ADD_CONSTS)
        for prop in ('builtin_libc_stubs', 'log_libc_calls', 'nop_unknown_externals'):
            original = getattr(emu, prop)
            setattr(emu, prop, not original)
            self.assertEqual(getattr(emu, prop), not original)
            setattr(emu, prop, original)
            self.assertEqual(getattr(emu, prop), original)


if __name__ == '__main__':
    unittest.main()
