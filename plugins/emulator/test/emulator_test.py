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
    def emulator_for(self, code: bytes, entries=(0,), entry_point=0, max_instructions=1000,
                     arch='x86_64'):
        bv = make_bv(code, entries=entries, arch=arch)
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


class BitOpTests(EmulatorTestBase):
    # x86-64 snippets whose lifted LLIL exercises the bit ops (BSWAP/POPCNT/CLZ/CTZ),
    # and aarch64 snippets for the ops with direct A64 instructions (RBIT/CLS).
    def test_bswap(self):
        # mov eax, 0x12345678 ; bswap eax ; ret
        emu = self.emulator_for(b'\xb8\x78\x56\x34\x12\x0f\xc8\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 0x78563412)

    def test_popcnt(self):
        # mov ecx, 0xff ; popcnt eax, ecx ; ret
        emu = self.emulator_for(b'\xb9\xff\x00\x00\x00\xf3\x0f\xb8\xc1\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 8)

    def test_clz(self):
        # mov ecx, 1 ; lzcnt eax, ecx ; ret   -> 31 leading zeros in a 32-bit 1
        emu = self.emulator_for(b'\xb9\x01\x00\x00\x00\xf3\x0f\xbd\xc1\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 31)

    def test_ctz(self):
        # mov ecx, 8 ; tzcnt eax, ecx ; ret   -> 3 trailing zeros
        emu = self.emulator_for(b'\xb9\x08\x00\x00\x00\xf3\x0f\xbc\xc1\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 3)

    def test_rbit(self):
        # aarch64: movz w0, #1 ; rbit w0, w0 ; ret   -> bit 0 -> bit 31
        emu = self.emulator_for(
            b'\x20\x00\x80\x52\x00\x00\xc0\x5a\xc0\x03\x5f\xd6', arch='aarch64')
        emu.run()
        self.assertEqual(emu.get_register('x0'), 0x80000000)

    def test_cls(self):
        # aarch64: movz w0, #1 ; cls w0, w0 ; ret   -> 30 leading sign (zero) bits below MSB
        emu = self.emulator_for(
            b'\x20\x00\x80\x52\x00\x14\xc0\x5a\xc0\x03\x5f\xd6', arch='aarch64')
        emu.run()
        self.assertEqual(emu.get_register('x0'), 30)


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


class FlagTests(EmulatorTestBase):
    # Flags are read back through setcc: Binary Ninja elides dead flag writes when lifting,
    # so a flag is only computed when a later instruction actually consumes it.
    def test_add_sets_overflow_and_sign(self):
        # mov eax, 0x7fffffff ; add eax, 1 ; seto cl ; sets dl ; ret
        # 0x7fffffff + 1 -> 0x80000000: signed overflow and negative.
        emu = self.emulator_for(b'\xb8\xff\xff\xff\x7f\x83\xc0\x01\x0f\x90\xc1\x0f\x98\xc2\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rcx') & 0xff, 1)  # overflow
        self.assertEqual(emu.get_register('rdx') & 0xff, 1)  # sign

    def test_add_sets_carry_and_zero(self):
        # mov eax, 0xffffffff ; add eax, 1 ; setc cl ; setz dl ; ret
        # 0xffffffff + 1 -> wraps to 0 with a carry out.
        emu = self.emulator_for(b'\xb8\xff\xff\xff\xff\x83\xc0\x01\x0f\x92\xc1\x0f\x94\xc2\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rcx') & 0xff, 1)  # carry
        self.assertEqual(emu.get_register('rdx') & 0xff, 1)  # zero

    def test_cmp_equal_sets_zero(self):
        # mov eax, 5 ; cmp eax, 5 ; setz al ; ret
        emu = self.emulator_for(b'\xb8\x05\x00\x00\x00\x83\xf8\x05\x0f\x94\xc0\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xff, 1)

    def test_signed_less_via_setl(self):
        # mov eax, -1 ; cmp eax, 1 ; setl al ; ret   -> -1 < 1 signed, so al = 1
        emu = self.emulator_for(b'\xb8\xff\xff\xff\xff\x83\xf8\x01\x0f\x9c\xc0\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xff, 1)


class ExtendTests(EmulatorTestBase):
    def test_movsx_sign_extends(self):
        # mov bl, 0xff ; movsx eax, bl ; ret   -> 0xffffffff
        emu = self.emulator_for(b'\xb3\xff\x0f\xbe\xc3\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xffffffff, 0xffffffff)

    def test_movzx_zero_extends(self):
        # mov bl, 0xff ; movzx eax, bl ; ret   -> 0xff
        emu = self.emulator_for(b'\xb3\xff\x0f\xb6\xc3\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xffffffff, 0xff)


class ShiftRotateTests(EmulatorTestBase):
    def test_shl(self):
        # mov eax, 1 ; shl eax, 4 ; ret -> 16
        emu = self.emulator_for(b'\xb8\x01\x00\x00\x00\xc1\xe0\x04\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 16)

    def test_shr(self):
        # mov eax, 0xff ; shr eax, 4 ; ret -> 0x0f
        emu = self.emulator_for(b'\xb8\xff\x00\x00\x00\xc1\xe8\x04\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax'), 0x0f)

    def test_sar_sign_fill(self):
        # mov eax, 0x80000000 ; sar eax, 31 ; ret -> 0xffffffff (arithmetic shift)
        emu = self.emulator_for(b'\xb8\x00\x00\x00\x80\xc1\xf8\x1f\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xffffffff, 0xffffffff)

    def test_rcl_rotates_through_carry(self):
        # stc ; mov al, 1 ; rcl al, 1 ; ret
        # The 9-bit value {carry=1, al=0x01} rotated left by 1 -> al = 0x03.
        # (mov does not affect flags, so stc's carry survives to rcl.)
        emu = self.emulator_for(b'\xf9\xb0\x01\xd0\xd0\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xff, 0x03)


class DivisionTests(EmulatorTestBase):
    def test_signed_div_intmin_by_neg1_does_not_crash(self):
        # mov eax, 0x80000000 ; cdq ; mov ecx, -1 ; idiv ecx ; ret
        # edx:eax is INT32_MIN sign-extended; dividing by -1 overflows on hardware but the
        # emulator must wrap (to INT32_MIN) rather than trap (SIGFPE) on INT_MIN / -1.
        emu = self.emulator_for(
            b'\xb8\x00\x00\x00\x80\x99\xb9\xff\xff\xff\xff\xf7\xf9\xc3')
        emu.run()
        self.assertEqual(emu.get_register('rax') & 0xffffffff, 0x80000000)

    def test_div_by_zero_stops_with_error(self):
        # xor edx,edx ; mov eax, 10 ; mov ecx, 0 ; div ecx ; ret
        emu = self.emulator_for(
            b'\x31\xd2\xb8\x0a\x00\x00\x00\xb9\x00\x00\x00\x00\xf7\xf1\xc3')
        reason = emu.run()
        self.assertEqual(reason, ILEmulatorStopReason.ILEmulatorError)


class MemoryBoundaryTests(EmulatorTestBase):
    def test_read_spans_gap_between_segments(self):
        # Two mapped segments with an unmapped gap between them; a read across the gap
        # zero-fills the hole and still returns the second segment's bytes.
        emu = self.emulator_for(ADD_CONSTS)
        emu.map_memory(0x500000, b'\xAA\xBB')
        emu.map_memory(0x500004, b'\xCC\xDD')  # gap at 0x500002..0x500003
        self.assertEqual(emu.read_memory(0x500000, 6), b'\xAA\xBB\x00\x00\xCC\xDD')

    def test_overlapping_map_is_rejected(self):
        emu = self.emulator_for(ADD_CONSTS)
        emu.map_memory(0x600000, 0x1000)
        emu.map_memory(0x600800, 0x1000)  # overlaps the first region
        starts = [r['start'] for r in emu.get_mapped_regions()]
        self.assertIn(0x600000, starts)
        self.assertNotIn(0x600800, starts)


if __name__ == '__main__':
    unittest.main()
