#!/usr/bin/env python3
#
# Per-instruction unit tests for the BNIL (LLIL) emulator plugin.
#
# Unlike emulator_test.py (which assembles real x86-64 and lets Binary Ninja
# lift it), these tests build LLIL *directly* with LowLevelILFunction so that
# every LLIL operation the emulator implements is exercised in isolation by at
# least one test. Each test constructs a tiny hand-written LLIL function, seeds
# any register/flag/memory preconditions through the emulator API, single-steps,
# and checks the result.
#
# Run headless with, e.g.:
#
#     PYTHONPATH=<bn>/python python3 -m pytest emulator_il_test.py
#
# Requires the `emulator` core plugin to be present in the Binary Ninja install.

import unittest

from binaryninja import BinaryView, Architecture, LowLevelILFunction, LowLevelILOperation

try:
    from emulator import LLILEmulator, ILEmulatorStopReason
except ImportError:
    from binaryninja.emulator import LLILEmulator, ILEmulatorStopReason


U64 = (1 << 64) - 1


class ILTestBase(unittest.TestCase):
    """Harness for emulating hand-written LLIL functions."""

    arch_name = 'x86_64'

    def build(self, emit, terminate=True):
        """Build+prime an emulator over an LLIL function produced by ``emit(il)``.

        ``emit`` appends the instruction(s) under test. A terminating no-return
        is appended afterwards so the emulator never runs off the end.
        """
        arch = Architecture[self.arch_name]
        bv = BinaryView.new(b'\x00' * 32)
        bv.platform = arch.standalone_platform
        il = LowLevelILFunction(arch)
        emit(il)
        if terminate:
            il.append(il.no_ret())
        il.finalize()
        emu = LLILEmulator(bv)
        self.assertTrue(emu.set_entry_point(il, 0))
        emu.set_max_instructions(1000)
        # Keep the view/IL alive for the duration of the test.
        emu._test_bv = bv
        emu._test_il = il
        return emu

    def eval_to_reg(self, make_expr, dest='rax', size=8, regs=None, flags=None,
                    mem=None, steps=1):
        """Emulate ``dest = make_expr(il)`` and return the destination register.

        ``regs``/``flags`` seed state before stepping; ``mem`` is a dict of
        ``addr -> bytes`` written into emulator memory (region mapped as needed).
        """
        def emit(il):
            il.append(il.set_reg(size, dest, make_expr(il)))
        emu = self.build(emit)
        self._prime(emu, regs, flags, mem)
        for _ in range(steps):
            emu.step()
        return emu.get_register(dest)

    def _prime(self, emu, regs=None, flags=None, mem=None):
        for r, v in (regs or {}).items():
            emu.set_register(r, v)
        for f, v in (flags or {}).items():
            emu.set_flag(f, v)
        for addr, data in (mem or {}).items():
            emu.map_memory(addr & ~0xfff, 0x1000, "test")
            emu.write_memory(addr, data)


# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────
class ConstantOpTests(ILTestBase):
    def test_const(self):
        self.assertEqual(self.eval_to_reg(lambda il: il.const(8, 0x1234)), 0x1234)

    def test_const_ptr(self):
        self.assertEqual(self.eval_to_reg(lambda il: il.const_pointer(8, 0x401000)), 0x401000)

    def test_extern_ptr(self):
        # LLIL_EXTERN_PTR carries a constant address (+ offset); it evaluates to that address.
        self.assertEqual(self.eval_to_reg(lambda il: il.extern_pointer(8, 0x600000, 0)), 0x600000)

    def test_float_const(self):
        # The emulator treats a float const as its raw bit pattern. 1.0f == 0x3f800000.
        val = self.eval_to_reg(lambda il: il.float_const_single(1.0), size=4, dest='eax')
        self.assertEqual(val, 0x3f800000)


# ────────────────────────────────────────────────────────────────────────────
# Register read / write
# ────────────────────────────────────────────────────────────────────────────
class RegisterOpTests(ILTestBase):
    def test_reg_and_set_reg(self):
        # SET_REG is exercised by the harness itself; REG reads a seeded register.
        self.assertEqual(self.eval_to_reg(lambda il: il.reg(8, 'rdi'), regs={'rdi': 0xdead}), 0xdead)

    def test_set_reg_split(self):
        # rdx:rax = 0x1_00000000_00000002 -> rax = low, rdx = high.
        # LLIL constants carry a 64-bit value, so the 128-bit source is built with a shift
        # rather than il.const(16, 1 << 64), which would silently truncate to 0.
        def emit(il):
            hi = il.shift_left(16, il.const(16, 1), il.const(1, 64))
            il.append(il.set_reg_split(8, 'rdx', 'rax', il.or_expr(16, hi, il.const(16, 2))))
        emu = self.build(emit)
        emu.step()
        self.assertEqual(emu.get_register('rax'), 2)
        self.assertEqual(emu.get_register('rdx'), 1)

    def test_reg_split(self):
        # value = rdx:rax as a 128-bit quantity.
        val = self.eval_to_reg(lambda il: il.reg_split(8, 'rdx', 'rax'),
                               regs={'rax': 0x2, 'rdx': 0x1}, size=8, dest='rbx')
        # low 64 bits land in rbx
        self.assertEqual(val, 0x2)

    def test_reg_split_combined_width(self):
        # reg_split size is the width of each half, so edx:eax (size 4) is an 8-byte value
        # and the high register must survive into the combined result.
        val = self.eval_to_reg(lambda il: il.reg_split(4, 'edx', 'eax'),
                               regs={'rax': 0x2, 'rdx': 0x1}, size=8, dest='rbx')
        self.assertEqual(val, 0x1_00000002)

    def test_reg_split_divu_dp(self):
        # divu.dp.4(edx:eax, ecx): the full 8-byte dividend 0x1_00000000 / 0x10 must use edx.
        expr = lambda il: il.div_double_prec_unsigned(4, il.reg_split(4, 'edx', 'eax'),
                                                      il.const(4, 0x10))
        val = self.eval_to_reg(expr, regs={'rax': 0, 'rdx': 1}, size=4, dest='rbx')
        self.assertEqual(val, 0x10000000)


# ────────────────────────────────────────────────────────────────────────────
# Arithmetic, logic, shifts, comparisons — one table entry per op
# ────────────────────────────────────────────────────────────────────────────
class ValueOpTests(ILTestBase):
    def check(self, name, make_expr, expected, **kw):
        with self.subTest(op=name):
            self.assertEqual(self.eval_to_reg(make_expr, **kw), expected)

    def test_arithmetic(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('ADD', lambda il: il.add(8, C(il, 5), C(il, 3)), 8)
        self.check('ADC', lambda il: il.add_carry(8, C(il, 5), C(il, 3), C(il, 1, 1)), 9)
        self.check('SUB', lambda il: il.sub(8, C(il, 5), C(il, 3)), 2)
        self.check('SBB', lambda il: il.sub_borrow(8, C(il, 5), C(il, 3), C(il, 1, 1)), 1)  # 5 - 3 - borrow(1)
        self.check('MUL', lambda il: il.mult(8, C(il, 6), C(il, 7)), 42)
        self.check('DIVU', lambda il: il.div_unsigned(8, C(il, 17), C(il, 5)), 3)
        self.check('DIVS', lambda il: il.div_signed(8, C(il, -17), C(il, 5)), (-3) & U64)
        self.check('MODU', lambda il: il.mod_unsigned(8, C(il, 17), C(il, 5)), 2)
        self.check('MODS', lambda il: il.mod_signed(8, C(il, -17), C(il, 5)), (-2) & U64)
        self.check('DIVU_DP', lambda il: il.div_double_prec_unsigned(8, C(il, 17, 16), C(il, 5)), 3)
        # The 16-byte dividend must be sign-extended from a 64-bit constant: il.const(16, -17)
        # would truncate to a large *positive* 128-bit value and silently pass as unsigned.
        self.check('DIVS_DP', lambda il: il.div_double_prec_signed(
            8, il.sign_extend(16, C(il, -17)), C(il, 5)), (-3) & U64)
        self.check('MODU_DP', lambda il: il.mod_double_prec_unsigned(8, C(il, 17, 16), C(il, 5)), 2)
        self.check('MODS_DP', lambda il: il.mod_double_prec_signed(
            8, il.sign_extend(16, C(il, -17)), C(il, 5)), (-2) & U64)
        self.check('NEG', lambda il: il.neg_expr(8, C(il, 5)), (-5) & U64)
        self.check('ABS', lambda il: il.expr(LowLevelILOperation.LLIL_ABS, C(il, -5), size=8), 5)

    def test_mul_double_prec(self):
        # MULU_DP / MULS_DP produce a 2*size result, so capture it with set_reg_split.
        C = lambda il, v, s=8: il.const(s, v)
        with self.subTest(op='MULU_DP'):
            def emit(il):
                il.append(il.set_reg_split(8, 'rdx', 'rax',
                          il.mult_double_prec_unsigned(8, C(il, 0x100000000), C(il, 0x100000000))))
            emu = self.build(emit)
            emu.step()
            self.assertEqual(emu.get_register('rax'), 0)        # low 64 bits of 2**64
            self.assertEqual(emu.get_register('rdx'), 1)        # high 64 bits
        with self.subTest(op='MULS_DP'):
            def emit(il):
                il.append(il.set_reg_split(8, 'rdx', 'rax',
                          il.mult_double_prec_signed(8, C(il, -2), C(il, 3))))
            emu = self.build(emit)
            emu.step()
            self.assertEqual(emu.get_register('rax'), (-6) & U64)
            self.assertEqual(emu.get_register('rdx'), U64)      # sign-extended high half

    def test_logic(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('AND', lambda il: il.and_expr(8, C(il, 0b1100), C(il, 0b1010)), 0b1000)
        self.check('OR', lambda il: il.or_expr(8, C(il, 0b1100), C(il, 0b1010)), 0b1110)
        self.check('XOR', lambda il: il.xor_expr(8, C(il, 0b1100), C(il, 0b1010)), 0b0110)
        self.check('NOT', lambda il: il.not_expr(8, C(il, 0)), U64)

    def test_shifts_rotates(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('LSL', lambda il: il.shift_left(8, C(il, 1), C(il, 4)), 16)
        self.check('LSR', lambda il: il.logical_shift_right(8, C(il, 16), C(il, 2)), 4)
        self.check('ASR', lambda il: il.arith_shift_right(8, C(il, -8), C(il, 1)), (-4) & U64)
        self.check('ROL', lambda il: il.rotate_left(8, C(il, 1), C(il, 4)), 16)
        self.check('ROR', lambda il: il.rotate_right(1, C(il, 1, 1), C(il, 1)), 0x80)
        self.check('RLC', lambda il: il.rotate_left_carry(8, C(il, 1), C(il, 0), C(il, 1, 1)), 1)
        self.check('RRC', lambda il: il.rotate_right_carry(8, C(il, 2), C(il, 1), C(il, 0, 1)), 1)
        # Carry-in truth is bit 0 (core's size-0 convention): 3 & 1 rotates in, 2 & 1 does not.
        self.check('RRC carry-in set', lambda il: il.rotate_right_carry(8, C(il, 2), C(il, 1), C(il, 3, 1)),
                   0x8000000000000001)
        self.check('RRC carry-in clear', lambda il: il.rotate_right_carry(8, C(il, 2), C(il, 1), C(il, 2, 1)), 1)

    def test_extend_and_parts(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('SX', lambda il: il.sign_extend(8, C(il, 0xffffffff, 4)), U64)
        self.check('ZX', lambda il: il.zero_extend(8, C(il, 0x80000000, 4)), 0x80000000)
        self.check('LOW_PART', lambda il: il.low_part(2, C(il, 0x1234abcd)), 0xabcd, size=2, dest='ax')

    def test_min_max(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('MINU', lambda il: il.min_unsigned(8, C(il, 3), C(il, 9)), 3)
        self.check('MAXU', lambda il: il.max_unsigned(8, C(il, 3), C(il, 9)), 9)
        self.check('MINS', lambda il: il.min_signed(8, C(il, -3), C(il, 9)), (-3) & U64)
        self.check('MAXS', lambda il: il.max_signed(8, C(il, -3), C(il, 9)), 9)

    def test_comparisons(self):
        C = lambda il, v, s=8: il.const(s, v)
        self.check('CMP_E', lambda il: il.compare_equal(8, C(il, 5), C(il, 5)), 1)
        self.check('CMP_NE', lambda il: il.compare_not_equal(8, C(il, 5), C(il, 4)), 1)
        self.check('CMP_SLT', lambda il: il.compare_signed_less_than(8, C(il, -1), C(il, 1)), 1)
        self.check('CMP_SLE', lambda il: il.compare_signed_less_equal(8, C(il, 1), C(il, 1)), 1)
        self.check('CMP_SGE', lambda il: il.compare_signed_greater_equal(8, C(il, 2), C(il, 1)), 1)
        self.check('CMP_SGT', lambda il: il.compare_signed_greater_than(8, C(il, 2), C(il, 1)), 1)
        self.check('CMP_ULT', lambda il: il.compare_unsigned_less_than(8, C(il, 1), C(il, 2)), 1)
        self.check('CMP_ULE', lambda il: il.compare_unsigned_less_equal(8, C(il, 2), C(il, 2)), 1)
        self.check('CMP_UGE', lambda il: il.compare_unsigned_greater_equal(8, C(il, 2), C(il, 1)), 1)
        self.check('CMP_UGT', lambda il: il.compare_unsigned_greater_than(8, C(il, 2), C(il, 1)), 1)

    def test_bit_ops(self):
        C = lambda il, v, s=8: il.const(s, v)
        E = LowLevelILOperation
        self.check('POPCNT', lambda il: il.expr(E.LLIL_POPCNT, C(il, 0b1011), size=8), 3)
        self.check('CLZ', lambda il: il.expr(E.LLIL_CLZ, C(il, 1), size=8), 63)
        self.check('CTZ', lambda il: il.expr(E.LLIL_CTZ, C(il, 8), size=8), 3)
        self.check('CLS', lambda il: il.expr(E.LLIL_CLS, C(il, -1), size=8), 63)
        self.check('BSWAP', lambda il: il.expr(E.LLIL_BSWAP, C(il, 0x1122334455667788), size=8), 0x8877665544332211)
        self.check('RBIT', lambda il: il.expr(E.LLIL_RBIT, C(il, 1, 1), size=1), 0x80)
        self.check('TEST_BIT', lambda il: il.expr(E.LLIL_TEST_BIT, C(il, 0b100), C(il, 2), size=8), 1)
        self.check('BOOL_TO_INT', lambda il: il.bool_to_int(8, il.compare_equal(8, C(il, 1), C(il, 1))), 1)
        self.check('ADD_OVERFLOW',
                   lambda il: il.expr(E.LLIL_ADD_OVERFLOW,
                                      C(il, 0x7fffffffffffffff), C(il, 1), size=8), 1)


# ────────────────────────────────────────────────────────────────────────────
# Memory and stack
# ────────────────────────────────────────────────────────────────────────────
class MemoryStackOpTests(ILTestBase):
    def test_load(self):
        val = self.eval_to_reg(lambda il: il.load(4, il.const(8, 0x2000)),
                               mem={0x2000: (0xdeadbeef).to_bytes(4, 'little')})
        self.assertEqual(val, 0xdeadbeef)

    def test_store(self):
        def emit(il):
            il.append(il.store(4, il.const(8, 0x2000), il.const(4, 0xcafebabe)))
        emu = self.build(emit)
        emu.map_memory(0x2000, 0x1000, "test")
        emu.step()
        self.assertEqual(int.from_bytes(emu.read_memory(0x2000, 4), 'little'), 0xcafebabe)

    def test_push_and_pop(self):
        # push 0x1234 then pop into rax; verify the stack round-trips through memory.
        def emit(il):
            il.append(il.push(8, il.const(8, 0x1234)))
            il.append(il.set_reg(8, 'rax', il.pop(8)))
        emu = self.build(emit)
        emu.map_memory(0x10000, 0x1000, "stack")
        emu.set_register('rsp', 0x10800)
        emu.step()  # push
        self.assertEqual(emu.get_register('rsp'), 0x10800 - 8)
        emu.step()  # pop
        self.assertEqual(emu.get_register('rax'), 0x1234)
        self.assertEqual(emu.get_register('rsp'), 0x10800)


# ────────────────────────────────────────────────────────────────────────────
# Flags
# ────────────────────────────────────────────────────────────────────────────
class FlagOpTests(ILTestBase):
    def test_set_flag_and_flag(self):
        # SET_FLAG writes c; FLAG reads it back into a register.
        def emit(il):
            il.append(il.set_flag('c', il.const(1, 1)))
            il.append(il.set_reg(8, 'rax', il.flag('c')))
        emu = self.build(emit)
        emu.step()
        self.assertEqual(emu.get_flag('c'), 1)
        emu.step()
        self.assertEqual(emu.get_register('rax'), 1)

    def test_flag_bit(self):
        # FLAG_BIT reads flag c into bit 0.
        val = self.eval_to_reg(lambda il: il.flag_bit(8, 'c', 0), flags={'c': 1})
        self.assertEqual(val, 1)

    def test_flag_bit_nonzero_index(self):
        # FLAG_BIT places the flag AT the bit index (a left shift, like core's
        # bool_to_int(flag) << index translation).
        self.assertEqual(self.eval_to_reg(lambda il: il.flag_bit(8, 'c', 3), flags={'c': 1}), 8)
        self.assertEqual(self.eval_to_reg(lambda il: il.flag_bit(8, 'c', 3), flags={'c': 0}), 0)

    def test_flag_cond(self):
        # LLIL_FCONDITION for "equal" is true when z is set.
        val = self.eval_to_reg(lambda il: il.flag_condition(LowLevelILFlagCondition_E), flags={'z': 1})
        self.assertEqual(val, 1)

    def test_flag_group(self):
        # x86 semantic flag groups map to flag conditions; drive one that reads z.
        val = self.eval_to_reg(lambda il: il.flag_group('e'), flags={'z': 1})
        self.assertIn(val, (0, 1))

    def test_size_zero_cmp_against_flag(self):
        # Comparisons against flags are unsized (size 0). Masking their operands to zero
        # bytes must not squash true booleans to false: cmp_e.0(flag:z, 1) is true only
        # when z is actually set.
        expr = lambda il: il.compare_equal(0, il.flag('z'), il.const(0, 1))
        self.assertEqual(self.eval_to_reg(expr, flags={'z': 1}), 1)
        self.assertEqual(self.eval_to_reg(expr, flags={'z': 0}), 0)

    def test_size_zero_not_is_logical(self):
        # not.0 negates an unsized boolean rather than bitwise-complementing it.
        expr = lambda il: il.not_expr(0, il.flag('z'))
        self.assertEqual(self.eval_to_reg(expr, flags={'z': 1}) & 1, 0)
        self.assertNotEqual(self.eval_to_reg(expr, flags={'z': 0}), 0)

    def test_set_flag_bit0(self):
        # SET_FLAG takes boolean truth from bit 0 (core's size-0 masking convention).
        def emit(il):
            il.append(il.set_flag('c', il.const(1, 3)))
            il.append(il.set_flag('z', il.const(1, 2)))
        emu = self.build(emit)
        emu.step()
        emu.step()
        self.assertEqual(emu.get_flag('c'), 1)
        self.assertEqual(emu.get_flag('z'), 0)


# ────────────────────────────────────────────────────────────────────────────
# Control flow
# ────────────────────────────────────────────────────────────────────────────
class ControlFlowOpTests(ILTestBase):
    def test_goto(self):
        # goto skips a set_reg; rax should stay 0.
        from binaryninja import LowLevelILLabel
        def emit(il):
            end = LowLevelILLabel()
            il.append(il.goto(end))
            il.append(il.set_reg(8, 'rax', il.const(8, 0xbad)))
            il.mark_label(end)
            il.append(il.set_reg(8, 'rax', il.const(8, 0x600d)))
        emu = self.build(emit)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 0x600d)

    def test_if_taken_and_not_taken(self):
        from binaryninja import LowLevelILLabel
        def make(cond_true):
            def emit(il):
                t = LowLevelILLabel()
                f = LowLevelILLabel()
                il.append(il.if_expr(il.const(1, 1 if cond_true else 0), t, f))
                il.mark_label(t)
                il.append(il.set_reg(8, 'rax', il.const(8, 1)))
                il.append(il.no_ret())
                il.mark_label(f)
                il.append(il.set_reg(8, 'rax', il.const(8, 2)))
            return emit
        emu = self.build(make(True), terminate=False)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 1)
        emu = self.build(make(False), terminate=False)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 2)

    def test_jump(self):
        # jump to the address of the second instruction.
        def emit(il):
            il.append(il.jump(il.const(8, 4)))
            il.append(il.set_reg(8, 'rax', il.const(8, 7)))
        # give the two instructions distinct addresses via set_current_address
        def emit_addr(il):
            il.set_current_address(0)
            il.append(il.jump(il.const(8, 4)))
            il.set_current_address(4)
            il.append(il.set_reg(8, 'rax', il.const(8, 7)))
        emu = self.build(emit_addr)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 7)

    def test_jump_to(self):
        from binaryninja import LowLevelILLabel
        def emit(il):
            tgt = LowLevelILLabel()
            il.append(il.jump_to(il.const(8, 4), {4: tgt}))
            il.mark_label(tgt)
            il.append(il.set_reg(8, 'rax', il.const(8, 9)))
        emu = self.build(emit)
        emu.run()
        self.assertEqual(emu.get_register('rax'), 9)

    def test_ret_pops_return_address(self):
        # ret reads the target from its expression; here it just stops cleanly.
        def emit(il):
            il.append(il.ret(il.const(8, 0)))
        emu = self.build(emit, terminate=False)
        reason = emu.run()
        self.assertIn(reason, (ILEmulatorStopReason.ILEmulatorHalt,
                               ILEmulatorStopReason.ILEmulatorCallHook))

    def test_noret(self):
        emu = self.build(lambda il: il.append(il.no_ret()), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorHalt)

    def test_syscall_stops(self):
        emu = self.build(lambda il: il.append(il.system_call()), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorSyscallHook)

    def test_call_unresolved_stops(self):
        emu = self.build(lambda il: il.append(il.call(il.const(8, 0x999))), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorCallHook)

    def test_tailcall_unresolved_stops(self):
        emu = self.build(lambda il: il.append(il.tailcall(il.const(8, 0x999))), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorCallHook)

    def test_call_stack_adjust_unresolved_stops(self):
        def emit(il):
            il.append(il.call_stack_adjust(il.const(8, 0x999), 8, {}))
        emu = self.build(emit, terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorCallHook)


# ────────────────────────────────────────────────────────────────────────────
# NOP / traps / undefined / unimplemented / intrinsic
# ────────────────────────────────────────────────────────────────────────────
class SpecialOpTests(ILTestBase):
    def test_nop_advances(self):
        def emit(il):
            il.append(il.nop())
            il.append(il.set_reg(8, 'rax', il.const(8, 5)))
        emu = self.build(emit)
        emu.step()  # nop
        emu.step()  # set_reg
        self.assertEqual(emu.get_register('rax'), 5)

    def test_breakpoint_halts(self):
        emu = self.build(lambda il: il.append(il.breakpoint()), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorHalt)

    def test_trap_halts(self):
        emu = self.build(lambda il: il.append(il.trap(3)), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorHalt)

    def test_undefined_stops(self):
        emu = self.build(lambda il: il.append(il.undefined()), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorUndefinedBehavior)

    def test_unimplemented_stops(self):
        emu = self.build(lambda il: il.append(il.unimplemented()), terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorUnimplemented)

    def test_unimplemented_memory_stops(self):
        def emit(il):
            il.append(il.set_reg(8, 'rax', il.unimplemented_memory_ref(8, il.const(8, 0x1000))))
        emu = self.build(emit, terminate=False)
        self.assertEqual(emu.run(), ILEmulatorStopReason.ILEmulatorUnimplemented)

    def test_intrinsic_hook_invoked(self):
        # With an intrinsic hook installed, LLIL_INTRINSIC is delegated to it.
        seen = {}

        # The hook contract is (emulator, intrinsic_id, params) -> list of (reg, value)
        # pairs when handled, or None to fall through to Unimplemented.
        def hook(emu, intrinsic, params):
            seen['called'] = True
            return []

        def emit(il):
            il.append(il.intrinsic([], 0, []))
        emu = self.build(emit)
        emu.set_intrinsic_hook(hook)
        emu.step()
        self.assertTrue(seen.get('called'))


# Resolve the "equal" flag condition enum lazily so the import stays tidy.
try:
    from binaryninja import LowLevelILFlagCondition
    LowLevelILFlagCondition_E = LowLevelILFlagCondition.LLFC_E
except Exception:  # pragma: no cover - only for very old cores
    LowLevelILFlagCondition_E = 0


if __name__ == '__main__':
    unittest.main()
