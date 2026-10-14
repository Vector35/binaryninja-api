"""PowerPC instruction regression tests; encodings cross-checked with GNU as.

Run with pytest against built bindings. No cross toolchain is needed to run tests.
"""
import operator
import struct

import pytest
import binaryninja as bn

ARCHES = ('ppc', 'ppc_le', 'ppc64', 'ppc64_le')


def lift(word, arch_name='ppc64', address=0x1000):
    arch = bn.Architecture[arch_name]
    data = word.to_bytes(4, 'little' if arch_name.endswith('_le') else 'big')
    il = bn.LowLevelILFunction(arch)
    assert arch.get_instruction_low_level_il(data, address, il) == 4
    il.finalize()
    return il


def signed(value, size):
    sign = 1 << (size * 8 - 1)
    return (value ^ sign) - sign


def evaluate(il, registers=None, flags=None, memory=None, intrinsic=None):
    """Evaluate the integer/memory subset used here; fail on unsupported IL.

    This checks emitted IL, not an emulation of the input instruction. Expected
    results in tests are computed independently from the Power ISA semantics.
    """
    registers, flags, memory = dict(registers or {}), dict(flags or {}), dict(memory or {})
    events = []

    def expr(e):
        op, args = e.operation.name.removeprefix('LLIL_'), e.operands
        mask = (1 << (e.size * 8)) - 1 if e.size else 1
        if op in ('CONST', 'CONST_PTR'): return args[0] & mask
        if op == 'REG': return registers.get(str(args[0]), 0) & mask
        if op == 'UNDEF': return 0  # Arbitrary value; tests must not assert undefined results.
        if op == 'FLAG': return flags.get(str(args[0]), 0)
        if op == 'BOOL_TO_INT': return int(bool(expr(args[0])))
        if op == 'FLAG_BIT': return flags.get(str(args[0]), 0) << args[1]
        if op == 'TEST_BIT': return int(bool(expr(args[0]) & (1 << expr(args[1]))))
        if op == 'LOAD': return memory.get(expr(args[0]), 0) & mask
        if op in ('LOW_PART', 'ZX'): return expr(args[0]) & mask
        if op == 'SX': return signed(expr(args[0]), args[0].size) & mask
        if op == 'NOT': return ~expr(args[0]) & mask
        if op in ('CLZ', 'CTZ'):
            value = expr(args[0])
            return (e.size * 8 - value.bit_length() if op == 'CLZ' else
                    (value & -value).bit_length() - 1 if value else e.size * 8)
        if op in ('INT_TO_FLOAT', 'FLOAT_CONV'):
            src = args[0]
            value = (float(signed(expr(src), src.size)) if op == 'INT_TO_FLOAT' else
                     struct.unpack('>d' if src.size == 8 else '>f', expr(src).to_bytes(src.size, 'big'))[0])
            return int.from_bytes(struct.pack('>d' if e.size == 8 else '>f', value), 'big')
        ops = {'ADD': operator.add, 'SUB': operator.sub, 'OR': operator.or_,
               'AND': operator.and_, 'XOR': operator.xor, 'LSL': operator.lshift,
               'LSR': operator.rshift, 'CMP_E': operator.eq, 'CMP_NE': operator.ne,
               'CMP_UGE': operator.ge, 'CMP_ULE': operator.le,
               'CMP_UGT': operator.gt, 'CMP_ULT': operator.lt,
               'CMP_SGE': operator.ge, 'CMP_SLE': operator.le,
               'CMP_SGT': operator.gt, 'CMP_SLT': operator.lt}
        if op in ops:
            a, b = expr(args[0]), expr(args[1])
            if op.startswith('CMP_S'):
                a, b = signed(a, args[0].size), signed(b, args[1].size)
            return int(ops[op](a, b)) & mask
        if op in ('MULU_DP', 'MULS_DP'):
            a, b = expr(args[0]), expr(args[1])
            if op == 'MULS_DP': a, b = signed(a, e.size), signed(b, e.size)
            return (a * b) & ((1 << (16 * e.size)) - 1)
        if op in ('MODS', 'MODU', 'DIVS', 'DIVU', 'DIVS_DP', 'DIVU_DP'):
            a, b = expr(args[0]), expr(args[1])
            if op in ('MODS', 'DIVS', 'DIVS_DP'):
                a, b = signed(a, args[0].size), signed(b, args[1].size)
            quotient = abs(a) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
            return (a - quotient * b if op.startswith('MOD') else quotient) & mask
        raise AssertionError(f'Unsupported expression: {e}')

    pc = 0
    for _ in range(1000):
        if pc >= len(il): break
        insn = il[pc]
        pc += 1
        op = insn.operation.name
        if op == 'LLIL_SET_REG': registers[str(insn.dest)] = expr(insn.src)
        elif op == 'LLIL_SET_FLAG': flags[str(insn.dest)] = expr(insn.src)
        elif op == 'LLIL_STORE': memory[expr(insn.dest)] = expr(insn.src)
        elif op == 'LLIL_INTRINSIC':
            params = [expr(p) for p in insn.params]
            events.append((str(insn.intrinsic), params))
            if insn.output:
                assert intrinsic, f'No evaluator for {insn}'
                outputs = intrinsic(str(insn.intrinsic), params)
                for dest, value in zip(insn.output, outputs):
                    (flags if isinstance(dest, bn.lowlevelil.ILFlag) else registers)[str(dest)] = value
        elif op == 'LLIL_IF': pc = insn.true if expr(insn.condition) else insn.false
        elif op == 'LLIL_GOTO': pc = insn.dest
        elif op == 'LLIL_NOP': pass
        elif op == 'LLIL_TRAP':
            events.append(('trap', []))
            break
        elif op in ('LLIL_RET', 'LLIL_UNDEF'): break
        else: raise AssertionError(f'Unsupported instruction: {insn}')
    else:
        raise AssertionError('IL did not terminate')
    return registers, flags, memory, events


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word', [0x7c600124, 0x7c610124, 0x7c600164, 0x7c610164])
def test_msr_decoding(arch_name, word):
    arch = bn.Architecture[arch_name]
    data = word.to_bytes(4, 'little' if arch_name.endswith('_le') else 'big')
    tokens, size = arch.get_instruction_text(data, 0)
    assert size == 4
    text = ''.join(str(t) for t in tokens).replace(' ', '')
    assert text.startswith('mtmsrd' if word & 0x40 else 'mtmsr')
    assert (',0x1' in text) == bool(word & 0x10000)


@pytest.mark.parametrize('arch_name', ARCHES)
def test_legacy_intrinsic_ids(arch_name):
    arch = bn.Architecture[arch_name]
    assert arch.get_intrinsic_index('__builtin_clz') == 0
    assert arch.get_intrinsic_index('float_round') == 1
    assert arch.get_intrinsic_index('copy_string_words') == 6


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word,trailing,bits', [(0x7c830034, False, 32), (0x7c830434, True, 32),
                                               (0x7c830074, False, 64), (0x7c830474, True, 64)])
@pytest.mark.parametrize('value', [0, 1, 0x80000000, 0xffffffffffffffff])
def test_count_zeros(arch_name, word, trailing, bits, value):
    if bits == 64 and not arch_name.startswith('ppc64'): pytest.skip('64-bit instruction')
    value &= (1 << bits) - 1
    expected = (bits - value.bit_length() if not trailing else
                (value & -value).bit_length() - 1 if value else bits)
    for record in (False, True):
        regs, flags, _, _ = evaluate(lift(word | int(record), arch_name), {'r4': value}, {'xer_so': 1})
        assert regs['r3'] == expected
        if record:
            assert [flags[f] for f in ('lt', 'gt', 'eq', 'so')] == [0, int(expected > 0), int(expected == 0), 1]


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('size,xo', [(4, 0x28), (8, 0xa8)])
@pytest.mark.parametrize('dest', [4, 5, 6])
def test_load_reserve_alias(arch_name, size, xo, dest):
    if size == 8 and not arch_name.startswith('ppc64'): pytest.skip('64-bit instruction')
    base = 0x100000000 if arch_name.startswith('ppc64') else 0x1000
    word = 0x7c042800 | (dest << 21) | xo
    regs, _, _, events = evaluate(lift(word, arch_name), {'r4': base, 'r5': 0x20}, memory={base + 0x20: 0x55})
    assert regs[f'r{dest}'] == 0x55
    assert events == [('__set_reservation', [base + 0x20, size])]


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('size,xo', [(4, 0x12d), (8, 0x1ad)])
@pytest.mark.parametrize('success', [0, 1])
def test_store_conditional(arch_name, size, xo, success):
    if size == 8 and not arch_name.startswith('ppc64'): pytest.skip('64-bit instruction')
    def check(name, params):
        assert name == '__check_reservation' and params == [0x1020, size]
        return [success]
    _, flags, memory, _ = evaluate(lift(0x7c642800 | xo, arch_name),
                                   {'r3': 0x1234, 'r4': 0x1000, 'r5': 0x20},
                                   {'xer_so': 1}, {0x1020: 0x55}, check)
    assert memory[0x1020] == (0x1234 if success else 0x55)
    assert [flags[f] for f in ('lt', 'gt', 'eq', 'so')] == [0, 0, success, 1]


@pytest.mark.parametrize('word,a,b,result,overflow', [
    (0x7c642dd3, 2, 3, 6, 0),  # mulldo.
    (0x7c642dd3, 1 << 62, 4, 0, 1),
    (0x7c642dd3, (1 << 64) - 1, 2, (1 << 64) - 2, 0),
    (0x7c642fd3, 9, 3, 3, 0),  # divdo.
    (0x7c642fd3, 1 << 63, (1 << 64) - 1, None, 1),
    (0x7c642fd3, 1, 0, None, 1),
])
@pytest.mark.parametrize('old_so', [0, 1])
def test_integer_overflow(word, a, b, result, overflow, old_so):
    regs, flags, _, _ = evaluate(lift(word), {'r4': a, 'r5': b}, {'xer_so': old_so, 'xer_ov': 1})
    if result is not None: assert regs['r3'] == result
    assert flags['xer_ov'] == overflow
    assert flags['xer_so'] == (old_so | overflow)
    assert flags['so'] == (old_so | overflow)


@pytest.mark.parametrize('word,a,b,expected', [(0x7c642892, -2, 3, -1),
                                            (0x7c642812, (1 << 64) - 1, 2, 1),
                                            (0x7c642e16, -5, 3, -2)])
def test_high_multiply_and_signed_modulo(word, a, b, expected):
    regs, _, _, _ = evaluate(lift(word), {'r4': a & ((1 << 64) - 1), 'r5': b})
    assert regs['r3'] == expected & ((1 << 64) - 1)


@pytest.mark.parametrize('to', range(32))
@pytest.mark.parametrize('a,b', [(0, 0), (0xffffffff, 1), (1, 0xffffffff)])
def test_trap_conditions(to, a, b):
    word = 0x7c032008 | (to << 21)
    _, _, _, events = evaluate(lift(word), {'r3': a, 'r4': b})
    expected = bool((to & 16 and signed(a, 4) < signed(b, 4)) or
                    (to & 8 and signed(a, 4) > signed(b, 4)) or
                    (to & 4 and a == b) or (to & 2 and a < b) or (to & 1 and a > b))
    assert ('trap', []) in events if expected else not events
