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
        if op == 'FCMP_GE':
            a, b = [struct.unpack('>d', expr(arg).to_bytes(8, 'big'))[0] for arg in args]
            return int(a >= b)
        if op == 'FLOAT_CONST': return int.from_bytes(struct.pack('>d' if e.size == 8 else '>f', args[0]), 'big')
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
@pytest.mark.parametrize('size,xo', [(1, 0x68), (2, 0xe8), (4, 0x28), (8, 0xa8)])
@pytest.mark.parametrize('dest', [4, 5, 6])
def test_load_reserve_alias(arch_name, size, xo, dest):
    if size == 8 and not arch_name.startswith('ppc64'): pytest.skip('64-bit instruction')
    base = 0x100000000 if arch_name.startswith('ppc64') else 0x1000
    word = 0x7c042800 | (dest << 21) | xo
    regs, _, _, events = evaluate(lift(word, arch_name), {'r4': base, 'r5': 0x20}, memory={base + 0x20: 0x55})
    assert regs[f'r{dest}'] == 0x55
    assert events == [('__set_reservation', [base + 0x20, size])]


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('size,xo', [(1, 0x56d), (2, 0x5ad), (4, 0x12d), (8, 0x1ad)])
@pytest.mark.parametrize('success', [0, 1])
def test_store_conditional(arch_name, size, xo, success):
    if size == 8 and not arch_name.startswith('ppc64'): pytest.skip('64-bit instruction')
    def check(name, params):
        assert name == '__check_reservation' and params == [0x1020, size]
        return [success]
    _, flags, memory, _ = evaluate(lift(0x7c642800 | xo, arch_name),
                                   {'r3': 0x1234, 'r4': 0x1000, 'r5': 0x20},
                                   {'xer_so': 1}, {0x1020: 0x55}, check)
    assert memory[0x1020] == (0x1234 & ((1 << (size * 8)) - 1) if success else 0x55)
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


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word,size,is_signed', [(0x7ca428ee, 1, False), (0x7ca42a6e, 2, False),
                                               (0x7ca42aee, 2, True), (0x7ca4286e, 4, False),
                                               (0x7ca4286a, 8, False), (0x7ca42aea, 4, True)])
def test_indexed_update_alias(arch_name, word, size, is_signed):
    if (size == 8 or word == 0x7ca42aea) and not arch_name.startswith('ppc64'):
        pytest.skip('64-bit instruction')
    base = 0x100000000 if arch_name.startswith('ppc64') else 0x1000
    value = (1 << (size * 8)) - 1
    regs, _, _, _ = evaluate(lift(word, arch_name), {'r4': base, 'r5': 0x20}, memory={base + 0x20: value})
    assert regs['r4'] == base + 0x20
    assert regs['r5'] == (1 << (bn.Architecture[arch_name].address_size * 8)) - 1 if is_signed else regs['r5'] == value


@pytest.mark.parametrize('arch_name', ('ppc64', 'ppc64_le'))
def test_d_form_update_and_doubleword_width(arch_name):
    regs, _, memory, _ = evaluate(lift(0xf821ffe1, arch_name), {'r1': 0x100000020})
    assert regs['r1'] == 0x100000000 and memory[0x100000000] == 0x100000020
    for word in (0xe8640011, 0x8c640010):  # ldu/lbzu r3,16(r4)
        regs, _, _, _ = evaluate(lift(word, arch_name), {'r4': 0x100000000}, memory={0x100000010: 0x55})
        assert regs['r4'] == 0x100000010 and regs['r3'] == 0x55
    _, _, memory, _ = evaluate(lift(0x7c64292a, arch_name),  # stdx
                               {'r3': 0x123456789abcdef0, 'r4': 0x100000000, 'r5': 0x20})
    assert memory[0x100000020] == 0x123456789abcdef0


@pytest.mark.parametrize('arch_name', ARCHES)
def test_single_float_load_representation(arch_name):
    base = 0x100000000 if arch_name.startswith('ppc64') else 0x1000
    regs, _, _, _ = evaluate(lift(0xc0240010, arch_name), {'r4': base}, memory={base + 16: 0x3f800000})
    assert regs['f1'] == 0x3ff0000000000000


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word,single,indexed', [(0xd4240010, True, False), (0x7c242d6e, True, True),
                                               (0xdc240010, False, False), (0x7c242dee, False, True),
                                               (0xcc240010, False, False), (0x7c242cee, False, True)])
def test_float_update_forms(arch_name, word, single, indexed):
    base = 0x100000000 if arch_name.startswith('ppc64') else 0x1000
    regs, _, memory, _ = evaluate(lift(word, arch_name),
                                  {'f1': 0x3ff0000000000000, 'r4': base, 'r5': 16},
                                  memory={base + 16: 0x4000000000000000})
    assert regs['r4'] == base + 16
    if word in (0xcc240010, 0x7c242cee): assert regs['f1'] == 0x4000000000000000
    else: assert memory[base + 16] == (0x3f800000 if single else 0x3ff0000000000000)


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word', [0x4c000024, 0x4c000224, 0x4c000066, 0x4c00004e, 0x4c00004c, 0x4c000924])
def test_system_return_boundaries(arch_name, word):
    arch = bn.Architecture[arch_name]
    order = 'little' if arch_name.endswith('_le') else 'big'
    data = word.to_bytes(4, order)
    assert [b.type for b in arch.get_instruction_info(data, 0).branches] == [bn.BranchType.FunctionReturn]
    with bn.BinaryView.new(data + (0x38600001).to_bytes(4, order) + (0x4e800020).to_bytes(4, order)) as bv:
        bv.add_function(0, plat=arch.standalone_platform)
        bv.update_analysis_and_wait()
        assert [(b.start, b.end) for b in bv.functions[0].basic_blocks] == [(0, 4)]


@pytest.mark.parametrize('arch_name', ('ppc64', 'ppc64_le'))
def test_byte_reverse_and_pc_materialization(arch_name):
    _, _, memory, _ = evaluate(lift(0x7c642d28, arch_name),
                               {'r3': 0x0102030405060708, 'r4': 0x100000000, 'r5': 0x20})
    assert memory[0x100000020] == 0x0807060504030201
    for word, result in [(0x4c600004, 0x1004), (0x4c7fffc5, 0xffffffffffff1004)]:
        regs, _, _, _ = evaluate(lift(word, arch_name))
        assert regs['r3'] == result


@pytest.mark.parametrize('word,size,is_signed', [(0x7c642b56, 4, True), (0x7c642b16, 4, False),
                                               (0x7c642b52, 8, True), (0x7c642b12, 8, False)])
@pytest.mark.parametrize('a,b', [(1, 3), (-1, 3), (3, 1), (1, 0)])
@pytest.mark.parametrize('old_so', [0, 1])
def test_extended_divide(word, size, is_signed, a, b, old_so):
    if not is_signed and a < 0: a = 1
    quotient = None if not b else abs(a << (size * 8)) // abs(b) * (-1 if (a < 0) != (b < 0) else 1)
    limit = 1 << (size * 8 - int(is_signed))
    overflow = quotient is None or not (-limit <= quotient < limit if is_signed else 0 <= quotient < limit)
    regs, flags, _, _ = evaluate(lift(word | 0x401),
                                 {'r4': a & ((1 << 64) - 1), 'r5': b}, {'xer_so': old_so})
    assert flags['xer_ov'] == overflow and flags['xer_so'] == (old_so | overflow)
    if not overflow: assert regs['r3'] == quotient & ((1 << 64) - 1)


@pytest.mark.parametrize('lt,gt', [(0, 0), (0, 1), (1, 0), (1, 1)])
def test_setb_priority(lt, gt):
    regs, _, _, _ = evaluate(lift(0x7c600100), flags={'lt': lt, 'gt': gt})
    assert regs['r3'] == (-1 if lt else 1 if gt else 0) & ((1 << 64) - 1)


FP_UNARY = [(0xfc20102c, '__fsqrt'), (0xec20102c, '__fsqrts'),
            (0xfc201310, '__frin'), (0xfc201350, '__friz'), (0xfc201390, '__frip'), (0xfc2013d0, '__frim'),
            (0xfc20101c, '__fctiw'), (0xfc20101e, '__fctiwz'),
            (0xfc20111c, '__fctiwu'), (0xfc20111e, '__fctiwuz'),
            (0xfc20165c, '__fctid'), (0xfc20165e, '__fctidz'),
            (0xfc20175c, '__fctidu'), (0xfc20175e, '__fctiduz'),
            (0xfc20169c, '__fcfid'), (0xfc20179c, '__fcfidu'),
            (0xec20169c, '__fcfids'), (0xec20179c, '__fcfidus')]


@pytest.mark.parametrize('arch_name', ARCHES)
@pytest.mark.parametrize('word,name', FP_UNARY)
def test_scalar_fp_intrinsic_contract(arch_name, word, name):
    for record in (False, True):
        il = lift(word | int(record), arch_name)
        assert il[0].operation == bn.LowLevelILOperation.LLIL_INTRINSIC
        assert str(il[0].intrinsic) == name
        assert [str(out) for out in il[0].output] == ['f1', 'fpscr']
        assert [p.size for p in il[0].params] == [8, 4]
        def fp(op, params):
            assert op == name and params == [0x8000000000000000, 3]
            return [0x43e0000000000000, 0xa0000003]
        regs, flags, _, events = evaluate(il, {'f2': 0x8000000000000000, 'fpscr': 3},
                                         {'lt': 1, 'gt': 1, 'eq': 0, 'so': 1}, intrinsic=fp)
        assert regs['f1'] == 0x43e0000000000000 and regs['fpscr'] == 0xa0000003
        assert [flags[f] for f in ('lt', 'gt', 'eq', 'so')] == [1, 1, 0, 1]
        if record:
            assert [flags[f'cr1{f}'] for f in ('lt', 'gt', 'eq', 'so')] == [1, 0, 1, 0]


def test_fcpsgn_record():
    regs, flags, _, _ = evaluate(lift(0xfc221811),
                                 {'f2': 1 << 63, 'f3': 0x3ff0000000000000, 'fpscr': 0x50000000}, {'eq': 1})
    assert regs['f1'] == 0xbff0000000000000 and regs['fpscr'] == 0x50000000
    assert flags['eq'] == 1
    assert [flags[f'cr1{f}'] for f in ('lt', 'gt', 'eq', 'so')] == [0, 1, 0, 1]


@pytest.mark.parametrize('value,selected', [(0.0, 3), (-0.0, 3), (-1.0, 4), (float('nan'), 4)])
def test_fsel_record(value, selected):
    bits = int.from_bytes(struct.pack('>d', value), 'big')
    regs, flags, _, _ = evaluate(lift(0xfc2220ef),
                                 {'f2': bits, 'f3': 0x33, 'f4': 0x44, 'fpscr': 0x50000000}, {'eq': 1})
    assert regs['f1'] == {3: 0x33, 4: 0x44}[selected]
    assert flags['eq'] == 1
    assert [flags[f'cr1{f}'] for f in ('lt', 'gt', 'eq', 'so')] == [0, 1, 0, 1]
