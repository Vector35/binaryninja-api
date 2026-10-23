"""AArch64 floating conditions must retain the architectural unordered outcome."""

import math

import pytest

import binaryninja as bn
from binaryninja import LowLevelILOperation as Op


# Bit positions represent the FCMP outcomes less, equal, greater, unordered.
# Each mask follows from the architectural NZCV values 1000, 0110, 0010, 0011.
CONDITIONS = [
    ("eq", 0b0010), ("ne", 0b1101), ("cs", 0b1110), ("cc", 0b0001),
    ("mi", 0b0001), ("pl", 0b1110), ("vs", 0b1000), ("vc", 0b0111),
    ("hi", 0b1100), ("ls", 0b0011), ("ge", 0b0110), ("lt", 0b1001),
    ("gt", 0b0100), ("le", 0b1011),
]
DIRECT_COMPARISONS = {
    "eq": Op.LLIL_FCMP_E, "ne": Op.LLIL_FCMP_NE, "cc": Op.LLIL_FCMP_LT,
    "mi": Op.LLIL_FCMP_LT, "vs": Op.LLIL_FCMP_UO, "vc": Op.LLIL_FCMP_O,
    "ls": Op.LLIL_FCMP_LE, "ge": Op.LLIL_FCMP_GE, "gt": Op.LLIL_FCMP_GT,
}
FLOAT_VALUES = (-1.0, -0.0, 0.0, 1.0, float("-inf"), float("inf"), float("nan"))
RET = bytes.fromhex("c0035fd6")
CMP_X0_X1 = bytes.fromhex("1f0001eb")


def _float_compare(size, signaling=False):
    # FCMP/FCMPE S0,S1 or D0,D1. FCMPE differs only in exception behavior,
    # which these predicate tests do not model.
    word = (0x1e212000 if size == 4 else 0x1e612000) | (0x10 if signaling else 0)
    return word.to_bytes(4, "little")


def _conditional_return(condition):
    # CSET W0,cond aliases CSINC W0,WZR,WZR,invert(cond).
    return (0x1a9f07e0 | ((condition ^ 1) << 12)).to_bytes(4, "little") + RET


def _analyze(code):
    view = bn.BinaryView.new(code)
    view.create_user_function(0, bn.Platform["linux-aarch64"])
    view.update_analysis_and_wait()
    return view, view.get_function_at(0)


def _expressions(il):
    return [expr for block in il for instr in block for expr in instr.traverse(lambda expr: expr)]


def _evaluate(expr, registers, flags):
    op = expr.operation
    if op == Op.LLIL_REG:
        return registers[expr.src.name]
    if op == Op.LLIL_FLAG:
        return flags[expr.src.name]
    if op in (Op.LLIL_CONST, Op.LLIL_FLOAT_CONST):
        return expr.constant
    if op == Op.LLIL_BOOL_TO_INT:
        return int(_evaluate(expr.src, registers, flags))
    if op == Op.LLIL_NOT:
        assert expr.size == 0, "Flag inversion must be boolean, not a bytewise complement"
        return not _evaluate(expr.src, registers, flags)
    if op == Op.LLIL_UNIMPL:
        pytest.fail(f"Unimplemented flag expression: {expr}")
    left = _evaluate(expr.left, registers, flags)
    right = _evaluate(expr.right, registers, flags)
    if op in (Op.LLIL_CMP_E, Op.LLIL_FCMP_E):
        return left == right
    if op in (Op.LLIL_CMP_NE, Op.LLIL_FCMP_NE):
        return left != right
    if op in (Op.LLIL_CMP_SLT, Op.LLIL_FCMP_LT):
        return left < right
    if op in (Op.LLIL_CMP_SLE, Op.LLIL_FCMP_LE):
        return left <= right
    if op in (Op.LLIL_CMP_SGE, Op.LLIL_FCMP_GE):
        return left >= right
    if op in (Op.LLIL_CMP_SGT, Op.LLIL_FCMP_GT):
        return left > right
    if op == Op.LLIL_FCMP_UO:
        return math.isnan(left) or math.isnan(right)
    if op == Op.LLIL_FCMP_O:
        return not (math.isnan(left) or math.isnan(right))
    if op == Op.LLIL_AND:
        assert expr.size == 0
        return bool(left) and bool(right)
    if op == Op.LLIL_OR:
        assert expr.size == 0
        return bool(left) or bool(right)
    if op == Op.LLIL_XOR:
        assert expr.size == 0
        return bool(left) != bool(right)
    pytest.fail(f"Unexpected predicate expression: {expr}")


def _result(il, registers):
    registers = dict(registers)
    flags = {}
    for instr in il.instructions:
        if instr.operation == Op.LLIL_SET_FLAG:
            flags[instr.dest.name] = _evaluate(instr.src, registers, flags)
        elif instr.operation == Op.LLIL_SET_REG:
            registers[instr.dest.name] = _evaluate(instr.src, registers, flags)
        elif instr.operation == Op.LLIL_RET:
            return registers["w0"]
        elif instr.operation == Op.LLIL_FSUB:
            # A comparison whose flags were overwritten can remain as an
            # unused expression. Floating-point exception state is not tested.
            assert not instr.flags
        else:
            pytest.fail(f"Unexpected instruction: {instr}")
    pytest.fail("Missing return")


def _registers(left, right):
    return {"s0": left, "s1": right, "d0": left, "d1": right}


def _outcome(left, right):
    if math.isnan(left) or math.isnan(right):
        return 8
    if left < right:
        return 1
    if left == right:
        return 2
    return 4


@pytest.mark.parametrize("size", [4, 8])
@pytest.mark.parametrize("signaling", [False, True], ids=["fcmp", "fcmpe"])
@pytest.mark.parametrize("condition", range(14), ids=[name for name, _ in CONDITIONS])
def test_float_condition_semantics(size, signaling, condition):
    name, mask = CONDITIONS[condition]
    view, function = _analyze(_float_compare(size, signaling) + _conditional_return(condition))
    with view:
        groups = [expr for expr in _expressions(function.lifted_il) if expr.operation == Op.LLIL_FLAG_GROUP]
        assert len(groups) == 1 and groups[0].semantic_group.name == name
        expressions = _expressions(function.llil)
        if name in DIRECT_COMPARISONS:
            comparisons = [expr for expr in expressions if expr.operation == DIRECT_COMPARISONS[name]]
            assert len(comparisons) == 1 and comparisons[0].size == size
        for left in FLOAT_VALUES:
            for right in FLOAT_VALUES:
                assert _result(function.llil, _registers(left, right)) == bool(mask & _outcome(left, right)), (
                    name, left, right, str(function.llil)
                )


@pytest.mark.parametrize("size", [4, 8])
@pytest.mark.parametrize("flag,mask", [("n", 0b0001), ("z", 0b0010), ("c", 0b1110), ("v", 0b1000)])
def test_float_compare_physical_flags(size, flag, mask):
    # Unmapped conditions and mixed flag definitions must expand real NZCV,
    # including C=1 and V=1 for an unordered comparison.
    arch = bn.Architecture["aarch64"]
    il = bn.LowLevelILFunction(arch)
    prefix = "s" if size == 4 else "d"
    expr = il.get_expr(arch.get_flag_write_low_level_il(Op.LLIL_FSUB, size, "f*", flag, [prefix + "0", prefix + "1"], il))
    assert expr is not None
    for left in FLOAT_VALUES:
        for right in FLOAT_VALUES:
            assert _evaluate(expr, _registers(left, right), {}) == bool(mask & _outcome(left, right)), (flag, left, right)


@pytest.mark.parametrize("float_size", [None, 4, 8], ids=["integer-only", "overwrite-f32", "overwrite-f64"])
def test_integer_compare_overwrites_floating_flags(float_size):
    prefix = b"" if float_size is None else _float_compare(float_size)
    view, function = _analyze(prefix + CMP_X0_X1 + _conditional_return(10))  # GE
    with view:
        expressions = _expressions(function.llil)
        assert any(expr.operation == Op.LLIL_CMP_SGE for expr in expressions)
        assert not any(expr.operation.name.startswith("LLIL_FCMP_") for expr in expressions)
        for left, right in ((-1, 1), (0, 0), (1, -1), (-(1 << 63), (1 << 63) - 1)):
            registers = {**_registers(float("nan"), 0.0), "x0": left, "x1": right}
            assert _result(function.llil, registers) == (left >= right)
