"""ARM conditions following VFP compares must preserve unordered outcomes."""

import math

import pytest

import binaryninja as bn
from binaryninja import LowLevelILOperation as Op


# Bit positions represent the VFP outcomes less, equal, greater, unordered.
# These are the hardware NZCV conditions, independently of the IL mappings.
CONDITIONS = [
	("eq", 0b0010), ("ne", 0b1101), ("cs", 0b1110), ("cc", 0b0001),
	("mi", 0b0001), ("pl", 0b1110), ("vs", 0b1000), ("vc", 0b0111),
	("hi", 0b1100), ("ls", 0b0011), ("ge", 0b0110), ("lt", 0b1001),
	("gt", 0b0100), ("le", 0b1011),
]
FLOAT_COMPARISONS = {
	"eq": Op.LLIL_FCMP_E, "ne": Op.LLIL_FCMP_NE, "cc": Op.LLIL_FCMP_LT,
	"mi": Op.LLIL_FCMP_LT, "vs": Op.LLIL_FCMP_UO, "vc": Op.LLIL_FCMP_O,
	"ls": Op.LLIL_FCMP_LE, "ge": Op.LLIL_FCMP_GE, "gt": Op.LLIL_FCMP_GT,
}


def _conditional_return(arch, condition):
	# mov r0, #0; mov<condition> r0, #1; bx lr. Thumb uses an IT block
	# and MOV.W so initializing the result does not overwrite the flags.
	if arch == "armv7":
		move = (0x03a00001 | condition << 28).to_bytes(4, "little")
		return bytes.fromhex("0000a0e3") + move + bytes.fromhex("1eff2fe1")
	it = (0xbf08 | condition << 4).to_bytes(2, "little")
	return bytes.fromhex("4ff00000") + it + bytes.fromhex("4ff001007047")


def _vfp_compare(arch, size):
	# vcmpe.f32 s0, s1 / vcmpe.f64 d0, d1; vmrs apsr_nzcv, fpscr
	if arch == "armv7":
		return bytes.fromhex("e00ab4ee10faf1ee" if size == 4 else "c10bb4ee10faf1ee")
	return bytes.fromhex("b4eee00af1ee10fa" if size == 4 else "b4eec10bf1ee10fa")


def _analyze(arch, code):
	bv = bn.BinaryView.new(code)
	bv.create_user_function(0, bn.Platform["linux-" + arch])
	bv.update_analysis_and_wait()
	return bv, bv.get_function_at(0)


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
	if op == Op.LLIL_NOT:
		assert expr.size == 0, "Flag inversions must be boolean, not bytewise complements"
		return not _evaluate(expr.src, registers, flags)
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
		return bool(left) and bool(right)
	if op == Op.LLIL_OR:
		return bool(left) or bool(right)
	pytest.fail(f"Unexpected condition expression: {expr}")


def _branch_value(il, left, right):
	registers = {"s0": left, "s1": right, "d0": left, "d1": right, "r0": left, "r1": right}
	flags = {}
	for block in il:
		for instr in block:
			if instr.operation == Op.LLIL_SET_FLAG:
				flags[instr.dest.name] = _evaluate(instr.src, registers, flags)
			elif instr.operation == Op.LLIL_SET_REG:
				registers[instr.dest.name] = _evaluate(instr.src, registers, flags)
			elif instr.operation == Op.LLIL_IF:
				return bool(_evaluate(instr.condition, registers, flags))
	pytest.fail("Expected a conditional instruction")


@pytest.mark.parametrize("arch", ["armv7", "thumb2"])
@pytest.mark.parametrize("size", [4, 8])
@pytest.mark.parametrize("condition", range(14), ids=[name for name, _ in CONDITIONS])
def test_vfp_condition_semantics(arch, size, condition):
	name, mask = CONDITIONS[condition]
	bv, function = _analyze(arch, _vfp_compare(arch, size) + _conditional_return(arch, condition))
	with bv:
		lifted_conditions = [expr.condition for block in function.lifted_il for expr in block
			if expr.operation == Op.LLIL_IF]
		assert len(lifted_conditions) == 1
		assert lifted_conditions[0].operation == Op.LLIL_FLAG_GROUP
		assert lifted_conditions[0].semantic_group.name == name
		assert function.arch.semantic_class_for_flag_write_type["fcmp"] == "float"
		expressions = _expressions(function.llil)
		if name in FLOAT_COMPARISONS:
			comparisons = [expr for expr in expressions if expr.operation == FLOAT_COMPARISONS[name]]
			assert len(comparisons) == 1
			assert comparisons[0].size == size
		for left, right in (
			(-1.0, 1.0), (1.0, 1.0), (1.0, -1.0),
			(float("nan"), 1.0), (1.0, float("nan")), (float("nan"), float("nan")),
			(-0.0, 0.0), (float("-inf"), float("inf")), (float("inf"), float("inf")),
		):
			if math.isnan(left) or math.isnan(right):
				outcome = 8
			elif left < right:
				outcome = 1
			elif left == right:
				outcome = 2
			else:
				outcome = 4
			assert _branch_value(function.llil, left, right) == bool(mask & outcome), (name, left, right)


@pytest.mark.parametrize("arch", ["armv7", "thumb2"])
@pytest.mark.parametrize("size", [4, 8])
def test_vfp_condition_with_overwritten_sign_flag(arch, size):
	# MOVS overwrites N/Z while leaving the VFP unordered flag V intact.
	# GE must use those mixed definitions, not the original float >= predicate.
	movs = bytes.fromhex("0020b0e3" if arch == "armv7" else "0022")
	bv, function = _analyze(arch, _vfp_compare(arch, size) + movs + _conditional_return(arch, 10))
	with bv:
		assert not any(expr.operation == Op.LLIL_FCMP_GE for expr in _expressions(function.llil))
		assert _branch_value(function.llil, -1.0, 1.0)
		assert not _branch_value(function.llil, float("nan"), 1.0)


@pytest.mark.parametrize("arch", ["armv7", "thumb2"])
def test_integer_ge_condition_keeps_signed_comparison(arch):
	# cmp r0, r1; conditional return. Semantic groups must retain integer semantics.
	cmp = bytes.fromhex("010050e1" if arch == "armv7" else "8842")
	bv, function = _analyze(arch, cmp + _conditional_return(arch, 10))
	with bv:
		expressions = _expressions(function.llil)
		assert any(expr.operation == Op.LLIL_CMP_SGE for expr in expressions)
		assert not any(expr.operation == Op.LLIL_FCMP_GE for expr in expressions)
		for left, right in ((-1, 1), (0, 0), (1, -1)):
			assert _branch_value(function.llil, left, right) == (left >= right)
