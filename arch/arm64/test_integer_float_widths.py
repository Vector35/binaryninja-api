"""Integer-to-float conversion must preserve the source width and signedness."""

import pytest

import binaryninja as bn
from binaryninja import LowLevelILOperation as Op


def _conversion(unsigned, integer_size, float_size):
	# SCVTF/UCVTF H0/S0/D0, W1/X1 (scalar general-purpose register encoding).
	word = 0x1e220020 | ({2: 3, 4: 0, 8: 1}[float_size] << 22)
	word |= (integer_size == 8) << 31
	word |= unsigned << 16
	return word.to_bytes(4, "little")


@pytest.mark.parametrize("unsigned", [False, True], ids=["scvtf", "ucvtf"])
@pytest.mark.parametrize("integer_size", [4, 8], ids=["w", "x"])
@pytest.mark.parametrize("float_size", [2, 4, 8], ids=["half", "single", "double"])
def test_scalar_integer_conversion_preserves_source(unsigned, integer_size, float_size):
	arch = bn.Architecture["aarch64"]
	instruction = arch.get_low_level_il_from_bytes(_conversion(unsigned, integer_size, float_size), 0)
	assert instruction.operation == Op.LLIL_SET_REG
	assert instruction.size == float_size
	conversion = instruction.src
	assert conversion.operation == Op.LLIL_INT_TO_FLOAT
	assert conversion.size == float_size
	source = conversion.src
	assert source.operation == (Op.LLIL_ZX if unsigned else Op.LLIL_SX)
	assert source.size >= integer_size, "The floating destination width must not truncate the integer"
	assert source.src.operation == Op.LLIL_REG
	assert source.src.size == integer_size
	assert source.src.src.name == ("x1" if integer_size == 8 else "w1")


@pytest.mark.parametrize("unsigned", [False, True], ids=["scvtf", "ucvtf"])
@pytest.mark.parametrize("integer_size", [4, 8], ids=["w", "x"])
@pytest.mark.parametrize("float_size", [4, 8], ids=["single", "double"])
def test_integer_conversion_analysis_preserves_width_and_signedness(unsigned, integer_size, float_size):
	# Keep an unknown argument so analysis cannot substitute a convenient constant.
	# MOV W1,W0 / MOV X1,X0; conversion; RET.
	move = bytes.fromhex("e103002a" if integer_size == 4 else "e10300aa")
	code = move + _conversion(unsigned, integer_size, float_size) + bytes.fromhex("c0035fd6")
	bv = bn.BinaryView.new(code)
	with bv:
		bv.create_user_function(0, bn.Architecture["aarch64"].standalone_platform)
		bv.update_analysis_and_wait()
		function = bv.get_function_at(0)
		function.type = ("float" if float_size == 4 else "double") + " repro(uint64_t bits);"
		bv.update_analysis_and_wait()
		conversions = [expr for block in function.mlil for instr in block
			for expr in instr.traverse(lambda expr: expr)
			if expr.operation == bn.MediumLevelILOperation.MLIL_INT_TO_FLOAT]
		assert len(conversions) == 1
		assert conversions[0].size == float_size
		source = conversions[0].src
		assert source.size >= integer_size
		assert source.expr_type.width >= integer_size
		assert bool(source.expr_type.signed) == (not unsigned)
