#include "acle_intrinsics.h"

#include "il_macros.h"
#include "lowlevelilinstruction.h"
#include "operands.h"

#include <unordered_map>

using namespace BinaryNinja;
using namespace std;

namespace {
// Represent an ACLE vector as one integer or float as wide as the whole vector, ignoring its
// element type.
Ref<Type> AcleType(exarmo_aarch64_intrinsic_type type, uint8_t& vectors)
{
	vectors = 1;
	exarmo_aarch64_intrinsic_type_def def;
	if (!exarmo_aarch64_intrinsic_type_at(type, &def))
		return nullptr;

	vectors = def.vectors ? def.vectors : 1;

	switch (def.kind)
	{
	case EXARMO_AARCH64_INTRINSIC_KIND_VOID:
		return nullptr;
	// A compile-time constant argument, such as a lane index.
	case EXARMO_AARCH64_INTRINSIC_KIND_CONST_INT:
		return Type::IntegerType(4, true);
	default:
		break;
	}

	// `width` is one vector. The caller expands a structure of vectors into `vectors` values of this
	// type. A pointer points to a single element.
	size_t width = (size_t)def.element_bits * def.lanes / 8;
	if (!width)
		return nullptr;

	Ref<Type> value;
	switch (def.kind)
	{
	case EXARMO_AARCH64_INTRINSIC_KIND_FLOAT:
	case EXARMO_AARCH64_INTRINSIC_KIND_BRAIN_FLOAT:
	case EXARMO_AARCH64_INTRINSIC_KIND_MICRO_FLOAT:
		value = Type::FloatType(width);
		break;
	case EXARMO_AARCH64_INTRINSIC_KIND_INT:
		value = Type::IntegerType(width, true);
		break;
	default:
		value = Type::IntegerType(width, false);
		break;
	}

	if (!def.pointer)
		return value;

	if (def.readonly)
		value = TypeBuilder(value.GetPtr()).SetConst(true).Finalize();

	return Type::PointerType(8, value);
}


bool AcleIntrinsicAt(uint32_t intrinsic, exarmo_aarch64_intrinsic_def& def)
{
	return IsAcleIntrinsic(intrinsic)
	    && exarmo_aarch64_intrinsic_at(intrinsic - AcleIntrinsicBase, &def);
}
}


string AcleIntrinsicName(uint32_t intrinsic)
{
	exarmo_aarch64_intrinsic_def def;
	if (!AcleIntrinsicAt(intrinsic, def))
		return "";

	return string(def.name.data, def.name.length);
}


uint32_t AcleIntrinsicNamed(string_view name)
{
	static const unordered_map<string_view, uint32_t> intrinsics = [] {
		unordered_map<string_view, uint32_t> all;
		exarmo_aarch64_intrinsic_def def;
		for (uint32_t id = 0; id < EXARMO_AARCH64_INTRINSIC_COUNT; id++)
		{
			if (exarmo_aarch64_intrinsic_at(id, &def))
				all.emplace(string_view(def.name.data, def.name.length), AcleIntrinsicBase + id);
		}

		return all;
	}();

	auto found = intrinsics.find(name);
	return found == intrinsics.end() ? ARM64_INTRIN_INVALID : found->second;
}


vector<NameAndType> AcleIntrinsicInputs(uint32_t intrinsic)
{
	exarmo_aarch64_intrinsic_def def;
	if (!AcleIntrinsicAt(intrinsic, def))
		return {};

	vector<NameAndType> result;
	for (uint8_t i = 0; i < def.parameter_count; i++)
	{
		uint8_t vectors = 1;
		Ref<Type> type = AcleType(def.parameters[i], vectors);
		for (uint8_t v = 0; type && v < vectors; v++)
			result.push_back(NameAndType(type));
	}

	return result;
}


vector<Confidence<Ref<Type>>> AcleIntrinsicOutputs(uint32_t intrinsic)
{
	exarmo_aarch64_intrinsic_def def;
	if (!AcleIntrinsicAt(intrinsic, def))
		return {};

	uint8_t vectors = 1;
	Ref<Type> type = AcleType(def.result, vectors);
	if (!type)
		return {};

	vector<Confidence<Ref<Type>>> result;
	for (uint8_t v = 0; v < vectors; v++)
		result.push_back(type);

	return result;
}


bool AcleGetLowLevelILForInstruction(
    LowLevelILFunction& il, const exarmo_aarch64_instruction& instr, exarmo_aarch64_operand* operands)
{
	// When exarmo lists several intrinsics, the encoding can't tell them apart. Use the first, which
	// exarmo orders as the one a reader expects.
	exarmo_aarch64_intrinsic realised;
	if (exarmo_aarch64_instruction_intrinsics(&instr, &realised, 1) == 0)
		return false;

	// Skip a result that is one element of a structure of vectors. An intrinsic call would claim to
	// write the whole structure.
	if (realised.result.kind == EXARMO_AARCH64_INTRINSIC_OUTPUT_ELEMENT)
		return false;

	vector<ExprId> inputs;
	for (uint8_t i = 0; i < realised.argument_count; i++)
	{
		const exarmo_aarch64_intrinsic_source& source = realised.arguments[i];
		exarmo_aarch64_operand& operand = operands[source.operand];
		switch (source.kind)
		{
		// A register list is one operand but supplies one argument per register.
		case EXARMO_AARCH64_INTRINSIC_SOURCE_OPERAND:
			if (operand.kind == EXARMO_AARCH64_OPERAND_LIST)
			{
				for (uint8_t member = 0; member < operand.list.len; member++)
				{
					Register reg = OperandRegisterAt(operand, member);
					inputs.push_back(il.Register(RegisterSize(reg), reg));
				}
				break;
			}

			inputs.push_back(ILREG_O(operand));
			break;
		// The intrinsic takes the operand's lane index as a separate argument.
		case EXARMO_AARCH64_INTRINSIC_SOURCE_INDEX:
		{
			int32_t index = OperandLaneIndex(operand);
			inputs.push_back(il.Const(1, index < 0 ? 0 : index));
			break;
		}
		case EXARMO_AARCH64_INTRINSIC_SOURCE_IMMEDIATE:
			inputs.push_back(il.Const(8, OperandImmediate(operand) >> source.shift));
			break;
		// FPMR is not modelled, and an UNUSED argument is fixed by the intrinsic. Pass zero for both.
		case EXARMO_AARCH64_INTRINSIC_SOURCE_FPMR:
		case EXARMO_AARCH64_INTRINSIC_SOURCE_UNUSED:
		default:
			inputs.push_back(il.Const(1, 0));
			break;
		}
	}

	// A register-list result writes one output per register.
	vector<RegisterOrFlag> outputs;
	if (realised.result.kind != EXARMO_AARCH64_INTRINSIC_OUTPUT_NONE)
	{
		exarmo_aarch64_operand& result = operands[realised.result.operand];
		size_t members = result.kind == EXARMO_AARCH64_OPERAND_LIST ? result.list.len : 1;
		for (size_t member = 0; member < members; member++)
		{
			Register reg = OperandRegisterAt(result, member);
			if (reg != REG_NONE)
				outputs.push_back(RegisterOrFlag::Register(reg));
		}
	}

	il.AddInstruction(il.Intrinsic(outputs, AcleIntrinsicBase + realised.id, inputs));
	return true;
}

