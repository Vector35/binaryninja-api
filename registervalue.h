#pragma once
#include "binaryninja_defs.h"

extern "C" {

	enum BNRegisterValueType
	{
		UndeterminedValue,
		EntryValue,
		ConstantValue,
		ConstantPointerValue,
		ExternalPointerValue,
		StackFrameOffset,
		ReturnAddressValue,
		ImportedAddressValue,

		// The following are only valid in BNPossibleValueSet
		SignedRangeValue,
		UnsignedRangeValue,
		LookupTableValue,
		InSetOfValues,
		NotInSetOfValues
	};


	struct BNLookupTableEntry
	{
		int64_t* fromValues;
		size_t fromCount;
		int64_t toValue;
	};

	struct BNRegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
	};

	struct BNRegisterValueWithConfidence
	{
		BNRegisterValue value;
		uint8_t confidence;
	};

	struct BNValueRange
	{
		uint64_t start, end, step;
	};

	struct BNPossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		BNValueRange* ranges;
		int64_t* valueSet;
		BNLookupTableEntry* table;
		size_t count;
	};

	struct BNRegisterSetWithConfidence
	{
		uint32_t* regs;
		size_t count;
		uint8_t confidence;
	};

	BINARYNINJACOREAPI void BNFreePossibleValueSet(BNPossibleValueSet* value);
}