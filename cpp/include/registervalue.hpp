#pragma once
#include "core/registervalue.h"
#include <vector>
#include <set>

namespace BinaryNinja {

	struct RegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;

		RegisterValue();

		bool IsConstant() const;

		static RegisterValue FromAPIObject(const BNRegisterValue& value);
		BNRegisterValue ToAPIObject();
	};


	struct LookupTableEntry
	{
		std::vector<int64_t> fromValues;
		int64_t toValue;
	};

	struct PossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		std::vector<BNValueRange> ranges;
		std::set<int64_t> valueSet;
		std::vector<LookupTableEntry> table;
		size_t count;

		static PossibleValueSet FromAPIObject(BNPossibleValueSet& value);
		BNPossibleValueSet ToAPIObject();
	};
}