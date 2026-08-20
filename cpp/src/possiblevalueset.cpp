// Copyright (c) 2015-2026 Vector 35 Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "binaryninjaapi.h"
#include "ffi.h"

using namespace BinaryNinja;
using namespace std;


PossibleValueSet PossibleValueSet::FromAPIObject(BNPossibleValueSet& value)
{
	PossibleValueSet result;
	result.state = value.state;
	result.value = value.value;
	result.offset = value.offset;
	result.size = value.size;
	if (value.state == LookupTableValue)
	{
		result.table.reserve(value.count);
		for (size_t i = 0; i < value.count; i++)
		{
			LookupTableEntry entry;
			entry.fromValues.insert(entry.fromValues.end(), &value.table[i].fromValues[0],
			    &value.table[i].fromValues[value.table[i].fromCount]);
			entry.toValue = value.table[i].toValue;
			result.table.push_back(entry);
		}
	}
	else if ((value.state == SignedRangeValue) || (value.state == UnsignedRangeValue))
	{
		result.ranges.reserve(value.count);
		for (size_t i = 0; i < value.count; i++)
			result.ranges.push_back(value.ranges[i]);
	}
	else if ((value.state == InSetOfValues) || (value.state == NotInSetOfValues))
	{
		for (size_t i = 0; i < value.count; i++)
			result.valueSet.insert(value.valueSet[i]);
	}

	result.count = value.count;
	BNFreePossibleValueSet(&value);
	return result;
}


BNPossibleValueSet PossibleValueSet::ToAPIObject() const
{
	BNPossibleValueSet result;
	result.state = state;
	result.value = value;
	result.offset = offset;
	result.size = size;
	result.count = 0;

	if ((state == SignedRangeValue) || (state == UnsignedRangeValue))
	{
		result.ranges = new BNValueRange[ranges.size()];
		result.count = ranges.size();
		for (size_t i = 0; i < ranges.size(); i++)
			result.ranges[i] = ranges[i];
	}
	else
	{
		result.ranges = nullptr;
	}

	if (state == LookupTableValue)
	{
		result.table = new BNLookupTableEntry[table.size()];
		result.count = table.size();
		for (size_t i = 0; i < table.size(); i++)
		{
			result.table[i].fromValues = new int64_t[table[i].fromValues.size()];
			memcpy(result.table[i].fromValues, &table[i].fromValues[0], sizeof(int64_t) * table[i].fromValues.size());
			result.table[i].fromCount = table[i].fromValues.size();
			result.table[i].toValue = table[i].toValue;
		}
	}
	else
	{
		result.table = nullptr;
	}

	if ((state == InSetOfValues) || (state == NotInSetOfValues))
	{
		result.valueSet = new int64_t[valueSet.size()];
		result.count = valueSet.size();
		size_t i = 0;
		for (auto j : valueSet)
			result.valueSet[i++] = j;
	}
	else
	{
		result.valueSet = nullptr;
	}

	return result;
}


void PossibleValueSet::FreeAPIObject(BNPossibleValueSet* value)
{
	switch (value->state)
	{
	case SignedRangeValue:
	case UnsignedRangeValue:
		delete[] value->ranges;
		break;
	case LookupTableValue:
		for (size_t i = 0; i < value->count; i ++)
		{
			delete[] value->table[i].fromValues;
		}
		delete[] value->table;
		break;
	case InSetOfValues:
	case NotInSetOfValues:
		delete[] value->valueSet;
		break;
	default:
		break;
	}
}


PossibleValueSet PossibleValueSet::Add(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetAdd(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Subtract(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetSubtract(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Multiply(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetMultiply(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::SignedDivide(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetSignedDivide(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::UnsignedDivide(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetUnsignedDivide(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::SignedMod(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetSignedMod(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::UnsignedMod(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetUnsignedMod(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::And(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetAnd(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Or(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetOr(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Xor(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetXor(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::ShiftLeft(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetShiftLeft(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::LogicalShiftRight(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetLogicalShiftRight(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::ArithShiftRight(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetArithShiftRight(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::RotateLeft(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetRotateLeft(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::RotateRight(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetRotateRight(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Union(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetUnion(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Intersection(const PossibleValueSet& other, size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet otherObj = other.ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetIntersection(&apiObj, &otherObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet::FreeAPIObject(&otherObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}



PossibleValueSet PossibleValueSet::Negate(size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetNegate(&apiObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}


PossibleValueSet PossibleValueSet::Not(size_t size) const
{
	BNPossibleValueSet apiObj = ToAPIObject();
	BNPossibleValueSet resultObj = BNPossibleValueSetNot(&apiObj, size);
	PossibleValueSet::FreeAPIObject(&apiObj);
	PossibleValueSet result = PossibleValueSet::FromAPIObject(resultObj);
	BNFreePossibleValueSet(&resultObj);
	return result;
}
