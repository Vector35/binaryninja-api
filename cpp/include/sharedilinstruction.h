// Copyright (c) 2025-2026 Vector 35 Inc
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

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <algorithm>

#ifdef BINARYNINJACORE_LIBRARY
#define BINARYNINJA_NAMESPACE BinaryNinjaCore
#else
#define BINARYNINJA_NAMESPACE BinaryNinja
#endif

namespace BINARYNINJA_NAMESPACE ::detail {


template <typename Traits>
struct ILInstructionOperandUsage
{
	using ILOperation = typename Traits::ILOperation;
	using OperandUsage = typename Traits::OperandUsage;
	static constexpr size_t MaxOperands = Traits::MaxOperands;

	ILOperation op;
	uint8_t count = 0;
	OperandUsage usages[MaxOperands] = {};
	uint8_t indices[MaxOperands] = {};

	explicit constexpr ILInstructionOperandUsage(ILOperation op)
		: op(op) {}

	template <size_t N>
	constexpr ILInstructionOperandUsage(ILOperation op, const OperandUsage (&ops)[N])
		: op(op), count(N)
	{
		static_assert(N <= MaxOperands, "Too many operands for instruction");
		std::copy(ops, ops + N, usages);

		uint8_t index = 0;
		for (size_t i = 0; i < N; i++)
		{
			indices[i] = index;
			index += Traits::GetOperandIndexAdvance(ops[i], i);
		}
	}
};


template <size_t Index, auto Expected, auto Actual>
struct ArrayMismatchError
{
	static_assert(Expected == Actual, "Array entries out of order");
};


template <typename ArrayType, const ArrayType& array, size_t Index = 0>
constexpr bool ValidateArrayOrdering()
{
	if constexpr (Index < array.size())
	{
		using OperationType = decltype(array[0].op);
		(void)ArrayMismatchError<Index, static_cast<OperationType>(Index), array[Index].op>{};
		return ValidateArrayOrdering<ArrayType, array, Index + 1>();
	}
	return true;
}


} // namespace BINARYNINJA_NAMESPACE ::detail


// Validate that the position of each instruction in `array` matches the value of its operation.
#define VALIDATE_INSTRUCTION_ORDER(array) \
	static_assert(BINARYNINJA_NAMESPACE ::detail::ValidateArrayOrdering<decltype(array), array>(), \
		"Array entries out of order, see ArrayMismatchError for details")
