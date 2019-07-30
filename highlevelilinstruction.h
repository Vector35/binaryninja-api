// Copyright (c) 2019 Vector 35 Inc
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

#include <functional>
#include <unordered_map>
#include <vector>
#ifdef BINARYNINJACORE_LIBRARY
#include "variable.h"
#else
#include "binaryninjaapi.h"
#endif
#include "mediumlevelilinstruction.h"

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
	class HighLevelILFunction;

	template <BNHighLevelILOperation N>
	struct HighLevelILInstructionAccessor {};

	struct HighLevelILInstruction;
	struct HighLevelILConstantInstruction;
	struct HighLevelILOneOperandInstruction;
	struct HighLevelILTwoOperandInstruction;
	struct HighLevelILTwoOperandWithCarryInstruction;
	struct HighLevelILDoublePrecisionInstruction;
	struct MediumLevelILInstruction;
	class HighLevelILOperand;
	class HighLevelILOperandList;

	enum HighLevelILOperandType
	{
		IntegerHighLevelOperand,
		IndexHighLevelOperand,
		IntrinsicHighLevelOperand,
		ExprHighLevelOperand,
		VariableHighLevelOperand,
		SSAVariableHighLevelOperand,
		ExprListHighLevelOperand,
		SSAVariableListHighLevelOperand
	};

	enum HighLevelILOperandUsage
	{
		SourceExprHighLevelOperandUsage,
		VariableHighLevelOperandUsage,
		SSAVariableHighLevelOperandUsage,
		DestSSAVariableHighLevelOperandUsage,
		DestExprHighLevelOperandUsage,
		LeftExprHighLevelOperandUsage,
		RightExprHighLevelOperandUsage,
		CarryExprHighLevelOperandUsage,
		IndexExprHighLevelOperandUsage,
		ConditionExprHighLevelOperandUsage,
		TrueExprHighLevelOperandUsage,
		FalseExprHighLevelOperandUsage,
		LoopExprHighLevelOperandUsage,
		InitExprHighLevelOperandUsage,
		UpdateExprHighLevelOperandUsage,
		DefaultExprHighLevelOperandUsage,
		HighExprHighLevelOperandUsage,
		LowExprHighLevelOperandUsage,
		OffsetHighLevelOperandUsage,
		ConstantHighLevelOperandUsage,
		VectorHighLevelOperandUsage,
		IntrinsicHighLevelOperandUsage,
		TargetHighLevelOperandUsage,
		ParameterExprsHighLevelOperandUsage,
		SourceExprsHighLevelOperandUsage,
		DestExprsHighLevelOperandUsage,
		BlockExprsHighLevelOperandUsage,
		CasesHighLevelOperandUsage,
		SourceSSAVariablesHighLevelOperandUsage
	};
}

namespace std
{
	template<> struct hash<BNHighLevelILOperation>
	{
		typedef BNHighLevelILOperation argument_type;
		typedef int result_type;
		result_type operator()(argument_type const& value) const
		{
			return (result_type)value;
		}
	};

#ifdef BINARYNINJACORE_LIBRARY
	template<> struct hash<BinaryNinjaCore::HighLevelILOperandUsage>
#else
	template<> struct hash<BinaryNinja::HighLevelILOperandUsage>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::HighLevelILOperandUsage argument_type;
#else
		typedef BinaryNinja::HighLevelILOperandUsage argument_type;
#endif
		typedef int result_type;
		result_type operator()(argument_type const& value) const
		{
			return (result_type)value;
		}
	};
}

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
	class HighLevelILInstructionAccessException: public std::exception
	{
	public:
		HighLevelILInstructionAccessException(): std::exception() {}
		virtual const char* what() const NOEXCEPT { return "invalid access to HLIL instruction"; }
	};

	class HighLevelILIntegerList
	{
		struct ListIterator
		{
#ifdef BINARYNINJACORE_LIBRARY
			HighLevelILFunction* function;
#else
			Ref<HighLevelILFunction> function;
#endif
			BNHighLevelILInstruction instr;
			size_t operand, count;

			bool operator==(const ListIterator& a) const;
			bool operator!=(const ListIterator& a) const;
			bool operator<(const ListIterator& a) const;
			ListIterator& operator++();
			uint64_t operator*();
			HighLevelILFunction* GetFunction() const { return function; }
		};

		ListIterator m_start;

	public:
		typedef ListIterator const_iterator;

		HighLevelILIntegerList(HighLevelILFunction* func, const BNHighLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		uint64_t operator[](size_t i) const;

		operator std::vector<uint64_t>() const;
	};

	class HighLevelILInstructionList
	{
		struct ListIterator
		{
			size_t instructionIndex;
			HighLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			const HighLevelILInstruction operator*();
		};

		HighLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		HighLevelILInstructionList(HighLevelILFunction* func, const BNHighLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const HighLevelILInstruction operator[](size_t i) const;

		operator std::vector<HighLevelILInstruction>() const;
	};

	class HighLevelILSSAVariableList
	{
		struct ListIterator
		{
			HighLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const SSAVariable operator*();
		};

		HighLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		HighLevelILSSAVariableList(HighLevelILFunction* func, const BNHighLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSAVariable operator[](size_t i) const;

		operator std::vector<SSAVariable>() const;
	};

	struct HighLevelILInstructionBase: public BNHighLevelILInstruction
	{
#ifdef BINARYNINJACORE_LIBRARY
		HighLevelILFunction* function;
#else
		Ref<HighLevelILFunction> function;
#endif
		size_t exprIndex;

		static std::unordered_map<HighLevelILOperandUsage, HighLevelILOperandType> operandTypeForUsage;
		static std::unordered_map<BNHighLevelILOperation,
			std::vector<HighLevelILOperandUsage>> operationOperandUsage;
		static std::unordered_map<BNHighLevelILOperation,
			std::unordered_map<HighLevelILOperandUsage, size_t>> operationOperandIndex;

		HighLevelILOperandList GetOperands() const;

		uint64_t GetRawOperandAsInteger(size_t operand) const;
		size_t GetRawOperandAsIndex(size_t operand) const;
		HighLevelILInstruction GetRawOperandAsExpr(size_t operand) const;
		Variable GetRawOperandAsVariable(size_t operand) const;
		SSAVariable GetRawOperandAsSSAVariable(size_t operand) const;
		HighLevelILInstructionList GetRawOperandAsExprList(size_t operand) const;
		HighLevelILSSAVariableList GetRawOperandAsSSAVariableList(size_t operand) const;

		void UpdateRawOperand(size_t operandIndex, ExprId value);
		void UpdateRawOperandAsSSAVariableList(size_t operandIndex, const std::vector<SSAVariable>& vars);
		void UpdateRawOperandAsExprList(size_t operandIndex, const std::vector<HighLevelILInstruction>& exprs);
		void UpdateRawOperandAsExprList(size_t operandIndex, const std::vector<size_t>& exprs);

		size_t GetMediumLevelILExprIndex() const;
		bool HasMediumLevelIL() const;
		MediumLevelILInstruction GetMediumLevelIL() const;
		MediumLevelILInstruction GetMediumLevelILSSAForm() const;

		void Replace(ExprId expr);

		size_t GetInstructionIndex() const;
		HighLevelILInstruction GetInstruction() const;

		template <BNHighLevelILOperation N>
		HighLevelILInstructionAccessor<N>& As()
		{
			if (operation != N)
				throw HighLevelILInstructionAccessException();
			return *(HighLevelILInstructionAccessor<N>*)this;
		}
		HighLevelILOneOperandInstruction& AsOneOperand()
		{
			return *(HighLevelILOneOperandInstruction*)this;
		}
		HighLevelILTwoOperandInstruction& AsTwoOperand()
		{
			return *(HighLevelILTwoOperandInstruction*)this;
		}
		HighLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry()
		{
			return *(HighLevelILTwoOperandWithCarryInstruction*)this;
		}

		template <BNHighLevelILOperation N>
		const HighLevelILInstructionAccessor<N>& As() const
		{
			if (operation != N)
				throw HighLevelILInstructionAccessException();
			return *(const HighLevelILInstructionAccessor<N>*)this;
		}
		const HighLevelILConstantInstruction& AsConstant() const
		{
			return *(const HighLevelILConstantInstruction*)this;
		}
		const HighLevelILOneOperandInstruction& AsOneOperand() const
		{
			return *(const HighLevelILOneOperandInstruction*)this;
		}
		const HighLevelILTwoOperandInstruction& AsTwoOperand() const
		{
			return *(const HighLevelILTwoOperandInstruction*)this;
		}
		const HighLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry() const
		{
			return *(const HighLevelILTwoOperandWithCarryInstruction*)this;
		}
	};

	struct HighLevelILInstruction: public HighLevelILInstructionBase
	{
		HighLevelILInstruction();
		HighLevelILInstruction(HighLevelILFunction* func, const BNHighLevelILInstruction& instr, size_t expr);
		HighLevelILInstruction(const HighLevelILInstructionBase& instr);

		void VisitExprs(const std::function<bool(const HighLevelILInstruction& expr)>& func) const;

		ExprId CopyTo(HighLevelILFunction* dest) const;
		ExprId CopyTo(HighLevelILFunction* dest,
			const std::function<ExprId(const HighLevelILInstruction& subExpr)>& subExprHandler) const;

		// Templated accessors for instruction operands, use these for efficient access to a known instruction
		template <BNHighLevelILOperation N> HighLevelILInstruction GetSourceExpr() const { return As<N>().GetSourceExpr(); }
		template <BNHighLevelILOperation N> Variable GetVariable() const { return As<N>().GetVariable(); }
		template <BNHighLevelILOperation N> SSAVariable GetSSAVariable() const { return As<N>().GetSSAVariable(); }
		template <BNHighLevelILOperation N> SSAVariable GetDestSSAVariable() const { return As<N>().GetDestSSAVariable(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetDestExpr() const { return As<N>().GetDestExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetLeftExpr() const { return As<N>().GetLeftExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetRightExpr() const { return As<N>().GetRightExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetCarryExpr() const { return As<N>().GetCarryExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetIndexExpr() const { return As<N>().GetIndexExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetConditionExpr() const { return As<N>().GetConditionExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetTrueExpr() const { return As<N>().GetTrueExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetFalseExpr() const { return As<N>().GetFalseExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetLoopExpr() const { return As<N>().GetLoopExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetInitExpr() const { return As<N>().GetInitExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetUpdateExpr() const { return As<N>().GetUpdateExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetDefaultExpr() const { return As<N>().GetDefaultExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetHighExpr() const { return As<N>().GetHighExpr(); }
		template <BNHighLevelILOperation N> HighLevelILInstruction GetLowExpr() const { return As<N>().GetLowExpr(); }
		template <BNHighLevelILOperation N> uint64_t GetOffset() const { return As<N>().GetOffset(); }
		template <BNHighLevelILOperation N> int64_t GetConstant() const { return As<N>().GetConstant(); }
		template <BNHighLevelILOperation N> int64_t GetVector() const { return As<N>().GetVector(); }
		template <BNHighLevelILOperation N> uint32_t GetIntrinsic() const { return As<N>().GetIntrinsic(); }
		template <BNHighLevelILOperation N> size_t GetTarget() const { return As<N>().GetTarget(); }
		template <BNHighLevelILOperation N> HighLevelILInstructionList GetParameterExprs() const { return As<N>().GetParameterExprs(); }
		template <BNHighLevelILOperation N> HighLevelILInstructionList GetSourceExprs() const { return As<N>().GetSourceExprs(); }
		template <BNHighLevelILOperation N> HighLevelILInstructionList GetDestExprs() const { return As<N>().GetDestExprs(); }
		template <BNHighLevelILOperation N> HighLevelILInstructionList GetBlockExprs() const { return As<N>().GetBlockExprs(); }
		template <BNHighLevelILOperation N> HighLevelILInstructionList GetCases() const { return As<N>().GetCases(); }
		template <BNHighLevelILOperation N> HighLevelILSSAVariableList GetSourceSSAVariables() const { return As<N>().GetSourceSSAVariables(); }

		template <BNHighLevelILOperation N> void SetSSAVersion(size_t version) { As<N>().SetSSAVersion(version); }
		template <BNHighLevelILOperation N> void SetParameterExprs(const std::vector<MediumLevelILInstruction>& params) { As<N>().SetParameterExprs(params); }
		template <BNHighLevelILOperation N> void SetParameterExprs(const std::vector<ExprId>& params) { As<N>().SetParameterExprs(params); }
		template <BNHighLevelILOperation N> void SetSourceExprs(const std::vector<MediumLevelILInstruction>& params) { As<N>().SetSourceExprs(params); }
		template <BNHighLevelILOperation N> void SetSourceExprs(const std::vector<ExprId>& params) { As<N>().SetSourceExprs(params); }
		template <BNHighLevelILOperation N> void SetDestExprs(const std::vector<MediumLevelILInstruction>& params) { As<N>().SetDestExprs(params); }
		template <BNHighLevelILOperation N> void SetDestExprs(const std::vector<ExprId>& params) { As<N>().SetDestExprs(params); }
		template <BNHighLevelILOperation N> void SetBlockExprs(const std::vector<MediumLevelILInstruction>& params) { As<N>().SetBlockExprs(params); }
		template <BNHighLevelILOperation N> void SetBlockExprs(const std::vector<ExprId>& params) { As<N>().SetBlockExprs(params); }
		template <BNHighLevelILOperation N> void SetCases(const std::vector<MediumLevelILInstruction>& params) { As<N>().SetCases(params); }
		template <BNHighLevelILOperation N> void SetCases(const std::vector<ExprId>& params) { As<N>().SetCases(params); }
		template <BNHighLevelILOperation N> void SetSourceSSAVariables(const std::vector<SSAVariable>& vars) { As<N>().SetSourceSSAVariables(vars); }

		bool GetOperandIndexForUsage(HighLevelILOperandUsage usage, size_t& operandIndex) const;

		// Generic accessors for instruction operands, these will throw a HighLevelILInstructionAccessException
		// on type mismatch. These are slower than the templated versions above.
		HighLevelILInstruction GetSourceExpr() const;
		Variable GetVariable() const;
		SSAVariable GetSSAVariable() const;
		SSAVariable GetDestSSAVariable() const;
		HighLevelILInstruction GetDestExpr() const;
		HighLevelILInstruction GetLeftExpr() const;
		HighLevelILInstruction GetRightExpr() const;
		HighLevelILInstruction GetCarryExpr() const;
		HighLevelILInstruction GetIndexExpr() const;
		HighLevelILInstruction GetConditionExpr() const;
		HighLevelILInstruction GetTrueExpr() const;
		HighLevelILInstruction GetFalseExpr() const;
		HighLevelILInstruction GetLoopExpr() const;
		HighLevelILInstruction GetInitExpr() const;
		HighLevelILInstruction GetUpdateExpr() const;
		HighLevelILInstruction GetDefaultExpr() const;
		HighLevelILInstruction GetHighExpr() const;
		HighLevelILInstruction GetLowExpr() const;
		uint64_t GetOffset() const;
		int64_t GetConstant() const;
		int64_t GetVector() const;
		uint32_t GetIntrinsic() const;
		size_t GetTarget() const;
		HighLevelILInstructionList GetParameterExprs() const;
		HighLevelILInstructionList GetSourceExprs() const;
		HighLevelILInstructionList GetDestExprs() const;
		HighLevelILInstructionList GetBlockExprs() const;
		HighLevelILInstructionList GetCases() const;
		HighLevelILSSAVariableList GetSourceSSAVariables() const;
	};

	class HighLevelILOperand
	{
		HighLevelILInstruction m_instr;
		HighLevelILOperandUsage m_usage;
		HighLevelILOperandType m_type;
		size_t m_operandIndex;

	public:
		HighLevelILOperand(const HighLevelILInstruction& instr, HighLevelILOperandUsage usage,
			size_t operandIndex);

		HighLevelILOperandType GetType() const { return m_type; }
		HighLevelILOperandUsage GetUsage() const { return m_usage; }

		uint64_t GetInteger() const;
		size_t GetIndex() const;
		uint32_t GetIntrinsic() const;
		HighLevelILInstruction GetExpr() const;
		Variable GetVariable() const;
		SSAVariable GetSSAVariable() const;
		HighLevelILInstructionList GetExprList() const;
		HighLevelILSSAVariableList GetSSAVariableList() const;
	};

	class HighLevelILOperandList
	{
		struct ListIterator
		{
			const HighLevelILOperandList* owner;
			std::vector<HighLevelILOperandUsage>::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			const HighLevelILOperand operator*();
		};

		HighLevelILInstruction m_instr;
		const std::vector<HighLevelILOperandUsage>& m_usageList;
		const std::unordered_map<HighLevelILOperandUsage, size_t>& m_operandIndexMap;

	public:
		typedef ListIterator const_iterator;

		HighLevelILOperandList(const HighLevelILInstruction& instr,
			const std::vector<HighLevelILOperandUsage>& usageList,
			const std::unordered_map<HighLevelILOperandUsage, size_t>& operandIndexMap);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const HighLevelILOperand operator[](size_t i) const;

		operator std::vector<HighLevelILOperand>() const;
	};

	struct HighLevelILConstantInstruction: public HighLevelILInstructionBase
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(0); }
	};

	struct HighLevelILOneOperandInstruction: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
	};

	struct HighLevelILTwoOperandInstruction: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
	};

	struct HighLevelILTwoOperandWithCarryInstruction: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
		HighLevelILInstruction GetCarryExpr() const { return GetRawOperandAsExpr(2); }
	};

	// Implementations of each instruction to fetch the correct operand value for the valid operands, these
	// are derived from HighLevelILInstructionBase so that invalid operand accessor functions will generate
	// a compiler error.
	template <> struct HighLevelILInstructionAccessor<HLIL_BLOCK>: public HighLevelILInstructionBase
	{
		HighLevelILInstructionList GetBlockExprs() const { return GetRawOperandAsExprList(0); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_IF>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetTrueExpr() const { return GetRawOperandAsExpr(1); }
		HighLevelILInstruction GetFalseExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_WHILE>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetLoopExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_DO_WHILE>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetLoopExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_FOR>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetInitExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(1); }
		HighLevelILInstruction GetUpdateExpr() const { return GetRawOperandAsExpr(2); }
		HighLevelILInstruction GetLoopExpr() const { return GetRawOperandAsExpr(3); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_SWITCH>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetDefaultExpr() const { return GetRawOperandAsExpr(1); }
		HighLevelILInstructionList GetCases() const { return GetRawOperandAsExprList(2); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_CASE>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetTrueExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_GOTO>: public HighLevelILInstructionBase
	{
		size_t GetTarget() const { return GetRawOperandAsIndex(0); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_LABEL>: public HighLevelILInstructionBase
	{
		size_t GetTarget() const { return GetRawOperandAsIndex(0); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_RET>: public HighLevelILInstructionBase
	{
		HighLevelILInstructionList GetSourceExprs() const { return GetRawOperandAsExprList(0); }
		void SetSourceExprs(const std::vector<ExprId>& exprs) { UpdateRawOperandAsExprList(0, exprs); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_ASSIGN>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_STRUCT_FIELD>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_DEREF_FIELD>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_ARRAY_INDEX>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetIndexExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_SPLIT>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetHighExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstruction GetLowExpr() const { return GetRawOperandAsExpr(1); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_VAR>: public HighLevelILInstructionBase
	{
		Variable GetVariable() const { return GetRawOperandAsVariable(0); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_VAR_SSA>: public HighLevelILInstructionBase
	{
		SSAVariable GetSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		void SetSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_VAR_PHI>: public HighLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		HighLevelILSSAVariableList GetSourceSSAVariables() const { return GetRawOperandAsSSAVariableList(2); }
		void SetSourceSSAVariables(const std::vector<SSAVariable>& vars) { UpdateRawOperandAsSSAVariableList(2, vars); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_JUMP>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_CALL>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(1); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_SYSCALL>: public HighLevelILInstructionBase
	{
		HighLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(0); }
	};
	template <> struct HighLevelILInstructionAccessor<HLIL_TAILCALL>: public HighLevelILInstructionBase
	{
		HighLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		HighLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(1); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_ASSIGN_UNPACK>: public HighLevelILInstructionBase
	{
		HighLevelILInstructionList GetDestExprs() const { return GetRawOperandAsExprList(0); }
		HighLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_INTRINSIC>: public HighLevelILInstructionBase
	{
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(2); }
		HighLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_TRAP>: public HighLevelILInstructionBase
	{
		int64_t GetVector() const { return GetRawOperandAsInteger(0); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_EXTERN_PTR>: public HighLevelILConstantInstruction
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(0); }
		int64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};

	template <> struct HighLevelILInstructionAccessor<HLIL_NOP>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_BREAK>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CONTINUE>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_NORET>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_BP>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_UNDEF>: public HighLevelILInstructionBase {};
	template <> struct HighLevelILInstructionAccessor<HLIL_UNIMPL>: public HighLevelILInstructionBase {};

	template <> struct HighLevelILInstructionAccessor<HLIL_CONST>: public HighLevelILConstantInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CONST_PTR>: public HighLevelILConstantInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FLOAT_CONST>: public HighLevelILConstantInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_IMPORT>: public HighLevelILConstantInstruction {};

	template <> struct HighLevelILInstructionAccessor<HLIL_ADD>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_SUB>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_AND>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_OR>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_XOR>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_LSL>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_LSR>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ASR>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ROL>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ROR>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MUL>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MULU_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MULS_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_DIVU>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_DIVS>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MODU>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MODS>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_DIVU_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_DIVS_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MODU_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_MODS_DP>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_E>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_NE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_SLT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_ULT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_SLE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_ULE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_SGE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_UGE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_SGT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CMP_UGT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_TEST_BIT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ADD_OVERFLOW>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FADD>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FSUB>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FMUL>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FDIV>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_E>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_NE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_LT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_LE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_GE>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_GT>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_O>: public HighLevelILTwoOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FCMP_UO>: public HighLevelILTwoOperandInstruction {};

	template <> struct HighLevelILInstructionAccessor<HLIL_ADC>: public HighLevelILTwoOperandWithCarryInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_SBB>: public HighLevelILTwoOperandWithCarryInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_RLC>: public HighLevelILTwoOperandWithCarryInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_RRC>: public HighLevelILTwoOperandWithCarryInstruction {};

	template <> struct HighLevelILInstructionAccessor<HLIL_DEREF>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ADDRESS_OF>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_NEG>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_NOT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_SX>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ZX>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_LOW_PART>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_BOOL_TO_INT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_UNIMPL_MEM>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FSQRT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FNEG>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FABS>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FLOAT_TO_INT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_INT_TO_FLOAT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FLOAT_CONV>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_ROUND_TO_INT>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FLOOR>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_CEIL>: public HighLevelILOneOperandInstruction {};
	template <> struct HighLevelILInstructionAccessor<HLIL_FTRUNC>: public HighLevelILOneOperandInstruction {};
}
