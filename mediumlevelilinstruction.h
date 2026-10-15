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

#pragma once

#ifdef BINARYNINJACORE_LIBRARY
	#include "constantdata.h"
	#include "variable.h"
	#include "ilsourcelocation.h"
#else
	#include "binaryninjaapi.h"
#endif

#include "base/compiler.h"
#include "base/function_ref.h"

#include <optional>
#include <unordered_map>
#include <vector>

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
#ifdef BINARYNINJACORE_LIBRARY
	typedef size_t ExprId;
#endif

	class MediumLevelILFunction;

	template <BNMediumLevelILOperation N>
	struct MediumLevelILInstructionAccessor
	{};

	struct MediumLevelILInstruction;
	struct MediumLevelILConstantInstruction;
	struct MediumLevelILConstantDataInstruction;
	struct MediumLevelILOneOperandInstruction;
	struct MediumLevelILTwoOperandInstruction;
	struct MediumLevelILTwoOperandWithCarryInstruction;
	struct MediumLevelILDoublePrecisionInstruction;
	struct MediumLevelILLabel;
	struct LowLevelILInstruction;
	class MediumLevelILOperand;
	class MediumLevelILOperandList;

	/*!
		\ingroup mediumlevelil
	*/
	struct SSAVariable
	{
		Variable var;
		size_t version = 0;

		// TODO: `= default` these when we can rely on C++20
		bool operator==(const SSAVariable& other) const
		{
			return var == other.var && version == other.version;
		}

		bool operator!=(const SSAVariable& other) const
		{
			return !(*this == other);
		}

		bool operator<(const SSAVariable& other) const
		{
			if (var != other.var)
				return var < other.var;
			return version < other.version;
		}
	};

	/*!
		\ingroup mediumlevelil
	*/
	enum MediumLevelILOperandType : uint8_t
	{
		IntegerMediumLevelOperand,
		ConstantDataMediumLevelOperand,
		IndexMediumLevelOperand,
		IntrinsicMediumLevelOperand,
		ExprMediumLevelOperand,
		VariableMediumLevelOperand,
		SSAVariableMediumLevelOperand,
		IndexListMediumLevelOperand,
		IndexMapMediumLevelOperand,
		VariableListMediumLevelOperand,
		SSAVariableListMediumLevelOperand,
		ExprListMediumLevelOperand,
		ConstraintMediumLevelOperand,
		ForceVersionReasonMediumLevelOperand
	};

	/*!
		\ingroup mediumlevelil
	*/
	// BEGIN GENERATED mlil-operand-usages: from api/il, do not edit
	enum MediumLevelILOperandUsage : uint8_t
	{
		DestVariableMediumLevelOperandUsage,
		SourceExprMediumLevelOperandUsage,
		OffsetMediumLevelOperandUsage,
		HighVariableMediumLevelOperandUsage,
		LowVariableMediumLevelOperandUsage,
		SourceVariableMediumLevelOperandUsage,
		ConstraintMediumLevelOperandUsage,
		ForceVersionReasonMediumLevelOperandUsage,
		DestExprMediumLevelOperandUsage,
		ConstantMediumLevelOperandUsage,
		ConstantDataMediumLevelOperandUsage,
		LeftExprMediumLevelOperandUsage,
		RightExprMediumLevelOperandUsage,
		CarryExprMediumLevelOperandUsage,
		TargetsMediumLevelOperandUsage,
		OutputExprsMediumLevelOperandUsage,
		ParameterExprsMediumLevelOperandUsage,
		UntypedParameterExprsMediumLevelOperandUsage,
		StackExprMediumLevelOperandUsage,
		SourceExprsMediumLevelOperandUsage,
		ConditionExprMediumLevelOperandUsage,
		TrueTargetMediumLevelOperandUsage,
		FalseTargetMediumLevelOperandUsage,
		TargetMediumLevelOperandUsage,
		OutputVariablesMediumLevelOperandUsage,
		IntrinsicMediumLevelOperandUsage,
		VectorMediumLevelOperandUsage,
		DestSSAVariableMediumLevelOperandUsage,
		PartialSSAVariableSourceMediumLevelOperandUsage,
		HighSSAVariableMediumLevelOperandUsage,
		LowSSAVariableMediumLevelOperandUsage,
		SourceSSAVariableMediumLevelOperandUsage,
		OutputExprsSubExprMediumLevelOperandUsage,
		OutputSSAMemoryVersionMediumLevelOperandUsage,
		SourceMemoryVersionMediumLevelOperandUsage,
		UntypedParameterSSAExprsMediumLevelOperandUsage,
		ParameterSSAMemoryVersionMediumLevelOperandUsage,
		DestMemoryVersionMediumLevelOperandUsage,
		OutputSSAVariablesMediumLevelOperandUsage,
		OutputSSAVariablesSubExprMediumLevelOperandUsage,
		SourceSSAVariablesMediumLevelOperandUsage,
		SourceMemoryVersionsMediumLevelOperandUsage,
	};
	// END GENERATED mlil-operand-usages
}  // namespace BinaryNinjaCore

namespace std {
#ifdef BINARYNINJACORE_LIBRARY
	template <>
	struct hash<BinaryNinjaCore::SSAVariable>
#else
	template <>
	struct hash<BinaryNinja::SSAVariable>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::SSAVariable argument_type;
#else
		typedef BinaryNinja::SSAVariable argument_type;
#endif
		size_t operator()(argument_type const& value) const
		{
			return std::hash<uint64_t>()(((uint64_t)value.var.ToIdentifier()) ^ ((uint64_t)value.version << 40));
		}
	};

	template <>
	struct hash<BNMediumLevelILOperation>
	{
		typedef BNMediumLevelILOperation argument_type;
		typedef int result_type;
		result_type operator()(argument_type const& value) const { return (result_type)value; }
	};

#ifdef BINARYNINJACORE_LIBRARY
	template <>
	struct hash<BinaryNinjaCore::MediumLevelILOperandUsage>
#else
	template <>
	struct hash<BinaryNinja::MediumLevelILOperandUsage>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::MediumLevelILOperandUsage argument_type;
#else
		typedef BinaryNinja::MediumLevelILOperandUsage argument_type;
#endif
		typedef int result_type;
		result_type operator()(argument_type const& value) const { return (result_type)value; }
	};
}  // namespace std

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
#ifdef BINARYNINJACORE_LIBRARY
	#define _STD_VECTOR        vector
	#define _STD_SET           set
	#define _STD_UNORDERED_MAP unordered_map
	#define _STD_MAP           map
#else
	#define _STD_VECTOR        std::vector
	#define _STD_SET           std::set
	#define _STD_UNORDERED_MAP std::unordered_map
	#define _STD_MAP           std::map
#endif

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILInstructionAccessException : public ExceptionWithStackTrace
	{
	  public:
		MediumLevelILInstructionAccessException() : ExceptionWithStackTrace("invalid access to MLIL instruction") {}
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILIntegerList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef uint64_t value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

#ifdef BINARYNINJACORE_LIBRARY
			MediumLevelILFunction* function;
#else
			Ref<MediumLevelILFunction> function;
#endif
			size_t offset;
			size_t count;

			bool operator==(const ListIterator& a) const;
			bool operator!=(const ListIterator& a) const;
			bool operator<(const ListIterator& a) const;
			ListIterator& operator++();
			uint64_t operator*();
			MediumLevelILFunction* GetFunction() const { return function; }
		};

		ListIterator m_start;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILIntegerList(MediumLevelILFunction* func, size_t offset, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		uint64_t operator[](size_t i) const;

		operator _STD_VECTOR<uint64_t>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILIndexList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef size_t value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			MediumLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			size_t operator*();
		};

		MediumLevelILIntegerList m_list;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILIndexList(MediumLevelILFunction* func, size_t offset, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		size_t operator[](size_t i) const;

		operator _STD_VECTOR<size_t>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILIndexMap
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef std::pair<uint64_t, size_t> value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			MediumLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const std::pair<uint64_t, size_t> operator*();
		};

		MediumLevelILIntegerList m_list;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILIndexMap(MediumLevelILFunction* func, size_t offset, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		size_t operator[](uint64_t) const;

		operator _STD_MAP<uint64_t, size_t>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILVariableList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef Variable value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			MediumLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const Variable operator*();
		};

		MediumLevelILIntegerList m_list;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILVariableList(MediumLevelILFunction* func, size_t offset, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const Variable operator[](size_t i) const;

		operator _STD_VECTOR<Variable>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILSSAVariableList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef SSAVariable value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			MediumLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const SSAVariable operator*();
		};

		MediumLevelILIntegerList m_list;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILSSAVariableList(
		    MediumLevelILFunction* func, size_t offset, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSAVariable operator[](size_t i) const;

		operator _STD_VECTOR<SSAVariable>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILInstructionList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef MediumLevelILInstruction value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			size_t instructionIndex;
			MediumLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const MediumLevelILInstruction operator*();
		};

		MediumLevelILIntegerList m_list;
		size_t m_instructionIndex;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILInstructionList(MediumLevelILFunction* func, size_t offset, size_t count,
		    size_t instructionIndex);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const MediumLevelILInstruction operator[](size_t i) const;

		operator _STD_VECTOR<MediumLevelILInstruction>() const;
		operator _STD_VECTOR<ExprId>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILInstructionBase : public BNMediumLevelILInstruction
	{
#ifdef BINARYNINJACORE_LIBRARY
		MediumLevelILFunction* function;
#else
		Ref<MediumLevelILFunction> function;
#endif
		size_t exprIndex, instructionIndex;

		MediumLevelILOperandList GetOperands() const;

		uint64_t GetRawOperandAsInteger(size_t operand) const;
		ConstantData GetRawOperandAsConstantData(size_t operand) const;
		size_t GetRawOperandAsIndex(size_t operand) const;
		MediumLevelILInstruction GetRawOperandAsExpr(size_t operand) const;
		Variable GetRawOperandAsVariable(size_t operand) const;
		SSAVariable GetRawOperandAsSSAVariable(size_t operand) const;
		SSAVariable GetRawOperandAsPartialSSAVariableSource(size_t operand) const;
		MediumLevelILIndexList GetRawOperandAsIndexList(size_t operand) const;
		MediumLevelILIndexMap GetRawOperandAsIndexMap(size_t operand) const;
		MediumLevelILVariableList GetRawOperandAsVariableList(size_t operand) const;
		MediumLevelILSSAVariableList GetRawOperandAsSSAVariableList(size_t operand) const;
		MediumLevelILInstructionList GetRawOperandAsExprList(size_t operand) const;
		PossibleValueSet GetRawOperandAsPossibleValueSet(size_t operand) const;

		void UpdateRawOperand(size_t operandIndex, ExprId value);
		void UpdateRawOperandAsSSAVariableList(size_t operandIndex, const _STD_VECTOR<SSAVariable>& vars);
		void UpdateRawOperandAsExprList(size_t operandIndex, const _STD_VECTOR<MediumLevelILInstruction>& exprs);
		void UpdateRawOperandAsExprList(size_t operandIndex, const _STD_VECTOR<size_t>& exprs);

		RegisterValue GetValue() const;
		PossibleValueSet GetPossibleValues(
		    const _STD_SET<BNDataFlowQueryOption>& options = _STD_SET<BNDataFlowQueryOption>()) const;
		Confidence<Ref<Type>> GetType() const;

		// Return (and leak) a string describing the instruction for debugger use
		char* Dump() const;

		size_t GetSSAVarVersion(const Variable& var);
		size_t GetSSAMemoryVersion();
		Variable GetVariableForRegister(uint32_t reg);
		Variable GetVariableForFlag(uint32_t flag);
		Variable GetVariableForStackLocation(int64_t offset);

		PossibleValueSet GetPossibleSSAVarValues(const SSAVariable& var);
		RegisterValue GetRegisterValue(uint32_t reg);
		RegisterValue GetRegisterValueAfter(uint32_t reg);
		PossibleValueSet GetPossibleRegisterValues(uint32_t reg);
		PossibleValueSet GetPossibleRegisterValuesAfter(uint32_t reg);
		RegisterValue GetFlagValue(uint32_t flag);
		RegisterValue GetFlagValueAfter(uint32_t flag);
		PossibleValueSet GetPossibleFlagValues(uint32_t flag);
		PossibleValueSet GetPossibleFlagValuesAfter(uint32_t flag);
		RegisterValue GetStackContents(int32_t offset, size_t len);
		RegisterValue GetStackContentsAfter(int32_t offset, size_t len);
		PossibleValueSet GetPossibleStackContents(int32_t offset, size_t len);
		PossibleValueSet GetPossibleStackContentsAfter(int32_t offset, size_t len);

		BNILBranchDependence GetBranchDependence(size_t branchInstr);
		BNILBranchDependence GetBranchDependence(const MediumLevelILInstruction& branch);
		_STD_UNORDERED_MAP<size_t, BNILBranchDependence> GetAllBranchDependence();

		size_t GetSSAInstructionIndex() const;
		size_t GetNonSSAInstructionIndex() const;
		size_t GetSSAExprIndex() const;
		size_t GetNonSSAExprIndex() const;

		MediumLevelILInstruction GetSSAForm() const;
		MediumLevelILInstruction GetNonSSAForm() const;

		size_t GetLowLevelILInstructionIndex() const;
		size_t GetLowLevelILExprIndex() const;
		size_t GetHighLevelILInstructionIndex() const;
		size_t GetHighLevelILExprIndex() const;

		bool HasLowLevelIL() const;
		LowLevelILInstruction GetLowLevelIL() const;

		void MarkInstructionForRemoval();
		void Replace(ExprId expr);
		void SetAttributes(uint32_t attributes);
		void SetAttribute(BNILInstructionAttribute attribute, bool state = true);
		void ClearAttribute(BNILInstructionAttribute attribute);

		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionAccessor<N>& As()
		{
			if (operation != N)
				throw MediumLevelILInstructionAccessException();
			return *(MediumLevelILInstructionAccessor<N>*)this;
		}
		MediumLevelILOneOperandInstruction& AsOneOperand() { return *(MediumLevelILOneOperandInstruction*)this; }
		MediumLevelILTwoOperandInstruction& AsTwoOperand() { return *(MediumLevelILTwoOperandInstruction*)this; }
		MediumLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry()
		{
			return *(MediumLevelILTwoOperandWithCarryInstruction*)this;
		}

		template <BNMediumLevelILOperation N>
		const MediumLevelILInstructionAccessor<N>& As() const
		{
			if (operation != N)
				throw MediumLevelILInstructionAccessException();
			return *(const MediumLevelILInstructionAccessor<N>*)this;
		}
		const MediumLevelILConstantInstruction& AsConstant() const
		{
			return *(const MediumLevelILConstantInstruction*)this;
		}
		const MediumLevelILConstantDataInstruction& AsConstantData() const
		{
			return *(const MediumLevelILConstantDataInstruction*)this;
		}
		const MediumLevelILOneOperandInstruction& AsOneOperand() const
		{
			return *(const MediumLevelILOneOperandInstruction*)this;
		}
		const MediumLevelILTwoOperandInstruction& AsTwoOperand() const
		{
			return *(const MediumLevelILTwoOperandInstruction*)this;
		}
		const MediumLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry() const
		{
			return *(const MediumLevelILTwoOperandWithCarryInstruction*)this;
		}
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction();
		MediumLevelILInstruction(
		    MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t expr, size_t instrIdx);
		MediumLevelILInstruction(const MediumLevelILInstructionBase& instr);

		void VisitExprs(bn::base::function_ref<bool(const MediumLevelILInstruction& expr)> func) const;

		ExprId CopyTo(MediumLevelILFunction* dest, const ILSourceLocation& sourceLocation = {}) const;
		ExprId CopyTo(MediumLevelILFunction* dest,
		    bn::base::function_ref<ExprId(const MediumLevelILInstruction& subExpr)> subExprHandler,
			const ILSourceLocation& sourceLocation = {}) const;

		// Templated accessors for instruction operands, use these for efficient access to a known instruction
		// BEGIN GENERATED mlil-instruction-templates: from api/il, do not edit
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetCarryExpr() const
		{
			return As<N>().GetCarryExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetConditionExpr() const
		{
			return As<N>().GetConditionExpr();
		}
		template <BNMediumLevelILOperation N>
		int64_t GetConstant() const
		{
			return As<N>().GetConstant();
		}
		template <BNMediumLevelILOperation N>
		ConstantData GetConstantData() const
		{
			return As<N>().GetConstantData();
		}
		template <BNMediumLevelILOperation N>
		PossibleValueSet GetConstraint() const
		{
			return As<N>().GetConstraint();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetDestExpr() const
		{
			return As<N>().GetDestExpr();
		}
		template <BNMediumLevelILOperation N>
		size_t GetDestMemoryVersion() const
		{
			return As<N>().GetDestMemoryVersion();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetDestSSAVariable() const
		{
			return As<N>().GetDestSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		Variable GetDestVariable() const
		{
			return As<N>().GetDestVariable();
		}
		template <BNMediumLevelILOperation N>
		size_t GetFalseTarget() const
		{
			return As<N>().GetFalseTarget();
		}
		template <BNMediumLevelILOperation N>
		BNForceVersionReason GetForceVersionReason() const
		{
			return As<N>().GetForceVersionReason();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetHighSSAVariable() const
		{
			return As<N>().GetHighSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		Variable GetHighVariable() const
		{
			return As<N>().GetHighVariable();
		}
		template <BNMediumLevelILOperation N>
		uint32_t GetIntrinsic() const
		{
			return As<N>().GetIntrinsic();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetLeftExpr() const
		{
			return As<N>().GetLeftExpr();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetLowSSAVariable() const
		{
			return As<N>().GetLowSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		Variable GetLowVariable() const
		{
			return As<N>().GetLowVariable();
		}
		template <BNMediumLevelILOperation N>
		uint64_t GetOffset() const
		{
			return As<N>().GetOffset();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionList GetOutputExprs() const
		{
			return As<N>().GetOutputExprs();
		}
		template <BNMediumLevelILOperation N>
		_STD_VECTOR<SSAVariable> GetOutputSSAVariables() const
		{
			return As<N>().GetOutputSSAVariables();
		}
		template <BNMediumLevelILOperation N>
		_STD_VECTOR<Variable> GetOutputVariables() const
		{
			return As<N>().GetOutputVariables();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return As<N>().GetParameterExprs();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetRightExpr() const
		{
			return As<N>().GetRightExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetSourceExpr() const
		{
			return As<N>().GetSourceExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionList GetSourceExprs() const
		{
			return As<N>().GetSourceExprs();
		}
		template <BNMediumLevelILOperation N>
		size_t GetSourceMemoryVersion() const
		{
			return As<N>().GetSourceMemoryVersion();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILIndexList GetSourceMemoryVersions() const
		{
			return As<N>().GetSourceMemoryVersions();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetSourceSSAVariable() const
		{
			return As<N>().GetSourceSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILSSAVariableList GetSourceSSAVariables() const
		{
			return As<N>().GetSourceSSAVariables();
		}
		template <BNMediumLevelILOperation N>
		Variable GetSourceVariable() const
		{
			return As<N>().GetSourceVariable();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetStackExpr() const
		{
			return As<N>().GetStackExpr();
		}
		template <BNMediumLevelILOperation N>
		size_t GetTarget() const
		{
			return As<N>().GetTarget();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILIndexMap GetTargets() const
		{
			return As<N>().GetTargets();
		}
		template <BNMediumLevelILOperation N>
		size_t GetTrueTarget() const
		{
			return As<N>().GetTrueTarget();
		}
		template <BNMediumLevelILOperation N>
		int64_t GetVector() const
		{
			return As<N>().GetVector();
		}
		template <BNMediumLevelILOperation N>
		bool IsUnknown() const
		{
			return As<N>().IsUnknown();
		}
		template <BNMediumLevelILOperation N>
		void SetDestMemoryVersion(size_t version)
		{
			As<N>().SetDestMemoryVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetDestSSAVersion(size_t version)
		{
			As<N>().SetDestSSAVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetHighSSAVersion(size_t version)
		{
			As<N>().SetHighSSAVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetLowSSAVersion(size_t version)
		{
			As<N>().SetLowSSAVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetOutputExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			As<N>().SetOutputExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetOutputExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			As<N>().SetOutputExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& values)
		{
			As<N>().SetOutputSSAVariables(values);
		}
		template <BNMediumLevelILOperation N>
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			As<N>().SetParameterExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			As<N>().SetParameterExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			As<N>().SetSourceExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			As<N>().SetSourceExprs(exprs);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceMemoryVersion(size_t version)
		{
			As<N>().SetSourceMemoryVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceSSAVersion(size_t version)
		{
			As<N>().SetSourceSSAVersion(version);
		}
		// END GENERATED mlil-instruction-templates

		// Finds the slot of the operand reported under `usage`. For a partial SSA source stored in this instruction,
		// that's the slot that holds its version.
		bool GetOperandIndexForUsage(MediumLevelILOperandUsage usage, size_t& operandIndex) const;

		// Generic accessors for instruction operands, these will throw a MediumLevelILInstructionAccessException
		// on type mismatch. These are slower than the templated versions above.
		// BEGIN GENERATED mlil-instruction-getters: from api/il, do not edit
		MediumLevelILInstruction GetCarryExpr() const;
		MediumLevelILInstruction GetConditionExpr() const;
		int64_t GetConstant() const;
		ConstantData GetConstantData() const;
		PossibleValueSet GetConstraint() const;
		MediumLevelILInstruction GetDestExpr() const;
		size_t GetDestMemoryVersion() const;
		SSAVariable GetDestSSAVariable() const;
		Variable GetDestVariable() const;
		size_t GetFalseTarget() const;
		BNForceVersionReason GetForceVersionReason() const;
		SSAVariable GetHighSSAVariable() const;
		Variable GetHighVariable() const;
		uint32_t GetIntrinsic() const;
		MediumLevelILInstruction GetLeftExpr() const;
		SSAVariable GetLowSSAVariable() const;
		Variable GetLowVariable() const;
		uint64_t GetOffset() const;
		MediumLevelILInstructionList GetOutputExprs() const;
		_STD_VECTOR<SSAVariable> GetOutputSSAVariables() const;
		_STD_VECTOR<Variable> GetOutputVariables() const;
		MediumLevelILInstructionList GetParameterExprs() const;
		MediumLevelILInstruction GetRightExpr() const;
		MediumLevelILInstruction GetSourceExpr() const;
		MediumLevelILInstructionList GetSourceExprs() const;
		size_t GetSourceMemoryVersion() const;
		MediumLevelILIndexList GetSourceMemoryVersions() const;
		SSAVariable GetSourceSSAVariable() const;
		MediumLevelILSSAVariableList GetSourceSSAVariables() const;
		Variable GetSourceVariable() const;
		MediumLevelILInstruction GetStackExpr() const;
		size_t GetTarget() const;
		MediumLevelILIndexMap GetTargets() const;
		size_t GetTrueTarget() const;
		int64_t GetVector() const;
		bool IsUnknown() const;
		// END GENERATED mlil-instruction-getters
	};

	/*! Describes where an instruction stores one of its operands.

		\ingroup mediumlevelil
	*/
	struct MediumLevelILOperandLocation
	{
		MediumLevelILOperandUsage usage;
		// The instruction's operand slot that holds the value, or holds the subexpression that does.
		uint8_t slot;
		// For a value stored in a subexpression, the subexpression's operand slot that holds it.
		std::optional<uint8_t> field = std::nullopt;
		// Set for an SSA variable whose version is two slots after it rather than in the next slot.
		bool partial = false;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILOperand
	{
		MediumLevelILInstruction m_instr;
		MediumLevelILOperandLocation m_location;
		MediumLevelILOperandType m_type;

		MediumLevelILInstruction Holder() const;
		size_t Slot() const;

	  public:
		MediumLevelILOperand(const MediumLevelILInstruction& instr, const MediumLevelILOperandLocation& location);

		MediumLevelILOperandType GetType() const { return m_type; }
		MediumLevelILOperandUsage GetUsage() const { return m_location.usage; }
		size_t GetOperandIndex() const { return m_location.slot; }

		uint64_t GetInteger() const;
		ConstantData GetConstantData() const;
		size_t GetIndex() const;
		uint32_t GetIntrinsic() const;
		MediumLevelILInstruction GetExpr() const;
		Variable GetVariable() const;
		SSAVariable GetSSAVariable() const;
		MediumLevelILIndexList GetIndexList() const;
		MediumLevelILIndexMap GetIndexMap() const;
		MediumLevelILVariableList GetVariableList() const;
		MediumLevelILSSAVariableList GetSSAVariableList() const;
		MediumLevelILInstructionList GetExprList() const;
		PossibleValueSet GetConstraint() const;
		BNForceVersionReason GetForceVersionReason() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILOperandList
	{
		struct ListIterator
		{
			typedef std::forward_iterator_tag iterator_category;
			typedef MediumLevelILOperand value_type;
			typedef std::ptrdiff_t difference_type;
			typedef void pointer;
			typedef value_type reference;

			const MediumLevelILOperandList* owner;
			size_t index;
			constexpr bool operator==(const ListIterator& a) const { return index == a.index; }
			constexpr auto operator<=>(const ListIterator& a) const { return index <=> a.index; }
			ListIterator& operator++()
			{
				++index;
				return *this;
			}
			const MediumLevelILOperand operator*();
		};

		MediumLevelILInstruction m_instr;
		const MediumLevelILOperandLocation* m_locations;
		uint8_t m_count;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILOperandList(
		    const MediumLevelILInstruction& instr, const MediumLevelILOperandLocation* locations, uint8_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const MediumLevelILOperand operator[](size_t i) const;

		operator _STD_VECTOR<MediumLevelILOperand>() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILConstantInstruction : public MediumLevelILInstructionBase
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(0); }
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILConstantDataInstruction : public MediumLevelILInstructionBase
	{
		ConstantData GetConstantData() const { return GetRawOperandAsConstantData(0); }
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILOneOperandInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILTwoOperandInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		MediumLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILTwoOperandWithCarryInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		MediumLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstruction GetCarryExpr() const { return GetRawOperandAsExpr(2); }
	};

	/*!
		\ingroup mediumlevelil
	*/
	struct MediumLevelILCallInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetOutputExprs() const { return GetRawOperandAsExprList(0); }
		_STD_VECTOR<Variable> GetOutputVariables() const;
	};

	/*!
	    \ingroup mediumlevelil
	*/
	struct MediumLevelILCallSSAInstruction : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetOutputExprs() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsExprList(1);
		}

		_STD_VECTOR<SSAVariable> GetOutputSSAVariables() const;

		void SetOutputExprs(const _STD_VECTOR<MediumLevelILInstruction>& outputs)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsExprList(1, outputs);
		}

		void SetOutputExprs(const _STD_VECTOR<ExprId>& outputs)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsExprList(1, outputs);
		}
	};

	// Implementations of each instruction to fetch the correct operand value for the valid operands, these
	// are derived from MediumLevelILInstructionBase so that invalid operand accessor functions will generate
	// a compiler error.
	// BEGIN GENERATED mlil-accessors: from api/il, do not edit
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NOP> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_FIELD> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_SPLIT> : public MediumLevelILInstructionBase
	{
		Variable GetHighVariable() const { return GetRawOperandAsVariable(0); }
		Variable GetLowVariable() const { return GetRawOperandAsVariable(1); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ASSERT> : public MediumLevelILInstructionBase
	{
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(0); }
		PossibleValueSet GetConstraint() const { return GetRawOperandAsPossibleValueSet(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FORCE_VER> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(1); }
		BNForceVersionReason GetForceVersionReason() const { return (BNForceVersionReason)GetRawOperandAsInteger(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOAD> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOAD_STRUCT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_STORE> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_STORE_STRUCT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR> : public MediumLevelILInstructionBase
	{
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_FIELD> : public MediumLevelILInstructionBase
	{
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_SPLIT> : public MediumLevelILInstructionBase
	{
		Variable GetHighVariable() const { return GetRawOperandAsVariable(0); }
		Variable GetLowVariable() const { return GetRawOperandAsVariable(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADDRESS_OF> : public MediumLevelILInstructionBase
	{
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADDRESS_OF_FIELD> : public MediumLevelILInstructionBase
	{
		Variable GetSourceVariable() const { return GetRawOperandAsVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_PASS_BY_REF> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RETURN_BY_REF> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST_DATA> : public MediumLevelILConstantDataInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST_PTR> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_EXTERN_PTR> : public MediumLevelILConstantInstruction
	{
		int64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FLOAT_CONST> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_IMPORT> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADD> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADC> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SUB> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SBB> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_AND> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_OR> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_XOR> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LSL> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LSR> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ASR> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ROL> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RLC> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ROR> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RRC> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MUL> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MULU_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MULS_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVU> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVU_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVS_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODU> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODU_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODS_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NEG> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NOT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SX> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ZX> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOW_PART> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_JUMP> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_JUMP_TO> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		MediumLevelILIndexMap GetTargets() const { return GetRawOperandAsIndexMap(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RET_HINT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL_UNTYPED> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(4); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SEPARATE_PARAM_LIST> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SHARED_PARAM_SLOT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT_FIELD> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_STORE_OUTPUT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RET> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetSourceExprs() const { return GetRawOperandAsExprList(0); }
		void SetSourceExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			UpdateRawOperandAsExprList(0, exprs);
		}
		void SetSourceExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(0, exprs); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NORET> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_IF> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetTrueTarget() const { return GetRawOperandAsIndex(1); }
		size_t GetFalseTarget() const { return GetRawOperandAsIndex(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_GOTO> : public MediumLevelILInstructionBase
	{
		size_t GetTarget() const { return GetRawOperandAsIndex(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_E> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_NE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_SLT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_ULT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_SLE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_ULE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_SGE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_UGE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_SGT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CMP_UGT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TEST_BIT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_BOOL_TO_INT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADD_OVERFLOW> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_UNTYPED> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_UNTYPED> : public MediumLevelILCallInstruction
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(4); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_INTRINSIC> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const { return GetRawOperandAsVariableList(0); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FREE_VAR_SLOT> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_BP> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TRAP> : public MediumLevelILInstructionBase
	{
		int64_t GetVector() const { return GetRawOperandAsInteger(0); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNDEF> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNIMPL> : public MediumLevelILInstructionBase
	{
		bool IsUnknown() const { return GetRawOperandAsInteger(0) != 0; }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNIMPL_MEM> : public MediumLevelILOneOperandInstruction
	{
		bool IsUnknown() const { return GetRawOperandAsInteger(1) != 0; }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FADD> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FSUB> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FMUL> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FDIV> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FSQRT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FNEG> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FABS> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FLOAT_TO_INT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_INT_TO_FLOAT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FLOAT_CONV> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ROUND_TO_INT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FLOOR> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CEIL> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FTRUNC> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_E> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_NE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_LT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_LE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_GE> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_GT> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_O> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FCMP_UO> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_SSA_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(3); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(4); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_SPLIT_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetHighSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetLowSSAVariable() const { return GetRawOperandAsSSAVariable(2); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(4); }
		void SetHighSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetLowSSAVersion(size_t version) { UpdateRawOperand(3, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_ALIASED> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SET_VAR_ALIASED_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(3); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(4); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_SSA_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(2); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_ALIASED> : public MediumLevelILInstructionBase
	{
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_ALIASED_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(2); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_SPLIT_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetHighSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetLowSSAVariable() const { return GetRawOperandAsSSAVariable(2); }
		void SetHighSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetLowSSAVersion(size_t version) { UpdateRawOperand(3, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ASSERT_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		PossibleValueSet GetConstraint() const { return GetRawOperandAsPossibleValueSet(2); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FORCE_VER_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsSSAVariable(2); }
		BNForceVersionReason GetForceVersionReason() const { return (BNForceVersionReason)GetRawOperandAsInteger(4); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(3, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			UpdateRawOperandAsExprList(2, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(2, exprs); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL_UNTYPED_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(0, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(1); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			UpdateRawOperandAsExprList(1, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(1, exprs); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(3, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_UNTYPED_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(1).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(1).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			GetRawOperandAsExpr(1).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			GetRawOperandAsExpr(1).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(1).UpdateRawOperand(0, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			UpdateRawOperandAsExprList(2, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(2, exprs); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_UNTYPED_SSA> : public MediumLevelILCallSSAInstruction
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& exprs)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, exprs);
		}
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(0, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT_SSA_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(3); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT_ALIASED> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_OUTPUT_ALIASED_FIELD> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(3); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOAD_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(1); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOAD_STRUCT_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(2); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_STORE_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(1); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(2); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_STORE_STRUCT_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(3); }
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(4); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(3, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_INTRINSIC_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILSSAVariableList GetOutputSSAVariables() const { return GetRawOperandAsSSAVariableList(0); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& values)
		{
			UpdateRawOperandAsSSAVariableList(0, values);
		}
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MEMORY_INTRINSIC_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& values)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, values);
		}
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FREE_VAR_SLOT_SSA> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		SSAVariable GetSourceSSAVariable() const { return GetRawOperandAsPartialSSAVariableSource(0); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(2, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_PHI> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		MediumLevelILSSAVariableList GetSourceSSAVariables() const { return GetRawOperandAsSSAVariableList(2); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MEM_PHI> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(0); }
		MediumLevelILIndexList GetSourceMemoryVersions() const { return GetRawOperandAsIndexList(1); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(0, version); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_BLOCK_TO_EXPAND> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetSourceExprs() const { return GetRawOperandAsExprList(0); }
		void SetSourceExprs(const _STD_VECTOR<MediumLevelILInstruction>& exprs)
		{
			UpdateRawOperandAsExprList(0, exprs);
		}
		void SetSourceExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(0, exprs); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_BSWAP> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_POPCNT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CLZ> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CTZ> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RBIT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CLS> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MINS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MAXS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MINU> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MAXU> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ABS> : public MediumLevelILOneOperandInstruction
	{};
	// END GENERATED mlil-accessors

#undef _STD_VECTOR
#undef _STD_SET
#undef _STD_UNORDERED_MAP
#undef _STD_MAP
}  // namespace BinaryNinjaCore

#ifdef BINARYNINJACORE_LIBRARY
#define IL_INS_NS BinaryNinjaCore
#else
#define IL_INS_NS BinaryNinja
#endif
template<> struct fmt::formatter<IL_INS_NS::MediumLevelILInstruction>
{
	// <empty> -> normal, ? -> debug
	char presentation = ' ';
	format_context::iterator format(const IL_INS_NS::MediumLevelILInstruction& obj, format_context& ctx) const;
	constexpr auto parse(format_parse_context& ctx) -> format_parse_context::iterator
	{
		auto it = ctx.begin(), end = ctx.end();
		if (it != end && *it == '?')
			presentation = *it++;
		if (it != end && *it != '}') report_error("invalid format");
		return it;
	}
};
#undef IL_INS_NS
