// Copyright (c) 2015-2024 Vector 35 Inc
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
	#include "constantdata.h"
	#include "variable.h"
#else
	#include "binaryninjaapi.h"
#endif

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
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
		size_t version;

		SSAVariable();
		SSAVariable(const Variable& v, size_t i);
		SSAVariable(const SSAVariable& v);

		SSAVariable& operator=(const SSAVariable& v);
		bool operator==(const SSAVariable& v) const;
		bool operator!=(const SSAVariable& v) const;
		bool operator<(const SSAVariable& v) const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	enum MediumLevelILOperandType
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
		ExprListMediumLevelOperand
	};

	/*!
		\ingroup mediumlevelil
	*/
	enum MediumLevelILOperandUsage
	{
		SourceExprMediumLevelOperandUsage,
		SourceVariableMediumLevelOperandUsage,
		SourceSSAVariableMediumLevelOperandUsage,
		PartialSSAVariableSourceMediumLevelOperandUsage,
		DestExprMediumLevelOperandUsage,
		DestVariableMediumLevelOperandUsage,
		DestSSAVariableMediumLevelOperandUsage,
		LeftExprMediumLevelOperandUsage,
		RightExprMediumLevelOperandUsage,
		CarryExprMediumLevelOperandUsage,
		StackExprMediumLevelOperandUsage,
		ConditionExprMediumLevelOperandUsage,
		HighVariableMediumLevelOperandUsage,
		LowVariableMediumLevelOperandUsage,
		HighSSAVariableMediumLevelOperandUsage,
		LowSSAVariableMediumLevelOperandUsage,
		OffsetMediumLevelOperandUsage,
		ConstantMediumLevelOperandUsage,
		ConstantDataMediumLevelOperandUsage,
		VectorMediumLevelOperandUsage,
		IntrinsicMediumLevelOperandUsage,
		TargetMediumLevelOperandUsage,
		TrueTargetMediumLevelOperandUsage,
		FalseTargetMediumLevelOperandUsage,
		DestMemoryVersionMediumLevelOperandUsage,
		SourceMemoryVersionMediumLevelOperandUsage,
		TargetsMediumLevelOperandUsage,
		SourceMemoryVersionsMediumLevelOperandUsage,
		OutputVariablesMediumLevelOperandUsage,
		OutputVariablesSubExprMediumLevelOperandUsage,
		OutputSSAVariablesMediumLevelOperandUsage,
		OutputSSAVariablesSubExprMediumLevelOperandUsage,
		OutputSSAMemoryVersionMediumLevelOperandUsage,
		ParameterExprsMediumLevelOperandUsage,
		SourceExprsMediumLevelOperandUsage,
		UntypedParameterExprsMediumLevelOperandUsage,
		UntypedParameterSSAExprsMediumLevelOperandUsage,
		ParameterSSAMemoryVersionMediumLevelOperandUsage,
		SourceSSAVariablesMediumLevelOperandUsages
	};
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
#ifdef BINARYNINJACORE_LIBRARY
			MediumLevelILFunction* function;
#else
			Ref<MediumLevelILFunction> function;
#endif
			BNMediumLevelILInstruction instr;
			size_t operand, count;

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

		MediumLevelILIntegerList(MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count);

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

		MediumLevelILIndexList(MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count);

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

		MediumLevelILIndexMap(MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count);

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

		MediumLevelILVariableList(MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count);

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
		    MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count);

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

		MediumLevelILInstructionList(MediumLevelILFunction* func, const BNMediumLevelILInstruction& instr, size_t count,
		    size_t instructionIndex);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const MediumLevelILInstruction operator[](size_t i) const;

		operator _STD_VECTOR<MediumLevelILInstruction>() const;
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

		static _STD_UNORDERED_MAP<MediumLevelILOperandUsage, MediumLevelILOperandType> operandTypeForUsage;
		static _STD_UNORDERED_MAP<BNMediumLevelILOperation, _STD_VECTOR<MediumLevelILOperandUsage>>
		    operationOperandUsage;
		static _STD_UNORDERED_MAP<BNMediumLevelILOperation, _STD_UNORDERED_MAP<MediumLevelILOperandUsage, size_t>>
		    operationOperandIndex;

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

		void VisitExprs(const std::function<bool(const MediumLevelILInstruction& expr)>& func) const;

		ExprId CopyTo(MediumLevelILFunction* dest) const;
		ExprId CopyTo(MediumLevelILFunction* dest,
		    const std::function<ExprId(const MediumLevelILInstruction& subExpr)>& subExprHandler) const;

		// Templated accessors for instruction operands, use these for efficient access to a known instruction
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetSourceExpr() const
		{
			return As<N>().GetSourceExpr();
		}
		template <BNMediumLevelILOperation N>
		Variable GetSourceVariable() const
		{
			return As<N>().GetSourceVariable();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetSourceSSAVariable() const
		{
			return As<N>().GetSourceSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetDestExpr() const
		{
			return As<N>().GetDestExpr();
		}
		template <BNMediumLevelILOperation N>
		Variable GetDestVariable() const
		{
			return As<N>().GetDestVariable();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetDestSSAVariable() const
		{
			return As<N>().GetDestSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetLeftExpr() const
		{
			return As<N>().GetLeftExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetRightExpr() const
		{
			return As<N>().GetRightExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetCarryExpr() const
		{
			return As<N>().GetCarryExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetStackExpr() const
		{
			return As<N>().GetStackExpr();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstruction GetConditionExpr() const
		{
			return As<N>().GetConditionExpr();
		}
		template <BNMediumLevelILOperation N>
		Variable GetHighVariable() const
		{
			return As<N>().GetHighVariable();
		}
		template <BNMediumLevelILOperation N>
		Variable GetLowVariable() const
		{
			return As<N>().GetLowVariable();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetHighSSAVariable() const
		{
			return As<N>().GetHighSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		SSAVariable GetLowSSAVariable() const
		{
			return As<N>().GetLowSSAVariable();
		}
		template <BNMediumLevelILOperation N>
		uint64_t GetOffset() const
		{
			return As<N>().GetOffset();
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
		int64_t GetVector() const
		{
			return As<N>().GetVector();
		}
		template <BNMediumLevelILOperation N>
		uint32_t GetIntrinsic() const
		{
			return As<N>().GetIntrinsic();
		}
		template <BNMediumLevelILOperation N>
		size_t GetTarget() const
		{
			return As<N>().GetTarget();
		}
		template <BNMediumLevelILOperation N>
		size_t GetTrueTarget() const
		{
			return As<N>().GetTrueTarget();
		}
		template <BNMediumLevelILOperation N>
		size_t GetFalseTarget() const
		{
			return As<N>().GetFalseTarget();
		}
		template <BNMediumLevelILOperation N>
		size_t GetDestMemoryVersion() const
		{
			return As<N>().GetDestMemoryVersion();
		}
		template <BNMediumLevelILOperation N>
		size_t GetSourceMemoryVersion() const
		{
			return As<N>().GetSourceMemoryVersion();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILIndexMap GetTargets() const
		{
			return As<N>().GetTargets();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILIndexList GetSourceMemoryVersions() const
		{
			return As<N>().GetSourceMemoryVersions();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILVariableList GetOutputVariables() const
		{
			return As<N>().GetOutputVariables();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return As<N>().GetOutputSSAVariables();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return As<N>().GetParameterExprs();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILInstructionList GetSourceExprs() const
		{
			return As<N>().GetSourceExprs();
		}
		template <BNMediumLevelILOperation N>
		MediumLevelILSSAVariableList GetSourceSSAVariables() const
		{
			return As<N>().GetSourceSSAVariables();
		}

		template <BNMediumLevelILOperation N>
		void SetDestSSAVersion(size_t version)
		{
			As<N>().SetDestSSAVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceSSAVersion(size_t version)
		{
			As<N>().SetSourceSSAVersion(version);
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
		void SetDestMemoryVersion(size_t version)
		{
			As<N>().SetDestMemoryVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceMemoryVersion(size_t version)
		{
			As<N>().SetSourceMemoryVersion(version);
		}
		template <BNMediumLevelILOperation N>
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			As<N>().SetOutputSSAVariables(vars);
		}
		template <BNMediumLevelILOperation N>
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			As<N>().SetParameterExprs(params);
		}
		template <BNMediumLevelILOperation N>
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params)
		{
			As<N>().SetParameterExprs(params);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			As<N>().SetSourceExprs(params);
		}
		template <BNMediumLevelILOperation N>
		void SetSourceExprs(const _STD_VECTOR<ExprId>& params)
		{
			As<N>().SetSourceExprs(params);
		}

		bool GetOperandIndexForUsage(MediumLevelILOperandUsage usage, size_t& operandIndex) const;

		// Generic accessors for instruction operands, these will throw a MediumLevelILInstructionAccessException
		// on type mismatch. These are slower than the templated versions above.
		MediumLevelILInstruction GetSourceExpr() const;
		Variable GetSourceVariable() const;
		SSAVariable GetSourceSSAVariable() const;
		MediumLevelILInstruction GetDestExpr() const;
		Variable GetDestVariable() const;
		SSAVariable GetDestSSAVariable() const;
		MediumLevelILInstruction GetLeftExpr() const;
		MediumLevelILInstruction GetRightExpr() const;
		MediumLevelILInstruction GetCarryExpr() const;
		MediumLevelILInstruction GetStackExpr() const;
		MediumLevelILInstruction GetConditionExpr() const;
		Variable GetHighVariable() const;
		Variable GetLowVariable() const;
		SSAVariable GetHighSSAVariable() const;
		SSAVariable GetLowSSAVariable() const;
		uint64_t GetOffset() const;
		int64_t GetConstant() const;
		ConstantData GetConstantData() const;
		int64_t GetVector() const;
		uint32_t GetIntrinsic() const;
		size_t GetTarget() const;
		size_t GetTrueTarget() const;
		size_t GetFalseTarget() const;
		size_t GetDestMemoryVersion() const;
		size_t GetSourceMemoryVersion() const;
		MediumLevelILIndexMap GetTargets() const;
		MediumLevelILIndexList GetSourceMemoryVersions() const;
		MediumLevelILVariableList GetOutputVariables() const;
		MediumLevelILSSAVariableList GetOutputSSAVariables() const;
		MediumLevelILInstructionList GetParameterExprs() const;
		MediumLevelILInstructionList GetSourceExprs() const;
		MediumLevelILSSAVariableList GetSourceSSAVariables() const;
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILOperand
	{
		MediumLevelILInstruction m_instr;
		MediumLevelILOperandUsage m_usage;
		MediumLevelILOperandType m_type;
		size_t m_operandIndex;

	  public:
		MediumLevelILOperand(
		    const MediumLevelILInstruction& instr, MediumLevelILOperandUsage usage, size_t operandIndex);

		MediumLevelILOperandType GetType() const { return m_type; }
		MediumLevelILOperandUsage GetUsage() const { return m_usage; }

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
	};

	/*!
		\ingroup mediumlevelil
	*/
	class MediumLevelILOperandList
	{
		struct ListIterator
		{
			const MediumLevelILOperandList* owner;
			_STD_VECTOR<MediumLevelILOperandUsage>::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const MediumLevelILOperand operator*();
		};

		MediumLevelILInstruction m_instr;
		const _STD_VECTOR<MediumLevelILOperandUsage>& m_usageList;
		const _STD_UNORDERED_MAP<MediumLevelILOperandUsage, size_t>& m_operandIndexMap;

	  public:
		typedef ListIterator const_iterator;

		MediumLevelILOperandList(const MediumLevelILInstruction& instr,
		    const _STD_VECTOR<MediumLevelILOperandUsage>& usageList,
		    const _STD_UNORDERED_MAP<MediumLevelILOperandUsage, size_t>& operandIndexMap);

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

	// Implementations of each instruction to fetch the correct operand value for the valid operands, these
	// are derived from MediumLevelILInstructionBase so that invalid operand accessor functions will generate
	// a compiler error.
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
	struct MediumLevelILInstructionAccessor<MLIL_LOAD> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_LOAD_STRUCT> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		uint64_t GetOffset() const { return GetRawOperandAsInteger(1); }
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
	struct MediumLevelILInstructionAccessor<MLIL_CALL> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const { return GetRawOperandAsVariableList(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL_UNTYPED> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsVariableList(0);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const { return GetRawOperandAsVariableList(0); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_UNTYPED> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsVariableList(0);
		}
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(1).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const { return GetRawOperandAsVariableList(0); }
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_UNTYPED> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsVariableList(0);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(0);
		}
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
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
	struct MediumLevelILInstructionAccessor<MLIL_CALL_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			UpdateRawOperandAsExprList(2, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params) { UpdateRawOperandAsExprList(2, params); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CALL_UNTYPED_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(0, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, params);
		}
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(1); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(3, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			UpdateRawOperandAsExprList(1, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params) { UpdateRawOperandAsExprList(1, params); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SYSCALL_UNTYPED_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(1).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(1).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(1).UpdateRawOperand(0, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			GetRawOperandAsExpr(1).UpdateRawOperandAsExprList(1, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params)
		{
			GetRawOperandAsExpr(1).UpdateRawOperandAsExprList(1, params);
		}
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			UpdateRawOperandAsExprList(2, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params) { UpdateRawOperandAsExprList(2, params); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_TAILCALL_UNTYPED_SSA> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		MediumLevelILSSAVariableList GetOutputSSAVariables() const
		{
			return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1);
		}
		MediumLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		MediumLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(2).GetRawOperandAsExprList(1);
		}
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(0); }
		MediumLevelILInstruction GetStackExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(0, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars)
		{
			GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars);
		}
		void SetParameterExprs(const _STD_VECTOR<MediumLevelILInstruction>& params)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, params);
		}
		void SetParameterExprs(const _STD_VECTOR<ExprId>& params)
		{
			GetRawOperandAsExpr(2).UpdateRawOperandAsExprList(1, params);
		}
	};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RET> : public MediumLevelILInstructionBase
	{
		MediumLevelILInstructionList GetSourceExprs() const { return GetRawOperandAsExprList(0); }
		void SetSourceExprs(const _STD_VECTOR<ExprId>& exprs) { UpdateRawOperandAsExprList(0, exprs); }
	};

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
	struct MediumLevelILInstructionAccessor<MLIL_INTRINSIC> : public MediumLevelILInstructionBase
	{
		MediumLevelILVariableList GetOutputVariables() const { return GetRawOperandAsVariableList(0); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_INTRINSIC_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILSSAVariableList GetOutputSSAVariables() const { return GetRawOperandAsSSAVariableList(0); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(2); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(3); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars) { UpdateRawOperandAsSSAVariableList(0, vars); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MEMORY_INTRINSIC_SSA> : public MediumLevelILInstructionBase
	{
		MediumLevelILSSAVariableList GetOutputSSAVariables() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSAVariableList(1); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(4); }
		uint32_t GetIntrinsic() const { return (uint32_t)GetRawOperandAsInteger(1); }
		MediumLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExprList(2); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(4, version); }
		void SetOutputSSAVariables(const _STD_VECTOR<SSAVariable>& vars) { GetRawOperandAsExpr(0).UpdateRawOperandAsSSAVariableList(1, vars); }
	};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FREE_VAR_SLOT> : public MediumLevelILInstructionBase
	{
		Variable GetDestVariable() const { return GetRawOperandAsVariable(0); }
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
	struct MediumLevelILInstructionAccessor<MLIL_TRAP> : public MediumLevelILInstructionBase
	{
		int64_t GetVector() const { return GetRawOperandAsInteger(0); }
	};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_VAR_PHI> : public MediumLevelILInstructionBase
	{
		SSAVariable GetDestSSAVariable() const { return GetRawOperandAsSSAVariable(0); }
		MediumLevelILSSAVariableList GetSourceSSAVariables() const { return GetRawOperandAsSSAVariableList(2); }
	};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MEM_PHI> : public MediumLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(0); }
		MediumLevelILIndexList GetSourceMemoryVersions() const { return GetRawOperandAsIndexList(1); }
	};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_EXTERN_PTR> : public MediumLevelILConstantInstruction
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(0); }
		int64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NOP> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_NORET> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_BP> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNDEF> : public MediumLevelILInstructionBase
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNIMPL> : public MediumLevelILInstructionBase
	{};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST_PTR> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_FLOAT_CONST> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_IMPORT> : public MediumLevelILConstantInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_CONST_DATA> : public MediumLevelILConstantDataInstruction
	{};

	template <>
	struct MediumLevelILInstructionAccessor<MLIL_ADD> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SUB> : public MediumLevelILTwoOperandInstruction
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
	struct MediumLevelILInstructionAccessor<MLIL_ROR> : public MediumLevelILTwoOperandInstruction
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
	struct MediumLevelILInstructionAccessor<MLIL_DIVS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODU> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODS> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVU_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_DIVS_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODU_DP> : public MediumLevelILTwoOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_MODS_DP> : public MediumLevelILTwoOperandInstruction
	{};
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
	struct MediumLevelILInstructionAccessor<MLIL_ADD_OVERFLOW> : public MediumLevelILTwoOperandInstruction
	{};
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
	struct MediumLevelILInstructionAccessor<MLIL_ADC> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_SBB> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RLC> : public MediumLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_RRC> : public MediumLevelILTwoOperandWithCarryInstruction
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
	struct MediumLevelILInstructionAccessor<MLIL_BOOL_TO_INT> : public MediumLevelILOneOperandInstruction
	{};
	template <>
	struct MediumLevelILInstructionAccessor<MLIL_UNIMPL_MEM> : public MediumLevelILOneOperandInstruction
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
