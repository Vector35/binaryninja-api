// Copyright (c) 2015-2019 Vector 35 Inc
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
#include "type.h"
#else
#include "binaryninjaapi.h"
#endif

#ifdef BINARYNINJACORE_LIBRARY
namespace BinaryNinjaCore
#else
namespace BinaryNinja
#endif
{
#ifdef BINARYNINJACORE_LIBRARY
	typedef size_t ExprId;
#endif

	class LowLevelILFunction;

	template <BNLowLevelILOperation N>
	struct LowLevelILInstructionAccessor {};

	struct LowLevelILInstruction;
	struct LowLevelILConstantInstruction;
	struct LowLevelILOneOperandInstruction;
	struct LowLevelILTwoOperandInstruction;
	struct LowLevelILTwoOperandWithCarryInstruction;
	struct LowLevelILLabel;
	struct MediumLevelILInstruction;
	class LowLevelILOperand;
	class LowLevelILOperandList;

	struct RegisterOrFlag
	{
		bool isFlag;
		uint32_t index;

		RegisterOrFlag();
		RegisterOrFlag(bool flag, uint32_t i);
		RegisterOrFlag(const RegisterOrFlag& v);

		bool IsRegister() const { return !isFlag; }
		bool IsFlag() const { return isFlag; }
		uint32_t GetRegister() const;
		uint32_t GetFlag() const;

		RegisterOrFlag& operator=(const RegisterOrFlag& v);
		bool operator==(const RegisterOrFlag& v) const;
		bool operator!=(const RegisterOrFlag& v) const;
		bool operator<(const RegisterOrFlag& v) const;

		uint64_t ToIdentifier() const;
		static RegisterOrFlag FromIdentifier(uint64_t id);

		static RegisterOrFlag Register(uint32_t reg) { return RegisterOrFlag(false, reg); }
		static RegisterOrFlag Flag(uint32_t flag) { return RegisterOrFlag(true, flag); }
	};

	struct SSARegister
	{
		uint32_t reg;
		size_t version;

		SSARegister();
		SSARegister(uint32_t r, size_t i);
		SSARegister(const SSARegister& v);

		SSARegister& operator=(const SSARegister& v);
		bool operator==(const SSARegister& v) const;
		bool operator!=(const SSARegister& v) const;
		bool operator<(const SSARegister& v) const;
	};

	struct SSARegisterStack
	{
		uint32_t regStack;
		size_t version;

		SSARegisterStack();
		SSARegisterStack(uint32_t r, size_t i);
		SSARegisterStack(const SSARegisterStack& v);

		SSARegisterStack& operator=(const SSARegisterStack& v);
		bool operator==(const SSARegisterStack& v) const;
		bool operator!=(const SSARegisterStack& v) const;
		bool operator<(const SSARegisterStack& v) const;
	};

	struct SSAFlag
	{
		uint32_t flag;
		size_t version;

		SSAFlag();
		SSAFlag(uint32_t f, size_t i);
		SSAFlag(const SSAFlag& v);

		SSAFlag& operator=(const SSAFlag& v);
		bool operator==(const SSAFlag& v) const;
		bool operator!=(const SSAFlag& v) const;
		bool operator<(const SSAFlag& v) const;
	};

	struct SSARegisterOrFlag
	{
		RegisterOrFlag regOrFlag;
		size_t version;

		SSARegisterOrFlag();
		SSARegisterOrFlag(const RegisterOrFlag& rf, size_t i);
		SSARegisterOrFlag(const SSARegister& v);
		SSARegisterOrFlag(const SSAFlag& v);
		SSARegisterOrFlag(const SSARegisterOrFlag& v);

		SSARegisterOrFlag& operator=(const SSARegisterOrFlag& v);
		bool operator==(const SSARegisterOrFlag& v) const;
		bool operator!=(const SSARegisterOrFlag& v) const;
		bool operator<(const SSARegisterOrFlag& v) const;
	};

	enum LowLevelILOperandType
	{
		IntegerLowLevelOperand,
		IndexLowLevelOperand,
		ExprLowLevelOperand,
		RegisterLowLevelOperand,
		RegisterStackLowLevelOperand,
		FlagLowLevelOperand,
		FlagConditionLowLevelOperand,
		IntrinsicLowLevelOperand,
		SemanticFlagClassLowLevelOperand,
		SemanticFlagGroupLowLevelOperand,
		SSARegisterLowLevelOperand,
		SSARegisterStackLowLevelOperand,
		SSAFlagLowLevelOperand,
		IndexListLowLevelOperand,
		IndexMapLowLevelOperand,
		ExprListLowLevelOperand,
		RegisterOrFlagListLowLevelOperand,
		SSARegisterListLowLevelOperand,
		SSARegisterStackListLowLevelOperand,
		SSAFlagListLowLevelOperand,
		SSARegisterOrFlagListLowLevelOperand,
		RegisterStackAdjustmentsLowLevelOperand
	};

	enum LowLevelILOperandUsage
	{
		SourceExprLowLevelOperandUsage,
		SourceRegisterLowLevelOperandUsage,
		SourceRegisterStackLowLevelOperandUsage,
		SourceFlagLowLevelOperandUsage,
		SourceSSARegisterLowLevelOperandUsage,
		SourceSSARegisterStackLowLevelOperandUsage,
		SourceSSAFlagLowLevelOperandUsage,
		DestExprLowLevelOperandUsage,
		DestRegisterLowLevelOperandUsage,
		DestRegisterStackLowLevelOperandUsage,
		DestFlagLowLevelOperandUsage,
		DestSSARegisterLowLevelOperandUsage,
		DestSSARegisterStackLowLevelOperandUsage,
		DestSSAFlagLowLevelOperandUsage,
		SemanticFlagClassLowLevelOperandUsage,
		SemanticFlagGroupLowLevelOperandUsage,
		PartialRegisterLowLevelOperandUsage,
		PartialSSARegisterStackSourceLowLevelOperandUsage,
		StackSSARegisterLowLevelOperandUsage,
		StackMemoryVersionLowLevelOperandUsage,
		TopSSARegisterLowLevelOperandUsage,
		LeftExprLowLevelOperandUsage,
		RightExprLowLevelOperandUsage,
		CarryExprLowLevelOperandUsage,
		ConditionExprLowLevelOperandUsage,
		HighRegisterLowLevelOperandUsage,
		HighSSARegisterLowLevelOperandUsage,
		LowRegisterLowLevelOperandUsage,
		LowSSARegisterLowLevelOperandUsage,
		IntrinsicLowLevelOperandUsage,
		ConstantLowLevelOperandUsage,
		VectorLowLevelOperandUsage,
		StackAdjustmentLowLevelOperandUsage,
		TargetLowLevelOperandUsage,
		TrueTargetLowLevelOperandUsage,
		FalseTargetLowLevelOperandUsage,
		BitIndexLowLevelOperandUsage,
		SourceMemoryVersionLowLevelOperandUsage,
		DestMemoryVersionLowLevelOperandUsage,
		FlagConditionLowLevelOperandUsage,
		OutputSSARegistersLowLevelOperandUsage,
		OutputMemoryVersionLowLevelOperandUsage,
		ParameterExprsLowLevelOperandUsage,
		SourceSSARegistersLowLevelOperandUsage,
		SourceSSARegisterStacksLowLevelOperandUsage,
		SourceSSAFlagsLowLevelOperandUsage,
		OutputRegisterOrFlagListLowLevelOperandUsage,
		OutputSSARegisterOrFlagListLowLevelOperandUsage,
		SourceMemoryVersionsLowLevelOperandUsage,
		TargetsLowLevelOperandUsage,
		RegisterStackAdjustmentsLowLevelOperandUsage,
		OffsetLowLevelOperandUsage
	};
}

namespace std
{
#ifdef BINARYNINJACORE_LIBRARY
	template<> struct hash<BinaryNinjaCore::SSARegister>
#else
	template<> struct hash<BinaryNinja::SSARegister>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::SSARegister argument_type;
#else
		typedef BinaryNinja::SSARegister argument_type;
#endif
		typedef uint32_t result_type;
		result_type operator()(argument_type const& value) const
		{
			return ((result_type)value.reg) ^ ((result_type)value.version << 16);
		}
	};

#ifdef BINARYNINJACORE_LIBRARY
	template<> struct hash<BinaryNinjaCore::SSARegisterStack>
#else
	template<> struct hash<BinaryNinja::SSARegisterStack>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::SSARegisterStack argument_type;
#else
		typedef BinaryNinja::SSARegisterStack argument_type;
#endif
		typedef uint64_t result_type;
		result_type operator()(argument_type const& value) const
		{
			return ((result_type)value.regStack) ^ ((result_type)value.version << 32);
		}
	};

#ifdef BINARYNINJACORE_LIBRARY
	template<> struct hash<BinaryNinjaCore::SSAFlag>
#else
	template<> struct hash<BinaryNinja::SSAFlag>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::SSAFlag argument_type;
#else
		typedef BinaryNinja::SSAFlag argument_type;
#endif
		typedef uint32_t result_type;
		result_type operator()(argument_type const& value) const
		{
			return ((result_type)value.flag) ^ ((result_type)value.version << 16);
		}
	};

	template<> struct hash<BNLowLevelILOperation>
	{
		typedef BNLowLevelILOperation argument_type;
		typedef int result_type;
		result_type operator()(argument_type const& value) const
		{
			return (result_type)value;
		}
	};

#ifdef BINARYNINJACORE_LIBRARY
	template<> struct hash<BinaryNinjaCore::LowLevelILOperandUsage>
#else
	template<> struct hash<BinaryNinja::LowLevelILOperandUsage>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::LowLevelILOperandUsage argument_type;
#else
		typedef BinaryNinja::LowLevelILOperandUsage argument_type;
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
	class LowLevelILInstructionAccessException: public std::exception
	{
	public:
		LowLevelILInstructionAccessException(): std::exception() {}
		virtual const char* what() const NOEXCEPT { return "invalid access to LLIL instruction"; }
	};

	class LowLevelILIntegerList
	{
		struct ListIterator
		{
#ifdef BINARYNINJACORE_LIBRARY
			LowLevelILFunction* function;
			const BNLowLevelILInstruction* instr;
#else
			Ref<LowLevelILFunction> function;
			BNLowLevelILInstruction instr;
#endif
			size_t operand, count;

			bool operator==(const ListIterator& a) const;
			bool operator!=(const ListIterator& a) const;
			bool operator<(const ListIterator& a) const;
			ListIterator& operator++();
			uint64_t operator*();
			LowLevelILFunction* GetFunction() const { return function; }
		};

		ListIterator m_start;

	public:
		typedef ListIterator const_iterator;

		LowLevelILIntegerList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		uint64_t operator[](size_t i) const;

		operator std::vector<uint64_t>() const;
	};

	class LowLevelILIndexList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			size_t operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILIndexList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		size_t operator[](size_t i) const;

		operator std::vector<size_t>() const;
	};

	class LowLevelILIndexMap
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const std::pair<uint64_t, size_t> operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILIndexMap(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		size_t operator[](uint64_t value) const;

		operator std::map<uint64_t, size_t>() const;
	};

	class LowLevelILInstructionList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			size_t instructionIndex;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			const LowLevelILInstruction operator*();
		};

		LowLevelILIntegerList m_list;
		size_t m_instructionIndex;

	public:
		typedef ListIterator const_iterator;

		LowLevelILInstructionList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr,
			size_t count, size_t instrIndex);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const LowLevelILInstruction operator[](size_t i) const;

		operator std::vector<LowLevelILInstruction>() const;
	};

	class LowLevelILRegisterOrFlagList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			const RegisterOrFlag operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILRegisterOrFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const RegisterOrFlag operator[](size_t i) const;

		operator std::vector<RegisterOrFlag>() const;
	};

	class LowLevelILSSARegisterList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const SSARegister operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegister operator[](size_t i) const;

		operator std::vector<SSARegister>() const;
	};

	class LowLevelILSSARegisterStackList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const SSARegisterStack operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterStackList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegisterStack operator[](size_t i) const;

		operator std::vector<SSARegisterStack>() const;
	};

	class LowLevelILSSAFlagList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const SSAFlag operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILSSAFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSAFlag operator[](size_t i) const;

		operator std::vector<SSAFlag>() const;
	};

	class LowLevelILSSARegisterOrFlagList
	{
		struct ListIterator
		{
			LowLevelILIntegerList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; ++pos; return *this; }
			const SSARegisterOrFlag operator*();
		};

		LowLevelILIntegerList m_list;

	public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterOrFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegisterOrFlag operator[](size_t i) const;

		operator std::vector<SSARegisterOrFlag>() const;
	};

	struct LowLevelILInstructionBase: public BNLowLevelILInstruction
	{
#ifdef BINARYNINJACORE_LIBRARY
		LowLevelILFunction* function;
#else
		Ref<LowLevelILFunction> function;
#endif
		size_t exprIndex, instructionIndex;

		static std::unordered_map<LowLevelILOperandUsage, LowLevelILOperandType> operandTypeForUsage;
		static std::unordered_map<BNLowLevelILOperation,
			std::vector<LowLevelILOperandUsage>> operationOperandUsage;
		static std::unordered_map<BNLowLevelILOperation,
			std::unordered_map<LowLevelILOperandUsage, size_t>> operationOperandIndex;

		LowLevelILOperandList GetOperands() const;

		uint64_t GetRawOperandAsInteger(size_t operand) const;
		uint32_t GetRawOperandAsRegister(size_t operand) const;
		size_t GetRawOperandAsIndex(size_t operand) const;
		BNLowLevelILFlagCondition GetRawOperandAsFlagCondition(size_t operand) const;
		LowLevelILInstruction GetRawOperandAsExpr(size_t operand) const;
		SSARegister GetRawOperandAsSSARegister(size_t operand) const;
		SSARegisterStack GetRawOperandAsSSARegisterStack(size_t operand) const;
		SSARegisterStack GetRawOperandAsPartialSSARegisterStackSource(size_t operand) const;
		SSAFlag GetRawOperandAsSSAFlag(size_t operand) const;
		LowLevelILIndexList GetRawOperandAsIndexList(size_t operand) const;
		LowLevelILIndexMap GetRawOperandAsIndexMap(size_t operand) const;
		LowLevelILInstructionList GetRawOperandAsExprList(size_t operand) const;
		LowLevelILRegisterOrFlagList GetRawOperandAsRegisterOrFlagList(size_t operand) const;
		LowLevelILSSARegisterList GetRawOperandAsSSARegisterList(size_t operand) const;
		LowLevelILSSARegisterStackList GetRawOperandAsSSARegisterStackList(size_t operand) const;
		LowLevelILSSAFlagList GetRawOperandAsSSAFlagList(size_t operand) const;
		LowLevelILSSARegisterOrFlagList GetRawOperandAsSSARegisterOrFlagList(size_t operand) const;
		std::map<uint32_t, int32_t> GetRawOperandAsRegisterStackAdjustments(size_t operand) const;

		void UpdateRawOperand(size_t operandIndex, ExprId value);
		void UpdateRawOperandAsSSARegisterList(size_t operandIndex, const std::vector<SSARegister>& regs);
		void UpdateRawOperandAsSSARegisterOrFlagList(size_t operandIndex, const std::vector<SSARegisterOrFlag>& outputs);

		RegisterValue GetValue() const;
		PossibleValueSet GetPossibleValues() const;

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

		size_t GetSSAInstructionIndex() const;
		size_t GetNonSSAInstructionIndex() const;
		size_t GetSSAExprIndex() const;
		size_t GetNonSSAExprIndex() const;

		LowLevelILInstruction GetSSAForm() const;
		LowLevelILInstruction GetNonSSAForm() const;

		size_t GetMediumLevelILInstructionIndex() const;
		size_t GetMediumLevelILExprIndex() const;
		size_t GetMappedMediumLevelILInstructionIndex() const;
		size_t GetMappedMediumLevelILExprIndex() const;

		bool HasMediumLevelIL() const;
		bool HasMappedMediumLevelIL() const;
		MediumLevelILInstruction GetMediumLevelIL() const;
		MediumLevelILInstruction GetMappedMediumLevelIL() const;

		void Replace(ExprId expr);

		template <BNLowLevelILOperation N>
		LowLevelILInstructionAccessor<N>& As()
		{
			if (operation != N)
				throw LowLevelILInstructionAccessException();
			return *(LowLevelILInstructionAccessor<N>*)this;
		}
		LowLevelILOneOperandInstruction& AsOneOperand()
		{
			return *(LowLevelILOneOperandInstruction*)this;
		}
		LowLevelILTwoOperandInstruction& AsTwoOperand()
		{
			return *(LowLevelILTwoOperandInstruction*)this;
		}
		LowLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry()
		{
			return *(LowLevelILTwoOperandWithCarryInstruction*)this;
		}

		template <BNLowLevelILOperation N>
		const LowLevelILInstructionAccessor<N>& As() const
		{
			if (operation != N)
				throw LowLevelILInstructionAccessException();
			return *(const LowLevelILInstructionAccessor<N>*)this;
		}
		const LowLevelILConstantInstruction& AsConstant() const
		{
			return *(const LowLevelILConstantInstruction*)this;
		}
		const LowLevelILOneOperandInstruction& AsOneOperand() const
		{
			return *(const LowLevelILOneOperandInstruction*)this;
		}
		const LowLevelILTwoOperandInstruction& AsTwoOperand() const
		{
			return *(const LowLevelILTwoOperandInstruction*)this;
		}
		const LowLevelILTwoOperandWithCarryInstruction& AsTwoOperandWithCarry() const
		{
			return *(const LowLevelILTwoOperandWithCarryInstruction*)this;
		}
	};

	struct LowLevelILInstruction: public LowLevelILInstructionBase
	{
		LowLevelILInstruction();
		LowLevelILInstruction(LowLevelILFunction* func, const BNLowLevelILInstruction& instr,
			size_t expr, size_t instrIdx);
		LowLevelILInstruction(const LowLevelILInstructionBase& instr);

		void VisitExprs(const std::function<bool(const LowLevelILInstruction& expr)>& func) const;

		ExprId CopyTo(LowLevelILFunction* dest) const;
		ExprId CopyTo(LowLevelILFunction* dest,
			const std::function<ExprId(const LowLevelILInstruction& subExpr)>& subExprHandler) const;

		// Templated accessors for instruction operands, use these for efficient access to a known instruction
		template <BNLowLevelILOperation N> LowLevelILInstruction GetSourceExpr() const { return As<N>().GetSourceExpr(); }
		template <BNLowLevelILOperation N> uint32_t GetSourceRegister() const { return As<N>().GetSourceRegister(); }
		template <BNLowLevelILOperation N> uint32_t GetSourceRegisterStack() const { return As<N>().GetSourceRegisterStack(); }
		template <BNLowLevelILOperation N> uint32_t GetSourceFlag() const { return As<N>().GetSourceFlag(); }
		template <BNLowLevelILOperation N> SSARegister GetSourceSSARegister() const { return As<N>().GetSourceSSARegister(); }
		template <BNLowLevelILOperation N> SSARegisterStack GetSourceSSARegisterStack() const { return As<N>().GetSourceSSARegisterStack(); }
		template <BNLowLevelILOperation N> SSAFlag GetSourceSSAFlag() const { return As<N>().GetSourceSSAFlag(); }
		template <BNLowLevelILOperation N> LowLevelILInstruction GetDestExpr() const { return As<N>().GetDestExpr(); }
		template <BNLowLevelILOperation N> uint32_t GetDestRegister() const { return As<N>().GetDestRegister(); }
		template <BNLowLevelILOperation N> uint32_t GetDestRegisterStack() const { return As<N>().GetDestRegisterStack(); }
		template <BNLowLevelILOperation N> uint32_t GetDestFlag() const { return As<N>().GetDestFlag(); }
		template <BNLowLevelILOperation N> SSARegister GetDestSSARegister() const { return As<N>().GetDestSSARegister(); }
		template <BNLowLevelILOperation N> SSARegisterStack GetDestSSARegisterStack() const { return As<N>().GetDestSSARegisterStack(); }
		template <BNLowLevelILOperation N> SSAFlag GetDestSSAFlag() const { return As<N>().GetDestSSAFlag(); }
		template <BNLowLevelILOperation N> uint32_t GetSemanticFlagClass() const { return As<N>().GetSemanticFlagClass(); }
		template <BNLowLevelILOperation N> uint32_t GetSemanticFlagGroup() const { return As<N>().GetSemanticFlagGroup(); }
		template <BNLowLevelILOperation N> uint32_t GetPartialRegister() const { return As<N>().GetPartialRegister(); }
		template <BNLowLevelILOperation N> SSARegister GetStackSSARegister() const { return As<N>().GetStackSSARegister(); }
		template <BNLowLevelILOperation N> SSARegister GetTopSSARegister() const { return As<N>().GetTopSSARegister(); }
		template <BNLowLevelILOperation N> LowLevelILInstruction GetLeftExpr() const { return As<N>().GetLeftExpr(); }
		template <BNLowLevelILOperation N> LowLevelILInstruction GetRightExpr() const { return As<N>().GetRightExpr(); }
		template <BNLowLevelILOperation N> LowLevelILInstruction GetCarryExpr() const { return As<N>().GetCarryExpr(); }
		template <BNLowLevelILOperation N> LowLevelILInstruction GetConditionExpr() const { return As<N>().GetConditionExpr(); }
		template <BNLowLevelILOperation N> uint32_t GetHighRegister() const { return As<N>().GetHighRegister(); }
		template <BNLowLevelILOperation N> SSARegister GetHighSSARegister() const { return As<N>().GetHighSSARegister(); }
		template <BNLowLevelILOperation N> uint32_t GetLowRegister() const { return As<N>().GetLowRegister(); }
		template <BNLowLevelILOperation N> SSARegister GetLowSSARegister() const { return As<N>().GetLowSSARegister(); }
		template <BNLowLevelILOperation N> uint32_t GetIntrinsic() const { return As<N>().GetIntrinsic(); }
		template <BNLowLevelILOperation N> int64_t GetConstant() const { return As<N>().GetConstant(); }
		template <BNLowLevelILOperation N> uint64_t GetOffset() const { return As<N>().GetOffset(); }
		template <BNLowLevelILOperation N> int64_t GetVector() const { return As<N>().GetVector(); }
		template <BNLowLevelILOperation N> int64_t GetStackAdjustment() const { return As<N>().GetStackAdjustment(); }
		template <BNLowLevelILOperation N> size_t GetTarget() const { return As<N>().GetTarget(); }
		template <BNLowLevelILOperation N> size_t GetTrueTarget() const { return As<N>().GetTrueTarget(); }
		template <BNLowLevelILOperation N> size_t GetFalseTarget() const { return As<N>().GetFalseTarget(); }
		template <BNLowLevelILOperation N> size_t GetBitIndex() const { return As<N>().GetBitIndex(); }
		template <BNLowLevelILOperation N> size_t GetSourceMemoryVersion() const { return As<N>().GetSourceMemoryVersion(); }
		template <BNLowLevelILOperation N> size_t GetDestMemoryVersion() const { return As<N>().GetDestMemoryVersion(); }
		template <BNLowLevelILOperation N> BNLowLevelILFlagCondition GetFlagCondition() const { return As<N>().GetFlagCondition(); }
		template <BNLowLevelILOperation N> LowLevelILSSARegisterList GetOutputSSARegisters() const { return As<N>().GetOutputSSARegisters(); }
		template <BNLowLevelILOperation N> LowLevelILInstructionList GetParameterExprs() const { return As<N>().GetParameterExprs(); }
		template <BNLowLevelILOperation N> LowLevelILSSARegisterList GetSourceSSARegisters() const { return As<N>().GetSourceSSARegisters(); }
		template <BNLowLevelILOperation N> LowLevelILSSARegisterStackList GetSourceSSARegisterStacks() const { return As<N>().GetSourceSSARegisterStacks(); }
		template <BNLowLevelILOperation N> LowLevelILSSAFlagList GetSourceSSAFlags() const { return As<N>().GetSourceSSAFlags(); }
		template <BNLowLevelILOperation N> LowLevelILRegisterOrFlagList GetOutputRegisterOrFlagList() const { return As<N>().GetOutputRegisterOrFlagList(); }
		template <BNLowLevelILOperation N> LowLevelILSSARegisterOrFlagList GetOutputSSARegisterOrFlagList() const { return As<N>().GetOutputSSARegisterOrFlagList(); }
		template <BNLowLevelILOperation N> LowLevelILIndexList GetSourceMemoryVersions() const { return As<N>().GetSourceMemoryVersions(); }
		template <BNLowLevelILOperation N> LowLevelILIndexMap GetTargets() const { return As<N>().GetTargets(); }
		template <BNLowLevelILOperation N> std::map<uint32_t, int32_t> GetRegisterStackAdjustments() const { return As<N>().GetRegisterStackAdjustments(); }

		template <BNLowLevelILOperation N> void SetDestSSAVersion(size_t version) { As<N>().SetDestSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetSourceSSAVersion(size_t version) { As<N>().SetSourceSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetHighSSAVersion(size_t version) { As<N>().SetHighSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetLowSSAVersion(size_t version) { As<N>().SetLowSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetStackSSAVersion(size_t version) { As<N>().SetStackSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetTopSSAVersion(size_t version) { As<N>().SetTopSSAVersion(version); }
		template <BNLowLevelILOperation N> void SetDestMemoryVersion(size_t version) { As<N>().SetDestMemoryVersion(version); }
		template <BNLowLevelILOperation N> void SetSourceMemoryVersion(size_t version) { As<N>().SetSourceMemoryVersion(version); }
		template <BNLowLevelILOperation N> void SetOutputSSARegisters(const std::vector<SSARegister>& regs) { As<N>().SetOutputSSARegisters(regs); }
		template <BNLowLevelILOperation N> void SetOutputSSARegisterOrFlagList(const std::vector<SSARegisterOrFlag>& outputs) { As<N>().SetOutputSSARegisterOrFlagList(outputs); }

		bool GetOperandIndexForUsage(LowLevelILOperandUsage usage, size_t& operandIndex) const;

		// Generic accessors for instruction operands, these will throw a LowLevelILInstructionAccessException
		// on type mismatch. These are slower than the templated versions above.
		LowLevelILInstruction GetSourceExpr() const;
		uint32_t GetSourceRegister() const;
		uint32_t GetSourceRegisterStack() const;
		uint32_t GetSourceFlag() const;
		SSARegister GetSourceSSARegister() const;
		SSARegisterStack GetSourceSSARegisterStack() const;
		SSAFlag GetSourceSSAFlag() const;
		LowLevelILInstruction GetDestExpr() const;
		uint32_t GetDestRegister() const;
		uint32_t GetDestRegisterStack() const;
		uint32_t GetDestFlag() const;
		SSARegister GetDestSSARegister() const;
		SSARegisterStack GetDestSSARegisterStack() const;
		SSAFlag GetDestSSAFlag() const;
		uint32_t GetSemanticFlagClass() const;
		uint32_t GetSemanticFlagGroup() const;
		uint32_t GetPartialRegister() const;
		SSARegister GetStackSSARegister() const;
		SSARegister GetTopSSARegister() const;
		LowLevelILInstruction GetLeftExpr() const;
		LowLevelILInstruction GetRightExpr() const;
		LowLevelILInstruction GetCarryExpr() const;
		LowLevelILInstruction GetConditionExpr() const;
		uint32_t GetHighRegister() const;
		SSARegister GetHighSSARegister() const;
		uint32_t GetLowRegister() const;
		SSARegister GetLowSSARegister() const;
		uint32_t GetIntrinsic() const;
		int64_t GetConstant() const;
		uint64_t GetOffset() const;
		int64_t GetVector() const;
		int64_t GetStackAdjustment() const;
		size_t GetTarget() const;
		size_t GetTrueTarget() const;
		size_t GetFalseTarget() const;
		size_t GetBitIndex() const;
		size_t GetSourceMemoryVersion() const;
		size_t GetDestMemoryVersion() const;
		BNLowLevelILFlagCondition GetFlagCondition() const;
		LowLevelILSSARegisterList GetOutputSSARegisters() const;
		LowLevelILInstructionList GetParameterExprs() const;
		LowLevelILSSARegisterList GetSourceSSARegisters() const;
		LowLevelILSSARegisterStackList GetSourceSSARegisterStacks() const;
		LowLevelILSSAFlagList GetSourceSSAFlags() const;
		LowLevelILRegisterOrFlagList GetOutputRegisterOrFlagList() const;
		LowLevelILSSARegisterOrFlagList GetOutputSSARegisterOrFlagList() const;
		LowLevelILIndexList GetSourceMemoryVersions() const;
		LowLevelILIndexMap GetTargets() const;
		std::map<uint32_t, int32_t> GetRegisterStackAdjustments() const;
	};

	class LowLevelILOperand
	{
		LowLevelILInstruction m_instr;
		LowLevelILOperandUsage m_usage;
		LowLevelILOperandType m_type;
		size_t m_operandIndex;

	public:
		LowLevelILOperand(const LowLevelILInstruction& instr, LowLevelILOperandUsage usage,
			size_t operandIndex);

		LowLevelILOperandType GetType() const { return m_type; }
		LowLevelILOperandUsage GetUsage() const { return m_usage; }

		uint64_t GetInteger() const;
		size_t GetIndex() const;
		LowLevelILInstruction GetExpr() const;
		uint32_t GetRegister() const;
		uint32_t GetRegisterStack() const;
		uint32_t GetFlag() const;
		uint32_t GetSemanticFlagClass() const;
		uint32_t GetSemanticFlagGroup() const;
		uint32_t GetIntrinsic() const;
		BNLowLevelILFlagCondition GetFlagCondition() const;
		SSARegister GetSSARegister() const;
		SSARegisterStack GetSSARegisterStack() const;
		SSAFlag GetSSAFlag() const;
		LowLevelILIndexList GetIndexList() const;
		LowLevelILIndexMap GetIndexMap() const;
		LowLevelILInstructionList GetExprList() const;
		LowLevelILSSARegisterList GetSSARegisterList() const;
		LowLevelILSSARegisterStackList GetSSARegisterStackList() const;
		LowLevelILSSAFlagList GetSSAFlagList() const;
		LowLevelILRegisterOrFlagList GetRegisterOrFlagList() const;
		LowLevelILSSARegisterOrFlagList GetSSARegisterOrFlagList() const;
		std::map<uint32_t, int32_t> GetRegisterStackAdjustments() const;
	};

	class LowLevelILOperandList
	{
		struct ListIterator
		{
			const LowLevelILOperandList* owner;
			std::vector<LowLevelILOperandUsage>::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++() { ++pos; return *this; }
			const LowLevelILOperand operator*();
		};

		LowLevelILInstruction m_instr;
		const std::vector<LowLevelILOperandUsage>& m_usageList;
		const std::unordered_map<LowLevelILOperandUsage, size_t>& m_operandIndexMap;

	public:
		typedef ListIterator const_iterator;

		LowLevelILOperandList(const LowLevelILInstruction& instr,
			const std::vector<LowLevelILOperandUsage>& usageList,
			const std::unordered_map<LowLevelILOperandUsage, size_t>& operandIndexMap);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const LowLevelILOperand operator[](size_t i) const;

		operator std::vector<LowLevelILOperand>() const;
	};

	struct LowLevelILConstantInstruction: public LowLevelILInstructionBase
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(0); }
	};

	struct LowLevelILOffsetInstruction: public LowLevelILInstructionBase
	{
		int64_t GetOffset() const { return GetRawOperandAsInteger(1); }
	};

	struct LowLevelILOneOperandInstruction: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
	};

	struct LowLevelILTwoOperandInstruction: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		LowLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
	};

	struct LowLevelILTwoOperandWithCarryInstruction: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(0); }
		LowLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(1); }
		LowLevelILInstruction GetCarryExpr() const { return GetRawOperandAsExpr(2); }
	};

	// Implementations of each instruction to fetch the correct operand value for the valid operands, these
	// are derived from LowLevelILInstructionBase so that invalid operand accessor functions will generate
	// a compiler error.
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG>: public LowLevelILInstructionBase
	{
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_SPLIT>: public LowLevelILInstructionBase
	{
		uint32_t GetHighRegister() const { return GetRawOperandAsRegister(0); }
		uint32_t GetLowRegister() const { return GetRawOperandAsRegister(1); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_SSA>: public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_SSA_PARTIAL>: public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(0); }
		uint32_t GetPartialRegister() const { return GetRawOperandAsRegister(2); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_SPLIT_SSA>: public LowLevelILInstructionBase
	{
		SSARegister GetHighSSARegister() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegister(0); }
		SSARegister GetLowSSARegister() const { return GetRawOperandAsExpr(1).GetRawOperandAsSSARegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		void SetHighSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(1, version); }
		void SetLowSSAVersion(size_t version) { GetRawOperandAsExpr(1).UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_REL>: public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_PUSH>: public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_REL_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterStack(0); }
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsPartialSSARegisterStackSource(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(2).GetRawOperandAsSSARegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(2, version); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_ABS_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterStack(0); }
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsPartialSSARegisterStackSource(0); }
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(1); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(2, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_FLAG>: public LowLevelILInstructionBase
	{
		uint32_t GetDestFlag() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SET_FLAG_SSA>: public LowLevelILInstructionBase
	{
		SSAFlag GetDestSSAFlag() const { return GetRawOperandAsSSAFlag(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_LOAD>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_LOAD_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(1); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_STORE>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_STORE_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(1); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(2); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(3); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(2, version); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_REG>: public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegister() const { return GetRawOperandAsRegister(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_SSA>: public LowLevelILInstructionBase
	{
		SSARegister GetSourceSSARegister() const { return GetRawOperandAsSSARegister(0); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_SSA_PARTIAL>: public LowLevelILInstructionBase
	{
		SSARegister GetSourceSSARegister() const { return GetRawOperandAsSSARegister(0); }
		uint32_t GetPartialRegister() const { return GetRawOperandAsRegister(2); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_REL>: public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegisterStack() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_POP>: public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegisterStack() const { return GetRawOperandAsRegister(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REG>: public LowLevelILInstructionBase
	{
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REL>: public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_REL_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(0); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(2); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(3).GetRawOperandAsSSARegister(0); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(3).UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_ABS_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(0); }
		uint32_t GetSourceRegister() const { return GetRawOperandAsRegister(2); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REL_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterStack(0); }
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsPartialSSARegisterStackSource(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(2).GetRawOperandAsSSARegister(0); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(2, version); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_ABS_SSA>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterStack(0); }
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsExpr(0).GetRawOperandAsPartialSSARegisterStackSource(0); }
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(1); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(1, version); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(2, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG>: public LowLevelILInstructionBase
	{
		uint32_t GetSourceFlag() const { return GetRawOperandAsRegister(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_BIT>: public LowLevelILInstructionBase
	{
		uint32_t GetSourceFlag() const { return GetRawOperandAsRegister(0); }
		size_t GetBitIndex() const { return GetRawOperandAsIndex(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_SSA>: public LowLevelILInstructionBase
	{
		SSAFlag GetSourceSSAFlag() const { return GetRawOperandAsSSAFlag(0); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_BIT_SSA>: public LowLevelILInstructionBase
	{
		SSAFlag GetSourceSSAFlag() const { return GetRawOperandAsSSAFlag(0); }
		size_t GetBitIndex() const { return GetRawOperandAsIndex(2); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(1, version); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_REG_SPLIT>: public LowLevelILInstructionBase
	{
		uint32_t GetHighRegister() const { return GetRawOperandAsRegister(0); }
		uint32_t GetLowRegister() const { return GetRawOperandAsRegister(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_SPLIT_SSA>: public LowLevelILInstructionBase
	{
		SSARegister GetHighSSARegister() const { return GetRawOperandAsSSARegister(0); }
		SSARegister GetLowSSARegister() const { return GetRawOperandAsSSARegister(2); }
		void SetHighSSAVersion(size_t version) { UpdateRawOperand(1, version); }
		void SetLowSSAVersion(size_t version) { UpdateRawOperand(3, version); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_JUMP>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_JUMP_TO>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		LowLevelILIndexMap GetTargets() const { return GetRawOperandAsIndexMap(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_CALL>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_CALL_STACK_ADJUST>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
		int64_t GetStackAdjustment() const { return GetRawOperandAsInteger(1); }
		std::map<uint32_t, int32_t> GetRegisterStackAdjustments() const { return GetRawOperandAsRegisterStackAdjustments(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_TAILCALL>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_RET>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(0); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_IF>: public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(0); }
		size_t GetTrueTarget() const { return GetRawOperandAsIndex(1); }
		size_t GetFalseTarget() const { return GetRawOperandAsIndex(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_GOTO>: public LowLevelILInstructionBase
	{
		size_t GetTarget() const { return GetRawOperandAsIndex(0); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_COND>: public LowLevelILInstructionBase
	{
		BNLowLevelILFlagCondition GetFlagCondition() const { return GetRawOperandAsFlagCondition(0); }
		uint32_t GetSemanticFlagClass() const { return GetRawOperandAsRegister(1); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_GROUP>: public LowLevelILInstructionBase
	{
		uint32_t GetSemanticFlagGroup() const { return GetRawOperandAsRegister(0); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_TRAP>: public LowLevelILInstructionBase
	{
		int64_t GetVector() const { return GetRawOperandAsInteger(0); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_CALL_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterList(1); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(2).GetRawOperandAsSSARegister(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(2); }
		LowLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(2, version); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(1, version); }
		void SetOutputSSARegisters(const std::vector<SSARegister>& regs) { GetRawOperandAsExpr(0).UpdateRawOperandAsSSARegisterList(1, regs); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_SYSCALL_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterList(1); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(1).GetRawOperandAsSSARegister(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(1).GetRawOperandAsIndex(2); }
		LowLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExpr(2).GetRawOperandAsExprList(0); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(1).UpdateRawOperand(2, version); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(1).UpdateRawOperand(1, version); }
		void SetOutputSSARegisters(const std::vector<SSARegister>& regs) { GetRawOperandAsExpr(0).UpdateRawOperandAsSSARegisterList(1, regs); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_TAILCALL_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const { return GetRawOperandAsExpr(0).GetRawOperandAsSSARegisterList(1); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(0).GetRawOperandAsIndex(0); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(1); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(2).GetRawOperandAsSSARegister(0); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(2).GetRawOperandAsIndex(2); }
		LowLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0); }
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(0).UpdateRawOperand(0, version); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(2, version); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(2).UpdateRawOperand(1, version); }
		void SetOutputSSARegisters(const std::vector<SSARegister>& regs) { GetRawOperandAsExpr(0).UpdateRawOperandAsSSARegisterList(1, regs); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_INTRINSIC>: public LowLevelILInstructionBase
	{
		LowLevelILRegisterOrFlagList GetOutputRegisterOrFlagList() const { return GetRawOperandAsRegisterOrFlagList(0); }
		uint32_t GetIntrinsic() const { return GetRawOperandAsRegister(2); }
		LowLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_INTRINSIC_SSA>: public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterOrFlagList GetOutputSSARegisterOrFlagList() const { return GetRawOperandAsSSARegisterOrFlagList(0); }
		uint32_t GetIntrinsic() const { return GetRawOperandAsRegister(2); }
		LowLevelILInstructionList GetParameterExprs() const { return GetRawOperandAsExpr(3).GetRawOperandAsExprList(0); }
		void SetOutputSSARegisterOrFlagList(const std::vector<SSARegisterOrFlag>& outputs) { UpdateRawOperandAsSSARegisterOrFlagList(0, outputs); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_REG_PHI>: public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(0); }
		LowLevelILSSARegisterList GetSourceSSARegisters() const { return GetRawOperandAsSSARegisterList(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_REG_STACK_PHI>: public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(0); }
		LowLevelILSSARegisterStackList GetSourceSSARegisterStacks() const { return GetRawOperandAsSSARegisterStackList(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLAG_PHI>: public LowLevelILInstructionBase
	{
		SSAFlag GetDestSSAFlag() const { return GetRawOperandAsSSAFlag(0); }
		LowLevelILSSAFlagList GetSourceSSAFlags() const { return GetRawOperandAsSSAFlagList(2); }
	};
	template <> struct LowLevelILInstructionAccessor<LLIL_MEM_PHI>: public LowLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(0); }
		LowLevelILIndexList GetSourceMemoryVersions() const { return GetRawOperandAsIndexList(1); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_EXTERN_PTR>: public LowLevelILConstantInstruction
	{
		size_t GetConstant() const { return GetRawOperandAsIndex(0); }
		size_t GetOffset() const { return GetRawOperandAsIndex(1); }
	};

	template <> struct LowLevelILInstructionAccessor<LLIL_NOP>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_POP>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_NORET>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_SYSCALL>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_BP>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_UNDEF>: public LowLevelILInstructionBase {};
	template <> struct LowLevelILInstructionAccessor<LLIL_UNIMPL>: public LowLevelILInstructionBase {};

	template <> struct LowLevelILInstructionAccessor<LLIL_CONST>: public LowLevelILConstantInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CONST_PTR>: public LowLevelILConstantInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLOAT_CONST>: public LowLevelILConstantInstruction {};

	template <> struct LowLevelILInstructionAccessor<LLIL_ADD>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_SUB>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_AND>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_OR>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_XOR>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_LSL>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_LSR>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ASR>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ROL>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ROR>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MUL>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MULU_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MULS_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_DIVU>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_DIVS>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MODU>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MODS>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_DIVU_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_DIVS_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MODU_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_MODS_DP>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_E>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_NE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_SLT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_ULT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_SLE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_ULE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_SGE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_UGE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_SGT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CMP_UGT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_TEST_BIT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ADD_OVERFLOW>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FADD>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FSUB>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FMUL>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FDIV>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_E>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_NE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_LT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_LE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_GE>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_GT>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_O>: public LowLevelILTwoOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FCMP_UO>: public LowLevelILTwoOperandInstruction {};

	template <> struct LowLevelILInstructionAccessor<LLIL_ADC>: public LowLevelILTwoOperandWithCarryInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_SBB>: public LowLevelILTwoOperandWithCarryInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_RLC>: public LowLevelILTwoOperandWithCarryInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_RRC>: public LowLevelILTwoOperandWithCarryInstruction {};

	template <> struct LowLevelILInstructionAccessor<LLIL_PUSH>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_NEG>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_NOT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_SX>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ZX>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_LOW_PART>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_BOOL_TO_INT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_UNIMPL_MEM>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FSQRT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FNEG>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FABS>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLOAT_TO_INT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_INT_TO_FLOAT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLOAT_CONV>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_ROUND_TO_INT>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FLOOR>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_CEIL>: public LowLevelILOneOperandInstruction {};
	template <> struct LowLevelILInstructionAccessor<LLIL_FTRUNC>: public LowLevelILOneOperandInstruction {};
}
