// Copyright (c) 2015-2023 Vector 35 Inc
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

#define BN_USE_EXPLICIT_ID_CASTS
#ifdef BN_USE_EXPLICIT_ID_CASTS
#define BN_ID_CAST_EXPLICIT explicit
#else
#define BN_ID_CAST_EXPLICIT
#endif

	class LLILExprId
	{
		BNLowLevelILExpressionId inner;
	public:
		LLILExprId() { inner.id = BN_INVALID_EXPR; }
		LLILExprId(BNLowLevelILExpressionId inner) { this->inner = inner; }
		operator BNLowLevelILExpressionId() { return inner; }

		static LLILExprId Invalid() { return LLILExprId(BN_INVALID_EXPR); }
		bool IsValid() const { return inner.id != BN_INVALID_EXPR; }

		BN_ID_CAST_EXPLICIT LLILExprId(size_t id) { inner.id = id; }
		BN_ID_CAST_EXPLICIT operator size_t() const { return inner.id; }

		bool operator<(const LLILExprId& other) const { return inner.id < other.inner.id; }
		bool operator==(const LLILExprId& other) const { return inner.id == other.inner.id; }
	};

	typedef LLILExprId LLILSSAExprId;
	typedef LLILExprId LLILNonSSAExprId;

	class LLILInstrId
	{
		BNLowLevelILInstructionId inner;
	public:
		LLILInstrId() { inner.id = BN_INVALID_EXPR; }
		LLILInstrId(BNLowLevelILInstructionId inner) { this->inner = inner; }
		operator BNLowLevelILInstructionId() { return inner; }

		static LLILInstrId Invalid() { return LLILInstrId(BN_INVALID_EXPR); }
		bool IsValid() const { return inner.id != BN_INVALID_EXPR; }

		BN_ID_CAST_EXPLICIT LLILInstrId(size_t id) { inner.id = id; }
		BN_ID_CAST_EXPLICIT operator size_t() const { return inner.id; }

		bool operator<(const LLILInstrId& other) const { return inner.id < other.inner.id; }
		bool operator==(const LLILInstrId& other) const { return inner.id == other.inner.id; }
	};

	typedef LLILInstrId LLILSSAInstrId;
	typedef LLILInstrId LLILNonSSAInstrId;

	class LLILOperandIndex
	{
		BNLowLevelILOperandIndex inner;
	public:
		LLILOperandIndex() { inner.index = BN_INVALID_OPERAND; }
		LLILOperandIndex(BNLowLevelILOperandIndex inner) { this->inner = inner; }
		operator BNLowLevelILOperandIndex() { return inner; }

		static LLILOperandIndex Invalid() { return LLILOperandIndex(BN_INVALID_OPERAND); }
		bool IsValid() const { return inner.index != BN_INVALID_OPERAND; }

		BN_ID_CAST_EXPLICIT LLILOperandIndex(size_t index) { inner.index = index; }
		BN_ID_CAST_EXPLICIT operator size_t() const { return inner.index; }

		bool operator<(const LLILOperandIndex& other) const { return inner.index < other.inner.index; }
		bool operator==(const LLILOperandIndex& other) const { return inner.index == other.inner.index; }
	};

	class LLILLabelIndex
	{
		BNLowLevelILLabelIndex inner;
	public:
		LLILLabelIndex() { inner.index = BN_INVALID_EXPR; }
		LLILLabelIndex(BNLowLevelILLabelIndex inner) { this->inner = inner; }
		operator BNLowLevelILLabelIndex() { return inner; }

		static LLILLabelIndex Invalid() { return LLILLabelIndex(BN_INVALID_EXPR); }
		bool IsValid() const { return inner.index != BN_INVALID_EXPR; }

		BN_ID_CAST_EXPLICIT LLILLabelIndex(size_t index) { inner.index = index; }
		BN_ID_CAST_EXPLICIT operator size_t() const { return inner.index; }

		bool operator<(const LLILLabelIndex& other) const { return inner.index < other.inner.index; }
		bool operator==(const LLILLabelIndex& other) const { return inner.index == other.inner.index; }
	};

	class LLILConstantInt
	{
		BNLowLevelILConstantInt inner;
	public:
		LLILConstantInt(BNLowLevelILConstantInt inner) { this->inner = inner; }
		operator BNLowLevelILConstantInt() { return inner; }

		BN_ID_CAST_EXPLICIT LLILConstantInt(uint64_t value) { inner.value = value; }
		BN_ID_CAST_EXPLICIT operator uint64_t() const { return inner.value; }

		bool operator<(const LLILConstantInt& other) const { return inner.value < other.inner.value; }
		bool operator==(const LLILConstantInt& other) const { return inner.value == other.inner.value; }
	};

	class LowLevelILFunction;

	template <BNLowLevelILOperation N>
	struct LowLevelILInstructionAccessor
	{};

	struct LowLevelILInstruction;
	struct LowLevelILConstantInstruction;
	struct LowLevelILOneOperandInstruction;
	struct LowLevelILTwoOperandInstruction;
	struct LowLevelILTwoOperandWithCarryInstruction;
	struct LowLevelILLabel;
	struct MediumLevelILInstruction;
	class LowLevelILOperand;
	class LowLevelILOperandList;

	/*!
		\ingroup lowlevelil
	*/
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

	/*!
		\ingroup lowlevelil
	*/
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

	/*!
		\ingroup lowlevelil
	*/
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

	/*!
		\ingroup lowlevelil
	*/
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

	/*!
		\ingroup lowlevelil
	*/
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

	class LLILRawOperand
	{
		BNLowLevelILOperand inner;
	public:
		LLILRawOperand() { this->inner.integer = 0; }
		LLILRawOperand(BNLowLevelILOperand inner) { this->inner = inner; }
		operator BNLowLevelILOperand() { return inner; }

		static LLILRawOperand FromInteger(uint64_t integer)
		{
			LLILRawOperand op;
			op.inner.integer = integer;
			return op;
		}
		static LLILRawOperand FromIndex(size_t index)
		{
			LLILRawOperand op;
			op.inner.index = index;
			return op;
		}
		static LLILRawOperand FromFlagCondition(BNLowLevelILFlagCondition flagCondition)
		{
			LLILRawOperand op;
			op.inner.flagCondition = flagCondition;
			return op;
		}
		static LLILRawOperand FromExprId(LLILExprId exprId)
		{
			LLILRawOperand op;
			op.inner.exprId = exprId;
			return op;
		}
		static LLILRawOperand FromConstant(LLILConstantInt constant)
		{
			LLILRawOperand op;
			op.inner.constant = constant;
			return op;
		}
		static LLILRawOperand FromRegister(uint32_t reg)
		{
			LLILRawOperand op;
			op.inner.reg = reg;
			return op;
		}
		static LLILRawOperand FromRegisterStack(uint32_t regStack)
		{
			LLILRawOperand op;
			op.inner.regStack = regStack;
			return op;
		}
		static LLILRawOperand FromFlag(uint32_t flag)
		{
			LLILRawOperand op;
			op.inner.flag = flag;
			return op;
		}
		static LLILRawOperand FromRegisterOrFlag(RegisterOrFlag registerOrFlag)
		{
			LLILRawOperand op;
			op.inner.registerOrFlag = registerOrFlag.ToIdentifier();
			return op;
		}
		static LLILRawOperand FromVersion(size_t version)
		{
			LLILRawOperand op;
			op.inner.version = version;
			return op;
		}
		static LLILRawOperand FromCount(size_t count)
		{
			LLILRawOperand op;
			op.inner.count = count;
			return op;
		}
		static LLILRawOperand FromAdjustment(int32_t adjustment)
		{
			LLILRawOperand op;
			op.inner.adjustment = adjustment;
			return op;
		}

		uint64_t GetInteger() const { return inner.integer; }
		size_t GetIndex() const { return inner.index; }
		BNLowLevelILFlagCondition GetFlagCondition() const { return inner.flagCondition; }
		LLILExprId GetExprId() const { return inner.exprId; }
		LLILConstantInt GetConstant() const { return inner.constant; }
		uint32_t GetRegister() const { return inner.reg; }
		uint32_t GetRegisterStack() const { return inner.regStack; }
		uint32_t GetFlag() const { return inner.flag; }
		RegisterOrFlag GetRegisterOrFlag() const { return RegisterOrFlag::FromIdentifier(inner.registerOrFlag); }
		size_t GetVersion() const { return inner.version; }
		size_t GetCount() const { return inner.count; }
		int32_t GetAdjustment() const { return inner.adjustment; }
		LLILLabelIndex GetLabelIndex() const { return inner.labelIndex; }
	};

	/*!
		\ingroup lowlevelil
	*/
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

	/*!
		\ingroup lowlevelil
	*/
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
}  // namespace BinaryNinjaCore

namespace std {
#ifdef BINARYNINJACORE_LIBRARY
	template <>
	struct hash<BinaryNinjaCore::SSARegister>
#else
	template <>
	struct hash<BinaryNinja::SSARegister>
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
	template <>
	struct hash<BinaryNinjaCore::SSARegisterStack>
#else
	template <>
	struct hash<BinaryNinja::SSARegisterStack>
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
	template <>
	struct hash<BinaryNinjaCore::SSAFlag>
#else
	template <>
	struct hash<BinaryNinja::SSAFlag>
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

	template <>
	struct hash<BNLowLevelILOperation>
	{
		typedef BNLowLevelILOperation argument_type;
		typedef int result_type;
		result_type operator()(argument_type const& value) const { return (result_type)value; }
	};

#ifdef BINARYNINJACORE_LIBRARY
	template <>
	struct hash<BinaryNinjaCore::LowLevelILOperandUsage>
#else
	template <>
	struct hash<BinaryNinja::LowLevelILOperandUsage>
#endif
	{
#ifdef BINARYNINJACORE_LIBRARY
		typedef BinaryNinjaCore::LowLevelILOperandUsage argument_type;
#else
		typedef BinaryNinja::LowLevelILOperandUsage argument_type;
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
		\ingroup lowlevelil
	*/
	class LowLevelILInstructionAccessException : public std::exception
	{
	  public:
		LowLevelILInstructionAccessException() : std::exception() {}
		virtual const char* what() const NOEXCEPT { return "invalid access to LLIL instruction"; }
	};

	struct OperandIterator
	{
#ifdef BINARYNINJACORE_LIBRARY
		LowLevelILFunction* function;
		const BNLowLevelILInstruction* instr;
#else
		Ref<LowLevelILFunction> function;
		BNLowLevelILInstruction instr;
#endif
		size_t operand, count;

		bool operator==(const OperandIterator& a) const;
		bool operator!=(const OperandIterator& a) const;
		bool operator<(const OperandIterator& a) const;
		OperandIterator& operator++();
		LLILRawOperand operator*();
		LowLevelILFunction* GetFunction() const { return function; }
	};

	/*!
		\ingroup lowlevelil
	*/
	class OperandList
	{
		typedef OperandIterator ListIterator;
		ListIterator m_start;

	  public:
		typedef ListIterator const_iterator;

		OperandList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		LLILRawOperand operator[](size_t i) const;

		operator _STD_VECTOR<LLILRawOperand>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILIntegerList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			LLILConstantInt operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILIntegerList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		LLILConstantInt operator[](size_t i) const;

		operator _STD_VECTOR<LLILConstantInt>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILIndexList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
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

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILIndexList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		size_t operator[](size_t i) const;

		operator _STD_VECTOR<size_t>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILIndexMap
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const std::pair<uint64_t, LLILLabelIndex> operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILIndexMap(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		LLILLabelIndex operator[](uint64_t value) const;

		operator _STD_MAP<uint64_t, LLILLabelIndex>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILInstructionList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			LLILInstrId instructionIndex;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const LowLevelILInstruction operator*();
		};

		OperandList m_list;
		LLILInstrId m_instructionIndex;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILInstructionList(
		    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count, LLILInstrId instrIndex);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const LowLevelILInstruction operator[](size_t i) const;

		operator _STD_VECTOR<LowLevelILInstruction>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILRegisterOrFlagList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const RegisterOrFlag operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILRegisterOrFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const RegisterOrFlag operator[](size_t i) const;

		operator _STD_VECTOR<RegisterOrFlag>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILSSARegisterList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const SSARegister operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegister operator[](size_t i) const;

		operator _STD_VECTOR<SSARegister>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILSSARegisterStackList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const SSARegisterStack operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterStackList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegisterStack operator[](size_t i) const;

		operator _STD_VECTOR<SSARegisterStack>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILSSAFlagList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const SSAFlag operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILSSAFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSAFlag operator[](size_t i) const;

		operator _STD_VECTOR<SSAFlag>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILSSARegisterOrFlagList
	{
		struct ListIterator
		{
			OperandList::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				++pos;
				return *this;
			}
			const SSARegisterOrFlag operator*();
		};

		OperandList m_list;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILSSARegisterOrFlagList(LowLevelILFunction* func, const BNLowLevelILInstruction& instr, size_t count);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const SSARegisterOrFlag operator[](size_t i) const;

		operator _STD_VECTOR<SSARegisterOrFlag>() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	struct LowLevelILInstructionBase : public BNLowLevelILInstruction
	{
#ifdef BINARYNINJACORE_LIBRARY
		LowLevelILFunction* function;
#else
		Ref<LowLevelILFunction> function;
#endif
		LLILExprId exprIndex;
		LLILInstrId instructionIndex;

		static _STD_UNORDERED_MAP<LowLevelILOperandUsage, LowLevelILOperandType> operandTypeForUsage;
		static _STD_UNORDERED_MAP<BNLowLevelILOperation, _STD_VECTOR<LowLevelILOperandUsage>> operationOperandUsage;
		static _STD_UNORDERED_MAP<BNLowLevelILOperation, _STD_UNORDERED_MAP<LowLevelILOperandUsage, LLILOperandIndex>>
		    operationOperandIndex;

		LowLevelILOperandList GetOperands() const;

		LLILRawOperand GetRawOperand(LLILOperandIndex operand) const;
		uint64_t GetRawOperandAsInteger(LLILOperandIndex operand) const;
		uint32_t GetRawOperandAsRegister(LLILOperandIndex operand) const;
		size_t GetRawOperandAsIndex(LLILOperandIndex operand) const;
		LLILLabelIndex GetRawOperandAsLabelIndex(LLILOperandIndex operand) const;
		BNLowLevelILFlagCondition GetRawOperandAsFlagCondition(LLILOperandIndex operand) const;
		LowLevelILInstruction GetRawOperandAsExpr(LLILOperandIndex operand) const;
		SSARegister GetRawOperandAsSSARegister(LLILOperandIndex operand) const;
		SSARegisterStack GetRawOperandAsSSARegisterStack(LLILOperandIndex operand) const;
		SSARegisterStack GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex operand) const;
		SSAFlag GetRawOperandAsSSAFlag(LLILOperandIndex operand) const;
		LowLevelILIndexList GetRawOperandAsIndexList(LLILOperandIndex operand) const;
		LowLevelILIndexMap GetRawOperandAsIndexMap(LLILOperandIndex operand) const;
		LowLevelILInstructionList GetRawOperandAsExprList(LLILOperandIndex operand) const;
		LowLevelILRegisterOrFlagList GetRawOperandAsRegisterOrFlagList(LLILOperandIndex operand) const;
		LowLevelILSSARegisterList GetRawOperandAsSSARegisterList(LLILOperandIndex operand) const;
		LowLevelILSSARegisterStackList GetRawOperandAsSSARegisterStackList(LLILOperandIndex operand) const;
		LowLevelILSSAFlagList GetRawOperandAsSSAFlagList(LLILOperandIndex operand) const;
		LowLevelILSSARegisterOrFlagList GetRawOperandAsSSARegisterOrFlagList(LLILOperandIndex operand) const;
		_STD_MAP<uint32_t, int32_t> GetRawOperandAsRegisterStackAdjustments(LLILOperandIndex operand) const;

		void UpdateRawOperand(LLILOperandIndex operandIndex, LLILRawOperand value);
		void UpdateRawOperandAsSSARegisterList(LLILOperandIndex operandIndex, const _STD_VECTOR<SSARegister>& regs);
		void UpdateRawOperandAsSSARegisterOrFlagList(
		    LLILOperandIndex operandIndex, const _STD_VECTOR<SSARegisterOrFlag>& outputs);

		RegisterValue GetValue() const;
		PossibleValueSet GetPossibleValues(
		    const _STD_SET<BNDataFlowQueryOption>& options = _STD_SET<BNDataFlowQueryOption>()) const;

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

		LLILInstrId GetSSAInstructionIndex() const;
		LLILInstrId GetNonSSAInstructionIndex() const;
		LLILExprId GetSSAExprIndex() const;
		LLILExprId GetNonSSAExprIndex() const;

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

		// Return (and leak) a string describing the instruction for debugger use
		char* Dump() const;

		void Replace(LLILExprId expr);
		void SetAttributes(uint32_t attributes);
		void SetAttribute(BNILInstructionAttribute attribute, bool state = true);
		void ClearAttribute(BNILInstructionAttribute attribute);

		template <BNLowLevelILOperation N>
		LowLevelILInstructionAccessor<N>& As()
		{
			if (operation != N)
				throw LowLevelILInstructionAccessException();
			return *(LowLevelILInstructionAccessor<N>*)this;
		}
		LowLevelILOneOperandInstruction& AsOneOperand() { return *(LowLevelILOneOperandInstruction*)this; }
		LowLevelILTwoOperandInstruction& AsTwoOperand() { return *(LowLevelILTwoOperandInstruction*)this; }
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
		const LowLevelILConstantInstruction& AsConstant() const { return *(const LowLevelILConstantInstruction*)this; }
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

	/*!
		\ingroup lowlevelil
	*/
	struct LowLevelILInstruction : public LowLevelILInstructionBase
	{
		LowLevelILInstruction();
		LowLevelILInstruction(
		    LowLevelILFunction* func, const BNLowLevelILInstruction& instr, LLILExprId expr, LLILInstrId instrIdx);
		LowLevelILInstruction(const LowLevelILInstructionBase& instr);

		void VisitExprs(const std::function<bool(const LowLevelILInstruction& expr)>& func) const;

		LLILExprId CopyTo(LowLevelILFunction* dest) const;
		LLILExprId CopyTo(LowLevelILFunction* dest,
		    const std::function<LLILExprId(const LowLevelILInstruction& subExpr)>& subExprHandler) const;

		// Templated accessors for instruction operands, use these for efficient access to a known instruction
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetSourceExpr() const
		{
			return As<N>().GetSourceExpr();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetSourceRegister() const
		{
			return As<N>().GetSourceRegister();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetSourceRegisterStack() const
		{
			return As<N>().GetSourceRegisterStack();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetSourceFlag() const
		{
			return As<N>().GetSourceFlag();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetSourceSSARegister() const
		{
			return As<N>().GetSourceSSARegister();
		}
		template <BNLowLevelILOperation N>
		SSARegisterStack GetSourceSSARegisterStack() const
		{
			return As<N>().GetSourceSSARegisterStack();
		}
		template <BNLowLevelILOperation N>
		SSAFlag GetSourceSSAFlag() const
		{
			return As<N>().GetSourceSSAFlag();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetDestExpr() const
		{
			return As<N>().GetDestExpr();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetDestRegister() const
		{
			return As<N>().GetDestRegister();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetDestRegisterStack() const
		{
			return As<N>().GetDestRegisterStack();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetDestFlag() const
		{
			return As<N>().GetDestFlag();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetDestSSARegister() const
		{
			return As<N>().GetDestSSARegister();
		}
		template <BNLowLevelILOperation N>
		SSARegisterStack GetDestSSARegisterStack() const
		{
			return As<N>().GetDestSSARegisterStack();
		}
		template <BNLowLevelILOperation N>
		SSAFlag GetDestSSAFlag() const
		{
			return As<N>().GetDestSSAFlag();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetSemanticFlagClass() const
		{
			return As<N>().GetSemanticFlagClass();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetSemanticFlagGroup() const
		{
			return As<N>().GetSemanticFlagGroup();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetPartialRegister() const
		{
			return As<N>().GetPartialRegister();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetStackSSARegister() const
		{
			return As<N>().GetStackSSARegister();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetTopSSARegister() const
		{
			return As<N>().GetTopSSARegister();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetLeftExpr() const
		{
			return As<N>().GetLeftExpr();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetRightExpr() const
		{
			return As<N>().GetRightExpr();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetCarryExpr() const
		{
			return As<N>().GetCarryExpr();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstruction GetConditionExpr() const
		{
			return As<N>().GetConditionExpr();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetHighRegister() const
		{
			return As<N>().GetHighRegister();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetHighSSARegister() const
		{
			return As<N>().GetHighSSARegister();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetLowRegister() const
		{
			return As<N>().GetLowRegister();
		}
		template <BNLowLevelILOperation N>
		SSARegister GetLowSSARegister() const
		{
			return As<N>().GetLowSSARegister();
		}
		template <BNLowLevelILOperation N>
		uint32_t GetIntrinsic() const
		{
			return As<N>().GetIntrinsic();
		}
		template <BNLowLevelILOperation N>
		int64_t GetConstant() const
		{
			return As<N>().GetConstant();
		}
		template <BNLowLevelILOperation N>
		uint64_t GetOffset() const
		{
			return As<N>().GetOffset();
		}
		template <BNLowLevelILOperation N>
		int64_t GetVector() const
		{
			return As<N>().GetVector();
		}
		template <BNLowLevelILOperation N>
		int64_t GetStackAdjustment() const
		{
			return As<N>().GetStackAdjustment();
		}
		template <BNLowLevelILOperation N>
		LLILLabelIndex GetTarget() const
		{
			return As<N>().GetTarget();
		}
		template <BNLowLevelILOperation N>
		LLILLabelIndex GetTrueTarget() const
		{
			return As<N>().GetTrueTarget();
		}
		template <BNLowLevelILOperation N>
		LLILLabelIndex GetFalseTarget() const
		{
			return As<N>().GetFalseTarget();
		}
		template <BNLowLevelILOperation N>
		size_t GetBitIndex() const
		{
			return As<N>().GetBitIndex();
		}
		template <BNLowLevelILOperation N>
		size_t GetSourceMemoryVersion() const
		{
			return As<N>().GetSourceMemoryVersion();
		}
		template <BNLowLevelILOperation N>
		size_t GetDestMemoryVersion() const
		{
			return As<N>().GetDestMemoryVersion();
		}
		template <BNLowLevelILOperation N>
		BNLowLevelILFlagCondition GetFlagCondition() const
		{
			return As<N>().GetFlagCondition();
		}
		template <BNLowLevelILOperation N>
		LowLevelILSSARegisterList GetOutputSSARegisters() const
		{
			return As<N>().GetOutputSSARegisters();
		}
		template <BNLowLevelILOperation N>
		LowLevelILInstructionList GetParameterExprs() const
		{
			return As<N>().GetParameterExprs();
		}
		template <BNLowLevelILOperation N>
		LowLevelILSSARegisterList GetSourceSSARegisters() const
		{
			return As<N>().GetSourceSSARegisters();
		}
		template <BNLowLevelILOperation N>
		LowLevelILSSARegisterStackList GetSourceSSARegisterStacks() const
		{
			return As<N>().GetSourceSSARegisterStacks();
		}
		template <BNLowLevelILOperation N>
		LowLevelILSSAFlagList GetSourceSSAFlags() const
		{
			return As<N>().GetSourceSSAFlags();
		}
		template <BNLowLevelILOperation N>
		LowLevelILRegisterOrFlagList GetOutputRegisterOrFlagList() const
		{
			return As<N>().GetOutputRegisterOrFlagList();
		}
		template <BNLowLevelILOperation N>
		LowLevelILSSARegisterOrFlagList GetOutputSSARegisterOrFlagList() const
		{
			return As<N>().GetOutputSSARegisterOrFlagList();
		}
		template <BNLowLevelILOperation N>
		LowLevelILIndexList GetSourceMemoryVersions() const
		{
			return As<N>().GetSourceMemoryVersions();
		}
		template <BNLowLevelILOperation N>
		LowLevelILIndexMap GetTargets() const
		{
			return As<N>().GetTargets();
		}
		template <BNLowLevelILOperation N>
		_STD_MAP<uint32_t, int32_t> GetRegisterStackAdjustments() const
		{
			return As<N>().GetRegisterStackAdjustments();
		}

		template <BNLowLevelILOperation N>
		void SetDestSSAVersion(size_t version)
		{
			As<N>().SetDestSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetSourceSSAVersion(size_t version)
		{
			As<N>().SetSourceSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetHighSSAVersion(size_t version)
		{
			As<N>().SetHighSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetLowSSAVersion(size_t version)
		{
			As<N>().SetLowSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetStackSSAVersion(size_t version)
		{
			As<N>().SetStackSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetTopSSAVersion(size_t version)
		{
			As<N>().SetTopSSAVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetDestMemoryVersion(size_t version)
		{
			As<N>().SetDestMemoryVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetSourceMemoryVersion(size_t version)
		{
			As<N>().SetSourceMemoryVersion(version);
		}
		template <BNLowLevelILOperation N>
		void SetOutputSSARegisters(const _STD_VECTOR<SSARegister>& regs)
		{
			As<N>().SetOutputSSARegisters(regs);
		}
		template <BNLowLevelILOperation N>
		void SetOutputSSARegisterOrFlagList(const _STD_VECTOR<SSARegisterOrFlag>& outputs)
		{
			As<N>().SetOutputSSARegisterOrFlagList(outputs);
		}

		bool GetOperandIndexForUsage(LowLevelILOperandUsage usage, LLILOperandIndex& operandIndex) const;

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
		LLILLabelIndex GetTarget() const;
		LLILLabelIndex GetTrueTarget() const;
		LLILLabelIndex GetFalseTarget() const;
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
		_STD_MAP<uint32_t, int32_t> GetRegisterStackAdjustments() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILOperand
	{
		LowLevelILInstruction m_instr;
		LowLevelILOperandUsage m_usage;
		LowLevelILOperandType m_type;
		LLILOperandIndex m_operandIndex;

	  public:
		LowLevelILOperand(const LowLevelILInstruction& instr, LowLevelILOperandUsage usage, LLILOperandIndex operandIndex);

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
		_STD_MAP<uint32_t, int32_t> GetRegisterStackAdjustments() const;
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILOperandList
	{
		struct ListIterator
		{
			const LowLevelILOperandList* owner;
			_STD_VECTOR<LowLevelILOperandUsage>::const_iterator pos;
			bool operator==(const ListIterator& a) const { return pos == a.pos; }
			bool operator!=(const ListIterator& a) const { return pos != a.pos; }
			bool operator<(const ListIterator& a) const { return pos < a.pos; }
			ListIterator& operator++()
			{
				++pos;
				return *this;
			}
			const LowLevelILOperand operator*();
		};

		LowLevelILInstruction m_instr;
		const _STD_VECTOR<LowLevelILOperandUsage>& m_usageList;
		const _STD_UNORDERED_MAP<LowLevelILOperandUsage, LLILOperandIndex>& m_operandIndexMap;

	  public:
		typedef ListIterator const_iterator;

		LowLevelILOperandList(const LowLevelILInstruction& instr, const _STD_VECTOR<LowLevelILOperandUsage>& usageList,
		    const _STD_UNORDERED_MAP<LowLevelILOperandUsage, LLILOperandIndex>& operandIndexMap);

		const_iterator begin() const;
		const_iterator end() const;
		size_t size() const;
		const LowLevelILOperand operator[](LLILOperandIndex i) const;

		operator _STD_VECTOR<LowLevelILOperand>() const;
	};

	struct LowLevelILConstantInstruction : public LowLevelILInstructionBase
	{
		int64_t GetConstant() const { return GetRawOperandAsInteger(LLILOperandIndex(0)); }
	};

	struct LowLevelILOffsetInstruction : public LowLevelILInstructionBase
	{
		int64_t GetOffset() const { return GetRawOperandAsInteger(LLILOperandIndex(1)); }
	};

	struct LowLevelILOneOperandInstruction : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
	};

	struct LowLevelILTwoOperandInstruction : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		LowLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};

	struct LowLevelILTwoOperandWithCarryInstruction : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetLeftExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		LowLevelILInstruction GetRightExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		LowLevelILInstruction GetCarryExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
	};

	// Implementations of each instruction to fetch the correct operand value for the valid operands, these
	// are derived from LowLevelILInstructionBase so that invalid operand accessor functions will generate
	// a compiler error.
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG> : public LowLevelILInstructionBase
	{
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_SPLIT> : public LowLevelILInstructionBase
	{
		uint32_t GetHighRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		uint32_t GetLowRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(1)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_SSA> : public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_SSA_PARTIAL> : public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		uint32_t GetPartialRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(2)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(3)); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_SPLIT_SSA> : public LowLevelILInstructionBase
	{
		SSARegister GetHighSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		SSARegister GetLowSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(1)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
		void SetHighSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetLowSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(1)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_REL> : public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_PUSH> : public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_REL_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
		}
		SSARegisterStack GetSourceSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
		}
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(3)); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_REG_STACK_ABS_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
		}
		SSARegisterStack GetSourceSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
		}
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(1)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_FLAG> : public LowLevelILInstructionBase
	{
		uint32_t GetDestFlag() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SET_FLAG_SSA> : public LowLevelILInstructionBase
	{
		SSAFlag GetDestSSAFlag() const { return GetRawOperandAsSSAFlag(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
		void SetDestSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_LOAD> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_LOAD_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(LLILOperandIndex(1)); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_STORE> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_STORE_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(LLILOperandIndex(1)); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsIndex(LLILOperandIndex(2)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(3)); }
		void SetDestMemoryVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetSourceMemoryVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG> : public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_SSA> : public LowLevelILInstructionBase
	{
		SSARegister GetSourceSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_SSA_PARTIAL> : public LowLevelILInstructionBase
	{
		SSARegister GetSourceSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		uint32_t GetPartialRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(2)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_REL> : public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegisterStack() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_POP> : public LowLevelILInstructionBase
	{
		uint32_t GetSourceRegisterStack() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REG> : public LowLevelILInstructionBase
	{
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REL> : public LowLevelILInstructionBase
	{
		uint32_t GetDestRegisterStack() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_REL_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(LLILOperandIndex(0)); }
		LowLevelILInstruction GetSourceExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(2)); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(3)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(3)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_ABS_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetSourceSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(LLILOperandIndex(0)); }
		uint32_t GetSourceRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(2)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_REL_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
		}
		SSARegisterStack GetSourceSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
		}
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		SSARegister GetTopSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
		void SetTopSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_FREE_ABS_SSA> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterStack(LLILOperandIndex(0));
		}
		SSARegisterStack GetSourceSSARegisterStack() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsPartialSSARegisterStackSource(LLILOperandIndex(0));
		}
		uint32_t GetDestRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(1)); }
		void SetDestSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetSourceSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG> : public LowLevelILInstructionBase
	{
		uint32_t GetSourceFlag() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_BIT> : public LowLevelILInstructionBase
	{
		uint32_t GetSourceFlag() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		size_t GetBitIndex() const { return GetRawOperandAsIndex(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_SSA> : public LowLevelILInstructionBase
	{
		SSAFlag GetSourceSSAFlag() const { return GetRawOperandAsSSAFlag(LLILOperandIndex(0)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_BIT_SSA> : public LowLevelILInstructionBase
	{
		SSAFlag GetSourceSSAFlag() const { return GetRawOperandAsSSAFlag(LLILOperandIndex(0)); }
		size_t GetBitIndex() const { return GetRawOperandAsIndex(LLILOperandIndex(2)); }
		void SetSourceSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_SPLIT> : public LowLevelILInstructionBase
	{
		uint32_t GetHighRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
		uint32_t GetLowRegister() const { return GetRawOperandAsRegister(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_SPLIT_SSA> : public LowLevelILInstructionBase
	{
		SSARegister GetHighSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		SSARegister GetLowSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(2)); }
		void SetHighSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetLowSSAVersion(size_t version) { UpdateRawOperand(LLILOperandIndex(3), LLILRawOperand::FromVersion(version)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_JUMP> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_JUMP_TO> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		LowLevelILIndexMap GetTargets() const { return GetRawOperandAsIndexMap(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CALL> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CALL_STACK_ADJUST> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		int64_t GetStackAdjustment() const { return GetRawOperandAsInteger(LLILOperandIndex(1)); }
		_STD_MAP<uint32_t, int32_t> GetRegisterStackAdjustments() const
		{
			return GetRawOperandAsRegisterStackAdjustments(LLILOperandIndex(2));
		}
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_TAILCALL> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_RET> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_IF> : public LowLevelILInstructionBase
	{
		LowLevelILInstruction GetConditionExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(0)); }
		LLILLabelIndex GetTrueTarget() const { return GetRawOperandAsLabelIndex(LLILOperandIndex(1)); }
		LLILLabelIndex GetFalseTarget() const { return GetRawOperandAsLabelIndex(LLILOperandIndex(2)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_GOTO> : public LowLevelILInstructionBase
	{
		LLILLabelIndex GetTarget() const { return GetRawOperandAsLabelIndex(LLILOperandIndex(0)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_COND> : public LowLevelILInstructionBase
	{
		BNLowLevelILFlagCondition GetFlagCondition() const { return GetRawOperandAsFlagCondition(LLILOperandIndex(0)); }
		uint32_t GetSemanticFlagClass() const { return GetRawOperandAsRegister(LLILOperandIndex(1)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_GROUP> : public LowLevelILInstructionBase
	{
		uint32_t GetSemanticFlagGroup() const { return GetRawOperandAsRegister(LLILOperandIndex(0)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_TRAP> : public LowLevelILInstructionBase
	{
		int64_t GetVector() const { return GetRawOperandAsInteger(LLILOperandIndex(0)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_CALL_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterList(LLILOperandIndex(1));
		}
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsIndex(LLILOperandIndex(0)); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsIndex(LLILOperandIndex(2)); }
		LowLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(3)).GetRawOperandAsExprList(LLILOperandIndex(0));
		}
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(0), LLILRawOperand::FromVersion(version)); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetOutputSSARegisters(const _STD_VECTOR<SSARegister>& regs)
		{
			GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperandAsSSARegisterList(LLILOperandIndex(1), regs);
		}
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SYSCALL_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterList(LLILOperandIndex(1));
		}
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsIndex(LLILOperandIndex(0)); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(1)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(1)).GetRawOperandAsIndex(LLILOperandIndex(2)); }
		LowLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsExprList(LLILOperandIndex(0));
		}
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(0), LLILRawOperand::FromVersion(version)); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(1)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(1)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetOutputSSARegisters(const _STD_VECTOR<SSARegister>& regs)
		{
			GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperandAsSSARegisterList(LLILOperandIndex(1), regs);
		}
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_TAILCALL_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterList GetOutputSSARegisters() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsSSARegisterList(LLILOperandIndex(1));
		}
		size_t GetDestMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(0)).GetRawOperandAsIndex(LLILOperandIndex(0)); }
		LowLevelILInstruction GetDestExpr() const { return GetRawOperandAsExpr(LLILOperandIndex(1)); }
		SSARegister GetStackSSARegister() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		size_t GetSourceMemoryVersion() const { return GetRawOperandAsExpr(LLILOperandIndex(2)).GetRawOperandAsIndex(LLILOperandIndex(2)); }
		LowLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(3)).GetRawOperandAsExprList(LLILOperandIndex(0));
		}
		void SetDestMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperand(LLILOperandIndex(0), LLILRawOperand::FromVersion(version)); }
		void SetSourceMemoryVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(2), LLILRawOperand::FromVersion(version)); }
		void SetStackSSAVersion(size_t version) { GetRawOperandAsExpr(LLILOperandIndex(2)).UpdateRawOperand(LLILOperandIndex(1), LLILRawOperand::FromVersion(version)); }
		void SetOutputSSARegisters(const _STD_VECTOR<SSARegister>& regs)
		{
			GetRawOperandAsExpr(LLILOperandIndex(0)).UpdateRawOperandAsSSARegisterList(LLILOperandIndex(1), regs);
		}
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_INTRINSIC> : public LowLevelILInstructionBase
	{
		LowLevelILRegisterOrFlagList GetOutputRegisterOrFlagList() const
		{
			return GetRawOperandAsRegisterOrFlagList(LLILOperandIndex(0));
		}
		uint32_t GetIntrinsic() const { return GetRawOperandAsRegister(LLILOperandIndex(2)); }
		LowLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(3)).GetRawOperandAsExprList(LLILOperandIndex(0));
		}
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_INTRINSIC_SSA> : public LowLevelILInstructionBase
	{
		LowLevelILSSARegisterOrFlagList GetOutputSSARegisterOrFlagList() const
		{
			return GetRawOperandAsSSARegisterOrFlagList(LLILOperandIndex(0));
		}
		uint32_t GetIntrinsic() const { return GetRawOperandAsRegister(LLILOperandIndex(2)); }
		LowLevelILInstructionList GetParameterExprs() const
		{
			return GetRawOperandAsExpr(LLILOperandIndex(3)).GetRawOperandAsExprList(LLILOperandIndex(0));
		}
		void SetOutputSSARegisterOrFlagList(const _STD_VECTOR<SSARegisterOrFlag>& outputs)
		{
			UpdateRawOperandAsSSARegisterOrFlagList(LLILOperandIndex(0), outputs);
		}
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_PHI> : public LowLevelILInstructionBase
	{
		SSARegister GetDestSSARegister() const { return GetRawOperandAsSSARegister(LLILOperandIndex(0)); }
		LowLevelILSSARegisterList GetSourceSSARegisters() const { return GetRawOperandAsSSARegisterList(LLILOperandIndex(2)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_REG_STACK_PHI> : public LowLevelILInstructionBase
	{
		SSARegisterStack GetDestSSARegisterStack() const { return GetRawOperandAsSSARegisterStack(LLILOperandIndex(0)); }
		LowLevelILSSARegisterStackList GetSourceSSARegisterStacks() const
		{
			return GetRawOperandAsSSARegisterStackList(LLILOperandIndex(2));
		}
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLAG_PHI> : public LowLevelILInstructionBase
	{
		SSAFlag GetDestSSAFlag() const { return GetRawOperandAsSSAFlag(LLILOperandIndex(0)); }
		LowLevelILSSAFlagList GetSourceSSAFlags() const { return GetRawOperandAsSSAFlagList(LLILOperandIndex(2)); }
	};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MEM_PHI> : public LowLevelILInstructionBase
	{
		size_t GetDestMemoryVersion() const { return GetRawOperandAsIndex(LLILOperandIndex(0)); }
		LowLevelILIndexList GetSourceMemoryVersions() const { return GetRawOperandAsIndexList(LLILOperandIndex(1)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_EXTERN_PTR> : public LowLevelILConstantInstruction
	{
		size_t GetConstant() const { return GetRawOperandAsIndex(LLILOperandIndex(0)); }
		size_t GetOffset() const { return GetRawOperandAsIndex(LLILOperandIndex(1)); }
	};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_NOP> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_POP> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_NORET> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SYSCALL> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_BP> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_UNDEF> : public LowLevelILInstructionBase
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_UNIMPL> : public LowLevelILInstructionBase
	{};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_CONST> : public LowLevelILConstantInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CONST_PTR> : public LowLevelILConstantInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLOAT_CONST> : public LowLevelILConstantInstruction
	{};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_ADD> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SUB> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_AND> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_OR> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_XOR> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_LSL> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_LSR> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ASR> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ROL> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ROR> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MUL> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MULU_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MULS_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_DIVU> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_DIVS> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MODU> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MODS> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_DIVU_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_DIVS_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MODU_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_MODS_DP> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_E> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_NE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_SLT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_ULT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_SLE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_ULE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_SGE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_UGE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_SGT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CMP_UGT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_TEST_BIT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ADD_OVERFLOW> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FADD> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FSUB> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FMUL> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FDIV> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_E> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_NE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_LT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_LE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_GE> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_GT> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_O> : public LowLevelILTwoOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FCMP_UO> : public LowLevelILTwoOperandInstruction
	{};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_ADC> : public LowLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SBB> : public LowLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_RLC> : public LowLevelILTwoOperandWithCarryInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_RRC> : public LowLevelILTwoOperandWithCarryInstruction
	{};

	template <>
	struct LowLevelILInstructionAccessor<LLIL_PUSH> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_NEG> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_NOT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_SX> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ZX> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_LOW_PART> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_BOOL_TO_INT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_UNIMPL_MEM> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FSQRT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FNEG> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FABS> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLOAT_TO_INT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_INT_TO_FLOAT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLOAT_CONV> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_ROUND_TO_INT> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FLOOR> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_CEIL> : public LowLevelILOneOperandInstruction
	{};
	template <>
	struct LowLevelILInstructionAccessor<LLIL_FTRUNC> : public LowLevelILOneOperandInstruction
	{};
#undef _STD_VECTOR
#undef _STD_SET
#undef _STD_UNORDERED_MAP
#undef _STD_MAP
}  // namespace BinaryNinjaCore
