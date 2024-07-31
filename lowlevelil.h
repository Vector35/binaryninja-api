#pragma once

#include "binaryninjacore.h"
#include "commonil.h"
#include "refcount.h"
#include <map>
#include <set>
#include <vector>

namespace BinaryNinja
{
	typedef size_t ExprId;

	class Architecture;
	struct ArchAndAddr;
	class BasicBlock;
	class DisassemblySettings;
	class FlowGraph;
	class Function;
	struct InstructionTextToken;
	struct LowLevelILInstruction;
	class MediumLevelILFunction;
	struct PossibleValueSet;
	struct RegisterOrFlag;
	struct RegisterValue;
	struct SSAFlag;
	struct SSARegister;
	struct SSARegisterOrFlag;
	struct SSARegisterStack;

	/*!
		\ingroup lowlevelil
	*/
	struct LowLevelILLabel : public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

	/*!
		\ingroup lowlevelil
	*/
	class LowLevelILFunction :
	    public CoreRefCountObject<BNLowLevelILFunction, BNNewLowLevelILFunctionReference, BNFreeLowLevelILFunction>
	{
	  public:
		LowLevelILFunction(Architecture* arch, Function* func = nullptr);
		LowLevelILFunction(BNLowLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		void PrepareToCopyFunction(LowLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);

		/*! Get the LowLevelILLabel for a given source instruction. The returned pointer is to an internal object with
			the same lifetime as the containing LowLevelILFunction.

			\param i The source instruction index
			\return The LowLevelILLabel for the source instruction
		*/
		BNLowLevelILLabel* GetLabelForSourceInstruction(size_t i);

		/*! Get the current IL address.
		*/
		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void ClearIndirectBranches();
		void SetIndirectBranches(const std::vector<ArchAndAddr>& branches);

		/*! Get a list of registers used in the LLIL function

			\see Architecture::GetAllRegisters, Architecture::GetRegisterName, Architecture::GetRegisterInfo

			\return The list of used registers
		*/
		std::vector<uint32_t> GetRegisters();

		/*! Get a list of used register stacks used in the LLIL function

			\return List of used register stacks
		*/
		std::vector<uint32_t> GetRegisterStacks();

		/*! Get the list of flags used in this LLIL function

			\see Architecture::GetAllFlags, Architecture::GetFlagName, Architecture::GetFlagRole

			\return The list of used flags.
		*/
		std::vector<uint32_t> GetFlags();

		// Get a list of SSA registers used in the LLIL SSA function, without versions.
		std::vector<SSARegister> GetSSARegistersWithoutVersions();
		std::vector<SSARegisterStack> GetSSARegisterStacksWithoutVersions();
		std::vector<SSAFlag> GetSSAFlagsWithoutVersions();

		// Get a list of SSA registers used in the LLIL SSA function, with versions
		std::vector<SSARegister> GetSSARegisters();
		std::vector<SSARegisterStack> GetSSARegisterStacks();
		std::vector<SSAFlag> GetSSAFlags();

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0,
		    ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		/*! No operation, this instruction does nothing.

			\param loc Optional IL Location this instruction was added from.
			\return
		*/
		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the register \c reg of size \c size to the expression \c value

			\param size Size of the register parameter in bytes
			\param reg The register name
			\param val An expression to set the register to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg = value</tt>
		*/
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Uses \c hi and \c lo as a single extended register setting \c hi:lo to the expression \c value .

			\param size Size of the register parameter in bytes
			\param high The high register name
			\param low The low register name
			\param val An expression to set the split registers to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>hi:lo = value</tt>
		*/
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSA(
		    size_t size, const SSARegister& reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low, ExprId val,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the top-relative entry \c entry of size \c size in register stack \c reg_stack to the expression
		 	\c value

			\param size Size of the register parameter in bytes
			\param regStack The register stack name
			\param entry An expression for which stack entry to set
			\param val An expression to set the entry to
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg_stack[entry] = value</tt>
		*/
		ExprId SetRegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Pushes the expression \c value of size \c size onto the top of the register
			stack \c reg_stack

			\param size Size of the register parameter in bytes
			\param regStack The register stack name
			\param val An expression to push
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>reg_stack.push(value)</tt>
		*/
		ExprId RegisterStackPush(size_t size, uint32_t regStack, ExprId val, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		ExprId SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    ExprId entry, const SSARegister& top, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
		    uint32_t reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the flag \c flag to the ExpressionIndex \c value

			\param flag Flag index
			\param val An expression to set the flag to
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>FLAG.flag = value</tt>
		*/
		ExprId SetFlag(uint32_t flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlagSSA(const SSAFlag& flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Reads \c size bytes from the expression \c addr

			\param size Number of bytes to read
			\param addr The expression to read memory from
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c [addr].size
		*/
		ExprId Load(size_t size, ExprId addr, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(
		    size_t size, ExprId addr, size_t sourceMemoryVer, const ILSourceLocation& loc = ILSourceLocation());

		/*! Writes \c size bytes to expression \c addr read from expression \c val

			\param size Number of bytes to write
			\param addr The expression to write to
			\param val The expression to be written
			\param flags Which flags are set by this operation
			\param loc Optional IL Location this instruction was added from.
			\return The expression <tt>[addr].size = value</tt>
		*/
		ExprId Store(
		    size_t size, ExprId addr, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId addr, ExprId val, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Writes \c size bytes from expression \c value to the stack, adjusting the stack by \c size .

			\param size Number of bytes to write and adjust the stack by
			\param val The expression to write
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c push(value)
		*/
		ExprId Push(size_t size, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Reads ``size`` bytes from the stack, adjusting the stack by ``size``.

			\param size Number of bytes to read from the stack
			\param flags Flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c pop
		*/
		ExprId Pop(size_t size, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a register of size \c size with name \c reg

			\param size The size of the register in bytes
			\param reg The name of the register
			\param loc Optional IL Location this instruction was added from.
			\return A register expression for the given register
		*/
		ExprId Register(size_t size, uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Combines registers of size ``size`` with names ``hi`` and ``lo``

			\param size The size of the register in bytes
			\param high Register holding high part of value
			\param low Register holding low part of value
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c hi:lo
		*/
		ExprId RegisterSplit(
		    size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a register stack entry of size \c size at top-relative
			location \c entry in register stack with name \c regStack

			\param size The size of the register in bytes
			\param regStack The index of the register stack
			\param entry An expression for which stack entry to fetch
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c reg_stack[entry]
		*/
		ExprId RegisterStackTopRelative(
		    size_t size, uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the top entry of size \c size in register stack with name \c reg_stack , and
			removes the entry from the stack

			\param size The size of the register in bytes
			\param regStack The index of the register stack
			\param flags Any flags set by this expression
			\param loc Optional IL Location this instruction was added from.
			\return The expression \c reg_stack.pop
		*/
		ExprId RegisterStackPop(
		    size_t size, uint32_t regStack, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());


		ExprId RegisterStackFreeReg(uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelative(
		    uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelativeSSA(size_t size, const SSARegisterStack& regStack, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackAbsoluteSSA(size_t size, const SSARegisterStack& regStack, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeTopRelativeSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, ExprId entry,
		    const SSARegister& top, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackFreeAbsoluteSSA(uint32_t regStack, size_t destVersion, size_t srcVersion, uint32_t reg,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant integer \c value with size \c size

			\param size The size of the constant in bytes
			\param val Integer value of the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant pointer \c value with size \c size

			\param size The size of the pointer in bytes
			\param val Address referenced by pointer
			\param loc Optional IL Location this instruction was added from.
			\return A constant pointer expression of given value and size
		*/
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant relocated pointer ``value`` with size ``size``

			\param size The size of the pointer in bytes
			\param val Address referenced by pointer
			\param offset
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the constant raw binary floating point
			value \c value with size \c size

		 	To clarify, \c value here is the representation of the float if its bits were instead interpreted as an integer.

			A given float \e could be converted to an integer value like so:

		 	\code{.cpp}
		    union {
				float floatValue;
				uint32_t integerValue;
				} bits;
			bits.floatValue = val;
		 	uint32_t myIntValueToPassToThisFunction = bits.integerValue;
		 	\endcode

		 	Do note this is exactly how FloatConstSingle and FloatConstDouble perform this conversion
		 		(and thus, converting it yourself is \e typically redundant.)

			\param size The size of the constant in bytes
			\param val Integer value for the raw binary representation of the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the single precision floating point value \c value

		 	\param val Float value for the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression for the double precision floating point value \c value

			\param val Float value for the constant
			\param loc Optional IL Location this instruction was added from.
			\return A constant expression of given value and size
		*/
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag expression for the given flag index.

			\param flag Flag index
			\param loc Optional IL Location this expression was added from.
			\return A flag expression for the given flag
		*/
		ExprId Flag(uint32_t flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc = ILSourceLocation());

		/*! Sets the flag with index \c flag and size \c size to the constant integer value \c bit

			\param size The size of the flag
			\param flag Flag index
			\param bitIndex Bit of the flag to set
			\param loc Optional IL Location this expression was added from.
			\return A constant expression of given value and size <tt>FLAG.reg = bit</tt>
		*/
		ExprId FlagBit(size_t size, uint32_t flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBitSSA(
		    size_t size, const SSAFlag& flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds expression \c a to expression \c b potentially setting flags \c flags and returning
			an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags flags to set
			\param loc Optional IL Location this expression was added from.
			\return A constant expression of given value and size <tt>FLAG.reg = bit</tt>
		*/
		ExprId Add(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds with carry expression \c a to expression \c b potentially setting flags \c flags and
			returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>adc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts expression \c b from expression \c a potentially setting flags \c flags and returning
			an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sub.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Sub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts with borrow expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sbb.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise and's expression \c a and expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>and.<size>{<flags>}(a, b)</tt>
		*/
		ExprId And(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise or's expression \c a and expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>or.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Or(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Xor's expression \c a with expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>xor.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Xor(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts left expression \c a by expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>lsl.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ShiftLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts logically right expression \c a by expression \c b potentially setting flags
			\c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>lsr.<size>{<flags>}(a, b)</tt>
		*/
		ExprId LogicalShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Shifts arithmetic right expression \c a by expression \c b potentially setting flags
			\c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>asr.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ArithShiftRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates left expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rol.<size>{<flags>}(a, b)</tt>
		*/
		ExprId RotateLeft(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates left with carry expression \c a by expression \c b potentially setting
			flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rlc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates right expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>ror.<size>{<flags>}(a, b)</tt>
		*/
		ExprId RotateRight(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise rotates right with carry expression \c a by expression \c b potentially setting
			flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param carry Carry flag expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>rrc.<size>{<flags>}(a, b, carry)</tt>
		*/
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies expression \c a by expression \c b potentially setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sbc.<size>{<flags>}(a, b)</tt>
		*/
		ExprId Mult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies unsigned with double precision expression \c a by expression \c b
			potentially setting flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mulu.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies signed with double precision expression \c a by expression \c b
			potentially setting flags \c flags and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>muls.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned divide expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divu.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned double precision divide using expression \c a as
			a single double precision register by expression \c b potentially  setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed divide expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divs.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed double precision divide using expression \c a as a
			single double precision register by expression \c b potentially setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>divs.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned modulus expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>modu.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Unsigned double precision modulus using expression \c a as
			a single double precision register by expression \c b potentially  setting flags \c flags and returning an
			expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>modu.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed modulus expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Signed double precision modulus using expression \c a as a single
			double precision register by expression \c b potentially  setting flags \c flags and returning an expression
			of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>mods.dp.<size>{<flags>}(a, b)</tt>
		*/
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Two's complement sign negation of expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to negate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>neg.<size>{<flags>}(value)</tt>
		*/
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Bitwise inverse of expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to bitwise invert
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>not.<size>{<flags>}(value)</tt>
		*/
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Two's complement sign-extends the expression in \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to sign extend
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sx.<size>(value)</tt>
		*/
		ExprId SignExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Zero-extends the expression in \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to zero extend
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sx.<size>(value)</tt>
		*/
		ExprId ZeroExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Truncates \c value to \c size bytes

			\param size The size of the result in bytes
			\param a The expression to truncate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>zx.<size>(value)</tt>
		*/
		ExprId LowPart(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression \c jump(dest)
		*/
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNLowLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which first pushes the address of the next instruction onto the stack then jumps
			(branches) to the expression \c dest

			\param dest The expression to call
			\param loc Optional IL Location this expression was added from.
			\return The expression \c call(dest)
		*/
		ExprId Call(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which first pushes the address of the next instruction onto the stack
			then jumps (branches) to the expression \c dest . After the function exits, \c stack_adjust is added to the
			stack pointer register.

			\param dest The expression to call
			\param adjust Stack adjustment
			\param regStackAdjust Register stack adjustment
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>call(dest), stack += stack_adjust</tt>
		*/
		ExprId CallStackAdjust(ExprId dest, int64_t adjust, const std::map<uint32_t, int32_t>& regStackAdjust,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>tailcall(dest)</tt>
		*/
		ExprId TailCall(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCallSSA(const std::vector<SSARegister>& output, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSARegister>& output, ExprId dest, const std::vector<ExprId>& params,
		    const SSARegister& stack, size_t newMemoryVer, size_t prevMemoryVer,
		    const ILSourceLocation& loc = ILSourceLocation());

		ExprId SeparateParamListSSA(
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SharedParamSlotSSA(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression which jumps (branches) to the expression \c dest . \c ret is a special alias for
			jump that makes the disassembler stop disassembling.

			\param dest The expression to jump to
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>jump(dest)</tt>
		*/
		ExprId Return(size_t dest, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an expression that halts disassembly

			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>noreturn</tt>
		*/
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag_condition expression for the given LowLevelILFlagCondition

			\param cond Flag condition expression to retrieve
			\param semClass Optional semantic flag class
			\param loc Optional IL Location this expression was added from.
			\return A flag_condition expression
		*/
		ExprId FlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a flag_group expression for the given semantic flag group

			\param semGroup Semantic flag group to access
			\param loc Optional IL Location this expression was added from.
			\return A flag_group expression
		*/
		ExprId FlagGroup(uint32_t semGroup, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is equal to
			expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is not equal to
			expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed less than expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned less than expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed less than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned less than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a
			is unsigned greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			signed greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns comparison expression of size \c size checking if expression \c a is
			unsigned greater than or equal to expression \c b

			\param size Size in bytes
			\param a LHS of comparison
			\param b RHS of comparison
			\param loc Optional IL Location this expression was added from.
			\return a comparison expression.
		*/
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a system call expression.

			\param loc Optional IL Location this expression was added from.
			\return System call expression.
		*/
		ExprId SystemCall(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns an intrinsic expression. 'Intrinsics' are emitted and lifted as if they were builtin functions that
			do not exist in the binary.

			\param outputs Registers and/or flags set by this intrinsic call.
			\param intrinsic Index of the intrinsic. <b>See also:</b> Architecture::GetIntrinsicName, Architecture::GetAllIntrinsics
		    \param params Parameter items passed to this intrinsic
			\param flags Flags
			\param loc Optional IL Location this expression was added from.
			\return An intrinsic expression.
		*/
		ExprId Intrinsic(const std::vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryIntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a processor breakpoint expression.

			\param loc Optional IL Location this expression was added from.
			\return A breakpoint expression.
		*/
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a processor trap (interrupt) expression of the given integer \c value .

			\param num trap (interrupt) number
			\param loc Optional IL Location this expression was added from.
			\return A trap expression.
		*/
		ExprId Trap(int64_t num, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the undefined expression. This should be used for instructions which perform functions but
			aren't important for dataflow or partial emulation purposes.

			\param loc Optional IL Location this expression was added from.
			\return The Undefined expression
		*/
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the unimplemented expression. This should be used for instructions which aren't implemented

			\param loc Optional IL Location this expression was added from.
			\return The unimplemented expression
		*/
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());

		/*! A memory reference to expression \c addr of size \c size with unimplemented operation.

			\param size Size in bytes of the memory reference
			\param addr Expression to reference memory
			\param loc Optional IL Location this expression was added from.
			\return The unimplemented memory reference expression.
		*/
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterPhi(const SSARegister& dest, const std::vector<SSARegister>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPhi(const SSARegisterStack& dest, const std::vector<SSARegisterStack>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagPhi(
		    const SSAFlag& dest, const std::vector<SSAFlag>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());

		/*! Adds floating point expression \c a to expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fadd.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatAdd(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Subtracts floating point expression \c b from expression \c a potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fsub.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatSub(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Multiplies floating point expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fmul.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatMult(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Divides floating point expression \c a by expression \c b potentially setting flags \c flags
			and returning an expression of \c size bytes.

			\param size The size of the result in bytes
			\param a LHS expression
			\param b RHS expression
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fdiv.<size>{<flags>}(a, b)</tt>
		*/
		ExprId FloatDiv(
		    size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the square root of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to calculate the square root of
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>sqrt.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatSqrt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns sign negation of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The expression to negate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fneg.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatNeg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns absolute value of floating point expression \c value of size \c size potentially setting flags.

			\param size The size of the result in bytes
			\param a The expression to get the absolute value of
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>fabs.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatAbs(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns integer value of floating point expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The float expression to convert to an int
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>int.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point value of integer expression \c value of size \c size potentially setting flags

			\param size The size of the result in bytes
			\param a The float expression to convert to a float
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>float.<size>{<flags>}(value)</tt>
		*/
		ExprId IntToFloat(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(
		    size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to the nearest integer

			\param size The size of the result in bytes
			\param a The expression to round to the nearest integer
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId RoundToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer, towards negative infinity

			\param size The size of the result in bytes
			\param a The expression to round down
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId Floor(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer, towards positive infinity

			\param size The size of the result in bytes
			\param a The expression to round up
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId Ceil(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Rounds a floating point value to an integer towards zero

			\param size The size of the result in bytes
			\param a The expression to truncate
			\param flags Flags to set
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>roundint.<size>{<flags>}(value)</tt>
		*/
		ExprId FloatTrunc(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f== b</tt>
		*/
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is not equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f!= b</tt>
		*/
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is less than expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f< b</tt>
		*/
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is less than or equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f<= b</tt>
		*/
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is greater than or equal to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f>= b</tt>
		*/
		ExprId FloatCompareGreaterEqual(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is greater than expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>a f> b</tt>
		*/
		ExprId FloatCompareGreaterThan(
		    size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is ordered relative to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>is_ordered(a, b)</tt>
		*/
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns floating point comparison expression of size \c size checking if
			expression \c a is unordered relative to expression \c b

			\param size The size of the operands in bytes
			\param a LHS expression
			\param b RHS expression
			\param loc Optional IL Location this expression was added from.
			\return The expression <tt>is_unordered(a, b)</tt>
		*/
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns a goto expression which jumps to the provided LowLevelILLabel.

			\param label Label to jump to
			\param loc Optional IL Location this expression was added from.
			\return a Goto expression
		*/
		ExprId Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());

		/*! Returns the \c if expression which depending on condition \c operand jumps to the LowLevelILLabel
			\c t when the condition expression \c operand is non-zero and \c f`` when it's zero.

			\param operand Comparison expression to evaluate.
			\param t Label for the true branch
			\param f Label for the false branch
			\param loc Optional IL Location this expression was added from.
			\return the ExpressionIndex for the if expression
		*/
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());

		/*! Assigns a LowLevelILLabel to the current IL address.

			\param label label to mark.
		*/
		void MarkLabel(BNLowLevelILLabel& label);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNLowLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t> operands);
		ExprId AddRegisterOrFlagList(const std::vector<RegisterOrFlag>& regs);
		ExprId AddSSARegisterList(const std::vector<SSARegister>& regs);
		ExprId AddSSARegisterStackList(const std::vector<SSARegisterStack>& regStacks);
		ExprId AddSSAFlagList(const std::vector<SSAFlag>& flags);
		ExprId AddSSARegisterOrFlagList(const std::vector<SSARegisterOrFlag>& regs);

		ExprId GetExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetNegExprForRegisterOrConstant(const BNRegisterOrConstant& operand, size_t size);
		ExprId GetExprForFlagOrConstant(const BNRegisterOrConstant& operand);
		ExprId GetExprForRegisterOrConstantOperation(
		    BNLowLevelILOperation op, size_t size, BNRegisterOrConstant* operands, size_t operandCount);

		ExprId Operand(size_t n, ExprId expr);

		BNLowLevelILInstruction GetRawExpr(size_t i) const;
		LowLevelILInstruction operator[](size_t i);
		LowLevelILInstruction GetInstruction(size_t i);
		LowLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);
		void SetExprAttributes(size_t expr, uint32_t attributes);

		void AddLabelForAddress(Architecture* arch, uint64_t addr);

		/*! Get the LowLevelILLabel for a given address. The returned pointer is to an internal object with
		    the same lifetime as the containing LowLevelILFunction.

			\param[in] arch Architecture for the address
			\param[in] addr Address to get the label for
			\return The LowLevelILLabel for the address
		*/
		BNLowLevelILLabel* GetLabelForAddress(Architecture* arch, uint64_t addr);

		/*! Ends the function and computes the list of basic blocks.
		*/
		void Finalize();
		/*! Generate SSA form given the current LLIL
		*/
		void GenerateSSAForm();

		/*! Get the list of InstructionTextTokens for a given expression

			\param[in] arch Architecture for the expression
			\param[in] expr Expression to get the text for
			\param[out] tokens Output reference to write the instruction tokens to
			\param[in] settings Optional structure with settings for rendering text
			\return True/False on success or failure
		*/
		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		/*! Get the list of InstructionTextTokens for a given instruction

			\param[in] func Function containing the instruction
			\param[in] arch Architecture for the instruction
		    \param[in] i Index of the instruction
			\param[out] tokens Output reference to write the instruction tokens to
			\param[in] settings Optional structure with settings for rendering text
			\return True/False on success or failure
		*/
		bool GetInstructionText(
		    Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		uint32_t GetTemporaryRegisterCount();
		uint32_t GetTemporaryFlagCount();

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<LowLevelILFunction> GetSSAForm() const;
		Ref<LowLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSARegisterDefinition(const SSARegister& reg) const;
		size_t GetSSAFlagDefinition(const SSAFlag& flag) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSARegisterUses(const SSARegister& reg) const;
		std::set<size_t> GetSSAFlagUses(const SSAFlag& flag) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;

		RegisterValue GetSSARegisterValue(const SSARegister& reg);
		RegisterValue GetSSAFlagValue(const SSAFlag& flag);

		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const LowLevelILInstruction& expr);
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const LowLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		RegisterValue GetRegisterValueAtInstruction(uint32_t reg, size_t instr);
		RegisterValue GetRegisterValueAfterInstruction(uint32_t reg, size_t instr);
		PossibleValueSet GetPossibleRegisterValuesAtInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleRegisterValuesAfterInstruction(uint32_t reg, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetFlagValueAtInstruction(uint32_t flag, size_t instr);
		RegisterValue GetFlagValueAfterInstruction(uint32_t flag, size_t instr);
		PossibleValueSet GetPossibleFlagValuesAtInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleFlagValuesAfterInstruction(uint32_t flag, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		RegisterValue GetStackContentsAtInstruction(int32_t offset, size_t len, size_t instr);
		RegisterValue GetStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr);
		PossibleValueSet GetPossibleStackContentsAtInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleStackContentsAfterInstruction(int32_t offset, size_t len, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		size_t GetMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;
		size_t GetMappedMediumLevelILInstructionIndex(size_t instr) const;
		size_t GetMappedMediumLevelILExprIndex(size_t expr) const;

		static bool IsConstantType(BNLowLevelILOperation type)
		{
			return type == LLIL_CONST || type == LLIL_CONST_PTR || type == LLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);
	};

}
