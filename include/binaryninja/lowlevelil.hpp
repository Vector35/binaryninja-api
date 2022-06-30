
#pragma once
#include "binaryninjaapi_new.hpp"
#include "ilsourcelocation.hpp"
#include "binaryninjacore/lowlevelil.h"
#include "lowlevelilinstruction.hpp"

struct BNRegisterOrConstant;

namespace BinaryNinja {
	typedef size_t ExprId;
	class Function;
	class Architecture;
	class BasicBlock;
	class SSARegister;
	class SSARegisterStack;
	class SSAFlag;
	class MediumLevelILFunction;
	class FlowGraph;
	class DisassemblySettings;
	class ArchAndAddr;

	struct LowLevelILLabel : public BNLowLevelILLabel
	{
		LowLevelILLabel();
	};

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
		BNLowLevelILLabel* GetLabelForSourceInstruction(size_t i);

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void ClearIndirectBranches();
		void SetIndirectBranches(const std::vector<ArchAndAddr>& branches);

		ExprId AddExpr(BNLowLevelILOperation operation, size_t size, uint32_t flags, ExprId a = 0, ExprId b = 0,
			ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
			uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddExprWithLocation(BNLowLevelILOperation operation, const ILSourceLocation& loc, size_t size,
			uint32_t flags, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0);
		ExprId AddInstruction(ExprId expr);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegister(size_t size, uint32_t reg, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplit(size_t size, uint32_t high, uint32_t low, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSA(
			size_t size, const SSARegister& reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg, ExprId val,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low, ExprId val,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelative(size_t size, uint32_t regStack, ExprId entry, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPush(size_t size, uint32_t regStack, ExprId val, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackTopRelativeSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
			ExprId entry, const SSARegister& top, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetRegisterStackAbsoluteSSA(size_t size, uint32_t regStack, size_t destVersion, size_t srcVersion,
			uint32_t reg, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlag(uint32_t flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetFlagSSA(const SSAFlag& flag, ExprId val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId addr, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(
			size_t size, ExprId addr, size_t sourceMemoryVer, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(
			size_t size, ExprId addr, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId addr, ExprId val, size_t newMemoryVer, size_t prevMemoryVer,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Push(size_t size, ExprId val, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Pop(size_t size, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Register(size_t size, uint32_t reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSA(size_t size, const SSARegister& reg, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSSAPartial(size_t size, const SSARegister& fullReg, uint32_t partialReg,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplit(
			size_t size, uint32_t high, uint32_t low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterSplitSSA(size_t size, const SSARegister& high, const SSARegister& low,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackTopRelative(
			size_t size, uint32_t regStack, ExprId entry, const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
			size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Flag(uint32_t flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagSSA(const SSAFlag& flag, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBit(size_t size, uint32_t flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagBitSSA(
			size_t size, const SSAFlag& flag, size_t bitIndex, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubBorrow(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(size_t size, ExprId a, ExprId b, ExprId carry, uint32_t flags = 0,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNLowLevelILLabel*>& targets,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallStackAdjust(ExprId dest, int64_t adjust, const std::map<uint32_t, int32_t>& regStackAdjust,
			const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Return(size_t dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagCondition(
			BNLowLevelILFlagCondition cond, uint32_t semClass = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagGroup(uint32_t semGroup, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SystemCall(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<RegisterOrFlag>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSARegisterOrFlag>& outputs, uint32_t intrinsic,
			const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t num, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId addr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterPhi(const SSARegister& dest, const std::vector<SSARegister>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId RegisterStackPhi(const SSARegisterStack& dest, const std::vector<SSARegisterStack>& sources,
			const ILSourceLocation& loc = ILSourceLocation());
		ExprId FlagPhi(
			const SSAFlag& dest, const std::vector<SSAFlag>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(
			size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(
			size_t size, ExprId a, ExprId b, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(
			size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, uint32_t flags = 0, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareNotEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessThan(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareLessEqual(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterEqual(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareGreaterThan(
			size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareOrdered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatCompareUnordered(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());

		ExprId Goto(BNLowLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNLowLevelILLabel& t, BNLowLevelILLabel& f,
			const ILSourceLocation& loc = ILSourceLocation());
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

		void AddLabelForAddress(Architecture* arch, ExprId addr);
		BNLowLevelILLabel* GetLabelForAddress(Architecture* arch, ExprId addr);

		void Finalize();
		void GenerateSSAForm();

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens);
		bool GetInstructionText(
			Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens);

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