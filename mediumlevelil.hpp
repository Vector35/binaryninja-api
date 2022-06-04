#pragma once
#include "ilsourcelocation.hpp"
#include "function.hpp"
#include "mediumlevelilinstruction.h"

namespace BinaryNinja {
	typedef size_t ExprId;
	class Function;
	class Architecture;
	class BasicBlock;
	class SSARegister;
	class HighLevelILFunction;

	struct MediumLevelILLabel : public BNMediumLevelILLabel
	{
		MediumLevelILLabel();
	};

	struct MediumLevelILInstruction;

	class MediumLevelILFunction :
	    public CoreRefCountObject<BNMediumLevelILFunction, BNNewMediumLevelILFunctionReference,
	        BNFreeMediumLevelILFunction>
	{
	  public:
		MediumLevelILFunction(Architecture* arch, Function* func = nullptr);
		MediumLevelILFunction(BNMediumLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);
		size_t GetInstructionStart(Architecture* arch, uint64_t addr);

		void PrepareToCopyFunction(MediumLevelILFunction* func);
		void PrepareToCopyBlock(BasicBlock* block);
		BNMediumLevelILLabel* GetLabelForSourceInstruction(size_t i);

		ExprId AddExpr(BNMediumLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, uint64_t addr, uint32_t sourceOperand,
		    size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNMediumLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVar(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarField(size_t size, const Variable& dest, uint64_t offset, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSplit(size_t size, const Variable& high, const Variable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSAField(size_t size, const Variable& dest, size_t newVersion, size_t prevVersion, uint64_t offset,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarSSASplit(size_t size, const SSAVariable& high, const SSAVariable& low, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliased(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SetVarAliasedField(size_t size, const Variable& dest, size_t newMemVersion, size_t prevMemVersion,
		    uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Load(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStruct(size_t size, ExprId src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadSSA(size_t size, ExprId src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LoadStructSSA(size_t size, ExprId src, uint64_t offset, size_t memVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Store(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStruct(
		    size_t size, ExprId dest, uint64_t offset, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreSSA(size_t size, ExprId dest, size_t newMemVersion, size_t prevMemVersion, ExprId src,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId StoreStructSSA(size_t size, ExprId dest, uint64_t offset, size_t newMemVersion, size_t prevMemVersion,
		    ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarField(
		    size_t size, const Variable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplit(
		    size_t size, const Variable& high, const Variable& low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSAField(
		    size_t size, const SSAVariable& src, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliased(
		    size_t size, const Variable& src, size_t memVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarAliasedField(size_t size, const Variable& src, size_t memVersion, uint64_t offset,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSplitSSA(size_t size, const SSAVariable& high, const SSAVariable& low,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOfField(const Variable& var, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Const(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ConstPointer(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ExternPointer(
		    size_t size, uint64_t val, uint64_t offset, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstRaw(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstSingle(float val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConstDouble(double val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ImportedAddress(size_t size, uint64_t val, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Add(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddWithCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Sub(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SubWithBorrow(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId And(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Or(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Xor(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ShiftLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LogicalShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArithShiftRight(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeft(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateLeftCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRight(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RotateRightCarry(
		    size_t size, ExprId left, ExprId right, ExprId carry, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Mult(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId MultDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DivDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModSigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModUnsigned(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecSigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ModDoublePrecUnsigned(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Neg(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Not(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SignExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ZeroExtend(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId LowPart(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId JumpTo(ExprId dest, const std::map<uint64_t, BNMediumLevelILLabel*>& targets,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ReturnHint(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Call(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
		    ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<Variable>& output, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntyped(const std::vector<Variable>& output, const std::vector<Variable>& params, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(const std::vector<Variable>& output, ExprId dest, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntyped(const std::vector<Variable>& output, ExprId dest, const std::vector<Variable>& params,
		    ExprId stack, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
		    const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<SSAVariable>& output, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallUntypedSSA(const std::vector<SSAVariable>& output, const std::vector<SSAVariable>& params,
		    size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallSSA(const std::vector<SSAVariable>& output, ExprId dest, const std::vector<ExprId>& params,
		    size_t newMemVersion, size_t prevMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCallUntypedSSA(const std::vector<SSAVariable>& output, ExprId dest,
		    const std::vector<SSAVariable>& params, size_t newMemVersion, size_t prevMemVersion, ExprId stack,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareEqual(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareNotEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedLessEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterEqual(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareSignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CompareUnsignedGreaterThan(
		    size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TestBit(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId BoolToInt(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddOverflow(size_t size, ExprId left, ExprId right, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Breakpoint(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Trap(int64_t vector, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Intrinsic(const std::vector<Variable>& outputs, uint32_t intrinsic, const std::vector<ExprId>& params,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(const std::vector<SSAVariable>& outputs, uint32_t intrinsic,
		    const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlot(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FreeVarSlotSSA(const Variable& var, size_t newVersion, size_t prevVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemoryPhi(size_t destMemVersion, const std::vector<size_t>& sourceMemVersions,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAdd(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSub(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatMult(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatDiv(size_t size, ExprId a, ExprId b, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatSqrt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatNeg(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatAbs(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntToFloat(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatConvert(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId RoundToInt(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Floor(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Ceil(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
		ExprId FloatTrunc(size_t size, ExprId a, const ILSourceLocation& loc = ILSourceLocation());
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

		ExprId Goto(BNMediumLevelILLabel& label, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(ExprId operand, BNMediumLevelILLabel& t, BNMediumLevelILLabel& f,
		    const ILSourceLocation& loc = ILSourceLocation());
		void MarkLabel(BNMediumLevelILLabel& label);

		ExprId AddInstruction(ExprId expr);

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddLabelMap(const std::map<uint64_t, BNMediumLevelILLabel*>& labels);
		ExprId AddOperandList(const std::vector<ExprId> operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddVariableList(const std::vector<Variable>& vars);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNMediumLevelILInstruction GetRawExpr(size_t i) const;
		MediumLevelILInstruction operator[](size_t i);
		MediumLevelILInstruction GetInstruction(size_t i);
		MediumLevelILInstruction GetExpr(size_t i);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void MarkInstructionForRemoval(size_t i);
		void ReplaceInstruction(size_t i, ExprId expr);
		void ReplaceExpr(size_t expr, size_t newExpr);

		void Finalize();
		void GenerateSSAForm(bool analyzeConditionals = true, bool handleAliases = true,
		    const std::set<Variable>& knownNotAliases = std::set<Variable>(),
		    const std::set<Variable>& knownAliases = std::set<Variable>());

		bool GetExprText(Architecture* arch, ExprId expr, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);
		bool GetInstructionText(Function* func, Architecture* arch, size_t i, std::vector<InstructionTextToken>& tokens,
		    DisassemblySettings* settings = nullptr);

		void VisitInstructions(
		    const std::function<void(BasicBlock* block, const MediumLevelILInstruction& instr)>& func);
		void VisitAllExprs(const std::function<bool(BasicBlock* block, const MediumLevelILInstruction& expr)>& func);

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<MediumLevelILFunction> GetSSAForm() const;
		Ref<MediumLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSAVarDefinition(const SSAVariable& var) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSAVarUses(const SSAVariable& var) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;
		bool IsSSAVarLive(const SSAVariable& var) const;

		std::set<size_t> GetVariableDefinitions(const Variable& var) const;
		std::set<size_t> GetVariableUses(const Variable& var) const;

		RegisterValue GetSSAVarValue(const SSAVariable& var);
		RegisterValue GetExprValue(size_t expr);
		RegisterValue GetExprValue(const MediumLevelILInstruction& expr);
		PossibleValueSet GetPossibleSSAVarValues(const SSAVariable& var, size_t instr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(
		    size_t expr, const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());
		PossibleValueSet GetPossibleExprValues(const MediumLevelILInstruction& expr,
		    const std::set<BNDataFlowQueryOption>& options = std::set<BNDataFlowQueryOption>());

		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;
		Variable GetVariableForRegisterAtInstruction(uint32_t reg, size_t instr) const;
		Variable GetVariableForFlagAtInstruction(uint32_t flag, size_t instr) const;
		Variable GetVariableForStackLocationAtInstruction(int64_t offset, size_t instr) const;

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

		BNILBranchDependence GetBranchDependenceAtInstruction(size_t curInstr, size_t branchInstr) const;
		std::unordered_map<size_t, BNILBranchDependence> GetAllBranchDependenceAtInstruction(size_t instr) const;

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		size_t GetLowLevelILInstructionIndex(size_t instr) const;
		size_t GetLowLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetLowLevelILExprIndexes(size_t expr) const;
		Ref<HighLevelILFunction> GetHighLevelIL() const;
		size_t GetHighLevelILInstructionIndex(size_t instr) const;
		size_t GetHighLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetHighLevelILExprIndexes(size_t expr) const;

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const MediumLevelILInstruction& expr);

		static bool IsConstantType(BNMediumLevelILOperation op)
		{
			return op == MLIL_CONST || op == MLIL_CONST_PTR || op == MLIL_EXTERN_PTR;
		}

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);
	};
}