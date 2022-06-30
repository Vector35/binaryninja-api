#pragma once
#include "ilsourcelocation.hpp"
#include "binaryninjacore/highlevelil.h"
#include "highlevelilinstruction.hpp"

namespace BinaryNinja {
    
	class HighLevelILFunction :
	    public CoreRefCountObject<BNHighLevelILFunction, BNNewHighLevelILFunctionReference, BNFreeHighLevelILFunction>
	{
	  public:
		HighLevelILFunction(Architecture* arch, Function* func = nullptr);
		HighLevelILFunction(BNHighLevelILFunction* func);

		Ref<Function> GetFunction() const;
		Ref<Architecture> GetArchitecture() const;

		uint64_t GetCurrentAddress() const;
		void SetCurrentAddress(Architecture* arch, uint64_t addr);

		HighLevelILInstruction GetRootExpr();
		void SetRootExpr(ExprId expr);
		void SetRootExpr(const HighLevelILInstruction& expr);

		ExprId AddExpr(BNHighLevelILOperation operation, size_t size, ExprId a = 0, ExprId b = 0, ExprId c = 0,
		    ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, uint64_t addr, uint32_t sourceOperand, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);
		ExprId AddExprWithLocation(BNHighLevelILOperation operation, const ILSourceLocation& loc, size_t size,
		    ExprId a = 0, ExprId b = 0, ExprId c = 0, ExprId d = 0, ExprId e = 0);

		ExprId Nop(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Block(const std::vector<ExprId>& exprs, const ILSourceLocation& loc = ILSourceLocation());
		ExprId If(
		    ExprId condition, ExprId trueExpr, ExprId falseExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId While(ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId WhileSSA(
		    ExprId conditionPhi, ExprId condition, ExprId loopExpr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhile(ExprId loopExpr, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DoWhileSSA(
		    ExprId loopExpr, ExprId conditionPhi, ExprId condition, const ILSourceLocation& loc = ILSourceLocation());
		ExprId For(ExprId initExpr, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ForSSA(ExprId initExpr, ExprId conditionPhi, ExprId condition, ExprId updateExpr, ExprId loopExpr,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Switch(ExprId condition, ExprId defaultExpr, const std::vector<ExprId>& cases,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Case(
		    const std::vector<ExprId>& condition, ExprId expr, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Break(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Continue(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Jump(ExprId dest, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Return(const std::vector<ExprId>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId NoReturn(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Goto(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Label(uint64_t target, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarDeclare(const Variable& var, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInit(size_t size, const Variable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarInitSSA(
		    size_t size, const SSAVariable& dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Assign(size_t size, ExprId dest, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpack(
		    const std::vector<ExprId>& output, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignMemSSA(size_t size, ExprId dest, size_t destMemVersion, ExprId src, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AssignUnpackMemSSA(const std::vector<ExprId>& output, size_t destMemVersion, ExprId src,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Var(size_t size, const Variable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarSSA(size_t size, const SSAVariable& src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId VarPhi(const SSAVariable& dest, const std::vector<SSAVariable>& sources,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId MemPhi(
		    size_t dest, const std::vector<size_t>& sources, const ILSourceLocation& loc = ILSourceLocation());
		ExprId StructField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndex(size_t size, ExprId src, ExprId idx, const ILSourceLocation& loc = ILSourceLocation());
		ExprId ArrayIndexSSA(size_t size, ExprId src, size_t srcMemVersion, ExprId idx,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId Split(size_t size, ExprId high, ExprId low, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Deref(size_t size, ExprId src, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefField(size_t size, ExprId src, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefSSA(
		    size_t size, ExprId src, size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId DerefFieldSSA(size_t size, ExprId src, size_t srcMemVersion, uint64_t offset, size_t memberIndex,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId AddressOf(ExprId src, const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Call(ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Syscall(const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId TailCall(
		    ExprId dest, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId CallSSA(ExprId dest, const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
		ExprId SyscallSSA(const std::vector<ExprId>& params, size_t destMemVersion, size_t srcMemVersion,
		    const ILSourceLocation& loc = ILSourceLocation());
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
		ExprId Intrinsic(
		    uint32_t intrinsic, const std::vector<ExprId>& params, const ILSourceLocation& loc = ILSourceLocation());
		ExprId IntrinsicSSA(uint32_t intrinsic, const std::vector<ExprId>& params, size_t destMemVersion,
		    size_t srcMemVersion, const ILSourceLocation& loc = ILSourceLocation());
		ExprId Undefined(const ILSourceLocation& loc = ILSourceLocation());
		ExprId Unimplemented(const ILSourceLocation& loc = ILSourceLocation());
		ExprId UnimplementedMemoryRef(size_t size, ExprId target, const ILSourceLocation& loc = ILSourceLocation());
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

		std::vector<uint64_t> GetOperandList(ExprId i, size_t listOperand);
		ExprId AddOperandList(const std::vector<ExprId>& operands);
		ExprId AddIndexList(const std::vector<size_t>& operands);
		ExprId AddSSAVariableList(const std::vector<SSAVariable>& vars);

		BNHighLevelILInstruction GetRawExpr(size_t i) const;
		BNHighLevelILInstruction GetRawNonASTExpr(size_t i) const;
		HighLevelILInstruction operator[](size_t i);
		HighLevelILInstruction GetInstruction(size_t i);
		HighLevelILInstruction GetExpr(size_t i, bool asFullAst = true);
		size_t GetIndexForInstruction(size_t i) const;
		size_t GetInstructionForExpr(size_t expr) const;
		size_t GetInstructionCount() const;
		size_t GetExprCount() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockForInstruction(size_t i) const;

		Ref<HighLevelILFunction> GetSSAForm() const;
		Ref<HighLevelILFunction> GetNonSSAForm() const;
		size_t GetSSAInstructionIndex(size_t instr) const;
		size_t GetNonSSAInstructionIndex(size_t instr) const;
		size_t GetSSAExprIndex(size_t instr) const;
		size_t GetNonSSAExprIndex(size_t instr) const;

		size_t GetSSAVarDefinition(const SSAVariable& var) const;
		size_t GetSSAMemoryDefinition(size_t version) const;
		std::set<size_t> GetSSAVarUses(const SSAVariable& var) const;
		std::set<size_t> GetSSAMemoryUses(size_t version) const;
		bool IsSSAVarLive(const SSAVariable& var) const;
		bool IsSSAVarLiveAt(const SSAVariable& var, const size_t instr) const;
		bool IsVarLiveAt(const Variable& var, const size_t instr) const;

		std::set<size_t> GetVariableDefinitions(const Variable& var) const;
		std::set<size_t> GetVariableUses(const Variable& var) const;
		size_t GetSSAVarVersionAtInstruction(const Variable& var, size_t instr) const;
		size_t GetSSAMemoryVersionAtInstruction(size_t instr) const;

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		size_t GetMediumLevelILExprIndex(size_t expr) const;
		std::set<size_t> GetMediumLevelILExprIndexes(size_t expr) const;

		void UpdateInstructionOperand(size_t i, size_t operandIndex, ExprId value);
		void ReplaceExpr(size_t expr, size_t newExpr);

		void Finalize();
		void GenerateSSAForm(const std::set<Variable>& aliases = std::set<Variable>());

		std::vector<DisassemblyTextLine> GetExprText(
		    ExprId expr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetExprText(
		    const HighLevelILInstruction& instr, bool asFullAst = true, DisassemblySettings* settings = nullptr);
		std::vector<DisassemblyTextLine> GetInstructionText(
		    size_t i, bool asFullAst = true, DisassemblySettings* settings = nullptr);

		Confidence<Ref<Type>> GetExprType(size_t expr);
		Confidence<Ref<Type>> GetExprType(const HighLevelILInstruction& expr);

		void VisitAllExprs(const std::function<bool(const HighLevelILInstruction& expr)>& func);

		Ref<FlowGraph> CreateFunctionGraph(DisassemblySettings* settings = nullptr);

		size_t GetExprIndexForLabel(uint64_t label);
		std::set<size_t> GetUsesForLabel(uint64_t label);
	};
}