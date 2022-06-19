#pragma once
#include "core/binaryninja_defs.h"

#define BN_MAX_INSTRUCTION_BRANCHES   3
#define BN_MAX_INSTRUCTION_LENGTH     256
#define BN_DEFAULT_INSTRUCTION_LENGTH 16
#define BN_DEFAULT_OPCODE_DISPLAY     8

extern "C" {
	struct BNArchitecture;
	struct BNCallingConvention;
	struct BNDataBuffer;
	struct BNDisassemblySettings;
	struct BNDisassemblyTextRenderer;
	struct BNFunction;
	struct BNFunctionRecognizer;
	struct BNInstructionTextToken;
	struct BNLowLevelILFunction;
	struct BNMediumLevelILFunction;
	struct BNNameAndType;
	struct BNRegisterOrConstant;
	struct BNType;
	struct BNTypeWithConfidence;
	struct BNHighLevelILFunction;
	struct BNBasicBlock;

	enum BNFlagRole
	{
		SpecialFlagRole = 0,
		ZeroFlagRole = 1,
		PositiveSignFlagRole = 2,
		NegativeSignFlagRole = 3,
		CarryFlagRole = 4,
		OverflowFlagRole = 5,
		HalfCarryFlagRole = 6,
		EvenParityFlagRole = 7,
		OddParityFlagRole = 8,
		OrderedFlagRole = 9,
		UnorderedFlagRole = 10
	};



	struct BNNameAndType
	{
		char* name;
		BNType* type;
		uint8_t typeConfidence;
	};

	struct BNRegisterStackInfo
	{
		uint32_t firstStorageReg, firstTopRelativeReg;
		uint32_t storageCount, topRelativeCount;
		uint32_t stackTopReg;
	};

	enum BNImplicitRegisterExtend
	{
		NoExtend,
		ZeroExtendToFullWidth,
		SignExtendToFullWidth
	};


	struct BNRegisterInfo
	{
		uint32_t fullWidthRegister;
		size_t offset;
		size_t size;
		BNImplicitRegisterExtend extend;
	};

	struct BNInstructionInfo
	{
		size_t length;
		size_t branchCount;
		bool archTransitionByTargetAddr;
		bool branchDelay;
		BNBranchType branchType[BN_MAX_INSTRUCTION_BRANCHES];
		uint64_t branchTarget[BN_MAX_INSTRUCTION_BRANCHES];
		BNArchitecture* branchArch[BN_MAX_INSTRUCTION_BRANCHES];  // If null, same architecture as instruction
	};

	struct BNInstructionTextLine
	{
		BNInstructionTextToken* tokens;
		size_t count;
	};


	struct BNFlagConditionForSemanticClass
	{
		uint32_t semanticClass;
		BNLowLevelILFlagCondition condition;
	};

	struct BNCustomArchitecture
	{
		void* context;
		void (*init)(void* context, BNArchitecture* obj);
		BNEndianness (*getEndianness)(void* ctxt);
		size_t (*getAddressSize)(void* ctxt);
		size_t (*getDefaultIntegerSize)(void* ctxt);
		size_t (*getInstructionAlignment)(void* ctxt);
		size_t (*getMaxInstructionLength)(void* ctxt);
		size_t (*getOpcodeDisplayLength)(void* ctxt);
		BNArchitecture* (*getAssociatedArchitectureByAddress)(void* ctxt, uint64_t* addr);
		bool (*getInstructionInfo)(
			void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		bool (*getInstructionText)(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
			BNInstructionTextToken** result, size_t* count);
		void (*freeInstructionText)(BNInstructionTextToken* tokens, size_t count);
		bool (*getInstructionLowLevelIL)(
			void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
		char* (*getRegisterName)(void* ctxt, uint32_t reg);
		char* (*getFlagName)(void* ctxt, uint32_t flag);
		char* (*getFlagWriteTypeName)(void* ctxt, uint32_t flags);
		char* (*getSemanticFlagClassName)(void* ctxt, uint32_t semClass);
		char* (*getSemanticFlagGroupName)(void* ctxt, uint32_t semGroup);
		uint32_t* (*getFullWidthRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getAllRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getAllFlags)(void* ctxt, size_t* count);
		uint32_t* (*getAllFlagWriteTypes)(void* ctxt, size_t* count);
		uint32_t* (*getAllSemanticFlagClasses)(void* ctxt, size_t* count);
		uint32_t* (*getAllSemanticFlagGroups)(void* ctxt, size_t* count);
		BNFlagRole (*getFlagRole)(void* ctxt, uint32_t flag, uint32_t semClass);
		uint32_t* (*getFlagsRequiredForFlagCondition)(
			void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
		uint32_t* (*getFlagsRequiredForSemanticFlagGroup)(void* ctxt, uint32_t semGroup, size_t* count);
		BNFlagConditionForSemanticClass* (*getFlagConditionsForSemanticFlagGroup)(
			void* ctxt, uint32_t semGroup, size_t* count);
		void (*freeFlagConditionsForSemanticFlagGroup)(void* ctxt, BNFlagConditionForSemanticClass* conditions);
		uint32_t* (*getFlagsWrittenByFlagWriteType)(void* ctxt, uint32_t writeType, size_t* count);
		uint32_t (*getSemanticClassForFlagWriteType)(void* ctxt, uint32_t writeType);
		size_t (*getFlagWriteLowLevelIL)(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
			uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il);
		size_t (*getFlagConditionLowLevelIL)(
			void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
		size_t (*getSemanticFlagGroupLowLevelIL)(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		void (*freeRegisterList)(void* ctxt, uint32_t* regs);
		void (*getRegisterInfo)(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		uint32_t (*getStackPointerRegister)(void* ctxt);
		uint32_t (*getLinkRegister)(void* ctxt);
		uint32_t* (*getGlobalRegisters)(void* ctxt, size_t* count);
		uint32_t* (*getSystemRegisters)(void* ctxt, size_t* count);

		char* (*getRegisterStackName)(void* ctxt, uint32_t regStack);
		uint32_t* (*getAllRegisterStacks)(void* ctxt, size_t* count);
		void (*getRegisterStackInfo)(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		char* (*getIntrinsicName)(void* ctxt, uint32_t intrinsic);
		uint32_t* (*getAllIntrinsics)(void* ctxt, size_t* count);
		BNNameAndType* (*getIntrinsicInputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeNameAndTypeList)(void* ctxt, BNNameAndType* nt, size_t count);
		BNTypeWithConfidence* (*getIntrinsicOutputs)(void* ctxt, uint32_t intrinsic, size_t* count);
		void (*freeTypeList)(void* ctxt, BNTypeWithConfidence* types, size_t count);

		bool (*canAssemble)(void* ctxt);
		bool (*assemble)(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);

		bool (*isNeverBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isAlwaysBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isInvertBranchPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isSkipAndReturnZeroPatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		bool (*isSkipAndReturnValuePatchAvailable)(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

		bool (*convertToNop)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*alwaysBranch)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*invertBranch)(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		bool (*skipAndReturnValue)(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value);
	};

	struct BNStackVariableReference
	{
		uint32_t sourceOperand;
		uint8_t typeConfidence;
		BNType* type;
		char* name;
		uint64_t varIdentifier;
		int64_t referencedOffset;
		size_t size;
	};

	// Architectures
	BINARYNINJACOREAPI BNArchitecture* BNGetArchitectureByName(const char* name);
	BINARYNINJACOREAPI BNArchitecture** BNGetArchitectureList(size_t* count);
	BINARYNINJACOREAPI void BNFreeArchitectureList(BNArchitecture** archs);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitecture(const char* name, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureExtension(
		const char* name, BNArchitecture* base, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI void BNAddArchitectureRedirection(
		BNArchitecture* arch, BNArchitecture* from, BNArchitecture* to);
	BINARYNINJACOREAPI BNArchitecture* BNRegisterArchitectureHook(BNArchitecture* base, BNCustomArchitecture* arch);
	BINARYNINJACOREAPI void BNFinalizeArchitectureHook(BNArchitecture* base);
	BINARYNINJACOREAPI BNArchitecture* BNGetNativeTypeParserArchitecture();

	BINARYNINJACOREAPI char* BNGetArchitectureName(BNArchitecture* arch);
	BINARYNINJACOREAPI BNEndianness BNGetArchitectureEndianness(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureAddressSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureDefaultIntegerSize(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureInstructionAlignment(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureMaxInstructionLength(BNArchitecture* arch);
	BINARYNINJACOREAPI size_t BNGetArchitectureOpcodeDisplayLength(BNArchitecture* arch);
	BINARYNINJACOREAPI BNArchitecture* BNGetAssociatedArchitectureByAddress(BNArchitecture* arch, uint64_t* addr);
	BINARYNINJACOREAPI bool BNGetInstructionInfo(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
	BINARYNINJACOREAPI bool BNGetInstructionText(BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t* len,
		BNInstructionTextToken** result, size_t* count);
	BINARYNINJACOREAPI bool BNGetInstructionLowLevelIL(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI void BNFreeInstructionText(BNInstructionTextToken* tokens, size_t count);
	BINARYNINJACOREAPI void BNFreeInstructionTextLines(BNInstructionTextLine* lines, size_t count);
	BINARYNINJACOREAPI char* BNGetArchitectureRegisterName(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI char* BNGetArchitectureFlagName(BNArchitecture* arch, uint32_t flag);
	BINARYNINJACOREAPI char* BNGetArchitectureFlagWriteTypeName(BNArchitecture* arch, uint32_t flags);
	BINARYNINJACOREAPI char* BNGetArchitectureSemanticFlagClassName(BNArchitecture* arch, uint32_t semClass);
	BINARYNINJACOREAPI char* BNGetArchitectureSemanticFlagGroupName(BNArchitecture* arch, uint32_t semGroup);
	BINARYNINJACOREAPI uint32_t* BNGetFullWidthArchitectureRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureFlags(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureFlagWriteTypes(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureSemanticFlagClasses(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureSemanticFlagGroups(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNFlagRole BNGetArchitectureFlagRole(BNArchitecture* arch, uint32_t flag, uint32_t semClass);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForFlagCondition(
		BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsRequiredForSemanticFlagGroup(
		BNArchitecture* arch, uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI BNFlagConditionForSemanticClass* BNGetArchitectureFlagConditionsForSemanticFlagGroup(
		BNArchitecture* arch, uint32_t semGroup, size_t* count);
	BINARYNINJACOREAPI void BNFreeFlagConditionsForSemanticFlagGroup(BNFlagConditionForSemanticClass* conditions);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureFlagsWrittenByFlagWriteType(
		BNArchitecture* arch, uint32_t writeType, size_t* count);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureSemanticClassForFlagWriteType(
		BNArchitecture* arch, uint32_t writeType);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagWriteLowLevelIL(BNArchitecture* arch, BNLowLevelILOperation op,
		size_t size, uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
		BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagWriteLowLevelIL(BNArchitecture* arch,
		BNLowLevelILOperation op, size_t size, BNFlagRole role, BNRegisterOrConstant* operands, size_t operandCount,
		BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureFlagConditionLowLevelIL(
		BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetDefaultArchitectureFlagConditionLowLevelIL(
		BNArchitecture* arch, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI size_t BNGetArchitectureSemanticFlagGroupLowLevelIL(
		BNArchitecture* arch, uint32_t semGroup, BNLowLevelILFunction* il);
	BINARYNINJACOREAPI uint32_t* BNGetModifiedArchitectureRegistersOnWrite(
		BNArchitecture* arch, uint32_t reg, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterList(uint32_t* regs);
	BINARYNINJACOREAPI BNRegisterInfo BNGetArchitectureRegisterInfo(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureStackPointerRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureLinkRegister(BNArchitecture* arch);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureGlobalRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI bool BNIsArchitectureGlobalRegister(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t* BNGetArchitectureSystemRegisters(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI bool BNIsArchitectureSystemRegister(BNArchitecture* arch, uint32_t reg);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterByName(BNArchitecture* arch, const char* name);

	BINARYNINJACOREAPI char* BNGetArchitectureRegisterStackName(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureRegisterStacks(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackInfo BNGetArchitectureRegisterStackInfo(BNArchitecture* arch, uint32_t regStack);
	BINARYNINJACOREAPI uint32_t BNGetArchitectureRegisterStackForRegister(BNArchitecture* arch, uint32_t reg);

	BINARYNINJACOREAPI char* BNGetArchitectureIntrinsicName(BNArchitecture* arch, uint32_t intrinsic);
	BINARYNINJACOREAPI uint32_t* BNGetAllArchitectureIntrinsics(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNNameAndType* BNGetArchitectureIntrinsicInputs(
		BNArchitecture* arch, uint32_t intrinsic, size_t* count);
	BINARYNINJACOREAPI void BNFreeNameAndTypeList(BNNameAndType* nt, size_t count);
	BINARYNINJACOREAPI BNTypeWithConfidence* BNGetArchitectureIntrinsicOutputs(
		BNArchitecture* arch, uint32_t intrinsic, size_t* count);
	BINARYNINJACOREAPI void BNFreeOutputTypeList(BNTypeWithConfidence* types, size_t count);

	BINARYNINJACOREAPI bool BNCanArchitectureAssemble(BNArchitecture* arch);
	BINARYNINJACOREAPI bool BNAssemble(
		BNArchitecture* arch, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);

	BINARYNINJACOREAPI bool BNIsArchitectureNeverBranchPatchAvailable(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureAlwaysBranchPatchAvailable(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureInvertBranchPatchAvailable(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnZeroPatchAvailable(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNIsArchitectureSkipAndReturnValuePatchAvailable(
		BNArchitecture* arch, const uint8_t* data, uint64_t addr, size_t len);

	BINARYNINJACOREAPI bool BNArchitectureConvertToNop(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureAlwaysBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureInvertBranch(BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len);
	BINARYNINJACOREAPI bool BNArchitectureSkipAndReturnValue(
		BNArchitecture* arch, uint8_t* data, uint64_t addr, size_t len, uint64_t value);
	BINARYNINJACOREAPI void BNRegisterArchitectureFunctionRecognizer(BNArchitecture* arch, BNFunctionRecognizer* rec);
	BINARYNINJACOREAPI bool BNIsBinaryViewTypeArchitectureConstantDefined(
		BNArchitecture* arch, const char* type, const char* name);
	BINARYNINJACOREAPI uint64_t BNGetBinaryViewTypeArchitectureConstant(
		BNArchitecture* arch, const char* type, const char* name, uint64_t defaultValue);
	BINARYNINJACOREAPI void BNSetBinaryViewTypeArchitectureConstant(
		BNArchitecture* arch, const char* type, const char* name, uint64_t value);

	BINARYNINJACOREAPI BNCallingConvention** BNGetArchitectureCallingConventions(BNArchitecture* arch, size_t* count);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureCallingConventionByName(
		BNArchitecture* arch, const char* name);

	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureDefaultCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureCdeclCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureStdcallCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI BNCallingConvention* BNGetArchitectureFastcallCallingConvention(BNArchitecture* arch);
	BINARYNINJACOREAPI void BNSetArchitectureDefaultCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureCdeclCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureStdcallCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);
	BINARYNINJACOREAPI void BNSetArchitectureFastcallCallingConvention(BNArchitecture* arch, BNCallingConvention* cc);

	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateDisassemblyTextRenderer(
		BNFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateLowLevelILDisassemblyTextRenderer(
		BNLowLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateMediumLevelILDisassemblyTextRenderer(
		BNMediumLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNCreateHighLevelILDisassemblyTextRenderer(
		BNHighLevelILFunction* func, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI BNDisassemblyTextRenderer* BNNewDisassemblyTextRendererReference(
		BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI void BNFreeDisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNFunction* BNGetDisassemblyTextRendererFunction(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetDisassemblyTextRendererLowLevelILFunction(
		BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetDisassemblyTextRendererMediumLevelILFunction(
		BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetDisassemblyTextRendererHighLevelILFunction(
		BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNBasicBlock* BNGetDisassemblyTextRendererBasicBlock(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNArchitecture* BNGetDisassemblyTextRendererArchitecture(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNDisassemblySettings* BNGetDisassemblyTextRendererSettings(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererBasicBlock(
		BNDisassemblyTextRenderer* renderer, BNBasicBlock* block);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererArchitecture(
		BNDisassemblyTextRenderer* renderer, BNArchitecture* arch);
	BINARYNINJACOREAPI void BNSetDisassemblyTextRendererSettings(
		BNDisassemblyTextRenderer* renderer, BNDisassemblySettings* settings);
	BINARYNINJACOREAPI bool BNIsILDisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI bool BNDisassemblyTextRendererHasDataFlow(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererInstructionAnnotations(
		BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererInstructionText(
		BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* len, BNDisassemblyTextLine** result, size_t* count);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererLines(
		BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t* len, BNDisassemblyTextLine** result, size_t* count);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNPostProcessDisassemblyTextRendererLines(
		BNDisassemblyTextRenderer* renderer, uint64_t addr, size_t len, BNDisassemblyTextLine* inLines, size_t inCount,
		size_t* outCount, const char* indentSpaces);
	BINARYNINJACOREAPI void BNResetDisassemblyTextRendererDeduplicatedComments(BNDisassemblyTextRenderer* renderer);
	BINARYNINJACOREAPI bool BNGetDisassemblyTextRendererSymbolTokens(BNDisassemblyTextRenderer* renderer, uint64_t addr,
		size_t size, size_t operand, BNInstructionTextToken** result, size_t* count);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererStackVariableReferenceTokens(
		BNDisassemblyTextRenderer* renderer, BNStackVariableReference* ref, size_t* count);
	BINARYNINJACOREAPI bool BNIsIntegerToken(BNInstructionTextTokenType type);
	BINARYNINJACOREAPI BNInstructionTextToken* BNGetDisassemblyTextRendererIntegerTokens(
		BNDisassemblyTextRenderer* renderer, BNInstructionTextToken* token, BNArchitecture* arch, uint64_t addr,
		size_t* count);
	BINARYNINJACOREAPI BNDisassemblyTextLine* BNDisassemblyTextRendererWrapComment(BNDisassemblyTextRenderer* renderer,
		const BNDisassemblyTextLine* inLine, size_t* outLineCount, const char* comment, bool hasAutoAnnotations,
		const char* leadingSpaces, const char* indentSpaces);

}