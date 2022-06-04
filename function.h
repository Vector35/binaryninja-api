#pragma once
#include "binaryninja_defs.h"
#include "registervalue.h"
#include "type.h"

extern "C" {
	struct BNArchitecture;
	struct BNBinaryView;
	struct BNFunction;
	struct BNPlatform;
	struct BNQualifiedName;
	struct BNReferenceSource;
	struct BNType;
	struct BNTypeWithConfidence;
	struct BNSymbol;
	struct BNLanguageRepresentationFunction;
	struct BNStackVariableReference;
	struct BNDisassemblySettings;
	struct BNWorkflow;
	struct BNPerformanceInfo;
	struct BNFlowGraph;

	struct BNILReferenceSource
	{
		BNFunction* func;
		BNArchitecture* arch;
		uint64_t addr;
		BNFunctionGraphType type;
		size_t exprId;
	};

	struct BNVariableNameAndType
	{
		BNVariable var;
		BNType* type;
		char* name;
		bool autoDefined;
		uint8_t typeConfidence;
	};

	struct BNVariableReferenceSource
	{
		BNVariable var;
		BNILReferenceSource source;
	};

	enum BNFunctionUpdateType
	{
		UserFunctionUpdate,
		FullAutoFunctionUpdate,
		IncrementalAutoFunctionUpdate
	};

	enum BNAnalysisSkipReason
	{
		NoSkipReason,
		AlwaysSkipReason,
		ExceedFunctionSizeSkipReason,
		ExceedFunctionAnalysisTimeSkipReason,
		ExceedFunctionUpdateCountSkipReason,
		NewAutoFunctionAnalysisSuppressedReason,
		BasicAnalysisSkipReason,
		IntermediateAnalysisSkipReason
	};

	enum BNFunctionAnalysisSkipOverride
	{
		DefaultFunctionAnalysisSkip,
		NeverSkipFunctionAnalysis,
		AlwaysSkipFunctionAnalysis
	};

	struct BNRegisterStackAdjustment
	{
		uint32_t regStack;
		int32_t adjustment;
		uint8_t confidence;
	};

	struct BNParameterVariablesWithConfidence
	{
		BNVariable* vars;
		size_t count;
		uint8_t confidence;
	};


	struct BNConstantReference
	{
		int64_t value;
		size_t size;
		bool pointer, intermediate;
	};

	struct BNArchitectureAndAddress
	{
		BNArchitecture* arch;
		uint64_t address;
	};

	struct BNUserVariableValue
	{
		BNVariable var;
		BNArchitectureAndAddress defSite;
		BNPossibleValueSet value;
	};

	struct BNIndirectBranchInfo
	{
		BNArchitecture* sourceArch;
		uint64_t sourceAddr;
		BNArchitecture* destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	struct BNPerformanceInfo
	{
		char* name;
		double seconds;
	};

	BINARYNINJACOREAPI void BNFreeILReferences(BNILReferenceSource* refs, size_t count);
	BINARYNINJACOREAPI void BNFreeVariableReferenceSourceList(BNVariableReferenceSource* vars, size_t count);

	BINARYNINJACOREAPI BNFunction* BNNewFunctionReference(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeFunction(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeFunctionList(BNFunction** funcs, size_t count);

	BINARYNINJACOREAPI BNBinaryView* BNGetFunctionData(BNFunction* func);
	BINARYNINJACOREAPI BNArchitecture* BNGetFunctionArchitecture(BNFunction* func);
	BINARYNINJACOREAPI BNPlatform* BNGetFunctionPlatform(BNFunction* func);
	BINARYNINJACOREAPI uint64_t BNGetFunctionStart(BNFunction* func);
	BINARYNINJACOREAPI BNSymbol* BNGetFunctionSymbol(BNFunction* func);
	BINARYNINJACOREAPI bool BNWasFunctionAutomaticallyDiscovered(BNFunction* func);
	BINARYNINJACOREAPI bool BNFunctionHasUserAnnotations(BNFunction* func);
	BINARYNINJACOREAPI BNBoolWithConfidence BNCanFunctionReturn(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAutoType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI void BNSetFunctionUserType(BNFunction* func, BNType* type);

	BINARYNINJACOREAPI char* BNGetFunctionComment(BNFunction* func);
	BINARYNINJACOREAPI char* BNGetCommentForAddress(BNFunction* func, uint64_t addr);
	BINARYNINJACOREAPI uint64_t* BNGetCommentedAddresses(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAddressList(uint64_t* addrs);
	BINARYNINJACOREAPI void BNSetFunctionComment(BNFunction* func, const char* comment);
	BINARYNINJACOREAPI void BNSetCommentForAddress(BNFunction* func, uint64_t addr, const char* comment);

	BINARYNINJACOREAPI void BNAddUserCodeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
	BINARYNINJACOREAPI void BNRemoveUserCodeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

	BINARYNINJACOREAPI void BNAddUserTypeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNRemoveUserTypeReference(
	    BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr, BNQualifiedName* name);
	BINARYNINJACOREAPI void BNAddUserTypeFieldReference(BNFunction* func, BNArchitecture* fromArch, uint64_t fromAddr,
	    BNQualifiedName* name, uint64_t offset, size_t size);
	BINARYNINJACOREAPI void BNRemoveUserTypeFieldReference(BNFunction* func, BNArchitecture* fromArch,
	    uint64_t fromAddr, BNQualifiedName* name, uint64_t offset, size_t size);


	BINARYNINJACOREAPI BNILReferenceSource* BNGetMediumLevelILVariableReferences(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesFrom(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNILReferenceSource* BNGetMediumLevelILVariableReferencesIfAvailable(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesFromIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetMediumLevelILVariableReferencesInRangeIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);

	BINARYNINJACOREAPI BNILReferenceSource* BNGetHighLevelILVariableReferences(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesFrom(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesInRange(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);
	BINARYNINJACOREAPI BNILReferenceSource* BNGetHighLevelILVariableReferencesIfAvailable(
	    BNFunction* func, BNVariable* var, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesFromIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, size_t* count);
	BINARYNINJACOREAPI BNVariableReferenceSource* BNGetHighLevelILVariableReferencesInRangeIfAvailable(
	    BNFunction* func, BNArchitecture* arch, uint64_t address, uint64_t len, size_t* count);

	BINARYNINJACOREAPI void BNReanalyzeFunction(BNFunction* func, BNFunctionUpdateType type);
	BINARYNINJACOREAPI void BNMarkUpdatesRequired(BNFunction* func, BNFunctionUpdateType type);
	BINARYNINJACOREAPI void BNMarkCallerUpdatesRequired(BNFunction* func, BNFunctionUpdateType type);

	BINARYNINJACOREAPI bool BNIsFunctionTooLarge(BNFunction* func);
	BINARYNINJACOREAPI bool BNIsFunctionAnalysisSkipped(BNFunction* func);
	BINARYNINJACOREAPI BNAnalysisSkipReason BNGetAnalysisSkipReason(BNFunction* func);
	BINARYNINJACOREAPI BNFunctionAnalysisSkipOverride BNGetFunctionAnalysisSkipOverride(BNFunction* func);
	BINARYNINJACOREAPI void BNSetFunctionAnalysisSkipOverride(BNFunction* func, BNFunctionAnalysisSkipOverride skip);

	BINARYNINJACOREAPI char* BNGetGotoLabelName(BNFunction* func, uint64_t labelId);
	BINARYNINJACOREAPI void BNSetUserGotoLabelName(BNFunction* func, uint64_t labelId, const char* name);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetStackLayout(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeVariableNameAndTypeList(BNVariableNameAndType* vars, size_t count);
	BINARYNINJACOREAPI void BNCreateAutoStackVariable(
	    BNFunction* func, int64_t offset, BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNCreateUserStackVariable(
	    BNFunction* func, int64_t offset, BNTypeWithConfidence* type, const char* name);
	BINARYNINJACOREAPI void BNDeleteAutoStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI void BNDeleteUserStackVariable(BNFunction* func, int64_t offset);
	BINARYNINJACOREAPI bool BNGetStackVariableAtFrameOffset(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, BNVariableNameAndType* var);
	BINARYNINJACOREAPI void BNFreeVariableNameAndType(BNVariableNameAndType* var);

	BINARYNINJACOREAPI BNVariableNameAndType* BNGetFunctionVariables(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNCreateAutoVariable(
	    BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type, const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNCreateUserVariable(
	    BNFunction* func, const BNVariable* var, BNTypeWithConfidence* type, const char* name, bool ignoreDisjointUses);
	BINARYNINJACOREAPI void BNDeleteUserVariable(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI bool BNIsVariableUserDefined(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetVariableType(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetVariableName(BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI char* BNGetRealVariableName(BNFunction* func, BNArchitecture* arch, const BNVariable* var);
	BINARYNINJACOREAPI BNDeadStoreElimination BNGetFunctionVariableDeadStoreElimination(
	    BNFunction* func, const BNVariable* var);
	BINARYNINJACOREAPI void BNSetFunctionVariableDeadStoreElimination(
	    BNFunction* func, const BNVariable* var, BNDeadStoreElimination mode);

	BINARYNINJACOREAPI BNReferenceSource* BNGetFunctionCallSites(BNFunction* func, size_t* count);

	BINARYNINJACOREAPI uint64_t BNToVariableIdentifier(const BNVariable* var);
	BINARYNINJACOREAPI BNVariable BNFromVariableIdentifier(uint64_t id);


	BINARYNINJACOREAPI bool BNIsFunctionUpdateNeeded(BNFunction* func);
	BINARYNINJACOREAPI void BNRequestAdvancedFunctionAnalysisData(BNFunction* func);
	BINARYNINJACOREAPI void BNReleaseAdvancedFunctionAnalysisData(BNFunction* func);
	BINARYNINJACOREAPI void BNReleaseAdvancedFunctionAnalysisDataMultiple(BNFunction* func, size_t count);

	BINARYNINJACOREAPI BNBasicBlock* BNGetFunctionBasicBlockAtAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI uint64_t BNGetFunctionHighestAddress(BNFunction* func);
	BINARYNINJACOREAPI uint64_t BNGetFunctionLowestAddress(BNFunction* func);
	BINARYNINJACOREAPI BNAddressRange* BNGetFunctionAddressRanges(BNFunction* func, size_t* count);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLowLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLowLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLowLevelILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILInstructionsForAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLowLevelILExitsForInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeILInstructionList(size_t* list);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMediumLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMediumLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMappedMediumLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNMediumLevelILFunction* BNGetFunctionMappedMediumLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFunctionHighLevelIL(BNFunction* func);
	BINARYNINJACOREAPI BNHighLevelILFunction* BNGetFunctionHighLevelILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNGetFunctionLanguageRepresentation(BNFunction* func);
	BINARYNINJACOREAPI BNLanguageRepresentationFunction* BNGetFunctionLanguageRepresentationIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetRegisterValueAfterInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t reg);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetStackContentsAfterInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t offset, size_t size);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNType* functionType, size_t i);
	BINARYNINJACOREAPI BNRegisterValue BNGetParameterValueAtLowLevelILInstruction(
	    BNFunction* func, size_t instr, BNType* functionType, size_t i);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersReadByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetRegistersWrittenByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNStackVariableReference* BNGetStackVariablesReferencedByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNStackVariableReference* BNGetStackVariablesReferencedByInstructionIfAvailable(
		BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeStackVariableReferenceList(BNStackVariableReference* refs, size_t count);
	BINARYNINJACOREAPI BNConstantReference* BNGetConstantsReferencedByInstruction(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNConstantReference* BNGetConstantsReferencedByInstructionIfAvailable(
		BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeConstantReferenceList(BNConstantReference* refs);

	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLiftedIL(BNFunction* func);
	BINARYNINJACOREAPI BNLowLevelILFunction* BNGetFunctionLiftedILIfAvailable(BNFunction* func);
	BINARYNINJACOREAPI size_t BNGetLiftedILForInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI size_t* BNGetLiftedILInstructionsForAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagUsesForDefinition(
	    BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI size_t* BNGetLiftedILFlagDefinitionsForUse(
	    BNFunction* func, size_t i, uint32_t flag, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsReadByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);
	BINARYNINJACOREAPI uint32_t* BNGetFlagsWrittenByLiftedILInstruction(BNFunction* func, size_t i, size_t* count);

	BINARYNINJACOREAPI BNType* BNGetFunctionType(BNFunction* func);
	BINARYNINJACOREAPI BNTypeWithConfidence BNGetFunctionReturnType(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionReturnRegisters(BNFunction* func);
	BINARYNINJACOREAPI BNCallingConventionWithConfidence BNGetFunctionCallingConvention(BNFunction* func);
	BINARYNINJACOREAPI BNParameterVariablesWithConfidence BNGetFunctionParameterVariables(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeParameterVariables(BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI BNBoolWithConfidence BNFunctionHasVariableArguments(BNFunction* func);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetFunctionStackAdjustment(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetFunctionRegisterStackAdjustments(
	    BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeRegisterStackAdjustments(BNRegisterStackAdjustment* adjustments);
	BINARYNINJACOREAPI BNRegisterSetWithConfidence BNGetFunctionClobberedRegisters(BNFunction* func);
	BINARYNINJACOREAPI void BNFreeRegisterSet(BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetAutoFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetAutoFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCallingConvention(
	    BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetAutoFunctionParameterVariables(
	    BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetAutoFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetAutoFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetAutoFunctionStackAdjustment(BNFunction* func, BNOffsetWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetAutoFunctionRegisterStackAdjustments(
	    BNFunction* func, BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetAutoFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNSetUserFunctionReturnType(BNFunction* func, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetUserFunctionReturnRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);
	BINARYNINJACOREAPI void BNSetUserFunctionCallingConvention(
	    BNFunction* func, BNCallingConventionWithConfidence* convention);
	BINARYNINJACOREAPI void BNSetUserFunctionParameterVariables(
	    BNFunction* func, BNParameterVariablesWithConfidence* vars);
	BINARYNINJACOREAPI void BNSetUserFunctionHasVariableArguments(BNFunction* func, BNBoolWithConfidence* varArgs);
	BINARYNINJACOREAPI void BNSetUserFunctionCanReturn(BNFunction* func, BNBoolWithConfidence* returns);
	BINARYNINJACOREAPI void BNSetUserFunctionStackAdjustment(BNFunction* func, BNOffsetWithConfidence* stackAdjust);
	BINARYNINJACOREAPI void BNSetUserFunctionRegisterStackAdjustments(
	    BNFunction* func, BNRegisterStackAdjustment* adjustments, size_t count);
	BINARYNINJACOREAPI void BNSetUserFunctionClobberedRegisters(BNFunction* func, BNRegisterSetWithConfidence* regs);

	BINARYNINJACOREAPI void BNApplyImportedTypes(BNFunction* func, BNSymbol* sym, BNType* type);
	BINARYNINJACOREAPI void BNApplyAutoDiscoveredFunctionType(BNFunction* func, BNType* type);
	BINARYNINJACOREAPI bool BNFunctionHasExplicitlyDefinedType(BNFunction* func);

	BINARYNINJACOREAPI BNDisassemblyTextLine* BNGetFunctionTypeTokens(
	    BNFunction* func, BNDisassemblySettings* settings, size_t* count);

	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionGlobalPointerValue(BNFunction* func);
	BINARYNINJACOREAPI BNRegisterValueWithConfidence BNGetFunctionRegisterValueAtExit(BNFunction* func, uint32_t reg);

	BINARYNINJACOREAPI bool BNGetInstructionContainingAddress(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint64_t* start);


	BINARYNINJACOREAPI void BNMarkFunctionAsRecentlyUsed(BNFunction* func);

	BINARYNINJACOREAPI void BNSetAutoIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	    BNArchitectureAndAddress* branches, size_t count);
	BINARYNINJACOREAPI void BNSetUserIndirectBranches(BNFunction* func, BNArchitecture* sourceArch, uint64_t source,
	    BNArchitectureAndAddress* branches, size_t count);

	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranches(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI BNIndirectBranchInfo* BNGetIndirectBranchesAt(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI void BNFreeIndirectBranchList(BNIndirectBranchInfo* branches);

	BINARYNINJACOREAPI uint64_t* BNGetUnresolvedIndirectBranches(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI bool BNHasUnresolvedIndirectBranches(BNFunction* func);

	BINARYNINJACOREAPI void BNSetAutoCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetUserCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNTypeWithConfidence* type);
	BINARYNINJACOREAPI void BNSetAutoCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, int64_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNRegisterStackAdjustment* adjust, size_t count);
	BINARYNINJACOREAPI void BNSetAutoCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);
	BINARYNINJACOREAPI void BNSetUserCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack, int32_t adjust, uint8_t confidence);

	BINARYNINJACOREAPI BNTypeWithConfidence BNGetCallTypeAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNOffsetWithConfidence BNGetCallStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI BNRegisterStackAdjustment* BNGetCallRegisterStackAdjustment(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);
	BINARYNINJACOREAPI BNRegisterStackAdjustment BNGetCallRegisterStackAdjustmentForRegisterStack(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, uint32_t regStack);
	BINARYNINJACOREAPI bool BNIsCallInstruction(BNFunction* func, BNArchitecture* arch, uint64_t addr);

	BINARYNINJACOREAPI BNInstructionTextLine* BNGetFunctionBlockAnnotations(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, size_t* count);

	BINARYNINJACOREAPI BNIntegerDisplayType BNGetIntegerConstantDisplayType(
	    BNFunction* func, BNArchitecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
	BINARYNINJACOREAPI void BNSetIntegerConstantDisplayType(BNFunction* func, BNArchitecture* arch, uint64_t instrAddr,
	    uint64_t value, size_t operand, BNIntegerDisplayType type);

	BINARYNINJACOREAPI void BNRequestFunctionDebugReport(BNFunction* func, const char* name);

	BINARYNINJACOREAPI void BNFreeVariableList(BNVariable* vars);

	BINARYNINJACOREAPI BNWorkflow* BNGetWorkflowForFunction(BNFunction* func);

	BINARYNINJACOREAPI BNHighlightColor BNGetInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr);
	BINARYNINJACOREAPI void BNSetAutoInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNHighlightColor color);
	BINARYNINJACOREAPI void BNSetUserInstructionHighlight(
	    BNFunction* func, BNArchitecture* arch, uint64_t addr, BNHighlightColor color);

	BINARYNINJACOREAPI BNPerformanceInfo* BNGetFunctionAnalysisPerformanceInfo(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeAnalysisPerformanceInfo(BNPerformanceInfo* info, size_t count);

	BINARYNINJACOREAPI BNFlowGraph* BNGetUnresolvedStackAdjustmentGraph(BNFunction* func);

	BINARYNINJACOREAPI void BNSetUserVariableValue(BNFunction* func, const BNVariable* var,
	    const BNArchitectureAndAddress* defSite, const BNPossibleValueSet* value);
	BINARYNINJACOREAPI void BNClearUserVariableValue(
	    BNFunction* func, const BNVariable* var, const BNArchitectureAndAddress* defSite);
	BINARYNINJACOREAPI BNUserVariableValue* BNGetAllUserVariableValues(BNFunction* func, size_t* count);
	BINARYNINJACOREAPI void BNFreeUserVariableValues(BNUserVariableValue* result);

}