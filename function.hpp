#pragma once
#include <vector>
#include <set>
#include <map>
#include "binaryninja_defs.h"
#include "function.h"

#include "binaryninjaapi_new.hpp"
#include "registervalue.hpp"
#include "confidence.hpp"
#include "variable.hpp"

namespace BinaryNinja {

	struct ArchAndAddr;
	class Architecture;
	class BasicBlock;
	class BinaryView;
	class CallingConvention;
	class DisassemblySettings;
	class DisassemblyTextLine;
	class FlowGraph;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class Platform;
	class QualifiedName;
	class SSAVariable;
	class Symbol;
	class Tag;
	class TagReference;
	class TagType;
	class Type;
	class VariableReferenceSource;
	class Workflow;
	struct StackVariableReference;
	struct InstructionTextToken;

	struct IndirectBranchInfo
	{
		Ref<Architecture> sourceArch;
		uint64_t sourceAddr;
		Ref<Architecture> destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	class Function : public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
		int m_advancedAnalysisRequests;

	  public:
		Function(BNFunction* func);
		virtual ~Function();

		Ref<BinaryView> GetView() const;
		Ref<Architecture> GetArchitecture() const;
		Ref<Platform> GetPlatform() const;
		uint64_t GetStart() const;
		Ref<Symbol> GetSymbol() const;
		bool WasAutomaticallyDiscovered() const;
		bool HasUserAnnotations() const;
		Confidence<bool> CanReturn() const;
		bool HasExplicitlyDefinedType() const;
		bool NeedsUpdate() const;

		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;
		void MarkRecentUse();

		std::string GetComment() const;
		std::string GetCommentForAddress(uint64_t addr) const;
		std::vector<uint64_t> GetCommentedAddresses() const;
		void SetComment(const std::string& comment);
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		std::vector<ReferenceSource> GetCallSites() const;

		void AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
		void RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);
		void AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);
		void RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);
		void AddUserTypeFieldReference(
			Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);
		void RemoveUserTypeFieldReference(
			Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		Ref<LowLevelILFunction> GetLowLevelIL() const;
		Ref<LowLevelILFunction> GetLowLevelILIfAvailable() const;
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLowLevelILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::vector<size_t> GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr);
		RegisterValue GetRegisterValueAtInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetRegisterValueAfterInstruction(Architecture* arch, uint64_t addr, uint32_t reg);
		RegisterValue GetStackContentsAtInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetStackContentsAfterInstruction(Architecture* arch, uint64_t addr, int64_t offset, size_t size);
		RegisterValue GetParameterValueAtInstruction(Architecture* arch, uint64_t addr, Type* functionType, size_t i);
		RegisterValue GetParameterValueAtLowLevelILInstruction(size_t instr, Type* functionType, size_t i);
		std::vector<uint32_t> GetRegistersReadByInstruction(Architecture* arch, uint64_t addr);
		std::vector<uint32_t> GetRegistersWrittenByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<StackVariableReference> GetStackVariablesReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstruction(Architecture* arch, uint64_t addr);
		std::vector<BNConstantReference> GetConstantsReferencedByInstructionIfAvailable(
			Architecture* arch, uint64_t addr);

		std::vector<ILReferenceSource> GetMediumLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRange(
			Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetMediumLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesFromIfAvailable(
			Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetMediumLevelILVariableReferencesInRangeIfAvailable(
			Architecture* arch, uint64_t addr, uint64_t len);

		std::vector<ILReferenceSource> GetHighLevelILVariableReferences(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFrom(Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRange(
			Architecture* arch, uint64_t addr, uint64_t len);
		std::vector<ILReferenceSource> GetHighLevelILVariableReferencesIfAvailable(const Variable& var);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesFromIfAvailable(
			Architecture* arch, uint64_t addr);
		std::vector<VariableReferenceSource> GetHighLevelILVariableReferencesInRangeIfAvailable(
			Architecture* arch, uint64_t addr, uint64_t len);

		Ref<LowLevelILFunction> GetLiftedIL() const;
		Ref<LowLevelILFunction> GetLiftedILIfAvailable() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		Ref<MediumLevelILFunction> GetMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMediumLevelILIfAvailable() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;
		Ref<MediumLevelILFunction> GetMappedMediumLevelILIfAvailable() const;
		Ref<HighLevelILFunction> GetHighLevelIL() const;
		Ref<HighLevelILFunction> GetHighLevelILIfAvailable() const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentation() const;
		Ref<LanguageRepresentationFunction> GetLanguageRepresentationIfAvailable() const;

		Ref<Type> GetType() const;
		Confidence<Ref<Type>> GetReturnType() const;
		Confidence<std::vector<uint32_t>> GetReturnRegisters() const;
		Confidence<Ref<CallingConvention>> GetCallingConvention() const;
		Confidence<std::vector<Variable>> GetParameterVariables() const;
		Confidence<bool> HasVariableArguments() const;
		Confidence<int64_t> GetStackAdjustment() const;
		std::map<uint32_t, Confidence<int32_t>> GetRegisterStackAdjustments() const;
		Confidence<std::set<uint32_t>> GetClobberedRegisters() const;

		void SetAutoType(Type* type);
		void SetAutoReturnType(const Confidence<Ref<Type>>& type);
		void SetAutoReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetAutoCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetAutoParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetAutoHasVariableArguments(const Confidence<bool>& varArgs);
		void SetAutoCanReturn(const Confidence<bool>& returns);
		void SetAutoStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetAutoRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetAutoClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void SetUserType(Type* type);
		void SetReturnType(const Confidence<Ref<Type>>& type);
		void SetReturnRegisters(const Confidence<std::vector<uint32_t>>& returnRegs);
		void SetCallingConvention(const Confidence<Ref<CallingConvention>>& convention);
		void SetParameterVariables(const Confidence<std::vector<Variable>>& vars);
		void SetHasVariableArguments(const Confidence<bool>& varArgs);
		void SetCanReturn(const Confidence<bool>& returns);
		void SetStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		void ApplyImportedTypes(Symbol* sym, Ref<Type> type = nullptr);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FlowGraph> CreateFunctionGraph(BNFunctionGraphType type, DisassemblySettings* settings = nullptr);

		std::map<int64_t, std::vector<VariableNameAndType>> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr, int64_t offset, VariableNameAndType& var);

		std::map<Variable, VariableNameAndType> GetVariables();
		std::set<Variable> GetMediumLevelILVariables();
		std::set<Variable> GetMediumLevelILAliasedVariables();
		std::set<SSAVariable> GetMediumLevelILSSAVariables();
		std::set<Variable> GetHighLevelILVariables();
		std::set<Variable> GetHighLevelILAliasedVariables();
		std::set<SSAVariable> GetHighLevelILSSAVariables();

		std::set<Variable> GetMediumLevelILVariablesIfAvailable();
		std::set<Variable> GetMediumLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetMediumLevelILSSAVariablesIfAvailable();
		std::set<Variable> GetHighLevelILVariablesIfAvailable();
		std::set<Variable> GetHighLevelILAliasedVariablesIfAvailable();
		std::set<SSAVariable> GetHighLevelILSSAVariablesIfAvailable();

		void CreateAutoVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
			bool ignoreDisjointUses = false);
		void CreateUserVariable(const Variable& var, const Confidence<Ref<Type>>& type, const std::string& name,
			bool ignoreDisjointUses = false);
		void DeleteAutoVariable(const Variable& var);
		void DeleteUserVariable(const Variable& var);
		bool IsVariableUserDefinded(const Variable& var);
		Confidence<Ref<Type>> GetVariableType(const Variable& var);
		std::string GetVariableName(const Variable& var);

		void SetAutoIndirectBranches(
			Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);
		void SetUserIndirectBranches(
			Architecture* sourceArch, uint64_t source, const std::vector<ArchAndAddr>& branches);

		std::vector<IndirectBranchInfo> GetIndirectBranches();
		std::vector<IndirectBranchInfo> GetIndirectBranchesAt(Architecture* arch, uint64_t addr);

		std::vector<uint64_t> GetUnresolvedIndirectBranches();
		bool HasUnresolvedIndirectBranches();

		void SetAutoCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetAutoCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetAutoCallRegisterStackAdjustment(
			Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetAutoCallRegisterStackAdjustment(
			Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);
		void SetUserCallTypeAdjustment(Architecture* arch, uint64_t addr, const Confidence<Ref<Type>>& adjust);
		void SetUserCallStackAdjustment(Architecture* arch, uint64_t addr, const Confidence<int64_t>& adjust);
		void SetUserCallRegisterStackAdjustment(
			Architecture* arch, uint64_t addr, const std::map<uint32_t, Confidence<int32_t>>& adjust);
		void SetUserCallRegisterStackAdjustment(
			Architecture* arch, uint64_t addr, uint32_t regStack, const Confidence<int32_t>& adjust);

		Confidence<Ref<Type>> GetCallTypeAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int64_t> GetCallStackAdjustment(Architecture* arch, uint64_t addr);
		std::map<uint32_t, Confidence<int32_t>> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr);
		Confidence<int32_t> GetCallRegisterStackAdjustment(Architecture* arch, uint64_t addr, uint32_t regStack);
		bool IsCallInstruction(Architecture* arch, uint64_t addr);

		std::vector<std::vector<InstructionTextToken>> GetBlockAnnotations(Architecture* arch, uint64_t addr);

		BNIntegerDisplayType GetIntegerConstantDisplayType(
			Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
		void SetIntegerConstantDisplayType(
			Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand, BNIntegerDisplayType type);

		BNHighlightColor GetInstructionHighlight(Architecture* arch, uint64_t addr);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetAutoInstructionHighlight(
			Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetAutoInstructionHighlight(
			Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightColor color);
		void SetUserInstructionHighlight(
			Architecture* arch, uint64_t addr, BNHighlightStandardColor color, uint8_t alpha = 255);
		void SetUserInstructionHighlight(Architecture* arch, uint64_t addr, BNHighlightStandardColor color,
			BNHighlightStandardColor mixColor, uint8_t mix, uint8_t alpha = 255);
		void SetUserInstructionHighlight(
			Architecture* arch, uint64_t addr, uint8_t r, uint8_t g, uint8_t b, uint8_t alpha = 255);

		std::vector<TagReference> GetAllTagReferences();
		std::vector<TagReference> GetTagReferencesOfType(Ref<TagType> tagType);

		std::vector<TagReference> GetAddressTagReferences();
		std::vector<TagReference> GetAutoAddressTagReferences();
		std::vector<TagReference> GetUserAddressTagReferences();
		std::vector<Ref<Tag>> GetAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAutoAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetUserAddressTags(Architecture* arch, uint64_t addr);
		std::vector<Ref<Tag>> GetAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		std::vector<TagReference> GetAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetAutoAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		std::vector<TagReference> GetUserAddressTagsInRange(Architecture* arch, uint64_t start, uint64_t end);
		void AddAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveAutoAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);
		void AddUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTag(Architecture* arch, uint64_t addr, Ref<Tag> tag);
		void RemoveUserAddressTagsOfType(Architecture* arch, uint64_t addr, Ref<TagType> tagType);

		std::vector<TagReference> GetFunctionTagReferences();
		std::vector<TagReference> GetAutoFunctionTagReferences();
		std::vector<TagReference> GetUserFunctionTagReferences();
		std::vector<Ref<Tag>> GetFunctionTags();
		std::vector<Ref<Tag>> GetAutoFunctionTags();
		std::vector<Ref<Tag>> GetUserFunctionTags();
		std::vector<Ref<Tag>> GetFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetAutoFunctionTagsOfType(Ref<TagType> tagType);
		std::vector<Ref<Tag>> GetUserFunctionTagsOfType(Ref<TagType> tagType);
		void AddAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTag(Ref<Tag> tag);
		void RemoveAutoFunctionTagsOfType(Ref<TagType> tagType);
		void AddUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTag(Ref<Tag> tag);
		void RemoveUserFunctionTagsOfType(Ref<TagType> tagType);

		Ref<Tag> CreateAutoAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
			const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(Architecture* arch, uint64_t addr, const std::string& tagTypeName,
			const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(const std::string& tagTypeName, const std::string& data, bool unique = false);

		Ref<Tag> CreateAutoAddressTag(
			Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserAddressTag(
			Architecture* arch, uint64_t addr, Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateAutoFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);
		Ref<Tag> CreateUserFunctionTag(Ref<TagType> tagType, const std::string& data, bool unique = false);

		void Reanalyze(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);
		void MarkCallerUpdatesRequired(BNFunctionUpdateType type = UserFunctionUpdate);

		Ref<Workflow> GetWorkflow() const;

		void RequestAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData();
		void ReleaseAdvancedAnalysisData(size_t count);

		std::map<std::string, double> GetAnalysisPerformanceInfo();

		std::vector<DisassemblyTextLine> GetTypeTokens(DisassemblySettings* settings = nullptr);

		Confidence<RegisterValue> GetGlobalPointerValue() const;
		Confidence<RegisterValue> GetRegisterValueAtExit(uint32_t reg) const;

		bool IsFunctionTooLarge();
		bool IsAnalysisSkipped();
		BNAnalysisSkipReason GetAnalysisSkipReason();
		BNFunctionAnalysisSkipOverride GetAnalysisSkipOverride();
		void SetAnalysisSkipOverride(BNFunctionAnalysisSkipOverride skip);

		Ref<FlowGraph> GetUnresolvedStackAdjustmentGraph();

		void SetUserVariableValue(const Variable& var, uint64_t defAddr, PossibleValueSet& value);
		void ClearUserVariableValue(const Variable& var, uint64_t defAddr);
		std::map<Variable, std::map<ArchAndAddr, PossibleValueSet>> GetAllUserVariableValues();
		void ClearAllUserVariableValues();

		void RequestDebugReport(const std::string& name);

		std::string GetGotoLabelName(uint64_t labelId);
		void SetGotoLabelName(uint64_t labelId, const std::string& name);

		BNDeadStoreElimination GetVariableDeadStoreElimination(const Variable& var);
		void SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode);

		uint64_t GetHighestAddress();
		uint64_t GetLowestAddress();
		std::vector<BNAddressRange> GetAddressRanges();

		bool GetInstructionContainingAddress(Architecture* arch, uint64_t addr, uint64_t* start);
	};

	class AdvancedFunctionAnalysisDataRequestor
	{
		Ref<Function> m_func;

	  public:
		AdvancedFunctionAnalysisDataRequestor(Function* func = nullptr);
		AdvancedFunctionAnalysisDataRequestor(const AdvancedFunctionAnalysisDataRequestor& req);
		~AdvancedFunctionAnalysisDataRequestor();
		AdvancedFunctionAnalysisDataRequestor& operator=(const AdvancedFunctionAnalysisDataRequestor& req);

		Ref<Function> GetFunction() { return m_func; }
		void SetFunction(Function* func);
	};
}