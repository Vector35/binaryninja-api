#pragma once

#include "confidence.h"
#include "refcount.h"
#include <map>
#include <set>
#include <string>
#include <vector>

namespace BinaryNinja
{
	class Architecture;
	class BasicBlock;
	class BinaryView;
	class CallingConvention;
	class DataBuffer;
	struct DisassemblyTextLine;
	class DisassemblySettings;
	class Function;
	class HighLevelILFunction;
	class LanguageRepresentationFunction;
	struct ILReferenceSource;
	struct InstructionTextToken;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class Platform;
	class QualifiedName;
	struct ReferenceSource;
	class Symbol;
	class Tag;
	class TagType;
	struct TagReference;
	class Type;
	struct VariableReferenceSource;
	class Workflow;

	/*!
		\ingroup function
	*/
	struct Variable : public BNVariable
	{
		Variable();
		Variable(BNVariableSourceType type, uint32_t index, uint64_t storage);
		Variable(BNVariableSourceType type, uint64_t storage);
		Variable(const BNVariable& var);
		Variable(const Variable& var);

		Variable& operator=(const Variable& var);

		bool operator==(const Variable& var) const;
		bool operator!=(const Variable& var) const;
		bool operator<(const Variable& var) const;

		uint64_t ToIdentifier() const;
		static Variable FromIdentifier(uint64_t id);
	};

	/*!
		\ingroup function
	*/
	struct VariableNameAndType
	{
		Variable var;
		Confidence<Ref<Type>> type;
		std::string name;
		bool autoDefined;

		bool operator==(const VariableNameAndType& a)
		{
			return (var == a.var) && (type == a.type) && (name == a.name) && (autoDefined == a.autoDefined);
		}
		bool operator!=(const VariableNameAndType& a)
		{
			return !(*this == a);
		}
	};

	/*!
		\ingroup function
	*/
	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Confidence<Ref<Type>> type;
		std::string name;
		Variable var;
		int64_t referencedOffset;
		size_t size;
	};

	/*!
		\ingroup function
	*/
	struct IndirectBranchInfo
	{
		Ref<Architecture> sourceArch;
		uint64_t sourceAddr;
		Ref<Architecture> destArch;
		uint64_t destAddr;
		bool autoDefined;
	};

	/*!
		\ingroup function
	*/
	struct ArchAndAddr
	{
		Ref<Architecture> arch;
		uint64_t address;

		ArchAndAddr& operator=(const ArchAndAddr& a)
		{
			arch = a.arch;
			address = a.address;
			return *this;
		}
		bool operator==(const ArchAndAddr& a) const { return (arch == a.arch) && (address == a.address); }
		bool operator<(const ArchAndAddr& a) const
		{
			if (arch < a.arch)
				return true;
			if (arch > a.arch)
				return false;
			return address < a.address;
		}
		ArchAndAddr() : arch(nullptr), address(0) {}
		ArchAndAddr(Architecture* a, uint64_t addr) : arch(a), address(addr) {}
	};

	/*!
		\ingroup function
	*/
	struct LookupTableEntry
	{
		std::vector<int64_t> fromValues;
		int64_t toValue;
	};

	/*!
		\ingroup function
	*/
	struct RegisterValue
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;

		RegisterValue();

		bool IsConstant() const;
		bool IsConstantData() const;

		static RegisterValue FromAPIObject(const BNRegisterValue& value);
		BNRegisterValue ToAPIObject();
	};

	struct ConstantData : public BNRegisterValue
	{
		Ref<Function> func = nullptr;

		ConstantData();
		ConstantData(BNRegisterValueType state, uint64_t value);
		ConstantData(BNRegisterValueType state, uint64_t value, size_t size, Ref<Function> func = nullptr);

		DataBuffer ToDataBuffer() const;
		RegisterValue ToRegisterValue() const;
	};

	/*!
		\ingroup function
	*/
	struct PossibleValueSet
	{
		BNRegisterValueType state;
		int64_t value;
		int64_t offset;
		size_t size;
		std::vector<BNValueRange> ranges;
		std::set<int64_t> valueSet;
		std::vector<LookupTableEntry> table;
		size_t count;

		static PossibleValueSet FromAPIObject(BNPossibleValueSet& value);
		BNPossibleValueSet ToAPIObject();
		static void FreeAPIObject(BNPossibleValueSet* value);
	};

	class FlowGraph;
	class Component;
	struct SSAVariable;

	/*!
		\ingroup function
	*/
	class Function : public CoreRefCountObject<BNFunction, BNNewFunctionReference, BNFreeFunction>
	{
		int m_advancedAnalysisRequests;

	  public:
		Function(BNFunction* func);
		virtual ~Function();

		/*! Get the BinaryView this Function is defined in

			\return a BinaryView reference
		*/
		Ref<BinaryView> GetView() const;

		/*! Get the architecture this function was defined with

			\return an Architecture reference
		*/
		Ref<Architecture> GetArchitecture() const;

		/*! Get the platform this function was defined with

			\return a Platform reference
		*/
		Ref<Platform> GetPlatform() const;

		/*! Get the starting virtual address of this function

			\return the start address
		*/
		uint64_t GetStart() const;

		/*! Get the Symbol for this function

			\return a Symbol reference
		*/
		Ref<Symbol> GetSymbol() const;

		/*! Whether this function was automatically discovered by analysis

			\return Whether the function was automatically discovered
		*/
		bool WasAutomaticallyDiscovered() const;

		/*! Whether this function has user annotations

			\return Whether this function has user annotations
		*/
		bool HasUserAnnotations() const;

		/*! Whether this function can return

			\return Whether this function can return
		*/
		Confidence<bool> CanReturn() const;

		/*! Whether this function is pure

			\return Whether this function is pure
		*/
		Confidence<bool> IsPure() const;

		/*! Whether this function has an explicitly defined type

			\return Whether this function has an explicitly defined type
		*/
		bool HasExplicitlyDefinedType() const;

		/*! Whether this function needs update

			\return Whether this function needs update
		*/
		bool NeedsUpdate() const;

		/*! Get a list of Basic Blocks for this function

			\return a list of BasicBlock references for this function
		*/
		std::vector<Ref<BasicBlock>> GetBasicBlocks() const;

		/*! Get the basic block an address is located in

			\param arch Architecture for the basic block
			\param addr Address to check
			\return
		*/
		Ref<BasicBlock> GetBasicBlockAtAddress(Architecture* arch, uint64_t addr) const;

		/*! Mark this function as recently used
		*/
		void MarkRecentUse();

		/*! Get the function comment

			\return The function comment
		*/
		std::string GetComment() const;

		/*! Get a comment located at an address

		 	\return The comment at an address
		*/
		std::string GetCommentForAddress(uint64_t addr) const;

		/*! Get a list of addresses with comments

			\return A list of virtual addresses with comments
		*/
		std::vector<uint64_t> GetCommentedAddresses() const;

		/*! Set the comment for the function

			\param comment The new function comment
		*/
		void SetComment(const std::string& comment);

		/*! Set the comment at an address

			\param addr Address for the comment
			\param comment Text of the comment
		*/
		void SetCommentForAddress(uint64_t addr, const std::string& comment);

		/*! Get a list of callsites for this function

			\return a list of ReferenceSource
		*/
		std::vector<ReferenceSource> GetCallSites() const;

		/*! Places a user-defined cross-reference from the instruction at
			the given address and architecture to the specified target address.

		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserCodeReference`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void AddUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Removes a user-defined cross-reference.

		    If the given address is not contained within this function, or if there is no such user-defined
		    cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param toAddr Virtual address of the xref's destination.
		*/
		void RemoveUserCodeReference(Architecture* fromArch, uint64_t fromAddr, uint64_t toAddr);

		/*! Places a user-defined type cross-reference from the instruction at
				the given address and architecture to the specified type.

		 	If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use `RemoveUserTypeReference`.

		    \param fromArch Architecture of the source instruction
		    \param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void AddUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Removes a user-defined type cross-reference.

			If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
		*/
		void RemoveUserTypeReference(Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name);

		/*! Places a user-defined type field cross-reference from the
			instruction at the given address and architecture to the specified type.

			If the specified source instruction is not contained within this function, no action is performed.
			To remove the reference, use :func:`remove_user_type_field_ref`.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void AddUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Removes a user-defined type field cross-reference.

		 	If the given address is not contained within this function, or if there is no
			such user-defined cross-reference, no action is performed.

			\param fromArch Architecture of the source instruction
			\param fromAddr Virtual address of the source instruction
			\param name Name of the referenced type
			\param offset Offset of the field, relative to the type
			\param size (Optional) size of the access
		*/
		void RemoveUserTypeFieldReference(
		    Architecture* fromArch, uint64_t fromAddr, const QualifiedName& name, uint64_t offset, size_t size = 0);

		/*! Get the LLIL for this function

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelIL() const;

		/*! Get the LLIL for this function if it is available

			\return a LowLevelILFunction reference
		*/
		Ref<LowLevelILFunction> GetLowLevelILIfAvailable() const;

		/*! Get the Low Level IL Instruction start for an instruction at an address

			\param arch Architecture for the instruction
			\param addr Address of the instruction
			\return Start address of the instruction
		*/
		size_t GetLowLevelILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLowLevelILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::vector<size_t> GetLowLevelILExitsForInstruction(Architecture* arch, uint64_t addr);

		DataBuffer GetConstantData(BNRegisterValueType state, uint64_t value, size_t size = 0);

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

		/*! Retrieves a LowLevelILFunction used to represent lifted IL.

			\return LowLevelILFunction used to represent lifted IL.
		*/
		Ref<LowLevelILFunction> GetLiftedIL() const;

		/*! Retrieves a LowLevelILFunction used to represent lifted IL, or None if not loaded.

			\return LowLevelILFunction used to represent lifted IL, or None if not loaded.
		*/
		Ref<LowLevelILFunction> GetLiftedILIfAvailable() const;
		size_t GetLiftedILForInstruction(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILInstructionsForAddress(Architecture* arch, uint64_t addr);
		std::set<size_t> GetLiftedILFlagUsesForDefinition(size_t i, uint32_t flag);
		std::set<size_t> GetLiftedILFlagDefinitionsForUse(size_t i, uint32_t flag);
		std::set<uint32_t> GetFlagsReadByLiftedILInstruction(size_t i);
		std::set<uint32_t> GetFlagsWrittenByLiftedILInstruction(size_t i);

		/*! Get the MLIL for this Function.

			\return The MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelIL() const;

		/*! Get the MLIL for this Function if it's available.

			\return The MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMediumLevelILIfAvailable() const;

		/*! Get the Mapped MLIL for this Function.

			\return The Mapped MLIL for this Function.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelIL() const;

		/*! Get the Mapped MLIL for this Function if it's available.

			\return The Mapped MLIL for this Function if it's available.
		*/
		Ref<MediumLevelILFunction> GetMappedMediumLevelILIfAvailable() const;

		/*! Get the HLIL for this Function.

			\return The HLIL for this Function.
		*/
		Ref<HighLevelILFunction> GetHighLevelIL() const;

		/*! Get the HLIL for this Function if it's available.

			\return The HLIL for this Function if it's available.
		*/
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
		void SetAutoPure(const Confidence<bool>& pure);
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
		void SetPure(const Confidence<bool>& pure);
		void SetStackAdjustment(const Confidence<int64_t>& stackAdjust);
		void SetRegisterStackAdjustments(const std::map<uint32_t, Confidence<int32_t>>& regStackAdjust);
		void SetClobberedRegisters(const Confidence<std::set<uint32_t>>& clobbered);

		bool HasUserType() const;

		void ApplyImportedTypes(Symbol* sym, Ref<Type> type = nullptr);
		void ApplyAutoDiscoveredType(Type* type);

		Ref<FlowGraph> CreateFunctionGraph(BNFunctionGraphType type, DisassemblySettings* settings = nullptr);

		std::map<int64_t, std::vector<VariableNameAndType>> GetStackLayout();
		void CreateAutoStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void CreateUserStackVariable(int64_t offset, const Confidence<Ref<Type>>& type, const std::string& name);
		void DeleteAutoStackVariable(int64_t offset);
		void DeleteUserStackVariable(int64_t offset);
		bool GetStackVariableAtFrameOffset(Architecture* arch, uint64_t addr, int64_t offset, VariableNameAndType& var);

		/*! List of Function Variables

			\return List of Function Variables
		*/
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
		std::string GetVariableNameOrDefault(const Variable& var);
		std::string GetLastSeenVariableNameOrDefault(const Variable& var);

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
		Ref<Type> GetIntegerConstantDisplayTypeEnumType(
			Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);
		void SetIntegerConstantDisplayType(
		    Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand, BNIntegerDisplayType type, Ref<Type> enumType = nullptr);
		std::pair<BNIntegerDisplayType, Ref<Type>> GetIntegerConstantDisplayTypeAndEnumType(Architecture* arch, uint64_t instrAddr, uint64_t value, size_t operand);

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
		bool UsesIncomingGlobalPointer() const;
		Confidence<RegisterValue> GetRegisterValueAtExit(uint32_t reg) const;

		/*! Whether the function is too large to automatically perform analysis

			\return Whether the function is too large to automatically perform analysis
		*/
		bool IsFunctionTooLarge();

		/*! Whether automatic analysis was skipped for this function.

			\return Whether automatic analysis was skipped for this function.
		*/
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

		/*! Get the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\return Name for the label
		*/
		std::string GetGotoLabelName(uint64_t labelId);

		/*! Set the name for a given label ID

			\param labelId ID For the label. Saved in the highlight token value.
			\param name New name for the label
		*/
		void SetGotoLabelName(uint64_t labelId, const std::string& name);

		BNDeadStoreElimination GetVariableDeadStoreElimination(const Variable& var);
		void SetVariableDeadStoreElimination(const Variable& var, BNDeadStoreElimination mode);

		std::map<Variable, std::set<Variable>> GetMergedVariables();
		void MergeVariables(const Variable& target, const std::set<Variable>& sources);
		void UnmergeVariables(const Variable& target, const std::set<Variable>& sources);
		std::set<Variable> GetSplitVariables();
		void SplitVariable(const Variable& var);
		void UnsplitVariable(const Variable& var);

		/*! The highest (largest) virtual address contained in a function.

			\return The highest (largest) virtual address contained in a function.
		*/
		uint64_t GetHighestAddress();

		/*! The lowest (smallest) virtual address contained in a function.

			\return The lowest (smallest) virtual address contained in a function.
		*/
		uint64_t GetLowestAddress();

		/*! All of the address ranges covered by a function

			\return All of the address ranges covered by a function
		*/
		std::vector<BNAddressRange> GetAddressRanges();

		bool GetInstructionContainingAddress(Architecture* arch, uint64_t addr, uint64_t* start);

		Confidence<bool> IsInlinedDuringAnalysis();
		void SetAutoInlinedDuringAnalysis(Confidence<bool> inlined);
		void SetUserInlinedDuringAnalysis(Confidence<bool> inlined);
	};

	/*!
		\ingroup function
	*/
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
