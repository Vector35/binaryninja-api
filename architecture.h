#pragma once

#include "binaryninjacore.h"
#include "confidence.h"
#include "refcount.h"
#include <map>
#include <string>
#include <vector>


namespace BinaryNinja
{
	typedef size_t ExprId;

	class CallingConvention;
	class DataBuffer;
	class FunctionRecognizer;
	struct InstructionInfo;
	struct InstructionTextToken;
	class LowLevelILFunction;
	struct NameAndType;
	class Platform;
	class RelocationHandler;
	class Type;
	class TypeLibrary;

	/*! The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
	    patching, and IL translation lifting for a given architecture.

	    \ingroup architectures
	*/
	class Architecture : public StaticCoreRefCountObject<BNArchitecture>
	{
	  protected:
		std::string m_nameForRegister;

		Architecture(BNArchitecture* arch);

		static void InitCallback(void* ctxt, BNArchitecture* obj);
		static BNEndianness GetEndiannessCallback(void* ctxt);
		static size_t GetAddressSizeCallback(void* ctxt);
		static size_t GetDefaultIntegerSizeCallback(void* ctxt);
		static size_t GetInstructionAlignmentCallback(void* ctxt);
		static size_t GetMaxInstructionLengthCallback(void* ctxt);
		static size_t GetOpcodeDisplayLengthCallback(void* ctxt);
		static BNArchitecture* GetAssociatedArchitectureByAddressCallback(void* ctxt, uint64_t* addr);
		static bool GetInstructionInfoCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result);
		static bool GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t* len,
		    BNInstructionTextToken** result, size_t* count);
		static void FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count);
		static bool GetInstructionLowLevelILCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il);
		static char* GetRegisterNameCallback(void* ctxt, uint32_t reg);
		static char* GetFlagNameCallback(void* ctxt, uint32_t flag);
		static char* GetFlagWriteTypeNameCallback(void* ctxt, uint32_t flags);
		static char* GetSemanticFlagClassNameCallback(void* ctxt, uint32_t semClass);
		static char* GetSemanticFlagGroupNameCallback(void* ctxt, uint32_t semGroup);
		static uint32_t* GetFullWidthRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagsCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllFlagWriteTypesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagClassesCallback(void* ctxt, size_t* count);
		static uint32_t* GetAllSemanticFlagGroupsCallback(void* ctxt, size_t* count);
		static BNFlagRole GetFlagRoleCallback(void* ctxt, uint32_t flag, uint32_t semClass);
		static uint32_t* GetFlagsRequiredForFlagConditionCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count);
		static uint32_t* GetFlagsRequiredForSemanticFlagGroupCallback(void* ctxt, uint32_t semGroup, size_t* count);
		static BNFlagConditionForSemanticClass* GetFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, uint32_t semGroup, size_t* count);
		static void FreeFlagConditionsForSemanticFlagGroupCallback(
		    void* ctxt, BNFlagConditionForSemanticClass* conditions);
		static uint32_t* GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count);
		static uint32_t GetSemanticClassForFlagWriteTypeCallback(void* ctxt, uint32_t writeType);
		static size_t GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size,
		    uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
		    BNLowLevelILFunction* il);
		static size_t GetFlagConditionLowLevelILCallback(
		    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il);
		static size_t GetSemanticFlagGroupLowLevelILCallback(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il);
		static void FreeRegisterListCallback(void* ctxt, uint32_t* regs);
		static void GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result);
		static uint32_t GetStackPointerRegisterCallback(void* ctxt);
		static uint32_t GetLinkRegisterCallback(void* ctxt);
		static uint32_t* GetGlobalRegistersCallback(void* ctxt, size_t* count);
		static uint32_t* GetSystemRegistersCallback(void* ctxt, size_t* count);

		static char* GetRegisterStackNameCallback(void* ctxt, uint32_t regStack);
		static uint32_t* GetAllRegisterStacksCallback(void* ctxt, size_t* count);
		static void GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result);

		static BNIntrinsicClass GetIntrinsicClassCallback(void* ctxt, uint32_t intrinsic);
		static char* GetIntrinsicNameCallback(void* ctxt, uint32_t intrinsic);
		static uint32_t* GetAllIntrinsicsCallback(void* ctxt, size_t* count);
		static BNNameAndType* GetIntrinsicInputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeNameAndTypeListCallback(void* ctxt, BNNameAndType* nt, size_t count);
		static BNTypeWithConfidence* GetIntrinsicOutputsCallback(void* ctxt, uint32_t intrinsic, size_t* count);
		static void FreeTypeListCallback(void* ctxt, BNTypeWithConfidence* types, size_t count);

		static bool CanAssembleCallback(void* ctxt);
		static bool AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors);
		static bool IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnZeroPatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);
		static bool IsSkipAndReturnValuePatchAvailableCallback(
		    void* ctxt, const uint8_t* data, uint64_t addr, size_t len);

		static bool ConvertToNopCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool AlwaysBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool InvertBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len);
		static bool SkipAndReturnValueCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		virtual void Register(BNCustomArchitecture* callbacks);

	  public:
		Architecture(const std::string& name);

		/*! Register an architecture

			\param arch Architecture to register
		*/
		static void Register(Architecture* arch);

		/*! Get an Architecture by name

			\param name Name of the architecture
			\return The architecture, if it was found.
		*/
		static Ref<Architecture> GetByName(const std::string& name);

		/*! Get the list of registered Architectures

			\return The list of registered architectures
		*/
		static std::vector<Ref<Architecture>> GetList();

		/*! Get the name of this architecture

			\return The name of this architecture
		*/
		std::string GetName() const;

		/*! Get the default endianness for this architecture

			\return The default endianness for this architecture
		*/
		virtual BNEndianness GetEndianness() const = 0;

		/*! Get the address size for this architecture

			\return The address size for this architecture
		*/
		virtual size_t GetAddressSize() const = 0;

		/*! Get the default integer size for this architecture

			\return The default integer size for this architecture
		*/
		virtual size_t GetDefaultIntegerSize() const;
		virtual size_t GetInstructionAlignment() const;

		/*! Get the maximum instruction length

			\return The maximum instruction length
		*/
		virtual size_t GetMaxInstructionLength() const;
		virtual size_t GetOpcodeDisplayLength() const;

		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr);

		/*! Retrieves an InstructionInfo struct for the instruction at the given virtual address

		 	\note Architecture subclasses should implement this method.
		 	\note The instruction info object should always set the InstructionInfo.length to the instruction length, \
					and the branches of the proper types should be added if the instruction is a branch.

			If the instruction is a branch instruction architecture plugins should add a branch of the proper type:

				===================== ===================================================
				BNBranchType          Description
				===================== ===================================================
				UnconditionalBranch   Branch will always be taken
				FalseBranch           False branch condition
				TrueBranch            True branch condition
				CallDestination       Branch is a call instruction (Branch with Link)
				FunctionReturn        Branch returns from a function
				SystemCall            System call instruction
				IndirectBranch        Branch destination is a memory address or register
				UnresolvedBranch      Branch destination is an unknown address
				===================== ===================================================

			\param[in] data pointer to the instruction data to retrieve info for
		    \param[in] addr address of the instruction data to retrieve info for
			\param[in] maxLen Maximum length of the instruction data to read
			\param[out] result Retrieved instruction info
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;

		/*! Retrieves a list of InstructionTextTokens

			\param[in] data pointer to the instruction data to retrieve text for
			\param[in] addr address of the instruction data to retrieve text for
			\param[out] len will be written to with the length of the instruction data which was translated
			\param[out] result
			\return Whether instruction info was successfully retrieved.
		*/
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) = 0;

		/*! Translates an instruction at addr and appends it onto the LowLevelILFunction& il.

		    \note Architecture subclasses should implement this method.

		    \param[in] data pointer to the instruction data to be translated
		    \param[in] addr address of the instruction data to be translated
		    \param[out] len will be written to with the length of the instruction data which was translated
		    \param[in,out] il the LowLevelILFunction to appended to.
		*/
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);

		/*! Gets a register name from a register index.

			\param reg Register index
			\return The register name
		*/
		virtual std::string GetRegisterName(uint32_t reg);

		/*! Gets a flag name from a flag index

			\param flag Flag index
			\return Flag name
		*/
		virtual std::string GetFlagName(uint32_t flag);

		/*! Gets the flag write type name for the given flag.

			\param flags flag
			\return Flag name
		*/
		virtual std::string GetFlagWriteTypeName(uint32_t flags);

		/*! Gets the name of a semantic flag class from the index.

			\param semClass Semantic class index
			\return The name of the semantic flag class
		*/
		virtual std::string GetSemanticFlagClassName(uint32_t semClass);

		/*! Gets the name of a semantic flag group from the index.

			\param semGroup Semantic flag group index
			\return Semantic flag group name
		*/
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup);

		/*! Get the list of full width register indices

			\return The list of full width register indices
		*/
		virtual std::vector<uint32_t> GetFullWidthRegisters();

		/*! Get the list of all register indices

			\return The list of all register indices
		*/
		virtual std::vector<uint32_t> GetAllRegisters();

		/*! Get the list of all flag indices

			\return The list of all flag indices
		*/
		virtual std::vector<uint32_t> GetAllFlags();

		/*! Get the list of all flag write type indices

			\return The list of all flag write type indices
		*/
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();

		/*! Get the list of all semantic flag class indices

			\return The list of all semantic flag class indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses();

		/*! Get the list of all semantic flag group indices

			\return The list of all semantic flag group indices
		*/
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups();

		/*! Get the role of a given flag.

			\param flag Flag index
			\param semClass Optional semantic flag class
			\return Flag role
		*/
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0);
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup);
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType);
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType);
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		ExprId GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
		    BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il);
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		ExprId GetDefaultFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il);
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il);

		/*! Get the register info for a given register index

			\param reg Register index
			\return Register info
		*/
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);

		/*! Get the register index corresponding to the stack pointer (SP)

			\return The register index corresponding to the stack pointer
		*/
		virtual uint32_t GetStackPointerRegister();

		/*! Get the register index corresponding to the link register (LR)

			\return The register index corresponding to the link register
		*/
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);

		/*! Get the list of system register indices

			\return The list of system register indices
		*/
		virtual std::vector<uint32_t> GetSystemRegisters();

		/*! Check whether a register is a system register

			\param reg Register index
			\return Whether a register is a system register
		*/
		bool IsSystemRegister(uint32_t reg);

		/*! Returns a list of register indices that are modified when \c reg is written to.

			\param reg Register index
			\return List of register indices modified on write.
		*/
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);

		/*! Get a register index by its name

			\param name Name of the register
			\return Index of the register
		*/
		uint32_t GetRegisterByName(const std::string& name);

		/*! Get a register stack name from a register stack number.

			\param regStack Register stack number
			\return The corresponding register string
		*/
		virtual std::string GetRegisterStackName(uint32_t regStack);
		virtual std::vector<uint32_t> GetAllRegisterStacks();
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack);
		uint32_t GetRegisterStackForRegister(uint32_t reg);

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic);
		virtual std::string GetIntrinsicName(uint32_t intrinsic);
		virtual std::vector<uint32_t> GetAllIntrinsics();
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic);
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic);

		/*! Check whether this architecture can assemble instructions

			\return Whether this architecture can assemble instructions
		*/
		virtual bool CanAssemble();

		/*! Converts the string of assembly instructions \c code loaded at virtual address \c addr to the
			byte representation of those instructions.

			\param[in] code String representation of the instructions to be assembled
			\param[in] addr Address of the instructions
			\param[out] result DataBuffer containing the compiled bytes
			\param[out] errors Any errors that occurred during assembly
			\return Whether assembly was successful
		*/
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors);

		/*! Returns true if the instruction at \c addr can be patched to never branch.

		    \note This is used in the UI to determine if "never branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the virtual address of the bytes, to be used when assembling
		    \param len amount of bytes to be checked
		    \return If the never branch patch is available
		*/
		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to always branch.

		    \note This is used in the UI to determine if "always branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
		    \return If the always branch patch is available
		*/
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Returns true if the instruction at addr can be patched to invert the branch.

		    \note This is used in the UI to determine if "invert branch" should be displayed in the right-click context
		    menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
			\param len amount of bytes to be checked
			\return If the invert branch patch is available
		*/
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return zero.

			\note This is used in the UI to determine if "skip and return zero" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return zero patch is available
		*/
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Checks if the instruction at addr is a call that can be patched to return a value.

		    \note This is used in the UI to determine if "skip and return value" should be displayed in the
		    right-click context menu when right-clicking on an instruction.

		    \param data Buffer of bytes to check
		    \param addr the address of the instruction in question
		    \param len amount of bytes to be checked
			\return If the skip and return value patch is available
		*/
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the instruction at addr to a no-operation instruction

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);

		/*! Converts the conditional branch instruction at addr to an unconditional branch.

			\note This is called when the right-click context menu item "always branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! InvertBranch converts the conditional branch instruction at addr to its invert.

			\note This is called when the right-click context menu item "invert branch" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \return Whether the conversion was successful
		*/
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! SkipAndReturnValue converts the call instruction at addr to an instruction that simulates that call
		    returning a value.

		    \note This is called when the right-click context menu item "skip and return value" is selected in the UI.

		    \param[in,out] data Buffer of bytes to convert
		    \param[in] addr the address of the instruction to be converted
		    \param[in] len Length of the bytes to be converted
		    \param[in] value Value to be returned
		    \return Whether the conversion was successful
		*/
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);
		void RegisterRelocationHandler(const std::string& viewName, RelocationHandler* handler);
		Ref<RelocationHandler> GetRelocationHandler(const std::string& viewName);

		// These three binary view type constant APIs are deprecated and should no longer be used. Their implementations
		// have been removed, and they now have no effects.
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t defaultValue = 0);
		/*! \deprecated This API has been deprecated. The implementation has been removed, and this function no longer has any effect
		*/
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		/*! Register a calling convention with this architecture

			\param cc calling convention to register
		*/
		void RegisterCallingConvention(CallingConvention* cc);

		/*! List of registered calling conventions

			\return The list of registered calling conventions
		*/
		std::vector<Ref<CallingConvention>> GetCallingConventions();

		/*! Get a calling convention by name

			\param name Name of the calling convention
			\return The calling convention
		*/
		Ref<CallingConvention> GetCallingConventionByName(const std::string& name);

		/*! Set the default calling convention

			\param cc The default calling convention
		*/
		void SetDefaultCallingConvention(CallingConvention* cc);

		/*! Set the cdecl calling convention

			\param cc The cdecl calling convention
		*/
		void SetCdeclCallingConvention(CallingConvention* cc);

		/*! Set the stdcall calling convention

			\param cc The stdcall calling convention
		*/
		void SetStdcallCallingConvention(CallingConvention* cc);

		/*! Set the fastcall calling convention

			\param cc The fastcall calling convention
		*/
		void SetFastcallCallingConvention(CallingConvention* cc);

		/*! Get the default calling convention

			\return The default calling convention
		*/
		Ref<CallingConvention> GetDefaultCallingConvention();

		/*! Get the cdecl calling convention

			\return The cdecl calling convention
		*/
		Ref<CallingConvention> GetCdeclCallingConvention();

		/*! Get the stdcall calling convention

			\return The stdcall calling convention
		*/
		Ref<CallingConvention> GetStdcallCallingConvention();

		/*! Get the fastcall calling convention

			\return The fastcall calling convention
		*/
		Ref<CallingConvention> GetFastcallCallingConvention();

		/*! Get the Architecture standalone platform

			\return Architecture standalone platform
		*/
		Ref<Platform> GetStandalonePlatform();

		std::vector<Ref<TypeLibrary>> GetTypeLibraries();

		void AddArchitectureRedirection(Architecture* from, Architecture* to);
	};

	/*!

	 	\ingroup architectures
	*/
	class CoreArchitecture : public Architecture
	{
	  public:
		CoreArchitecture(BNArchitecture* arch);
		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;

		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic) override;
		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureExtension : public Architecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureExtension(const std::string& name, Architecture* base);

		Ref<Architecture> GetBaseArchitecture() const { return m_base; }

		virtual BNEndianness GetEndianness() const override;
		virtual size_t GetAddressSize() const override;
		virtual size_t GetDefaultIntegerSize() const override;
		virtual size_t GetInstructionAlignment() const override;
		virtual size_t GetMaxInstructionLength() const override;
		virtual size_t GetOpcodeDisplayLength() const override;
		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
		virtual bool GetInstructionInfo(
		    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
		virtual bool GetInstructionText(
		    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override;
		virtual bool GetInstructionLowLevelIL(
		    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
		virtual std::string GetRegisterName(uint32_t reg) override;
		virtual std::string GetFlagName(uint32_t flag) override;
		virtual std::string GetFlagWriteTypeName(uint32_t flags) override;
		virtual std::string GetSemanticFlagClassName(uint32_t semClass) override;
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFullWidthRegisters() override;
		virtual std::vector<uint32_t> GetAllRegisters() override;
		virtual std::vector<uint32_t> GetAllFlags() override;
		virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses() override;
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups() override;
		virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(
		    BNLowLevelILFlagCondition cond, uint32_t semClass = 0) override;
		virtual std::vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
		virtual std::map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(
		    uint32_t semGroup) override;
		virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
		virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
		virtual ExprId GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
		virtual ExprId GetFlagConditionLowLevelIL(
		    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il) override;
		virtual ExprId GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
		virtual uint32_t GetStackPointerRegister() override;
		virtual uint32_t GetLinkRegister() override;
		virtual std::vector<uint32_t> GetGlobalRegisters() override;
		virtual std::vector<uint32_t> GetSystemRegisters() override;

		virtual std::string GetRegisterStackName(uint32_t regStack) override;
		virtual std::vector<uint32_t> GetAllRegisterStacks() override;
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

		virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic) override;
		virtual std::string GetIntrinsicName(uint32_t intrinsic) override;
		virtual std::vector<uint32_t> GetAllIntrinsics() override;
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

		virtual bool CanAssemble() override;
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors) override;

		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override;

		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override;
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override;
	};

	/*!

		\ingroup architectures
	*/
	class ArchitectureHook : public CoreArchitecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureHook(Architecture* base);
	};

}
