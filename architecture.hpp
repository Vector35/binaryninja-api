
#pragma once
#include <string>
#include <vector>
#include <map>

#include "binaryninja_defs.h"
#include "architecture.h"
#include "confidence.hpp"
#include "relocationhandler.hpp"
#include "function.hpp"

struct BNDisassemblyTextRenderer;

namespace BinaryNinja {

	typedef size_t ExprId;
	class Architecture;
	class BasicBlock;
	class CallingConvention;
	class DataBuffer;
	class DisassemblySettings;
	class DisassemblyTextLine;
	class Function;
	class FunctionRecognizer;
	class HighLevelILFunction;
	class LowLevelILFunction;
	class MediumLevelILFunction;
	class Platform;
	class Symbol;
	class Type;

	struct InstructionTextToken;

	struct NameAndType
	{
		std::string name;
		Confidence<Ref<Type>> type;

		NameAndType() = default;
		NameAndType(const Confidence<Ref<Type>>& t);
		NameAndType(const std::string& n, const Confidence<Ref<Type>>& t);
	};

	struct InstructionInfo : public BNInstructionInfo
	{
		InstructionInfo();
		void AddBranch(BNBranchType type, uint64_t target = 0, Architecture* arch = nullptr, bool hasDelaySlot = false);
	};
	/*!
		The Architecture class is the base class for all CPU architectures. This provides disassembly, assembly,
		patching, and IL translation lifting for a given architecture.
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

		static void Register(Architecture* arch);
		static Ref<Architecture> GetByName(const std::string& name);
		static std::vector<Ref<Architecture>> GetList();

		std::string GetName() const;

		virtual BNEndianness GetEndianness() const = 0;
		virtual size_t GetAddressSize() const = 0;
		virtual size_t GetDefaultIntegerSize() const;

		virtual size_t GetInstructionAlignment() const;
		virtual size_t GetMaxInstructionLength() const;
		virtual size_t GetOpcodeDisplayLength() const;

		virtual Ref<Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr);

		virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) = 0;
		virtual bool GetInstructionText(
			const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) = 0;

		/*! GetInstructionLowLevelIL
			Translates an instruction at addr and appends it onto the LowLevelILFunction& il.
			\param data pointer to the instruction data to be translated
			\param addr address of the instruction data to be translated
			\param len length of the instruction data to be translated
			\param il the LowLevelILFunction which
		*/
		virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il);
		virtual std::string GetRegisterName(uint32_t reg);
		virtual std::string GetFlagName(uint32_t flag);
		virtual std::string GetFlagWriteTypeName(uint32_t flags);
		virtual std::string GetSemanticFlagClassName(uint32_t semClass);
		virtual std::string GetSemanticFlagGroupName(uint32_t semGroup);
		virtual std::vector<uint32_t> GetFullWidthRegisters();
		virtual std::vector<uint32_t> GetAllRegisters();
		virtual std::vector<uint32_t> GetAllFlags();
		virtual std::vector<uint32_t> GetAllFlagWriteTypes();
		virtual std::vector<uint32_t> GetAllSemanticFlagClasses();
		virtual std::vector<uint32_t> GetAllSemanticFlagGroups();
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
		virtual BNRegisterInfo GetRegisterInfo(uint32_t reg);
		virtual uint32_t GetStackPointerRegister();
		virtual uint32_t GetLinkRegister();
		virtual std::vector<uint32_t> GetGlobalRegisters();
		bool IsGlobalRegister(uint32_t reg);
		virtual std::vector<uint32_t> GetSystemRegisters();
		bool IsSystemRegister(uint32_t reg);
		std::vector<uint32_t> GetModifiedRegistersOnWrite(uint32_t reg);
		uint32_t GetRegisterByName(const std::string& name);

		virtual std::string GetRegisterStackName(uint32_t regStack);
		virtual std::vector<uint32_t> GetAllRegisterStacks();
		virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack);
		uint32_t GetRegisterStackForRegister(uint32_t reg);

		virtual std::string GetIntrinsicName(uint32_t intrinsic);
		virtual std::vector<uint32_t> GetAllIntrinsics();
		virtual std::vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic);
		virtual std::vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic);

		virtual bool CanAssemble();
		virtual bool Assemble(const std::string& code, uint64_t addr, DataBuffer& result, std::string& errors);

		/*! IsNeverBranchPatchAvailable returns true if the instruction at addr can be patched to never branch.
			This is used in the UI to determine if "never branch" should be displayed in the right-click context
			menu when right-clicking on an instruction.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsAlwaysBranchPatchAvailable returns true if the instruction at addr can be patched to always branch.
			This is used in the UI to determine if "always branch" should be displayed in the right-click context
			menu when right-clicking on an instruction.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsInvertBranchPatchAvailable returns true if the instruction at addr can be patched to invert the branch.
			This is used in the UI to determine if "invert branch" should be displayed in the right-click context
			menu when right-clicking on an instruction.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsSkipAndReturnZeroPatchAvailable returns true if the instruction at addr is a call that can be patched to
			return zero. This is used in the UI to determine if "skip and return zero" should be displayed in the
			right-click context menu when right-clicking on an instruction.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! IsSkipAndReturnValuePatchAvailable returns true if the instruction at addr is a call that can be patched to
			return a value. This is used in the UI to determine if "skip and return value" should be displayed in the
			right-click context menu when right-clicking on an instruction.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len);

		/*! ConvertToNop converts the instruction at addr to a no-operation instruction
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool ConvertToNop(uint8_t* data, uint64_t addr, size_t len);

		/*! AlwaysBranch converts the conditional branch instruction at addr to an unconditional branch. This is called
			when the right-click context menu item "always branch" is selected in the UI.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! InvertBranch converts the conditional branch instruction at addr to its invert. This is called
			when the right-click context menu item "invert branch" is selected in the UI.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len);

		/*! SkipAndReturnValue converts the call instruction at addr to an instruction that simulates that call
			returning a value. This is called when the right-click context menu item "skip and return value" is selected
			in the UI.
			\param arch the architecture of the instruction
			\param addr the address of the instruction in question
		*/
		virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value);

		void RegisterFunctionRecognizer(FunctionRecognizer* recog);
		void RegisterRelocationHandler(const std::string& viewName, RelocationHandler* handler);
		Ref<RelocationHandler> GetRelocationHandler(const std::string& viewName);

		bool IsBinaryViewTypeConstantDefined(const std::string& type, const std::string& name);
		uint64_t GetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t defaultValue = 0);
		void SetBinaryViewTypeConstant(const std::string& type, const std::string& name, uint64_t value);

		void RegisterCallingConvention(CallingConvention* cc);
		std::vector<Ref<CallingConvention>> GetCallingConventions();
		Ref<CallingConvention> GetCallingConventionByName(const std::string& name);

		void SetDefaultCallingConvention(CallingConvention* cc);
		void SetCdeclCallingConvention(CallingConvention* cc);
		void SetStdcallCallingConvention(CallingConvention* cc);
		void SetFastcallCallingConvention(CallingConvention* cc);
		Ref<CallingConvention> GetDefaultCallingConvention();
		Ref<CallingConvention> GetCdeclCallingConvention();
		Ref<CallingConvention> GetStdcallCallingConvention();
		Ref<CallingConvention> GetFastcallCallingConvention();
		Ref<Platform> GetStandalonePlatform();

		void AddArchitectureRedirection(Architecture* from, Architecture* to);
	};

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

	class ArchitectureHook : public CoreArchitecture
	{
	  protected:
		Ref<Architecture> m_base;

		virtual void Register(BNCustomArchitecture* callbacks) override;

	  public:
		ArchitectureHook(Architecture* base);
	};


	struct ArchAndAddr
	{
		Ref<Architecture> arch;
		uint64_t address;

		ArchAndAddr();
		ArchAndAddr(Architecture* a, uint64_t addr);

		ArchAndAddr& operator=(const ArchAndAddr& a);
		bool operator==(const ArchAndAddr& a) const;
		bool operator<(const ArchAndAddr& a) const;
	};

	struct StackVariableReference
	{
		uint32_t sourceOperand;
		Confidence<Ref<Type>> type;
		std::string name;
		Variable var;
		int64_t referencedOffset;
		size_t size;
	};

	class DisassemblyTextRenderer :
	    public CoreRefCountObject<BNDisassemblyTextRenderer, BNNewDisassemblyTextRendererReference,
	        BNFreeDisassemblyTextRenderer>
	{
	  public:
		DisassemblyTextRenderer(Function* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(LowLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(MediumLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(HighLevelILFunction* func, DisassemblySettings* settings = nullptr);
		DisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer);

		Ref<Function> GetFunction() const;
		Ref<LowLevelILFunction> GetLowLevelILFunction() const;
		Ref<MediumLevelILFunction> GetMediumLevelILFunction() const;
		Ref<HighLevelILFunction> GetHighLevelILFunction() const;

		Ref<BasicBlock> GetBasicBlock() const;
		Ref<Architecture> GetArchitecture() const;
		Ref<DisassemblySettings> GetSettings() const;
		void SetBasicBlock(BasicBlock* block);
		void SetArchitecture(Architecture* arch);
		void SetSettings(DisassemblySettings* settings);

		virtual bool IsIL() const;
		virtual bool HasDataFlow() const;

		virtual void GetInstructionAnnotations(std::vector<InstructionTextToken>& tokens, uint64_t addr);
		virtual bool GetInstructionText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		std::vector<DisassemblyTextLine> PostProcessInstructionTextLines(uint64_t addr, size_t len,
		    const std::vector<DisassemblyTextLine>& lines, const std::string& indentSpaces = "");

		virtual bool GetDisassemblyText(uint64_t addr, size_t& len, std::vector<DisassemblyTextLine>& lines);
		void ResetDeduplicatedComments();

		bool AddSymbolToken(std::vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand);
		void AddStackVariableReferenceTokens(
		    std::vector<InstructionTextToken>& tokens, const StackVariableReference& ref);

		static bool IsIntegerToken(BNInstructionTextTokenType type);
		void AddIntegerToken(std::vector<InstructionTextToken>& tokens, const InstructionTextToken& token,
		    Architecture* arch, uint64_t addr);

		void WrapComment(DisassemblyTextLine& line, std::vector<DisassemblyTextLine>& lines, const std::string& comment,
		    bool hasAutoAnnotations, const std::string& leadingSpaces = "  ", const std::string& indentSpaces = "");
		static std::string GetDisplayStringForInteger(Ref<BinaryView> binaryView, BNIntegerDisplayType type,
		    uint64_t value, size_t inputWidth, bool isSigned = true);
	};
}