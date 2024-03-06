#define _CRT_SECURE_NO_WARNINGS
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sstream>
#include "binaryninjaapi.h"
#include "il.h"
extern "C" {
    #include "xed-interface.h"
}

using namespace BinaryNinja;
using namespace std;

typedef struct
{
	vector<NameAndType> input;
	vector<Confidence<Ref<Type>>> output;
} IntrinsicInputAndOuput;

class X86CommonArchitecture: public Architecture
{
protected:
	const size_t m_bits;
	DISASSEMBLY_OPTIONS m_disassembly_options;

	bool Decode(const uint8_t* data, size_t len, xed_decoded_inst_t* xedd);

	size_t GetAddressSizeBits()  const;
	uint64_t GetAddressMask() const;

	void SetInstructionInfoForInstruction(uint64_t addr, InstructionInfo& result, xed_decoded_inst_t* xedd);
	bool IsConditionalJump(xed_decoded_inst_t* xedd);
	string GetSizeString(const size_t size) const;

	BNRegisterInfo RegisterInfo(xed_reg_enum_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false);
	static void GetAddressSizeToken(const short bytes, vector<InstructionTextToken>& result, const bool lowerCase);
	unsigned short GetInstructionOpcode(const xed_decoded_inst_t* const xedd,
        const xed_operand_values_t* const ov, vector<InstructionTextToken>& result) const;
	void GetInstructionPadding(const unsigned int instruction_name_length, vector<InstructionTextToken>& result) const;
	void GetOperandTextIntel(const xed_decoded_inst_t* const xedd, const uint64_t addr,const size_t len,
        const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const;
	void GetOperandTextBNIntel(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len,
        const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const;
	void GetOperandTextATT(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len,
        const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const;
	void GetOperandTextXED(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t,
        const xed_operand_values_t* const, const xed_inst_t* const, vector<InstructionTextToken>& result) const;
	void GetOperandText(const xed_decoded_inst_t* const xedd, const uint64_t addr, const size_t len,
        const xed_operand_values_t* const ov, const xed_inst_t* const xi, vector<InstructionTextToken>& result) const;


public:
	X86CommonArchitecture(const string& name, size_t bits);
	virtual BNEndianness GetEndianness() const override;
	virtual vector<uint32_t> GetGlobalRegisters() override;
	virtual vector<uint32_t> GetSystemRegisters() override;
	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override;
	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override;

    virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override;
	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
		uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il) override;
	virtual size_t GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il) override;

	virtual string GetRegisterName(uint32_t reg) override;
	virtual string GetFlagName(uint32_t flag) override;
	virtual vector<uint32_t> GetAllFlags() override;
	virtual string GetSemanticFlagClassName(uint32_t semClass) override;
	virtual vector<uint32_t> GetAllSemanticFlagClasses() override;
	virtual string GetSemanticFlagGroupName(uint32_t semGroup) override;
	virtual vector<uint32_t> GetAllSemanticFlagGroups() override;
	virtual string GetFlagWriteTypeName(uint32_t flags) override;
	virtual uint32_t GetSemanticClassForFlagWriteType(uint32_t writeType) override;
	virtual vector<uint32_t> GetAllFlagWriteTypes() override;
	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass) override;
	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass) override;
	virtual vector<uint32_t> GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup) override;
	virtual map<uint32_t, BNLowLevelILFlagCondition> GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup) override;
	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t writeType) override;
	virtual string GetRegisterStackName(uint32_t regStack) override;
	virtual vector<uint32_t> GetAllRegisterStacks() override;
	virtual BNRegisterStackInfo GetRegisterStackInfo(uint32_t regStack) override;

	virtual BNIntrinsicClass GetIntrinsicClass(uint32_t intrinsic) override;
	virtual string GetIntrinsicName(uint32_t intrinsic) override;
	virtual vector<uint32_t> GetAllIntrinsics() override;
	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override;
	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override;

	virtual bool CanAssemble() override;
	virtual bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override;
	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len) override;
	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len) override;
	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t, size_t len) override;
	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t, size_t len) override;
	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t, size_t len) override;
	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override;
	size_t FindOpcodeOffset(const uint8_t* data, size_t len);
	virtual bool AlwaysBranch(uint8_t* data, uint64_t, size_t len) override;
	virtual bool InvertBranch(uint8_t* data, uint64_t, size_t len) override;
	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t, size_t len, uint64_t value) override;

	static void InitializeCachedTypes();
	static void InitializeCachedInputTypes();
	static void InitializeCachedOutputTypes();

	inline static vector<NameAndType> *cached_input_types;
	inline static vector<Confidence<Ref<Type>>> *cached_output_types;
};
