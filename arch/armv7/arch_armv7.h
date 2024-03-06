#pragma once

#include "binaryninjaapi.h"
#include "armv7.h"

#define BINARYNINJA_MANUAL_RELOCATION ((uint64_t)-2)

class ArmCommonArchitecture: public BinaryNinja::Architecture
{
protected:
	BNEndianness m_endian;
	BinaryNinja::Ref<BinaryNinja::Architecture> m_armArch, m_thumbArch;

	virtual std::string GetAssemblerTriple() = 0;

public:
	ArmCommonArchitecture(const char* name, BNEndianness endian);
	void SetArmAndThumbArchitectures(Architecture* arm, Architecture* thumb);

	virtual size_t GetAddressSize() const override;
	virtual BNEndianness GetEndianness() const override;
	virtual BinaryNinja::Ref<BinaryNinja::Architecture> GetAssociatedArchitectureByAddress(uint64_t& addr) override;
	virtual std::string GetFlagName(uint32_t flag) override;
	virtual std::string GetFlagWriteTypeName(uint32_t flags) override;
	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t semClass = 0) override;
	virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override;
	virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass) override;
	virtual size_t GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType, uint32_t flag,
			BNRegisterOrConstant* operands, size_t operandCount, BinaryNinja::LowLevelILFunction& il) override;
	virtual std::string GetRegisterName(uint32_t reg) override;
	virtual std::vector<uint32_t> GetFullWidthRegisters() override;
	virtual std::vector<uint32_t> GetAllRegisters() override;
	virtual std::vector<uint32_t> GetAllFlags() override;
	virtual std::vector<uint32_t> GetAllFlagWriteTypes() override;
	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override;
	virtual uint32_t GetStackPointerRegister() override;
	virtual uint32_t GetLinkRegister() override;
	virtual bool CanAssemble() override;
	virtual bool Assemble(const std::string& code, uint64_t addr, BinaryNinja::DataBuffer& result,
		std::string& errors) override;
};

ArmCommonArchitecture* InitThumb2Architecture(const char* name, BNEndianness endian);
