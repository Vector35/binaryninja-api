// Copyright (c) 2015-2017 Vector 35 LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <inttypes.h>
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;


InstructionInfo::InstructionInfo()
{
	length = 0;
	branchCount = 0;
	branchDelay = false;
}


void InstructionInfo::AddBranch(BNBranchType type, uint64_t target, Architecture* arch, bool hasDelaySlot)
{
	if (branchCount >= BN_MAX_INSTRUCTION_BRANCHES)
		return;
	branchDelay = hasDelaySlot;
	branchType[branchCount] = type;
	branchTarget[branchCount] = target;
	branchArch[branchCount++] = arch ? arch->GetObject() : nullptr;
}


InstructionTextToken::InstructionTextToken(): type(TextToken), value(0), confidence(BN_FULL_CONFIDENCE)
{
}


InstructionTextToken::InstructionTextToken(BNInstructionTextTokenType t, const std::string& txt, uint64_t val,
	size_t s, size_t o, uint8_t c) : type(t), text(txt), value(val), size(s), operand(o), context(NoTokenContext),
	confidence(c), address(0)
{
}


InstructionTextToken::InstructionTextToken(BNInstructionTextTokenType t, BNInstructionTextTokenContext ctxt,
	const string& txt, uint64_t a, uint64_t val, size_t s, size_t o, uint8_t c):
	type(t), text(txt), value(val), size(s), operand(o), context(ctxt), confidence(c), address(a)
{
}


InstructionTextToken InstructionTextToken::WithConfidence(uint8_t conf)
{
	return InstructionTextToken(type, context, text, address, value, size, operand, conf);
}


Architecture::Architecture(BNArchitecture* arch)
{
	m_object = arch;
}


Architecture::Architecture(const string& name): m_nameForRegister(name)
{
	m_object = nullptr;
}


void Architecture::InitCallback(void* ctxt, BNArchitecture* obj)
{
	Architecture* arch = (Architecture*)ctxt;
	arch->m_object = obj;
}


BNEndianness Architecture::GetEndiannessCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetEndianness();
}


size_t Architecture::GetAddressSizeCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetAddressSize();
}


size_t Architecture::GetDefaultIntegerSizeCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetDefaultIntegerSize();
}


size_t Architecture::GetMaxInstructionLengthCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetMaxInstructionLength();
}


size_t Architecture::GetOpcodeDisplayLengthCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetOpcodeDisplayLength();
}


BNArchitecture* Architecture::GetAssociatedArchitectureByAddressCallback(void* ctxt, uint64_t* addr)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetAssociatedArchitectureByAddress(*addr)->GetObject();
}


bool Architecture::GetInstructionInfoCallback(void* ctxt, const uint8_t* data, uint64_t addr,
                                              size_t maxLen, BNInstructionInfo* result)
{
	Architecture* arch = (Architecture*)ctxt;

	InstructionInfo info;
	bool ok = arch->GetInstructionInfo(data, addr, maxLen, info);
	*result = info;
	return ok;
}


bool Architecture::GetInstructionTextCallback(void* ctxt, const uint8_t* data, uint64_t addr,
                                              size_t* len, BNInstructionTextToken** result, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;

	vector<InstructionTextToken> tokens;
	bool ok = arch->GetInstructionText(data, addr, *len, tokens);
	if (!ok)
	{
		*result = nullptr;
		*count = 0;
		return false;
	}

	*count = tokens.size();
	*result = new BNInstructionTextToken[tokens.size()];
	for (size_t i = 0; i < tokens.size(); i++)
	{
		(*result)[i].type = tokens[i].type;
		(*result)[i].text = BNAllocString(tokens[i].text.c_str());
		(*result)[i].value = tokens[i].value;
		(*result)[i].size = tokens[i].size;
		(*result)[i].operand = tokens[i].operand;
		(*result)[i].context = tokens[i].context;
		(*result)[i].confidence = tokens[i].confidence;
		(*result)[i].address = tokens[i].address;
	}
	return true;
}


void Architecture::FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeString(tokens[i].text);
	delete[] tokens;
}


bool Architecture::GetInstructionLowLevelILCallback(void* ctxt, const uint8_t* data, uint64_t addr,
                                                    size_t* len, BNLowLevelILFunction* il)
{
	Architecture* arch = (Architecture*)ctxt;
	LowLevelILFunction func(il);
	return arch->GetInstructionLowLevelIL(data, addr, *len, func);
}


char* Architecture::GetRegisterNameCallback(void* ctxt, uint32_t reg)
{
	Architecture* arch = (Architecture*)ctxt;
	string result = arch->GetRegisterName(reg);
	return BNAllocString(result.c_str());
}


char* Architecture::GetFlagNameCallback(void* ctxt, uint32_t flag)
{
	Architecture* arch = (Architecture*)ctxt;
	string result = arch->GetFlagName(flag);
	return BNAllocString(result.c_str());
}


char* Architecture::GetFlagWriteTypeNameCallback(void* ctxt, uint32_t flags)
{
	Architecture* arch = (Architecture*)ctxt;
	string result = arch->GetFlagWriteTypeName(flags);
	return BNAllocString(result.c_str());
}


uint32_t* Architecture::GetFullWidthRegistersCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetFullWidthRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllRegistersCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetAllRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllFlagsCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetAllFlags();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllFlagWriteTypesCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetAllFlagWriteTypes();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


BNFlagRole Architecture::GetFlagRoleCallback(void* ctxt, uint32_t flag)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetFlagRole(flag);
}


uint32_t* Architecture::GetFlagsRequiredForFlagConditionCallback(void* ctxt, BNLowLevelILFlagCondition cond, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> flags = arch->GetFlagsRequiredForFlagCondition(cond);
	*count = flags.size();

	uint32_t* result = new uint32_t[flags.size()];
	for (size_t i = 0; i < flags.size(); i++)
		result[i] = flags[i];
	return result;
}


uint32_t* Architecture::GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> flags = arch->GetFlagsWrittenByFlagWriteType(writeType);
	*count = flags.size();

	uint32_t* result = new uint32_t[flags.size()];
	for (size_t i = 0; i < flags.size(); i++)
		result[i] = flags[i];
	return result;
}


size_t Architecture::GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
	uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, BNLowLevelILFunction* il)
{
	Architecture* arch = (Architecture*)ctxt;
	LowLevelILFunction func(il);
	return arch->GetFlagWriteLowLevelIL(op, size, flagWriteType, flag, operands, operandCount, func);
}


size_t Architecture::GetFlagConditionLowLevelILCallback(void* ctxt, BNLowLevelILFlagCondition cond,
	BNLowLevelILFunction* il)
{
	Architecture* arch = (Architecture*)ctxt;
	LowLevelILFunction func(il);
	return arch->GetFlagConditionLowLevelIL(cond, func);
}


void Architecture::FreeRegisterListCallback(void*, uint32_t* regs)
{
	delete[] regs;
}


void Architecture::GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result)
{
	Architecture* arch = (Architecture*)ctxt;
	*result = arch->GetRegisterInfo(reg);
}


uint32_t Architecture::GetStackPointerRegisterCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetStackPointerRegister();
}


uint32_t Architecture::GetLinkRegisterCallback(void* ctxt)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->GetLinkRegister();
}


uint32_t* Architecture::GetGlobalRegistersCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetGlobalRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


char* Architecture::GetRegisterStackNameCallback(void* ctxt, uint32_t regStack)
{
	Architecture* arch = (Architecture*)ctxt;
	string result = arch->GetRegisterStackName(regStack);
	return BNAllocString(result.c_str());
}


uint32_t* Architecture::GetAllRegisterStacksCallback(void* ctxt, size_t* count)
{
	Architecture* arch = (Architecture*)ctxt;
	vector<uint32_t> regs = arch->GetAllRegisterStacks();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


void Architecture::GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result)
{
	Architecture* arch = (Architecture*)ctxt;
	*result = arch->GetRegisterStackInfo(regStack);
}


bool Architecture::AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors)
{
	Architecture* arch = (Architecture*)ctxt;
	DataBuffer buf;
	string errorStr;
	bool ok = arch->Assemble(code, addr, buf, errorStr);

	BNSetDataBufferContents(result, buf.GetData(), buf.GetLength());
	*errors = BNAllocString(errorStr.c_str());
	return ok;
}


bool Architecture::IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->IsNeverBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->IsAlwaysBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->IsInvertBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsSkipAndReturnZeroPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->IsSkipAndReturnZeroPatchAvailable(data, addr, len);
}


bool Architecture::IsSkipAndReturnValuePatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->IsSkipAndReturnValuePatchAvailable(data, addr, len);
}


bool Architecture::ConvertToNopCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->ConvertToNop(data, addr, len);
}


bool Architecture::AlwaysBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->AlwaysBranch(data, addr, len);
}


bool Architecture::InvertBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->InvertBranch(data, addr, len);
}


bool Architecture::SkipAndReturnValueCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value)
{
	Architecture* arch = (Architecture*)ctxt;
	return arch->SkipAndReturnValue(data, addr, len, value);
}


void Architecture::Register(Architecture* arch)
{
	BNCustomArchitecture callbacks;
	callbacks.context = arch;
	callbacks.init = InitCallback;
	callbacks.getEndianness = GetEndiannessCallback;
	callbacks.getAddressSize = GetAddressSizeCallback;
	callbacks.getDefaultIntegerSize = GetDefaultIntegerSizeCallback;
	callbacks.getMaxInstructionLength = GetMaxInstructionLengthCallback;
	callbacks.getOpcodeDisplayLength = GetOpcodeDisplayLengthCallback;
	callbacks.getAssociatedArchitectureByAddress = GetAssociatedArchitectureByAddressCallback;
	callbacks.getInstructionInfo = GetInstructionInfoCallback;
	callbacks.getInstructionText = GetInstructionTextCallback;
	callbacks.freeInstructionText = FreeInstructionTextCallback;
	callbacks.getInstructionLowLevelIL = GetInstructionLowLevelILCallback;
	callbacks.getRegisterName = GetRegisterNameCallback;
	callbacks.getFlagName = GetFlagNameCallback;
	callbacks.getFlagWriteTypeName = GetFlagWriteTypeNameCallback;
	callbacks.getFullWidthRegisters = GetFullWidthRegistersCallback;
	callbacks.getAllRegisters = GetAllRegistersCallback;
	callbacks.getAllFlags = GetAllFlagsCallback;
	callbacks.getAllFlagWriteTypes = GetAllFlagWriteTypesCallback;
	callbacks.getFlagRole = GetFlagRoleCallback;
	callbacks.getFlagsRequiredForFlagCondition = GetFlagsRequiredForFlagConditionCallback;
	callbacks.getFlagsWrittenByFlagWriteType = GetFlagsWrittenByFlagWriteTypeCallback;
	callbacks.getFlagWriteLowLevelIL = GetFlagWriteLowLevelILCallback;
	callbacks.getFlagConditionLowLevelIL = GetFlagConditionLowLevelILCallback;
	callbacks.freeRegisterList = FreeRegisterListCallback;
	callbacks.getRegisterInfo = GetRegisterInfoCallback;
	callbacks.getStackPointerRegister = GetStackPointerRegisterCallback;
	callbacks.getLinkRegister = GetLinkRegisterCallback;
	callbacks.getGlobalRegisters = GetGlobalRegistersCallback;
	callbacks.getRegisterStackName = GetRegisterStackNameCallback;
	callbacks.getAllRegisterStacks = GetAllRegisterStacksCallback;
	callbacks.getRegisterStackInfo = GetRegisterStackInfoCallback;
	callbacks.assemble = AssembleCallback;
	callbacks.isNeverBranchPatchAvailable = IsNeverBranchPatchAvailableCallback;
	callbacks.isAlwaysBranchPatchAvailable = IsAlwaysBranchPatchAvailableCallback;
	callbacks.isInvertBranchPatchAvailable = IsInvertBranchPatchAvailableCallback;
	callbacks.isSkipAndReturnZeroPatchAvailable = IsSkipAndReturnZeroPatchAvailableCallback;
	callbacks.isSkipAndReturnValuePatchAvailable = IsSkipAndReturnValuePatchAvailableCallback;
	callbacks.convertToNop = ConvertToNopCallback;
	callbacks.alwaysBranch = AlwaysBranchCallback;
	callbacks.invertBranch = InvertBranchCallback;
	callbacks.skipAndReturnValue = SkipAndReturnValueCallback;
	arch->AddRefForRegistration();
	BNRegisterArchitecture(arch->m_nameForRegister.c_str(), &callbacks);
}


Ref<Architecture> Architecture::GetByName(const string& name)
{
	BNArchitecture* arch = BNGetArchitectureByName(name.c_str());
	if (!arch)
		return nullptr;
	return new CoreArchitecture(arch);
}


vector<Ref<Architecture>> Architecture::GetList()
{
	BNArchitecture** archs;
	size_t count;
	archs = BNGetArchitectureList(&count);

	vector<Ref<Architecture>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreArchitecture(archs[i]));

	BNFreeArchitectureList(archs);
	return result;
}


string Architecture::GetName() const
{
	char* name = BNGetArchitectureName(m_object);
	string result = name;
	BNFreeString(name);
	return result;
}


size_t Architecture::GetDefaultIntegerSize() const
{
	if (GetAddressSize() < 4)
		return GetAddressSize();
	return 4;
}


size_t Architecture::GetMaxInstructionLength() const
{
	return BN_DEFAULT_NSTRUCTION_LENGTH;
}


size_t Architecture::GetOpcodeDisplayLength() const
{
	size_t maxLen = GetMaxInstructionLength();
	if (maxLen < BN_DEFAULT_OPCODE_DISPLAY)
		return maxLen;
	return BN_DEFAULT_OPCODE_DISPLAY;
}


Ref<Architecture> Architecture::GetAssociatedArchitectureByAddress(uint64_t&)
{
	return this;
}


bool Architecture::GetInstructionLowLevelIL(const uint8_t*, uint64_t, size_t&, LowLevelILFunction& il)
{
	il.AddInstruction(il.Undefined());
	return false;
}


string Architecture::GetRegisterName(uint32_t reg)
{
	char regStr[32];
	sprintf(regStr, "r%" PRIu32, reg);
	return regStr;
}


string Architecture::GetFlagName(uint32_t flag)
{
	char flagStr[32];
	sprintf(flagStr, "flag%" PRIu32, flag);
	return flagStr;
}


string Architecture::GetFlagWriteTypeName(uint32_t flags)
{
	char flagStr[32];
	sprintf(flagStr, "update%" PRIu32, flags);
	return flagStr;
}


vector<uint32_t> Architecture::GetFullWidthRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetAllRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetAllFlags()
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetAllFlagWriteTypes()
{
	return vector<uint32_t>();
}


BNFlagRole Architecture::GetFlagRole(uint32_t)
{
	return SpecialFlagRole;
}


vector<uint32_t> Architecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition)
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetFlagsWrittenByFlagWriteType(uint32_t)
{
	return vector<uint32_t>();
}


size_t Architecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
	uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,LowLevelILFunction& il)
{
	(void)flagWriteType;
	BNFlagRole role = GetFlagRole(flag);
	return BNGetDefaultArchitectureFlagWriteLowLevelIL(m_object, op, size, role, operands,
		operandCount, il.GetObject());
}


size_t Architecture::GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
	BNRegisterOrConstant* operands, size_t operandCount,LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagWriteLowLevelIL(m_object, op, size, role, operands,
		operandCount, il.GetObject());
}


ExprId Architecture::GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagConditionLowLevelIL(m_object, cond, il.GetObject());
}


ExprId Architecture::GetDefaultFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagConditionLowLevelIL(m_object, cond, il.GetObject());
}


BNRegisterInfo Architecture::GetRegisterInfo(uint32_t)
{
	BNRegisterInfo result;
	result.fullWidthRegister = 0;
	result.offset = 0;
	result.size = 0;
	result.extend = NoExtend;
	return result;
}


uint32_t Architecture::GetStackPointerRegister()
{
	return 0;
}


uint32_t Architecture::GetLinkRegister()
{
	return BN_INVALID_REGISTER;
}


vector<uint32_t> Architecture::GetGlobalRegisters()
{
	return vector<uint32_t>();
}


bool Architecture::IsGlobalRegister(uint32_t reg)
{
	return BNIsArchitectureGlobalRegister(m_object, reg);
}


string Architecture::GetRegisterStackName(uint32_t regStack)
{
	char regStr[32];
	sprintf(regStr, "reg_stack_%" PRIu32, regStack);
	return regStr;
}


vector<uint32_t> Architecture::GetAllRegisterStacks()
{
	return vector<uint32_t>();
}


BNRegisterStackInfo Architecture::GetRegisterStackInfo(uint32_t)
{
	BNRegisterStackInfo result;
	result.firstStorageReg = BN_INVALID_REGISTER;
	result.topRelativeCount = BN_INVALID_REGISTER;
	result.storageCount = 0;
	result.topRelativeCount = 0;
	result.stackTopReg = BN_INVALID_REGISTER;
	return result;
}


uint32_t Architecture::GetRegisterStackForRegister(uint32_t reg)
{
	return BNGetArchitectureRegisterStackForRegister(m_object, reg);
}


vector<uint32_t> Architecture::GetModifiedRegistersOnWrite(uint32_t reg)
{
	size_t count;
	uint32_t* regs = BNGetModifiedArchitectureRegistersOnWrite(m_object, reg, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


uint32_t Architecture::GetRegisterByName(const string& name)
{
	return BNGetArchitectureRegisterByName(m_object, name.c_str());
}


bool Architecture::Assemble(const std::string&, uint64_t, DataBuffer&, std::string& errors)
{
	errors = "Architecture does not implement an assembler.\n";
	return false;
}


bool Architecture::IsNeverBranchPatchAvailable(const uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::IsAlwaysBranchPatchAvailable(const uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::IsInvertBranchPatchAvailable(const uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::IsSkipAndReturnZeroPatchAvailable(const uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::IsSkipAndReturnValuePatchAvailable(const uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::ConvertToNop(uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::AlwaysBranch(uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::InvertBranch(uint8_t*, uint64_t, size_t)
{
	return false;
}


bool Architecture::SkipAndReturnValue(uint8_t*, uint64_t, size_t, uint64_t)
{
	return false;
}


void Architecture::RegisterFunctionRecognizer(FunctionRecognizer* recog)
{
	FunctionRecognizer::RegisterArchitectureFunctionRecognizer(this, recog);
}


bool Architecture::IsBinaryViewTypeConstantDefined(const string& type, const string& name)
{
	return BNIsBinaryViewTypeArchitectureConstantDefined(m_object, type.c_str(), name.c_str());
}


uint64_t Architecture::GetBinaryViewTypeConstant(const string& type, const string& name, uint64_t defaultValue)
{
	return BNGetBinaryViewTypeArchitectureConstant(m_object, type.c_str(), name.c_str(), defaultValue);
}


void Architecture::SetBinaryViewTypeConstant(const string& type, const string& name, uint64_t value)
{
	BNSetBinaryViewTypeArchitectureConstant(m_object, type.c_str(), name.c_str(), value);
}


void Architecture::RegisterCallingConvention(CallingConvention* cc)
{
	BNRegisterCallingConvention(m_object, cc->GetObject());
}


vector<Ref<CallingConvention>> Architecture::GetCallingConventions()
{
	size_t count;
	BNCallingConvention** list = BNGetArchitectureCallingConventions(m_object, &count);

	vector<Ref<CallingConvention>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(new CoreCallingConvention(BNNewCallingConventionReference(list[i])));

	BNFreeCallingConventionList(list, count);
	return result;
}


Ref<CallingConvention> Architecture::GetCallingConventionByName(const string& name)
{
	BNCallingConvention* cc = BNGetArchitectureCallingConventionByName(m_object, name.c_str());
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


void Architecture::SetDefaultCallingConvention(CallingConvention* cc)
{
	BNSetArchitectureDefaultCallingConvention(m_object, cc->GetObject());
}


void Architecture::SetCdeclCallingConvention(CallingConvention* cc)
{
	BNSetArchitectureCdeclCallingConvention(m_object, cc->GetObject());
}


void Architecture::SetStdcallCallingConvention(CallingConvention* cc)
{
	BNSetArchitectureStdcallCallingConvention(m_object, cc->GetObject());
}


void Architecture::SetFastcallCallingConvention(CallingConvention* cc)
{
	BNSetArchitectureFastcallCallingConvention(m_object, cc->GetObject());
}


Ref<CallingConvention> Architecture::GetDefaultCallingConvention()
{
	BNCallingConvention* cc = BNGetArchitectureDefaultCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Architecture::GetCdeclCallingConvention()
{
	BNCallingConvention* cc = BNGetArchitectureCdeclCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Architecture::GetStdcallCallingConvention()
{
	BNCallingConvention* cc = BNGetArchitectureStdcallCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<CallingConvention> Architecture::GetFastcallCallingConvention()
{
	BNCallingConvention* cc = BNGetArchitectureFastcallCallingConvention(m_object);
	if (!cc)
		return nullptr;
	return new CoreCallingConvention(cc);
}


Ref<Platform> Architecture::GetStandalonePlatform()
{
	return new Platform(BNGetArchitectureStandalonePlatform(m_object));
}


CoreArchitecture::CoreArchitecture(BNArchitecture* arch): Architecture(arch)
{
}


BNEndianness CoreArchitecture::GetEndianness() const
{
	return BNGetArchitectureEndianness(m_object);
}


size_t CoreArchitecture::GetAddressSize() const
{
	return BNGetArchitectureAddressSize(m_object);
}


size_t CoreArchitecture::GetDefaultIntegerSize() const
{
	return BNGetArchitectureDefaultIntegerSize(m_object);
}


size_t CoreArchitecture::GetMaxInstructionLength() const
{
	return BNGetArchitectureMaxInstructionLength(m_object);
}


size_t CoreArchitecture::GetOpcodeDisplayLength() const
{
	return BNGetArchitectureOpcodeDisplayLength(m_object);
}


Ref<Architecture> CoreArchitecture::GetAssociatedArchitectureByAddress(uint64_t& addr)
{
	return new CoreArchitecture(BNGetAssociatedArchitectureByAddress(m_object, &addr));
}


bool CoreArchitecture::GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result)
{
	return BNGetInstructionInfo(m_object, data, addr, maxLen, &result);
}


bool CoreArchitecture::GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result)
{
	BNInstructionTextToken* tokens = nullptr;
	size_t count = 0;
	if (!BNGetInstructionText(m_object, data, addr, &len, &tokens, &count))
		return false;

	for (size_t i = 0; i < count; i++)
	{
		result.push_back(InstructionTextToken(tokens[i].type, tokens[i].context, tokens[i].text, tokens[i].address,
			tokens[i].value, tokens[i].size, tokens[i].operand, tokens[i].confidence));
	}

	BNFreeInstructionText(tokens, count);
	return true;
}


bool CoreArchitecture::GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il)
{
	return BNGetInstructionLowLevelIL(m_object, data, addr, &len, il.GetObject());
}


string CoreArchitecture::GetRegisterName(uint32_t reg)
{
	char* name = BNGetArchitectureRegisterName(m_object, reg);
	string result = name;
	BNFreeString(name);
	return result;
}


string CoreArchitecture::GetFlagName(uint32_t flag)
{
	char* name = BNGetArchitectureFlagName(m_object, flag);
	string result = name;
	BNFreeString(name);
	return result;
}


string CoreArchitecture::GetFlagWriteTypeName(uint32_t flags)
{
	char* name = BNGetArchitectureFlagWriteTypeName(m_object, flags);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<uint32_t> CoreArchitecture::GetFullWidthRegisters()
{
	size_t count;
	uint32_t* regs = BNGetFullWidthArchitectureRegisters(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllRegisters()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureRegisters(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllFlags()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureFlags(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllFlagWriteTypes()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureFlagWriteTypes(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


BNFlagRole CoreArchitecture::GetFlagRole(uint32_t flag)
{
	return BNGetArchitectureFlagRole(m_object, flag);
}


vector<uint32_t> CoreArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond)
{
	size_t count;
	uint32_t* flags = BNGetArchitectureFlagsRequiredForFlagCondition(m_object, cond, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(flags[i]);

	BNFreeRegisterList(flags);
	return result;
}


vector<uint32_t> CoreArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t writeType)
{
	size_t count;
	uint32_t* flags = BNGetArchitectureFlagsWrittenByFlagWriteType(m_object, writeType, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(flags[i]);

	BNFreeRegisterList(flags);
	return result;
}


size_t CoreArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
	uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	return BNGetArchitectureFlagWriteLowLevelIL(m_object, op, size, flagWriteType, flag, operands,
		operandCount, il.GetObject());
}


ExprId CoreArchitecture::GetFlagConditionLowLevelIL(BNLowLevelILFlagCondition cond, LowLevelILFunction& il)
{
	return (ExprId)BNGetArchitectureFlagConditionLowLevelIL(m_object, cond, il.GetObject());
}


BNRegisterInfo CoreArchitecture::GetRegisterInfo(uint32_t reg)
{
	return BNGetArchitectureRegisterInfo(m_object, reg);
}


uint32_t CoreArchitecture::GetStackPointerRegister()
{
	return BNGetArchitectureStackPointerRegister(m_object);
}


uint32_t CoreArchitecture::GetLinkRegister()
{
	return BNGetArchitectureLinkRegister(m_object);
}


vector<uint32_t> CoreArchitecture::GetGlobalRegisters()
{
	size_t count;
	uint32_t* regs = BNGetArchitectureGlobalRegisters(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


string CoreArchitecture::GetRegisterStackName(uint32_t regStack)
{
	char* name = BNGetArchitectureRegisterStackName(m_object, regStack);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllRegisterStacks()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureRegisterStacks(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


BNRegisterStackInfo CoreArchitecture::GetRegisterStackInfo(uint32_t regStack)
{
	return BNGetArchitectureRegisterStackInfo(m_object, regStack);
}


bool CoreArchitecture::Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors)
{
	char* errorStr = nullptr;
	bool ok = BNAssemble(m_object, code.c_str(), addr, result.GetBufferObject(), &errorStr);
	if (errorStr)
	{
		errors = errorStr;
		BNFreeString(errorStr);
	}
	return ok;
}


bool CoreArchitecture::IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return BNIsArchitectureNeverBranchPatchAvailable(m_object, data, addr, len);
}


bool CoreArchitecture::IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return BNIsArchitectureAlwaysBranchPatchAvailable(m_object, data, addr, len);
}


bool CoreArchitecture::IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return BNIsArchitectureInvertBranchPatchAvailable(m_object, data, addr, len);
}


bool CoreArchitecture::IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return BNIsArchitectureSkipAndReturnZeroPatchAvailable(m_object, data, addr, len);
}


bool CoreArchitecture::IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return BNIsArchitectureSkipAndReturnValuePatchAvailable(m_object, data, addr, len);
}


bool CoreArchitecture::ConvertToNop(uint8_t* data, uint64_t addr, size_t len)
{
	return BNArchitectureConvertToNop(m_object, data, addr, len);
}


bool CoreArchitecture::AlwaysBranch(uint8_t* data, uint64_t addr, size_t len)
{
	return BNArchitectureAlwaysBranch(m_object, data, addr, len);
}


bool CoreArchitecture::InvertBranch(uint8_t* data, uint64_t addr, size_t len)
{
	return BNArchitectureInvertBranch(m_object, data, addr, len);
}


bool CoreArchitecture::SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value)
{
	return BNArchitectureSkipAndReturnValue(m_object, data, addr, len, value);
}
