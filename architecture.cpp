// Copyright (c) 2015-2024 Vector 35 Inc
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
#include <cstdio>
#include <cstdint>
#include <inttypes.h>
#include <vector>
#include "binaryninjaapi.h"
#include "ffi.h"

using namespace BinaryNinja;
using namespace std;


InstructionInfo::InstructionInfo()
{
	length = 0;
	archTransitionByTargetAddr = false;
	branchCount = 0;
	delaySlots = 0;
}


void InstructionInfo::AddBranch(BNBranchType type, uint64_t target, Architecture* arch, uint8_t delaySlot)
{
	if (branchCount >= BN_MAX_INSTRUCTION_BRANCHES)
		return;
	delaySlots = delaySlot;
	branchType[branchCount] = type;
	branchTarget[branchCount] = target;
	branchArch[branchCount++] = arch ? arch->GetObject() : nullptr;
}


InstructionTextToken::InstructionTextToken() :
    type(TextToken), value(0), width(WidthIsByteCount), size(0), operand(BN_INVALID_OPERAND),
    context(NoTokenContext), confidence(BN_FULL_CONFIDENCE), address(0), exprIndex(BN_INVALID_EXPR)
{
	if (width == WidthIsByteCount)
	{
		width = text.size();
	}
}


InstructionTextToken::InstructionTextToken(uint8_t confidence, BNInstructionTextTokenType t, const string& txt) :
	type(t), text(txt), value(0), width(WidthIsByteCount), size(0), operand(BN_INVALID_OPERAND),
	context(NoTokenContext), confidence(confidence), address(0), exprIndex(BN_INVALID_EXPR)
{
	if (width == WidthIsByteCount)
	{
		width = text.size();
	}
}


InstructionTextToken::InstructionTextToken(BNInstructionTextTokenType t, const std::string& txt, uint64_t val, size_t s,
    size_t o, uint8_t c, const vector<string>& n, uint64_t w) :
    type(t),
    text(txt), value(val), width(w), size(s), operand(o), context(NoTokenContext), confidence(c), address(0),
    typeNames(n), exprIndex(BN_INVALID_EXPR)
{
	if (width == WidthIsByteCount)
	{
		width = text.size();
	}
}


InstructionTextToken::InstructionTextToken(BNInstructionTextTokenType t, BNInstructionTextTokenContext ctxt,
    const string& txt, uint64_t a, uint64_t val, size_t s, size_t o, uint8_t c, const vector<string>& n, uint64_t w) :
    type(t),
    text(txt), value(val), width(w), size(s), operand(o), context(ctxt), confidence(c), address(a), typeNames(n),
    exprIndex(BN_INVALID_EXPR)
{
	if (width == WidthIsByteCount)
	{
		width = text.size();
	}
}


InstructionTextToken::InstructionTextToken(const BNInstructionTextToken& token) :
    type(token.type), text(token.text), value(token.value), width(token.width), size(token.size),
    operand(token.operand), context(token.context), confidence(token.confidence), address(token.address),
    exprIndex(token.exprIndex)
{
	typeNames.reserve(token.namesCount);
	for (size_t j = 0; j < token.namesCount; j++)
		typeNames.push_back(token.typeNames[j]);
	if (width == WidthIsByteCount)
	{
		width = text.size();
	}
}


InstructionTextToken InstructionTextToken::WithConfidence(uint8_t conf)
{
	return InstructionTextToken(type, context, text, address, value, size, operand, conf, typeNames, width);
}


void InstructionTextToken::ConvertInstructionTextToken(const InstructionTextToken& token, BNInstructionTextToken* result)
{
	result->type = token.type;
	result->text = BNAllocString(token.text.c_str());
	result->value = token.value;
	result->width = token.width;
	result->size = token.size;
	result->operand = token.operand;
	result->context = token.context;
	result->confidence = token.confidence;
	result->address = token.address;
	result->typeNames = new char*[token.typeNames.size()];
	for (size_t i = 0; i < token.typeNames.size(); i++)
		result->typeNames[i] = BNAllocString(token.typeNames[i].c_str());
	result->namesCount = token.typeNames.size();
	result->exprIndex = token.exprIndex;
}


vector<InstructionTextToken> InstructionTextToken::ConvertAndFreeInstructionTextTokenList(
    BNInstructionTextToken* tokens, size_t count)
{
	auto result = ConvertInstructionTextTokenList(tokens, count);
	BNFreeInstructionText(tokens, count);
	return result;
}


BNInstructionTextToken* InstructionTextToken::CreateInstructionTextTokenList(const vector<InstructionTextToken>& tokens)
{
	BNInstructionTextToken* result = new BNInstructionTextToken[tokens.size()];
	for (size_t i = 0; i < tokens.size(); i++)
		ConvertInstructionTextToken(tokens[i], &result[i]);
	return result;
}


void InstructionTextToken::FreeInstructionTextToken(BNInstructionTextToken* token)
{
	BNFreeString(token->text);
	for (size_t j = 0; j < token->namesCount; j++)
		BNFreeString(token->typeNames[j]);
	delete[] token->typeNames;
}


void InstructionTextToken::FreeInstructionTextTokenList(BNInstructionTextToken* tokens, size_t count)
{
	for (size_t i = 0; i < count; i++)
		FreeInstructionTextToken(&tokens[i]);
	delete[] tokens;
}


vector<InstructionTextToken> InstructionTextToken::ConvertInstructionTextTokenList(
    const BNInstructionTextToken* tokens, size_t count)
{
	vector<InstructionTextToken> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(tokens[i]);
	return result;
}


Architecture::Architecture(BNArchitecture* arch)
{
	m_object = arch;
}


Architecture::Architecture(const string& name) : m_nameForRegister(name)
{
	m_object = nullptr;
}


void Architecture::InitCallback(void* ctxt, BNArchitecture* obj)
{
	CallbackRef<Architecture> arch(ctxt);
	arch->m_object = obj;
}


BNEndianness Architecture::GetEndiannessCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetEndianness();
}


size_t Architecture::GetAddressSizeCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetAddressSize();
}


size_t Architecture::GetDefaultIntegerSizeCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetDefaultIntegerSize();
}


size_t Architecture::GetInstructionAlignmentCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetInstructionAlignment();
}


size_t Architecture::GetMaxInstructionLengthCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetMaxInstructionLength();
}


size_t Architecture::GetOpcodeDisplayLengthCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetOpcodeDisplayLength();
}


BNArchitecture* Architecture::GetAssociatedArchitectureByAddressCallback(void* ctxt, uint64_t* addr)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetAssociatedArchitectureByAddress(*addr)->GetObject();
}


bool Architecture::GetInstructionInfoCallback(
    void* ctxt, const uint8_t* data, uint64_t addr, size_t maxLen, BNInstructionInfo* result)
{
	CallbackRef<Architecture> arch(ctxt);

	InstructionInfo info;
	info.delaySlots = result->delaySlots;
	bool ok = arch->GetInstructionInfo(data, addr, maxLen, info);
	*result = info;
	return ok;
}


bool Architecture::GetInstructionTextCallback(
    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNInstructionTextToken** result, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);

	vector<InstructionTextToken> tokens;
	bool ok = arch->GetInstructionText(data, addr, *len, tokens);
	if (!ok)
	{
		*result = nullptr;
		*count = 0;
		return false;
	}

	*count = tokens.size();
	*result = InstructionTextToken::CreateInstructionTextTokenList(tokens);
	return true;
}


void Architecture::FreeInstructionTextCallback(BNInstructionTextToken* tokens, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNFreeString(tokens[i].text);
		for (size_t j = 0; j < tokens[j].namesCount; j++)
			BNFreeString(tokens[i].typeNames[j]);
		delete[] tokens[i].typeNames;
	}
	delete[] tokens;
}


bool Architecture::GetInstructionLowLevelILCallback(
    void* ctxt, const uint8_t* data, uint64_t addr, size_t* len, BNLowLevelILFunction* il)
{
	CallbackRef<Architecture> arch(ctxt);
	Ref<LowLevelILFunction> func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)));
	return arch->GetInstructionLowLevelIL(data, addr, *len, *func);
}


char* Architecture::GetRegisterNameCallback(void* ctxt, uint32_t reg)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetRegisterName(reg);
	return BNAllocString(result.c_str());
}


char* Architecture::GetFlagNameCallback(void* ctxt, uint32_t flag)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetFlagName(flag);
	return BNAllocString(result.c_str());
}


char* Architecture::GetFlagWriteTypeNameCallback(void* ctxt, uint32_t flags)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetFlagWriteTypeName(flags);
	return BNAllocString(result.c_str());
}


char* Architecture::GetSemanticFlagClassNameCallback(void* ctxt, uint32_t semClass)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetSemanticFlagClassName(semClass);
	return BNAllocString(result.c_str());
}


char* Architecture::GetSemanticFlagGroupNameCallback(void* ctxt, uint32_t semGroup)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetSemanticFlagGroupName(semGroup);
	return BNAllocString(result.c_str());
}


uint32_t* Architecture::GetFullWidthRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetFullWidthRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllFlagsCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllFlags();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllFlagWriteTypesCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllFlagWriteTypes();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllSemanticFlagClassesCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllSemanticFlagClasses();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetAllSemanticFlagGroupsCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllSemanticFlagGroups();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


BNFlagRole Architecture::GetFlagRoleCallback(void* ctxt, uint32_t flag, uint32_t semClass)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetFlagRole(flag, semClass);
}


uint32_t* Architecture::GetFlagsRequiredForFlagConditionCallback(
    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> flags = arch->GetFlagsRequiredForFlagCondition(cond, semClass);
	*count = flags.size();

	uint32_t* result = new uint32_t[flags.size()];
	for (size_t i = 0; i < flags.size(); i++)
		result[i] = flags[i];
	return result;
}


uint32_t* Architecture::GetFlagsRequiredForSemanticFlagGroupCallback(void* ctxt, uint32_t semGroup, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> flags = arch->GetFlagsRequiredForSemanticFlagGroup(semGroup);
	*count = flags.size();

	uint32_t* result = new uint32_t[flags.size()];
	for (size_t i = 0; i < flags.size(); i++)
		result[i] = flags[i];
	return result;
}


BNFlagConditionForSemanticClass* Architecture::GetFlagConditionsForSemanticFlagGroupCallback(
    void* ctxt, uint32_t semGroup, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	map<uint32_t, BNLowLevelILFlagCondition> conditions = arch->GetFlagConditionsForSemanticFlagGroup(semGroup);
	*count = conditions.size();

	BNFlagConditionForSemanticClass* result = new BNFlagConditionForSemanticClass[conditions.size()];
	size_t i = 0;
	for (auto& j : conditions)
	{
		result[i].semanticClass = j.first;
		result[i].condition = j.second;
		i++;
	}
	return result;
}


void Architecture::FreeFlagConditionsForSemanticFlagGroupCallback(void*, BNFlagConditionForSemanticClass* conditions, size_t)
{
	delete[] conditions;
}


uint32_t* Architecture::GetFlagsWrittenByFlagWriteTypeCallback(void* ctxt, uint32_t writeType, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> flags = arch->GetFlagsWrittenByFlagWriteType(writeType);
	*count = flags.size();

	uint32_t* result = new uint32_t[flags.size()];
	for (size_t i = 0; i < flags.size(); i++)
		result[i] = flags[i];
	return result;
}


uint32_t Architecture::GetSemanticClassForFlagWriteTypeCallback(void* ctxt, uint32_t writeType)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetSemanticClassForFlagWriteType(writeType);
}


size_t Architecture::GetFlagWriteLowLevelILCallback(void* ctxt, BNLowLevelILOperation op, size_t size,
    uint32_t flagWriteType, uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount,
    BNLowLevelILFunction* il)
{
	CallbackRef<Architecture> arch(ctxt);
	Ref<LowLevelILFunction> func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)));
	return arch->GetFlagWriteLowLevelIL(op, size, flagWriteType, flag, operands, operandCount, *func);
}


size_t Architecture::GetFlagConditionLowLevelILCallback(
    void* ctxt, BNLowLevelILFlagCondition cond, uint32_t semClass, BNLowLevelILFunction* il)
{
	CallbackRef<Architecture> arch(ctxt);
	Ref<LowLevelILFunction> func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)));
	return arch->GetFlagConditionLowLevelIL(cond, semClass, *func);
}


size_t Architecture::GetSemanticFlagGroupLowLevelILCallback(void* ctxt, uint32_t semGroup, BNLowLevelILFunction* il)
{
	CallbackRef<Architecture> arch(ctxt);
	Ref<LowLevelILFunction> func(new LowLevelILFunction(BNNewLowLevelILFunctionReference(il)));
	return arch->GetSemanticFlagGroupLowLevelIL(semGroup, *func);
}


void Architecture::FreeRegisterListCallback(void*, uint32_t* regs, size_t)
{
	delete[] regs;
}


void Architecture::GetRegisterInfoCallback(void* ctxt, uint32_t reg, BNRegisterInfo* result)
{
	CallbackRef<Architecture> arch(ctxt);
	*result = arch->GetRegisterInfo(reg);
}


uint32_t Architecture::GetStackPointerRegisterCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetStackPointerRegister();
}


uint32_t Architecture::GetLinkRegisterCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetLinkRegister();
}


uint32_t* Architecture::GetGlobalRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetGlobalRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* Architecture::GetSystemRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetSystemRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


char* Architecture::GetRegisterStackNameCallback(void* ctxt, uint32_t regStack)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetRegisterStackName(regStack);
	return BNAllocString(result.c_str());
}


uint32_t* Architecture::GetAllRegisterStacksCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllRegisterStacks();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


void Architecture::GetRegisterStackInfoCallback(void* ctxt, uint32_t regStack, BNRegisterStackInfo* result)
{
	CallbackRef<Architecture> arch(ctxt);
	*result = arch->GetRegisterStackInfo(regStack);
}


BNIntrinsicClass Architecture::GetIntrinsicClassCallback(void* ctxt, uint32_t intrinsic)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->GetIntrinsicClass(intrinsic);
}


char* Architecture::GetIntrinsicNameCallback(void* ctxt, uint32_t intrinsic)
{
	CallbackRef<Architecture> arch(ctxt);
	string result = arch->GetIntrinsicName(intrinsic);
	return BNAllocString(result.c_str());
}


uint32_t* Architecture::GetAllIntrinsicsCallback(void* ctxt, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<uint32_t> regs = arch->GetAllIntrinsics();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


BNNameAndType* Architecture::GetIntrinsicInputsCallback(void* ctxt, uint32_t intrinsic, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<NameAndType> inputs = arch->GetIntrinsicInputs(intrinsic);
	*count = inputs.size();

	BNNameAndType* result = new BNNameAndType[inputs.size()];
	for (size_t i = 0; i < inputs.size(); i++)
	{
		result[i].name = BNAllocString(inputs[i].name.c_str());
		result[i].type = BNNewTypeReference(inputs[i].type.GetValue()->GetObject());
		result[i].typeConfidence = inputs[i].type.GetConfidence();
	}
	return result;
}


void Architecture::FreeNameAndTypeListCallback(void*, BNNameAndType* nt, size_t count)
{
	for (size_t i = 0; i < count; i++)
	{
		BNFreeString(nt[i].name);
		BNFreeType(nt[i].type);
	}
	delete[] nt;
}


BNTypeWithConfidence* Architecture::GetIntrinsicOutputsCallback(void* ctxt, uint32_t intrinsic, size_t* count)
{
	CallbackRef<Architecture> arch(ctxt);
	vector<Confidence<Ref<Type>>> outputs = arch->GetIntrinsicOutputs(intrinsic);
	*count = outputs.size();

	BNTypeWithConfidence* result = new BNTypeWithConfidence[outputs.size()];
	for (size_t i = 0; i < outputs.size(); i++)
	{
		result[i].type = BNNewTypeReference(outputs[i].GetValue()->GetObject());
		result[i].confidence = outputs[i].GetConfidence();
	}
	return result;
}


void Architecture::FreeTypeListCallback(void*, BNTypeWithConfidence* types, size_t count)
{
	for (size_t i = 0; i < count; i++)
		BNFreeType(types[i].type);
	delete[] types;
}

bool Architecture::CanAssembleCallback(void* ctxt)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->CanAssemble();
}

bool Architecture::AssembleCallback(void* ctxt, const char* code, uint64_t addr, BNDataBuffer* result, char** errors)
{
	CallbackRef<Architecture> arch(ctxt);
	DataBuffer buf;
	string errorStr;
	bool ok = arch->Assemble(code, addr, buf, errorStr);

	BNSetDataBufferContents(result, buf.GetData(), buf.GetLength());
	*errors = BNAllocString(errorStr.c_str());
	return ok;
}


bool Architecture::IsNeverBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->IsNeverBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsAlwaysBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->IsAlwaysBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsInvertBranchPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->IsInvertBranchPatchAvailable(data, addr, len);
}


bool Architecture::IsSkipAndReturnZeroPatchAvailableCallback(void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->IsSkipAndReturnZeroPatchAvailable(data, addr, len);
}


bool Architecture::IsSkipAndReturnValuePatchAvailableCallback(
    void* ctxt, const uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->IsSkipAndReturnValuePatchAvailable(data, addr, len);
}


bool Architecture::ConvertToNopCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->ConvertToNop(data, addr, len);
}


bool Architecture::AlwaysBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->AlwaysBranch(data, addr, len);
}


bool Architecture::InvertBranchCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->InvertBranch(data, addr, len);
}


bool Architecture::SkipAndReturnValueCallback(void* ctxt, uint8_t* data, uint64_t addr, size_t len, uint64_t value)
{
	CallbackRef<Architecture> arch(ctxt);
	return arch->SkipAndReturnValue(data, addr, len, value);
}


void Architecture::Register(BNCustomArchitecture* callbacks)
{
	AddRefForRegistration();
	BNRegisterArchitecture(m_nameForRegister.c_str(), callbacks);
}


void Architecture::Register(Architecture* arch)
{
	BNCustomArchitecture callbacks;
	callbacks.context = arch;
	callbacks.init = InitCallback;
	callbacks.getEndianness = GetEndiannessCallback;
	callbacks.getAddressSize = GetAddressSizeCallback;
	callbacks.getDefaultIntegerSize = GetDefaultIntegerSizeCallback;
	callbacks.getInstructionAlignment = GetInstructionAlignmentCallback;
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
	callbacks.getSemanticFlagClassName = GetSemanticFlagClassNameCallback;
	callbacks.getSemanticFlagGroupName = GetSemanticFlagGroupNameCallback;
	callbacks.getFullWidthRegisters = GetFullWidthRegistersCallback;
	callbacks.getAllRegisters = GetAllRegistersCallback;
	callbacks.getAllFlags = GetAllFlagsCallback;
	callbacks.getAllFlagWriteTypes = GetAllFlagWriteTypesCallback;
	callbacks.getAllSemanticFlagClasses = GetAllSemanticFlagClassesCallback;
	callbacks.getAllSemanticFlagGroups = GetAllSemanticFlagGroupsCallback;
	callbacks.getFlagRole = GetFlagRoleCallback;
	callbacks.getFlagsRequiredForFlagCondition = GetFlagsRequiredForFlagConditionCallback;
	callbacks.getFlagsRequiredForSemanticFlagGroup = GetFlagsRequiredForSemanticFlagGroupCallback;
	callbacks.getFlagConditionsForSemanticFlagGroup = GetFlagConditionsForSemanticFlagGroupCallback;
	callbacks.freeFlagConditionsForSemanticFlagGroup = FreeFlagConditionsForSemanticFlagGroupCallback;
	callbacks.getFlagsWrittenByFlagWriteType = GetFlagsWrittenByFlagWriteTypeCallback;
	callbacks.getSemanticClassForFlagWriteType = GetSemanticClassForFlagWriteTypeCallback;
	callbacks.getFlagWriteLowLevelIL = GetFlagWriteLowLevelILCallback;
	callbacks.getFlagConditionLowLevelIL = GetFlagConditionLowLevelILCallback;
	callbacks.getSemanticFlagGroupLowLevelIL = GetSemanticFlagGroupLowLevelILCallback;
	callbacks.freeRegisterList = FreeRegisterListCallback;
	callbacks.getRegisterInfo = GetRegisterInfoCallback;
	callbacks.getStackPointerRegister = GetStackPointerRegisterCallback;
	callbacks.getLinkRegister = GetLinkRegisterCallback;
	callbacks.getGlobalRegisters = GetGlobalRegistersCallback;
	callbacks.getSystemRegisters = GetSystemRegistersCallback;
	callbacks.getRegisterStackName = GetRegisterStackNameCallback;
	callbacks.getAllRegisterStacks = GetAllRegisterStacksCallback;
	callbacks.getRegisterStackInfo = GetRegisterStackInfoCallback;
	callbacks.getIntrinsicClass = GetIntrinsicClassCallback;
	callbacks.getIntrinsicName = GetIntrinsicNameCallback;
	callbacks.getAllIntrinsics = GetAllIntrinsicsCallback;
	callbacks.getIntrinsicInputs = GetIntrinsicInputsCallback;
	callbacks.freeNameAndTypeList = FreeNameAndTypeListCallback;
	callbacks.getIntrinsicOutputs = GetIntrinsicOutputsCallback;
	callbacks.freeTypeList = FreeTypeListCallback;
	callbacks.canAssemble = CanAssembleCallback;
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
	arch->Register(&callbacks);
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
	result.reserve(count);
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


size_t Architecture::GetInstructionAlignment() const
{
	return 1;
}


size_t Architecture::GetMaxInstructionLength() const
{
	return BN_DEFAULT_INSTRUCTION_LENGTH;
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
	return fmt::format("r{}", reg);
}


string Architecture::GetFlagName(uint32_t flag)
{
	return fmt::format("flag{}", flag);
}


string Architecture::GetFlagWriteTypeName(uint32_t flags)
{
	return fmt::format("update{}", flags);
}


string Architecture::GetSemanticFlagClassName(uint32_t semClass)
{
	if (semClass == 0)
		return "";
	return fmt::format("semantic{}", semClass);
}


string Architecture::GetSemanticFlagGroupName(uint32_t semGroup)
{
	return fmt::format("group{}", semGroup);
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


vector<uint32_t> Architecture::GetAllSemanticFlagClasses()
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetAllSemanticFlagGroups()
{
	return vector<uint32_t>();
}


BNFlagRole Architecture::GetFlagRole(uint32_t, uint32_t)
{
	return SpecialFlagRole;
}


vector<uint32_t> Architecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition, uint32_t)
{
	return vector<uint32_t>();
}


vector<uint32_t> Architecture::GetFlagsRequiredForSemanticFlagGroup(uint32_t)
{
	return vector<uint32_t>();
}


map<uint32_t, BNLowLevelILFlagCondition> Architecture::GetFlagConditionsForSemanticFlagGroup(uint32_t)
{
	return map<uint32_t, BNLowLevelILFlagCondition>();
}


vector<uint32_t> Architecture::GetFlagsWrittenByFlagWriteType(uint32_t)
{
	return vector<uint32_t>();
}


uint32_t Architecture::GetSemanticClassForFlagWriteType(uint32_t)
{
	return 0;
}


size_t Architecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	BNFlagRole role = GetFlagRole(flag, GetSemanticClassForFlagWriteType(flagWriteType));
	return BNGetDefaultArchitectureFlagWriteLowLevelIL(
	    m_object, op, size, role, operands, operandCount, il.GetObject());
}


size_t Architecture::GetDefaultFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, BNFlagRole role,
    BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagWriteLowLevelIL(
	    m_object, op, size, role, operands, operandCount, il.GetObject());
}


ExprId Architecture::GetFlagConditionLowLevelIL(
    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagConditionLowLevelIL(m_object, cond, semClass, il.GetObject());
}


ExprId Architecture::GetDefaultFlagConditionLowLevelIL(
    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il)
{
	return BNGetDefaultArchitectureFlagConditionLowLevelIL(m_object, cond, semClass, il.GetObject());
}


ExprId Architecture::GetSemanticFlagGroupLowLevelIL(uint32_t, LowLevelILFunction& il)
{
	return il.Unimplemented();
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


vector<uint32_t> Architecture::GetSystemRegisters()
{
	return vector<uint32_t>();
}


bool Architecture::IsGlobalRegister(uint32_t reg)
{
	return BNIsArchitectureGlobalRegister(m_object, reg);
}


bool Architecture::IsSystemRegister(uint32_t reg)
{
	return BNIsArchitectureSystemRegister(m_object, reg);
}


string Architecture::GetRegisterStackName(uint32_t regStack)
{
	return fmt::format("reg_stack_{}", regStack);
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


BNIntrinsicClass Architecture::GetIntrinsicClass(uint32_t intrinsic)
{
	return GeneralIntrinsicClass;
}


string Architecture::GetIntrinsicName(uint32_t intrinsic)
{
	return fmt::format("intrinsic_{}", intrinsic);
}


vector<uint32_t> Architecture::GetAllIntrinsics()
{
	return vector<uint32_t>();
}


vector<NameAndType> Architecture::GetIntrinsicInputs(uint32_t)
{
	return vector<NameAndType>();
}


vector<Confidence<Ref<Type>>> Architecture::GetIntrinsicOutputs(uint32_t)
{
	return vector<Confidence<Ref<Type>>>();
}


vector<uint32_t> Architecture::GetModifiedRegistersOnWrite(uint32_t reg)
{
	size_t count;
	uint32_t* regs = BNGetModifiedArchitectureRegistersOnWrite(m_object, reg, &count);

	vector<uint32_t> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


uint32_t Architecture::GetRegisterByName(const string& name)
{
	return BNGetArchitectureRegisterByName(m_object, name.c_str());
}

bool Architecture::CanAssemble()
{
	return false;
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


void Architecture::RegisterRelocationHandler(const string& viewName, RelocationHandler* handler)
{
	BNArchitectureRegisterRelocationHandler(m_object, viewName.c_str(), handler->GetObject());
}


Ref<RelocationHandler> Architecture::GetRelocationHandler(const std::string& viewName)
{
	auto handler = BNArchitectureGetRelocationHandler(m_object, viewName.c_str());
	if (!handler)
		return nullptr;
	return new CoreRelocationHandler(handler);
}

bool Architecture::IsBinaryViewTypeConstantDefined(const string& type, const string& name)
{
	return false;
}


uint64_t Architecture::GetBinaryViewTypeConstant(const string& type, const string& name, uint64_t defaultValue)
{
	return 0;
}


void Architecture::SetBinaryViewTypeConstant(const string& type, const string& name, uint64_t value)
{

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
	result.reserve(count);
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
	return new CorePlatform(BNGetArchitectureStandalonePlatform(m_object));
}


vector<Ref<TypeLibrary>> Architecture::GetTypeLibraries()
{
	size_t count;
	BNTypeLibrary** libs = BNGetArchitectureTypeLibraries(m_object, &count);

	vector<Ref<TypeLibrary>> result;
	for (size_t i = 0; i < count; ++i)
	{
		result.push_back(new TypeLibrary(BNNewTypeLibraryReference(libs[i])));
	}

	BNFreeTypeLibraryList(libs, count);
	return result;
}


void Architecture::AddArchitectureRedirection(Architecture* from, Architecture* to)
{
	BNAddArchitectureRedirection(m_object, from->GetObject(), to->GetObject());
}


CoreArchitecture::CoreArchitecture(BNArchitecture* arch) : Architecture(arch) {}


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


size_t CoreArchitecture::GetInstructionAlignment() const
{
	return BNGetArchitectureInstructionAlignment(m_object);
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


bool CoreArchitecture::GetInstructionText(
    const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result)
{
	BNInstructionTextToken* tokens = nullptr;
	size_t count = 0;
	if (!BNGetInstructionText(m_object, data, addr, &len, &tokens, &count))
		return false;

	result = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(tokens, count);
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


string CoreArchitecture::GetSemanticFlagClassName(uint32_t semClass)
{
	char* name = BNGetArchitectureSemanticFlagClassName(m_object, semClass);
	string result = name;
	BNFreeString(name);
	return result;
}


string CoreArchitecture::GetSemanticFlagGroupName(uint32_t semGroup)
{
	char* name = BNGetArchitectureSemanticFlagGroupName(m_object, semGroup);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<uint32_t> CoreArchitecture::GetFullWidthRegisters()
{
	size_t count;
	uint32_t* regs = BNGetFullWidthArchitectureRegisters(m_object, &count);

	vector<uint32_t> result;
	result.reserve(count);
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
	result.reserve(count);
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
	result.reserve(count);
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllSemanticFlagClasses()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureSemanticFlagClasses(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllSemanticFlagGroups()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureSemanticFlagGroups(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


BNFlagRole CoreArchitecture::GetFlagRole(uint32_t flag, uint32_t semClass)
{
	return BNGetArchitectureFlagRole(m_object, flag, semClass);
}


vector<uint32_t> CoreArchitecture::GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t semClass)
{
	size_t count;
	uint32_t* flags = BNGetArchitectureFlagsRequiredForFlagCondition(m_object, cond, semClass, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(flags[i]);

	BNFreeRegisterList(flags);
	return result;
}


vector<uint32_t> CoreArchitecture::GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup)
{
	size_t count;
	uint32_t* flags = BNGetArchitectureFlagsRequiredForSemanticFlagGroup(m_object, semGroup, &count);

	vector<uint32_t> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(flags[i]);

	BNFreeRegisterList(flags);
	return result;
}


map<uint32_t, BNLowLevelILFlagCondition> CoreArchitecture::GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup)
{
	size_t count;
	BNFlagConditionForSemanticClass* conditions =
	    BNGetArchitectureFlagConditionsForSemanticFlagGroup(m_object, semGroup, &count);

	map<uint32_t, BNLowLevelILFlagCondition> result;
	for (size_t i = 0; i < count; i++)
		result[conditions[i].semanticClass] = conditions[i].condition;

	BNFreeFlagConditionsForSemanticFlagGroup(conditions);
	return result;
}


vector<uint32_t> CoreArchitecture::GetFlagsWrittenByFlagWriteType(uint32_t writeType)
{
	size_t count;
	uint32_t* flags = BNGetArchitectureFlagsWrittenByFlagWriteType(m_object, writeType, &count);

	vector<uint32_t> result;
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(flags[i]);

	BNFreeRegisterList(flags);
	return result;
}


uint32_t CoreArchitecture::GetSemanticClassForFlagWriteType(uint32_t writeType)
{
	return BNGetArchitectureSemanticClassForFlagWriteType(m_object, writeType);
}


size_t CoreArchitecture::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	return BNGetArchitectureFlagWriteLowLevelIL(
	    m_object, op, size, flagWriteType, flag, operands, operandCount, il.GetObject());
}


ExprId CoreArchitecture::GetFlagConditionLowLevelIL(
    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il)
{
	return (ExprId)BNGetArchitectureFlagConditionLowLevelIL(m_object, cond, semClass, il.GetObject());
}


ExprId CoreArchitecture::GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il)
{
	return (ExprId)BNGetArchitectureSemanticFlagGroupLowLevelIL(m_object, semGroup, il.GetObject());
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
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreArchitecture::GetSystemRegisters()
{
	size_t count;
	uint32_t* regs = BNGetArchitectureSystemRegisters(m_object, &count);

	vector<uint32_t> result;
	result.reserve(count);
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


BNIntrinsicClass CoreArchitecture::GetIntrinsicClass(uint32_t intrinsic)
{
	return BNGetArchitectureIntrinsicClass(m_object, intrinsic);
}


string CoreArchitecture::GetIntrinsicName(uint32_t intrinsic)
{
	char* name = BNGetArchitectureIntrinsicName(m_object, intrinsic);
	string result = name;
	BNFreeString(name);
	return result;
}


vector<uint32_t> CoreArchitecture::GetAllIntrinsics()
{
	size_t count;
	uint32_t* regs = BNGetAllArchitectureIntrinsics(m_object, &count);

	vector<uint32_t> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(regs[i]);

	BNFreeRegisterList(regs);
	return result;
}


vector<NameAndType> CoreArchitecture::GetIntrinsicInputs(uint32_t intrinsic)
{
	size_t count;
	BNNameAndType* inputs = BNGetArchitectureIntrinsicInputs(m_object, intrinsic, &count);

	vector<NameAndType> result;
	for (size_t i = 0; i < count; i++)
	{
		result.push_back(NameAndType(inputs[i].name,
		    Confidence<Ref<Type>>(new Type(BNNewTypeReference(inputs[i].type)), inputs[i].typeConfidence)));
	}

	BNFreeNameAndTypeList(inputs, count);
	return result;
}


vector<Confidence<Ref<Type>>> CoreArchitecture::GetIntrinsicOutputs(uint32_t intrinsic)
{
	size_t count;
	BNTypeWithConfidence* outputs = BNGetArchitectureIntrinsicOutputs(m_object, intrinsic, &count);

	vector<Confidence<Ref<Type>>> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(Confidence<Ref<Type>>(new Type(BNNewTypeReference(outputs[i].type)), outputs[i].confidence));

	BNFreeOutputTypeList(outputs, count);
	return result;
}

bool CoreArchitecture::CanAssemble()
{
	return BNCanArchitectureAssemble(m_object);
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


ArchitectureExtension::ArchitectureExtension(const string& name, Architecture* base) : Architecture(name), m_base(base)
{}


void ArchitectureExtension::Register(BNCustomArchitecture* callbacks)
{
	AddRefForRegistration();
	BNRegisterArchitectureExtension(m_nameForRegister.c_str(), m_base->GetObject(), callbacks);
}


BNEndianness ArchitectureExtension::GetEndianness() const
{
	return m_base->GetEndianness();
}


size_t ArchitectureExtension::GetAddressSize() const
{
	return m_base->GetAddressSize();
}


size_t ArchitectureExtension::GetDefaultIntegerSize() const
{
	return m_base->GetDefaultIntegerSize();
}


size_t ArchitectureExtension::GetInstructionAlignment() const
{
	return m_base->GetInstructionAlignment();
}


size_t ArchitectureExtension::GetMaxInstructionLength() const
{
	return m_base->GetMaxInstructionLength();
}


size_t ArchitectureExtension::GetOpcodeDisplayLength() const
{
	return m_base->GetOpcodeDisplayLength();
}


Ref<Architecture> ArchitectureExtension::GetAssociatedArchitectureByAddress(uint64_t& addr)
{
	Ref<Architecture> result = m_base->GetAssociatedArchitectureByAddress(addr);
	if (result == m_base)
		return this;
	return result;
}


bool ArchitectureExtension::GetInstructionInfo(
    const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result)
{
	return m_base->GetInstructionInfo(data, addr, maxLen, result);
}


bool ArchitectureExtension::GetInstructionText(
    const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result)
{
	return m_base->GetInstructionText(data, addr, len, result);
}


bool ArchitectureExtension::GetInstructionLowLevelIL(
    const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il)
{
	return m_base->GetInstructionLowLevelIL(data, addr, len, il);
}


string ArchitectureExtension::GetRegisterName(uint32_t reg)
{
	return m_base->GetRegisterName(reg);
}


string ArchitectureExtension::GetFlagName(uint32_t flag)
{
	return m_base->GetFlagName(flag);
}


string ArchitectureExtension::GetFlagWriteTypeName(uint32_t flags)
{
	return m_base->GetFlagWriteTypeName(flags);
}


string ArchitectureExtension::GetSemanticFlagClassName(uint32_t semClass)
{
	return m_base->GetSemanticFlagClassName(semClass);
}


string ArchitectureExtension::GetSemanticFlagGroupName(uint32_t semGroup)
{
	return m_base->GetSemanticFlagGroupName(semGroup);
}


vector<uint32_t> ArchitectureExtension::GetFullWidthRegisters()
{
	return m_base->GetFullWidthRegisters();
}


vector<uint32_t> ArchitectureExtension::GetAllRegisters()
{
	return m_base->GetAllRegisters();
}


vector<uint32_t> ArchitectureExtension::GetAllFlags()
{
	return m_base->GetAllFlags();
}


vector<uint32_t> ArchitectureExtension::GetAllFlagWriteTypes()
{
	return m_base->GetAllFlagWriteTypes();
}


vector<uint32_t> ArchitectureExtension::GetAllSemanticFlagClasses()
{
	return m_base->GetAllSemanticFlagClasses();
}


vector<uint32_t> ArchitectureExtension::GetAllSemanticFlagGroups()
{
	return m_base->GetAllSemanticFlagGroups();
}


BNFlagRole ArchitectureExtension::GetFlagRole(uint32_t flag, uint32_t semClass)
{
	return m_base->GetFlagRole(flag, semClass);
}


vector<uint32_t> ArchitectureExtension::GetFlagsRequiredForFlagCondition(
    BNLowLevelILFlagCondition cond, uint32_t semClass)
{
	return m_base->GetFlagsRequiredForFlagCondition(cond, semClass);
}


vector<uint32_t> ArchitectureExtension::GetFlagsRequiredForSemanticFlagGroup(uint32_t semGroup)
{
	return m_base->GetFlagsRequiredForSemanticFlagGroup(semGroup);
}


map<uint32_t, BNLowLevelILFlagCondition> ArchitectureExtension::GetFlagConditionsForSemanticFlagGroup(uint32_t semGroup)
{
	return m_base->GetFlagConditionsForSemanticFlagGroup(semGroup);
}


vector<uint32_t> ArchitectureExtension::GetFlagsWrittenByFlagWriteType(uint32_t writeType)
{
	return m_base->GetFlagsWrittenByFlagWriteType(writeType);
}


uint32_t ArchitectureExtension::GetSemanticClassForFlagWriteType(uint32_t writeType)
{
	return m_base->GetSemanticClassForFlagWriteType(writeType);
}


ExprId ArchitectureExtension::GetFlagWriteLowLevelIL(BNLowLevelILOperation op, size_t size, uint32_t flagWriteType,
    uint32_t flag, BNRegisterOrConstant* operands, size_t operandCount, LowLevelILFunction& il)
{
	return m_base->GetFlagWriteLowLevelIL(op, size, flagWriteType, flag, operands, operandCount, il);
}


ExprId ArchitectureExtension::GetFlagConditionLowLevelIL(
    BNLowLevelILFlagCondition cond, uint32_t semClass, LowLevelILFunction& il)
{
	return m_base->GetFlagConditionLowLevelIL(cond, semClass, il);
}


ExprId ArchitectureExtension::GetSemanticFlagGroupLowLevelIL(uint32_t semGroup, LowLevelILFunction& il)
{
	return m_base->GetSemanticFlagGroupLowLevelIL(semGroup, il);
}


BNRegisterInfo ArchitectureExtension::GetRegisterInfo(uint32_t reg)
{
	return m_base->GetRegisterInfo(reg);
}


uint32_t ArchitectureExtension::GetStackPointerRegister()
{
	return m_base->GetStackPointerRegister();
}


uint32_t ArchitectureExtension::GetLinkRegister()
{
	return m_base->GetLinkRegister();
}


vector<uint32_t> ArchitectureExtension::GetGlobalRegisters()
{
	return m_base->GetGlobalRegisters();
}


vector<uint32_t> ArchitectureExtension::GetSystemRegisters()
{
	return m_base->GetSystemRegisters();
}


string ArchitectureExtension::GetRegisterStackName(uint32_t regStack)
{
	return m_base->GetRegisterStackName(regStack);
}


vector<uint32_t> ArchitectureExtension::GetAllRegisterStacks()
{
	return m_base->GetAllRegisterStacks();
}


BNRegisterStackInfo ArchitectureExtension::GetRegisterStackInfo(uint32_t regStack)
{
	return m_base->GetRegisterStackInfo(regStack);
}


BNIntrinsicClass ArchitectureExtension::GetIntrinsicClass(uint32_t intrinsic)
{
	return m_base->GetIntrinsicClass(intrinsic);
}


string ArchitectureExtension::GetIntrinsicName(uint32_t intrinsic)
{
	return m_base->GetIntrinsicName(intrinsic);
}


vector<uint32_t> ArchitectureExtension::GetAllIntrinsics()
{
	return m_base->GetAllIntrinsics();
}


vector<NameAndType> ArchitectureExtension::GetIntrinsicInputs(uint32_t intrinsic)
{
	return m_base->GetIntrinsicInputs(intrinsic);
}


vector<Confidence<Ref<Type>>> ArchitectureExtension::GetIntrinsicOutputs(uint32_t intrinsic)
{
	return m_base->GetIntrinsicOutputs(intrinsic);
}

bool ArchitectureExtension::CanAssemble()
{
	return m_base->CanAssemble();
}

bool ArchitectureExtension::Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors)
{
	return m_base->Assemble(code, addr, result, errors);
}


bool ArchitectureExtension::IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->IsNeverBranchPatchAvailable(data, addr, len);
}


bool ArchitectureExtension::IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->IsAlwaysBranchPatchAvailable(data, addr, len);
}


bool ArchitectureExtension::IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->IsInvertBranchPatchAvailable(data, addr, len);
}


bool ArchitectureExtension::IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->IsSkipAndReturnValuePatchAvailable(data, addr, len);
}


bool ArchitectureExtension::IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->IsSkipAndReturnValuePatchAvailable(data, addr, len);
}


bool ArchitectureExtension::ConvertToNop(uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->ConvertToNop(data, addr, len);
}


bool ArchitectureExtension::AlwaysBranch(uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->AlwaysBranch(data, addr, len);
}


bool ArchitectureExtension::InvertBranch(uint8_t* data, uint64_t addr, size_t len)
{
	return m_base->InvertBranch(data, addr, len);
}


bool ArchitectureExtension::SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value)
{
	return m_base->SkipAndReturnValue(data, addr, len, value);
}


ArchitectureHook::ArchitectureHook(Architecture* base) : CoreArchitecture(nullptr), m_base(base)
{
	// Architecture hooks allow existing architecture implementations to be extended without creating
	// a new Architecture object for the changes. By deriving from the ArchitectureHook class and passing
	// the original Architecture object of the architecture to be extended, any reimplemented functions
	// will be called first before the original architecture's implementation. You MUST call the base
	// class method to call the original implementation's version of the function, as calling the
	// same function on the original Architecture object will call your implementation again.

	// Example of a hook to modify the lifting process:

	// class ArchitectureHookExample: public ArchitectureHook
	// {
	// public:
	//     ArchitectureHookExample(Architecture* existingArch) : ArchitectureHook(existingArch)
	//     {
	//     }
	//
	//     virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len,
	//         LowLevelILFunction& il) override
	//     {
	//         // Perform extra lifting here
	//         // ...
	//         // For unhandled cases, call the original architecture's implementation
	//         return ArchitectureHook::GetInstructionLowLevelIL(data, addr, len, il);
	//     }
	// };
}


void ArchitectureHook::Register(BNCustomArchitecture* callbacks)
{
	AddRefForRegistration();
	m_object = BNRegisterArchitectureHook(m_base->GetObject(), callbacks);
	BNFinalizeArchitectureHook(m_base->GetObject());
}


string DisassemblyTextRenderer::GetDisplayStringForInteger(
    Ref<BinaryView> binaryView, BNIntegerDisplayType type, uint64_t value, size_t inputWidth, bool isSigned)
{
	char* str = BNGetDisplayStringForInteger(binaryView ? binaryView->GetObject() : nullptr,
		type, value, inputWidth, isSigned);
	string s(str);
	BNFreeString(str);
	return s;
}


DisassemblyTextRenderer::DisassemblyTextRenderer(Function* func, DisassemblySettings* settings)
{
	m_object = BNCreateDisassemblyTextRenderer(func->GetObject(), settings ? settings->GetObject() : nullptr);
}


DisassemblyTextRenderer::DisassemblyTextRenderer(LowLevelILFunction* func, DisassemblySettings* settings)
{
	m_object = BNCreateLowLevelILDisassemblyTextRenderer(func->GetObject(), settings ? settings->GetObject() : nullptr);
}


DisassemblyTextRenderer::DisassemblyTextRenderer(MediumLevelILFunction* func, DisassemblySettings* settings)
{
	m_object =
	    BNCreateMediumLevelILDisassemblyTextRenderer(func->GetObject(), settings ? settings->GetObject() : nullptr);
}


DisassemblyTextRenderer::DisassemblyTextRenderer(HighLevelILFunction* func, DisassemblySettings* settings)
{
	m_object =
	    BNCreateHighLevelILDisassemblyTextRenderer(func->GetObject(), settings ? settings->GetObject() : nullptr);
}


DisassemblyTextRenderer::DisassemblyTextRenderer(BNDisassemblyTextRenderer* renderer)
{
	m_object = renderer;
}


Ref<BasicBlock> DisassemblyTextRenderer::GetBasicBlock() const
{
	BNBasicBlock* block = BNGetDisassemblyTextRendererBasicBlock(m_object);
	if (block)
		return new BasicBlock(block);
	return nullptr;
}


Ref<Architecture> DisassemblyTextRenderer::GetArchitecture() const
{
	return new CoreArchitecture(BNGetDisassemblyTextRendererArchitecture(m_object));
}


Ref<DisassemblySettings> DisassemblyTextRenderer::GetSettings() const
{
	return new DisassemblySettings(BNGetDisassemblyTextRendererSettings(m_object));
}


Ref<Function> DisassemblyTextRenderer::GetFunction() const
{
	return new Function(BNGetDisassemblyTextRendererFunction(m_object));
}


Ref<LowLevelILFunction> DisassemblyTextRenderer::GetLowLevelILFunction() const
{
	BNLowLevelILFunction* result = BNGetDisassemblyTextRendererLowLevelILFunction(m_object);
	if (result)
		return new LowLevelILFunction(result);
	return nullptr;
}


Ref<MediumLevelILFunction> DisassemblyTextRenderer::GetMediumLevelILFunction() const
{
	BNMediumLevelILFunction* result = BNGetDisassemblyTextRendererMediumLevelILFunction(m_object);
	if (result)
		return new MediumLevelILFunction(result);
	return nullptr;
}


Ref<HighLevelILFunction> DisassemblyTextRenderer::GetHighLevelILFunction() const
{
	BNHighLevelILFunction* result = BNGetDisassemblyTextRendererHighLevelILFunction(m_object);
	if (result)
		return new HighLevelILFunction(result);
	return nullptr;
}


void DisassemblyTextRenderer::SetBasicBlock(BasicBlock* block)
{
	BNSetDisassemblyTextRendererBasicBlock(m_object, block ? block->GetObject() : nullptr);
}


void DisassemblyTextRenderer::SetArchitecture(Architecture* arch)
{
	BNSetDisassemblyTextRendererArchitecture(m_object, arch->GetObject());
}


void DisassemblyTextRenderer::SetSettings(DisassemblySettings* settings)
{
	BNSetDisassemblyTextRendererSettings(m_object, settings ? settings->GetObject() : nullptr);
}


bool DisassemblyTextRenderer::IsIL() const
{
	return BNIsILDisassemblyTextRenderer(m_object);
}


bool DisassemblyTextRenderer::HasDataFlow() const
{
	return BNDisassemblyTextRendererHasDataFlow(m_object);
}


void DisassemblyTextRenderer::GetInstructionAnnotations(vector<InstructionTextToken>& tokens, uint64_t addr)
{
	size_t count = 0;
	BNInstructionTextToken* result = BNGetDisassemblyTextRendererInstructionAnnotations(m_object, addr, &count);
	vector<InstructionTextToken> newTokens;
	newTokens = InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());
}


bool DisassemblyTextRenderer::GetInstructionText(uint64_t addr, size_t& len, vector<DisassemblyTextLine>& lines)
{
	BNDisassemblyTextLine* result = nullptr;
	size_t count = 0;
	if (!BNGetDisassemblyTextRendererInstructionText(m_object, addr, &len, &result, &count))
		return false;

	lines = ParseAPIObjectList<DisassemblyTextLine>(result, count);
	BNFreeDisassemblyTextLines(result, count);
	return true;
}


vector<DisassemblyTextLine> DisassemblyTextRenderer::PostProcessInstructionTextLines(
    uint64_t addr, size_t len, const vector<DisassemblyTextLine>& lines, const string& indentSpaces)
{
	size_t inCount = 0;
	BNDisassemblyTextLine* inLines = AllocAPIObjectList<DisassemblyTextLine>(lines, &inCount);
	BNDisassemblyTextLine* result = nullptr;
	size_t count = 0;
	result = BNPostProcessDisassemblyTextRendererLines(
	    m_object, addr, len, inLines, inCount, &count, indentSpaces.c_str());

	vector<DisassemblyTextLine> outLines = ParseAPIObjectList<DisassemblyTextLine>(result, count);
	FreeAPIObjectList<DisassemblyTextLine>(inLines, inCount);
	BNFreeDisassemblyTextLines(result, count);
	return outLines;
}


bool DisassemblyTextRenderer::GetDisassemblyText(uint64_t addr, size_t& len, vector<DisassemblyTextLine>& lines)
{
	BNDisassemblyTextLine* result = nullptr;
	size_t count = 0;
	if (!BNGetDisassemblyTextRendererLines(m_object, addr, &len, &result, &count))
		return false;

	lines = ParseAPIObjectList<DisassemblyTextLine>(result, count);
	BNFreeDisassemblyTextLines(result, count);
	return true;
}


void DisassemblyTextRenderer::ResetDeduplicatedComments()
{
	BNResetDisassemblyTextRendererDeduplicatedComments(m_object);
}


bool DisassemblyTextRenderer::AddSymbolToken(
    vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand)
{
	BNInstructionTextToken* result = nullptr;
	size_t count = 0;
	if (!BNGetDisassemblyTextRendererSymbolTokens(m_object, addr, size, operand, &result, &count))
		return false;
	vector<InstructionTextToken> newTokens =
	    InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());
	return true;
}


BNSymbolDisplayResult DisassemblyTextRenderer::AddSymbolTokenStatic(
	std::vector<InstructionTextToken>& tokens, uint64_t addr, size_t size, size_t operand,
	BinaryView* data, size_t maxSymbolWidth, Function* func, uint8_t confidence,
	BNSymbolDisplayType symbolDisplay, BNOperatorPrecedence precedence, uint64_t instrAddr, uint64_t exprIndex)
{
	BNInstructionTextToken* result = nullptr;
	size_t count = 0;
	BNSymbolDisplayResult display = BNGetDisassemblyTextRendererSymbolTokensStatic(
		addr, size, operand, data ? data->GetObject() : nullptr,
		maxSymbolWidth, func ? func->GetObject() : nullptr, confidence, symbolDisplay, precedence,
		instrAddr, exprIndex, &result, &count);
	vector<InstructionTextToken> newTokens =
		InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());
	return display;
}


void DisassemblyTextRenderer::AddStackVariableReferenceTokens(
    vector<InstructionTextToken>& tokens, const StackVariableReference& ref)
{
	BNStackVariableReference stackRef;
	stackRef.sourceOperand = ref.sourceOperand;
	stackRef.type = ref.type.GetValue() ? ref.type->GetObject() : nullptr;
	stackRef.typeConfidence = ref.type.GetConfidence();
	stackRef.name = BNAllocString(ref.name.c_str());
	stackRef.varIdentifier = ref.var.ToIdentifier();
	stackRef.referencedOffset = ref.referencedOffset;
	stackRef.size = ref.size;

	size_t count = 0;
	BNInstructionTextToken* result =
	    BNGetDisassemblyTextRendererStackVariableReferenceTokens(m_object, &stackRef, &count);
	BNFreeString(stackRef.name);

	vector<InstructionTextToken> newTokens =
	    InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());
}


bool DisassemblyTextRenderer::IsIntegerToken(BNInstructionTextTokenType type)
{
	return BNIsIntegerToken(type);
}


void DisassemblyTextRenderer::AddIntegerToken(
    vector<InstructionTextToken>& tokens, const InstructionTextToken& token, Architecture* arch, uint64_t addr)
{
	BNInstructionTextToken inToken;
	InstructionTextToken::ConvertInstructionTextToken(token, &inToken);

	size_t count = 0;
	BNInstructionTextToken* result =
	    BNGetDisassemblyTextRendererIntegerTokens(m_object, &inToken, arch ? arch->GetObject() : nullptr, addr, &count);

	vector<InstructionTextToken> newTokens =
	    InstructionTextToken::ConvertAndFreeInstructionTextTokenList(result, count);
	tokens.insert(tokens.end(), newTokens.begin(), newTokens.end());

	BNFreeString(inToken.text);
	for (size_t i = 0; i < inToken.namesCount; i++)
		BNFreeString(inToken.typeNames[i]);
	delete[] inToken.typeNames;
}


void DisassemblyTextRenderer::WrapComment(DisassemblyTextLine& line, vector<DisassemblyTextLine>& lines,
    const string& comment, bool hasAutoAnnotations, const string& leadingSpaces, const string& indentSpaces)
{
	BNDisassemblyTextLine inLine = line.GetAPIObject();
	size_t count = 0;
	BNDisassemblyTextLine* result = BNDisassemblyTextRendererWrapComment(
	    m_object, &inLine, &count, comment.c_str(), hasAutoAnnotations, leadingSpaces.c_str(), indentSpaces.c_str());

	lines = ParseAPIObjectList<DisassemblyTextLine>(result, count);
	BNFreeDisassemblyTextLines(result, count);
	DisassemblyTextLine::FreeAPIObject(&inLine);
}


string DisassemblyTextRenderer::GetStringLiteralPrefix(BNStringType type)
{
	char* prefix = BNGetStringLiteralPrefix(type);
	string result = prefix;
	BNFreeString(prefix);
	return result;
}


FunctionViewType::FunctionViewType(BNFunctionGraphType viewType) : type(viewType)
{
	if (type == HighLevelLanguageRepresentationFunctionGraph)
		name = "Pseudo C";
}


FunctionViewType::FunctionViewType(const BNFunctionViewType& viewType) : type(viewType.type)
{
	if (type == HighLevelLanguageRepresentationFunctionGraph)
	{
		if (viewType.name)
			name = viewType.name;
		else
			name = "Pseudo C";
	}
}


BNFunctionViewType FunctionViewType::ToAPIObject() const
{
	BNFunctionViewType result;
	result.type = type;
	result.name = nullptr;
	if (type == HighLevelLanguageRepresentationFunctionGraph)
		result.name = name.c_str();
	return result;
}


BNFunctionGraphType FunctionViewType::GetBackingILType() const
{
	if (type == HighLevelLanguageRepresentationFunctionGraph)
		return HighLevelILFunctionGraph;
	return type;
}


bool FunctionViewType::IsValidForView(BinaryView* view) const
{
	if (type != HighLevelLanguageRepresentationFunctionGraph)
		return true;
	Ref<LanguageRepresentationFunctionType> type = LanguageRepresentationFunctionType::GetByName(name);
	if (!type)
		return false;
	return type->IsValid(view);
}


bool FunctionViewType::operator==(const FunctionViewType& other) const
{
	if (type != other.type)
	    return false;
	if (type != HighLevelLanguageRepresentationFunctionGraph)
		return true;
	return name == other.name;
}


bool FunctionViewType::operator!=(const FunctionViewType& other) const
{
	if (type != other.type)
	    return true;
	if (type != HighLevelLanguageRepresentationFunctionGraph)
		return false;
	return name != other.name;
}


bool FunctionViewType::operator<(const FunctionViewType& other) const
{
	if (type < other.type)
		return true;
	if (type > other.type)
		return false;
	if (type != HighLevelLanguageRepresentationFunctionGraph)
		return false;
	return name < other.name;
}
