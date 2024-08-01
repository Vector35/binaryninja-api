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

#include "binaryninjaapi.h"

using namespace std;
using namespace BinaryNinja;


CallingConvention::CallingConvention(BNCallingConvention* cc)
{
	m_object = cc;
}


CallingConvention::CallingConvention(Architecture* arch, const string& name)
{
	BNCustomCallingConvention cc;
	cc.context = this;
	cc.freeObject = FreeCallback;
	cc.getCallerSavedRegisters = GetCallerSavedRegistersCallback;
	cc.getCalleeSavedRegisters = GetCalleeSavedRegistersCallback;
	cc.getIntegerArgumentRegisters = GetIntegerArgumentRegistersCallback;
	cc.getFloatArgumentRegisters = GetFloatArgumentRegistersCallback;
	cc.freeRegisterList = FreeRegisterListCallback;
	cc.areArgumentRegistersSharedIndex = AreArgumentRegistersSharedIndexCallback;
	cc.areArgumentRegistersUsedForVarArgs = AreArgumentRegistersUsedForVarArgsCallback;
	cc.isStackReservedForArgumentRegisters = IsStackReservedForArgumentRegistersCallback;
	cc.isStackAdjustedOnReturn = IsStackAdjustedOnReturnCallback;
	cc.isEligibleForHeuristics = IsEligibleForHeuristicsCallback;
	cc.getIntegerReturnValueRegister = GetIntegerReturnValueRegisterCallback;
	cc.getHighIntegerReturnValueRegister = GetHighIntegerReturnValueRegisterCallback;
	cc.getFloatReturnValueRegister = GetFloatReturnValueRegisterCallback;
	cc.getGlobalPointerRegister = GetGlobalPointerRegisterCallback;
	cc.getImplicitlyDefinedRegisters = GetImplicitlyDefinedRegistersCallback;
	cc.getIncomingRegisterValue = GetIncomingRegisterValueCallback;
	cc.getIncomingFlagValue = GetIncomingFlagValueCallback;
	cc.getIncomingVariableForParameterVariable = GetIncomingVariableForParameterVariableCallback;
	cc.getParameterVariableForIncomingVariable = GetParameterVariableForIncomingVariableCallback;

	AddRefForRegistration();
	m_object = BNCreateCallingConvention(arch->GetObject(), name.c_str(), &cc);
}


void CallingConvention::FreeCallback(void* ctxt)
{
	CallingConvention* cc = (CallingConvention*)ctxt;
	cc->ReleaseForRegistration();
}


uint32_t* CallingConvention::GetCallerSavedRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetCallerSavedRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetCalleeSavedRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetCalleeSavedRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetIntegerArgumentRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetIntegerArgumentRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetFloatArgumentRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetFloatArgumentRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


void CallingConvention::FreeRegisterListCallback(void*, uint32_t* regs, size_t)
{
	delete[] regs;
}


bool CallingConvention::AreArgumentRegistersSharedIndexCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->AreArgumentRegistersSharedIndex();
}


bool CallingConvention::AreArgumentRegistersUsedForVarArgsCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->AreArgumentRegistersUsedForVarArgs();
}


bool CallingConvention::IsStackReservedForArgumentRegistersCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->IsStackReservedForArgumentRegisters();
}


bool CallingConvention::IsStackAdjustedOnReturnCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->IsStackAdjustedOnReturn();
}


bool CallingConvention::IsEligibleForHeuristicsCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->IsEligibleForHeuristics();
}


uint32_t CallingConvention::GetIntegerReturnValueRegisterCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->GetIntegerReturnValueRegister();
}


uint32_t CallingConvention::GetHighIntegerReturnValueRegisterCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->GetHighIntegerReturnValueRegister();
}


uint32_t CallingConvention::GetFloatReturnValueRegisterCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->GetFloatReturnValueRegister();
}


uint32_t CallingConvention::GetGlobalPointerRegisterCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->GetGlobalPointerRegister();
}


uint32_t* CallingConvention::GetImplicitlyDefinedRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetImplicitlyDefinedRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


void CallingConvention::GetIncomingRegisterValueCallback(
    void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<Function> funcObj;
	if (func)
		funcObj = new Function(BNNewFunctionReference(func));
	*result = cc->GetIncomingRegisterValue(reg, funcObj).ToAPIObject();
}


void CallingConvention::GetIncomingFlagValueCallback(
    void* ctxt, uint32_t reg, BNFunction* func, BNRegisterValue* result)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<Function> funcObj;
	if (func)
		funcObj = new Function(BNNewFunctionReference(func));
	*result = cc->GetIncomingFlagValue(reg, funcObj).ToAPIObject();
}


void CallingConvention::GetIncomingVariableForParameterVariableCallback(
    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<Function> funcObj;
	if (func)
		funcObj = new Function(BNNewFunctionReference(func));
	*result = cc->GetIncomingVariableForParameterVariable(*var, funcObj);
}


void CallingConvention::GetParameterVariableForIncomingVariableCallback(
    void* ctxt, const BNVariable* var, BNFunction* func, BNVariable* result)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<Function> funcObj;
	if (func)
		funcObj = new Function(BNNewFunctionReference(func));
	*result = cc->GetParameterVariableForIncomingVariable(*var, funcObj);
}


Ref<Architecture> CallingConvention::GetArchitecture() const
{
	return new CoreArchitecture(BNGetCallingConventionArchitecture(m_object));
}


string CallingConvention::GetName() const
{
	char* str = BNGetCallingConventionName(m_object);
	string result = str;
	BNFreeString(str);
	return result;
}


vector<uint32_t> CallingConvention::GetCallerSavedRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetCalleeSavedRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetIntegerArgumentRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetFloatArgumentRegisters()
{
	return vector<uint32_t>();
}


bool CallingConvention::AreArgumentRegistersSharedIndex()
{
	return false;
}


bool CallingConvention::AreArgumentRegistersUsedForVarArgs()
{
	return true;
}


bool CallingConvention::IsStackReservedForArgumentRegisters()
{
	return false;
}


bool CallingConvention::IsStackAdjustedOnReturn()
{
	return false;
}


bool CallingConvention::IsEligibleForHeuristics()
{
	return true;
}


uint32_t CallingConvention::GetHighIntegerReturnValueRegister()
{
	return BN_INVALID_REGISTER;
}


uint32_t CallingConvention::GetFloatReturnValueRegister()
{
	return BN_INVALID_REGISTER;
}


uint32_t CallingConvention::GetGlobalPointerRegister()
{
	return BN_INVALID_REGISTER;
}


vector<uint32_t> CallingConvention::GetImplicitlyDefinedRegisters()
{
	return vector<uint32_t>();
}


RegisterValue CallingConvention::GetIncomingRegisterValue(uint32_t reg, Function*)
{
	uint32_t regStack = GetArchitecture()->GetRegisterStackForRegister(reg);
	if ((regStack != BN_INVALID_REGISTER) && (reg == GetArchitecture()->GetRegisterStackInfo(regStack).stackTopReg))
	{
		RegisterValue value;
		value.state = ConstantValue;
		value.value = 0;
		return value;
	}
	return RegisterValue();
}


RegisterValue CallingConvention::GetIncomingFlagValue(uint32_t, Function*)
{
	return RegisterValue();
}


Variable CallingConvention::GetIncomingVariableForParameterVariable(const Variable& var, Function*)
{
	return BNGetDefaultIncomingVariableForParameterVariable(m_object, &var);
}


Variable CallingConvention::GetParameterVariableForIncomingVariable(const Variable& var, Function*)
{
	return BNGetDefaultParameterVariableForIncomingVariable(m_object, &var);
}


CoreCallingConvention::CoreCallingConvention(BNCallingConvention* cc) : CallingConvention(cc) {}


vector<uint32_t> CoreCallingConvention::GetCallerSavedRegisters()
{
	size_t count;
	uint32_t* regs = BNGetCallerSavedRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetCalleeSavedRegisters()
{
	size_t count;
	uint32_t* regs = BNGetCalleeSavedRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetIntegerArgumentRegisters()
{
	size_t count;
	uint32_t* regs = BNGetIntegerArgumentRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetFloatArgumentRegisters()
{
	size_t count;
	uint32_t* regs = BNGetFloatArgumentRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


bool CoreCallingConvention::AreArgumentRegistersSharedIndex()
{
	return BNAreArgumentRegistersSharedIndex(m_object);
}


bool CoreCallingConvention::AreArgumentRegistersUsedForVarArgs()
{
	return BNAreArgumentRegistersUsedForVarArgs(m_object);
}


bool CoreCallingConvention::IsStackReservedForArgumentRegisters()
{
	return BNIsStackReservedForArgumentRegisters(m_object);
}


bool CoreCallingConvention::IsStackAdjustedOnReturn()
{
	return BNIsStackAdjustedOnReturn(m_object);
}


bool CoreCallingConvention::IsEligibleForHeuristics()
{
	return BNIsEligibleForHeuristics(m_object);
}


uint32_t CoreCallingConvention::GetIntegerReturnValueRegister()
{
	return BNGetIntegerReturnValueRegister(m_object);
}


uint32_t CoreCallingConvention::GetHighIntegerReturnValueRegister()
{
	return BNGetHighIntegerReturnValueRegister(m_object);
}


uint32_t CoreCallingConvention::GetFloatReturnValueRegister()
{
	return BNGetFloatReturnValueRegister(m_object);
}


uint32_t CoreCallingConvention::GetGlobalPointerRegister()
{
	return BNGetGlobalPointerRegister(m_object);
}


vector<uint32_t> CoreCallingConvention::GetImplicitlyDefinedRegisters()
{
	size_t count;
	uint32_t* regs = BNGetImplicitlyDefinedRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


RegisterValue CoreCallingConvention::GetIncomingRegisterValue(uint32_t reg, Function* func)
{
	return RegisterValue::FromAPIObject(BNGetIncomingRegisterValue(m_object, reg, func ? func->GetObject() : nullptr));
}


RegisterValue CoreCallingConvention::GetIncomingFlagValue(uint32_t flag, Function* func)
{
	return RegisterValue::FromAPIObject(BNGetIncomingFlagValue(m_object, flag, func ? func->GetObject() : nullptr));
}


Variable CoreCallingConvention::GetIncomingVariableForParameterVariable(const Variable& var, Function* func)
{
	return BNGetIncomingVariableForParameterVariable(m_object, &var, func ? func->GetObject() : nullptr);
}


Variable CoreCallingConvention::GetParameterVariableForIncomingVariable(const Variable& var, Function* func)
{
	return BNGetParameterVariableForIncomingVariable(m_object, &var, func ? func->GetObject() : nullptr);
}
