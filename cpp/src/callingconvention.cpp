// Copyright (c) 2015-2026 Vector 35 Inc
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


CallLayout CallLayout::FromAPIObject(BNCallLayout* layout)
{
	CallLayout result;
	result.parameters.reserve(layout->parameterCount);
	for (size_t i = 0; i < layout->parameterCount; i++)
		result.parameters.push_back(ValueLocation::FromAPIObject(&layout->parameters[i]));
	if (layout->returnValueValid)
		result.returnValue = ValueLocation::FromAPIObject(&layout->returnValue);
	result.stackAdjustment = layout->stackAdjustment;
	for (size_t i = 0; i < layout->registerStackAdjustmentCount; i++)
	{
		result.registerStackAdjustments[layout->registerStackAdjustmentRegisters[i]] =
			layout->registerStackAdjustmentAmounts[i];
	}
	return result;
}


BNCallLayout CallLayout::ToAPIObject() const
{
	BNCallLayout result;
	result.parameters = new BNValueLocation[parameters.size()];
	result.parameterCount = parameters.size();
	for (size_t i = 0; i < parameters.size(); i++)
		result.parameters[i] = parameters[i].ToAPIObject();
	result.returnValue = returnValue.value_or(ValueLocation()).ToAPIObject();
	result.returnValueValid = returnValue.has_value();
	result.stackAdjustment = stackAdjustment;

	result.registerStackAdjustmentCount = registerStackAdjustments.size();
	result.registerStackAdjustmentRegisters = new uint32_t[registerStackAdjustments.size()];
	result.registerStackAdjustmentAmounts = new int32_t[registerStackAdjustments.size()];
	size_t i = 0;
	for (auto [reg, adjust] : registerStackAdjustments)
	{
		result.registerStackAdjustmentRegisters[i] = reg;
		result.registerStackAdjustmentAmounts[i] = adjust;
		i++;
	}

	return result;
}


void CallLayout::FreeAPIObject(BNCallLayout* layout)
{
	for (size_t i = 0; i < layout->parameterCount; i++)
		ValueLocation::FreeAPIObject(&layout->parameters[i]);
	delete[] layout->parameters;
	ValueLocation::FreeAPIObject(&layout->returnValue);
	delete[] layout->registerStackAdjustmentRegisters;
	delete[] layout->registerStackAdjustmentAmounts;
}


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
	cc.getRequiredArgumentRegisters = GetRequiredArgumentRegistersCallback;
	cc.getRequiredClobberedRegisters = GetRequiredClobberedRegistersCallback;
	cc.freeRegisterList = FreeRegisterListCallback;
	cc.areArgumentRegistersSharedIndex = AreArgumentRegistersSharedIndexCallback;
	cc.areArgumentRegistersUsedForVarArgs = AreArgumentRegistersUsedForVarArgsCallback;
	cc.isStackReservedForArgumentRegisters = IsStackReservedForArgumentRegistersCallback;
	cc.isStackAdjustedOnReturn = IsStackAdjustedOnReturnCallback;
	cc.isEligibleForHeuristics = IsEligibleForHeuristicsCallback;
	cc.getIntegerReturnValueRegister = GetIntegerReturnValueRegisterCallback;
	cc.getHighIntegerReturnValueRegister = GetHighIntegerReturnValueRegisterCallback;
	cc.getFloatReturnValueRegister = GetFloatReturnValueRegisterCallback;
	cc.getGlobalPointerRegisters = GetGlobalPointerRegistersCallback;
	cc.getImplicitlyDefinedRegisters = GetImplicitlyDefinedRegistersCallback;
	cc.getIncomingRegisterValue = GetIncomingRegisterValueCallback;
	cc.getIncomingFlagValue = GetIncomingFlagValueCallback;
	cc.getIncomingVariableForParameterVariable = GetIncomingVariableForParameterVariableCallback;
	cc.getParameterVariableForIncomingVariable = GetParameterVariableForIncomingVariableCallback;
	cc.isReturnTypeRegisterCompatible = IsReturnTypeRegisterCompatibleCallback;
	cc.getIndirectReturnValueLocation = GetIndirectReturnValueLocationCallback;
	cc.getReturnedIndirectReturnValuePointer = GetReturnedIndirectReturnValuePointerCallback;
	cc.isArgumentTypeRegisterCompatible = IsArgumentTypeRegisterCompatibleCallback;
	cc.isNonRegisterArgumentIndirect = IsNonRegisterArgumentIndirectCallback;
	cc.areStackArgumentsNaturallyAligned = AreStackArgumentsNaturallyAlignedCallback;
	cc.areStackArgumentsPushedLeftToRight = AreStackArgumentsPushedLeftToRightCallback;
	cc.getCallLayout = GetCallLayoutCallback;
	cc.freeCallLayout = FreeCallLayoutCallback;
	cc.getReturnValueLocation = GetReturnValueLocationCallback;
	cc.freeValueLocation = FreeValueLocationCallback;
	cc.getParameterLocations = GetParameterLocationsCallback;
	cc.freeParameterLocations = FreeParameterLocationsCallback;
	cc.getParameterOrderingForVariables = GetParameterOrderingForVariablesCallback;
	cc.freeVariableList = FreeVariableListCallback;
	cc.getStackAdjustmentForLocations = GetStackAdjustmentForLocationsCallback;
	cc.getRegisterStackAdjustments = GetRegisterStackAdjustmentsCallback;
	cc.freeRegisterStackAdjustments = FreeRegisterStackAdjustmentsCallback;

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


uint32_t* CallingConvention::GetRequiredArgumentRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetRequiredArgumentRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


uint32_t* CallingConvention::GetRequiredClobberedRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetRequiredClobberedRegisters();
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


uint32_t* CallingConvention::GetGlobalPointerRegistersCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetGlobalPointerRegisters();
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
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


bool CallingConvention::IsReturnTypeRegisterCompatibleCallback(void* ctxt, BNBinaryView* view, BNType* type)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj;
	if (type)
		typeObj = new Type(BNNewTypeReference(type));
	return cc->IsReturnTypeRegisterCompatible(viewObj, typeObj);
}


void CallingConvention::GetIndirectReturnValueLocationCallback(void* ctxt, BNVariable* outVar)
{
	CallbackRef<CallingConvention> cc(ctxt);
	*outVar = cc->GetIndirectReturnValueLocation();
}


bool CallingConvention::GetReturnedIndirectReturnValuePointerCallback(void* ctxt, BNVariable* outVar)
{
	CallbackRef<CallingConvention> cc(ctxt);
	auto var = cc->GetReturnedIndirectReturnValuePointer();
	if (var.has_value())
		*outVar = var.value();
	return var.has_value();
}


bool CallingConvention::IsArgumentTypeRegisterCompatibleCallback(void* ctxt, BNBinaryView* view, BNType* type)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj;
	if (type)
		typeObj = new Type(BNNewTypeReference(type));
	return cc->IsArgumentTypeRegisterCompatible(viewObj, typeObj);
}


bool CallingConvention::IsNonRegisterArgumentIndirectCallback(void* ctxt, BNBinaryView* view, BNType* type)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	Ref<Type> typeObj;
	if (type)
		typeObj = new Type(BNNewTypeReference(type));
	return cc->IsNonRegisterArgumentIndirect(viewObj, typeObj);
}


bool CallingConvention::AreStackArgumentsNaturallyAlignedCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->AreStackArgumentsNaturallyAligned();
}


bool CallingConvention::AreStackArgumentsPushedLeftToRightCallback(void* ctxt)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->AreStackArgumentsPushedLeftToRight();
}


void CallingConvention::GetCallLayoutCallback(void* ctxt, BNBinaryView* view, BNReturnValue* returnValue,
	BNFunctionParameter* params, size_t paramCount, bool hasPermittedRegs, uint32_t* permittedRegs,
	size_t permittedRegCount, BNCallLayout* result)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	auto ret = ReturnValue::FromAPIObject(returnValue);
	vector<FunctionParameter> paramObjs;
	paramObjs.reserve(paramCount);
	for (size_t i = 0; i < paramCount; i++)
		paramObjs.push_back(FunctionParameter::FromAPIObject(&params[i]));
	optional<set<uint32_t>> regOpt;
	if (hasPermittedRegs)
	{
		set<uint32_t> regs;
		for (size_t i = 0; i < permittedRegCount; i++)
			regs.insert(permittedRegs[i]);
		regOpt = regs;
	}

	auto layout = cc->GetCallLayout(viewObj, ret, paramObjs, regOpt);
	*result = layout.ToAPIObject();
}


void CallingConvention::FreeCallLayoutCallback(void*, BNCallLayout* layout)
{
	CallLayout::FreeAPIObject(layout);
}


void CallingConvention::GetReturnValueLocationCallback(
	void* ctxt, BNBinaryView* view, BNReturnValue* returnValue, BNValueLocation* outLocation)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	ReturnValue ret = ReturnValue::FromAPIObject(returnValue);
	ValueLocation location = cc->GetReturnValueLocation(viewObj, ret);
	*outLocation = location.ToAPIObject();
}


void CallingConvention::FreeValueLocationCallback(void*, BNValueLocation* location)
{
	ValueLocation::FreeAPIObject(location);
}


BNValueLocation* CallingConvention::GetParameterLocationsCallback(void* ctxt, BNBinaryView* view,
	BNValueLocation* returnValue, BNFunctionParameter* params, size_t paramCount, bool hasPermittedRegs,
	uint32_t* permittedRegs, size_t permittedRegCount, size_t* outLocationCount)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	std::optional<ValueLocation> ret;
	if (returnValue)
		ret = ValueLocation::FromAPIObject(returnValue);
	vector<FunctionParameter> paramObjs;
	paramObjs.reserve(paramCount);
	for (size_t i = 0; i < paramCount; i++)
		paramObjs.push_back(FunctionParameter::FromAPIObject(&params[i]));
	optional<set<uint32_t>> regOpt;
	if (hasPermittedRegs)
	{
		set<uint32_t> regs;
		for (size_t i = 0; i < permittedRegCount; i++)
			regs.insert(permittedRegs[i]);
		regOpt = regs;
	}

	vector<ValueLocation> locations = cc->GetParameterLocations(viewObj, ret, paramObjs, regOpt);

	*outLocationCount = locations.size();
	BNValueLocation* result = new BNValueLocation[locations.size()];
	for (size_t i = 0; i < locations.size(); i++)
		result[i] = locations[i].ToAPIObject();
	return result;
}


void CallingConvention::FreeParameterLocationsCallback(void*, BNValueLocation* locations, size_t count)
{
	for (size_t i = 0; i < count; i++)
		ValueLocation::FreeAPIObject(&locations[i]);
	delete[] locations;
}


BNVariable* CallingConvention::GetParameterOrderingForVariablesCallback(
	void* ctxt, BNBinaryView* view, BNVariable* vars, BNType** types, size_t paramCount, size_t* outCount)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	map<Variable, Ref<Type>> params;
	for (size_t i = 0; i < paramCount; i++)
		params[vars[i]] = types[i] ? new Type(BNNewTypeReference(types[i])) : nullptr;

	auto outVars = cc->GetParameterOrderingForVariables(viewObj, params);

	*outCount = outVars.size();
	BNVariable* result = new BNVariable[outVars.size()];
	for (size_t i = 0; i < outVars.size(); i++)
		result[i] = outVars[i];
	return result;
}


void CallingConvention::FreeVariableListCallback(void*, BNVariable* vars, size_t)
{
	delete[] vars;
}


int64_t CallingConvention::GetStackAdjustmentForLocationsCallback(void* ctxt, BNBinaryView* view,
	BNValueLocation* returnValue, BNValueLocation* locations, BNType** types, size_t paramCount)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	std::optional<ValueLocation> ret;
	if (returnValue)
		ret = ValueLocation::FromAPIObject(returnValue);
	vector<ValueLocation> locationObjs;
	locationObjs.reserve(paramCount);
	for (size_t i = 0; i < paramCount; i++)
		locationObjs.push_back(ValueLocation::FromAPIObject(&locations[i]));
	vector<Ref<Type>> typeObjs;
	typeObjs.reserve(paramCount);
	for (size_t i = 0; i < paramCount; i++)
		typeObjs.push_back(new Type(BNNewTypeReference(types[i])));

	return cc->GetStackAdjustmentForLocations(viewObj, ret, locationObjs, typeObjs);
}


size_t CallingConvention::GetRegisterStackAdjustmentsCallback(void* ctxt, BNBinaryView* view,
	BNValueLocation* returnValue, BNValueLocation* params, size_t paramCount, uint32_t** outRegs, int32_t** outAdjust)
{
	CallbackRef<CallingConvention> cc(ctxt);
	Ref<BinaryView> viewObj;
	if (view)
		viewObj = new BinaryView(BNNewViewReference(view));
	std::optional<ValueLocation> ret;
	if (returnValue)
		ret = ValueLocation::FromAPIObject(returnValue);
	vector<ValueLocation> paramObjs;
	paramObjs.reserve(paramCount);
	for (size_t i = 0; i < paramCount; i++)
		paramObjs.push_back(ValueLocation::FromAPIObject(&params[i]));

	auto result = cc->GetRegisterStackAdjustments(viewObj, ret, paramObjs);

	*outRegs = new uint32_t[result.size()];
	*outAdjust = new int32_t[result.size()];
	size_t i = 0;
	for (auto it = result.begin(); it != result.end(); ++it, ++i)
	{
		(*outRegs)[i] = it->first;
		(*outAdjust)[i] = it->second;
	}
	return result.size();
}


void CallingConvention::FreeRegisterStackAdjustmentsCallback(void*, uint32_t* regs, int32_t* adjust, size_t)
{
	delete[] regs;
	delete[] adjust;
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


vector<uint32_t> CallingConvention::GetRequiredArgumentRegisters()
{
	return vector<uint32_t>();
}


vector<uint32_t> CallingConvention::GetRequiredClobberedRegisters()
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


vector<uint32_t> CallingConvention::GetGlobalPointerRegisters()
{
	uint32_t reg = GetGlobalPointerRegister();
	if (reg == BN_INVALID_REGISTER)
		return vector<uint32_t>();
	return vector<uint32_t> { reg };
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


bool CallingConvention::IsReturnTypeRegisterCompatible(BinaryView*, Type* type)
{
	return DefaultIsReturnTypeRegisterCompatible(type);
}


bool CallingConvention::DefaultIsReturnTypeRegisterCompatible(Type* type)
{
	return BNDefaultIsReturnTypeRegisterCompatible(m_object, type ? type->GetObject() : nullptr);
}


Variable CallingConvention::GetIndirectReturnValueLocation()
{
	return GetDefaultIndirectReturnValueLocation();
}


Variable CallingConvention::GetDefaultIndirectReturnValueLocation()
{
	return BNGetDefaultIndirectReturnValueLocation(m_object);
}


std::optional<Variable> CallingConvention::GetReturnedIndirectReturnValuePointer()
{
	return std::nullopt;
}


bool CallingConvention::IsArgumentTypeRegisterCompatible(BinaryView*, Type* type)
{
	return DefaultIsArgumentTypeRegisterCompatible(type);
}


bool CallingConvention::DefaultIsArgumentTypeRegisterCompatible(Type* type)
{
	return BNDefaultIsArgumentTypeRegisterCompatible(m_object, type ? type->GetObject() : nullptr);
}


bool CallingConvention::IsNonRegisterArgumentIndirect(BinaryView*, Type*)
{
	return false;
}


bool CallingConvention::AreStackArgumentsNaturallyAligned()
{
	return false;
}


bool CallingConvention::AreStackArgumentsPushedLeftToRight()
{
	return false;
}


CallLayout CallingConvention::GetCallLayout(BinaryView* view, const ReturnValue& returnValue,
	const vector<FunctionParameter>& params, const optional<set<uint32_t>>& permittedRegs)
{
	return GetDefaultCallLayout(view, returnValue, params, permittedRegs);
}


ValueLocation CallingConvention::GetReturnValueLocation(BinaryView* view, const ReturnValue& returnValue)
{
	return GetDefaultReturnValueLocation(view, returnValue);
}


vector<ValueLocation> CallingConvention::GetParameterLocations(BinaryView* view,
	const optional<ValueLocation>& returnValue, const vector<FunctionParameter>& params,
	const optional<set<uint32_t>>& permittedRegs)
{
	return GetDefaultParameterLocations(view, returnValue, params, permittedRegs);
}


std::vector<Variable> CallingConvention::GetParameterOrderingForVariables(
	BinaryView*, const std::map<Variable, Ref<Type>>& params)
{
	return GetDefaultParameterOrderingForVariables(params);
}


int64_t CallingConvention::GetStackAdjustmentForLocations(BinaryView*, const std::optional<ValueLocation>& returnValue,
	const std::vector<ValueLocation>& locations, const std::vector<Ref<Type>>& types)
{
	return GetDefaultStackAdjustmentForLocations(returnValue, locations, types);
}


std::map<uint32_t, int32_t> CallingConvention::GetRegisterStackAdjustments(
	BinaryView*, const std::optional<ValueLocation>& returnValue, const std::vector<ValueLocation>& params)
{
	return GetDefaultRegisterStackAdjustments(returnValue, params);
}


CallLayout CallingConvention::GetDefaultCallLayout(BinaryView* view, const ReturnValue& returnValue,
	const vector<FunctionParameter>& params, const optional<set<uint32_t>>& permittedRegs)
{
	BNReturnValue ret = returnValue.ToAPIObject();
	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	BNCallLayout layout;
	if (permittedRegs.has_value())
	{
		uint32_t* regs = new uint32_t[permittedRegs->size()];
		size_t i = 0;
		for (auto reg : *permittedRegs)
			regs[i++] = reg;
		layout = BNGetDefaultCallLayout(
			m_object, view ? view->GetObject() : nullptr, &ret, paramArray, params.size(), regs, permittedRegs->size());
		delete[] regs;
	}
	else
	{
		layout = BNGetDefaultCallLayoutDefaultPermittedArgs(
			m_object, view ? view->GetObject() : nullptr, &ret, paramArray, params.size());
	}

	ReturnValue::FreeAPIObject(&ret);
	for (size_t i = 0; i < params.size(); i++)
		FunctionParameter::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	CallLayout result = CallLayout::FromAPIObject(&layout);
	BNFreeCallLayout(&layout);
	return result;
}


ValueLocation CallingConvention::GetDefaultReturnValueLocation(BinaryView* view, const ReturnValue& returnValue)
{
	BNReturnValue ret = returnValue.ToAPIObject();
	BNValueLocation location = BNGetDefaultReturnValueLocation(m_object, view ? view->GetObject() : nullptr, &ret);
	ReturnValue::FreeAPIObject(&ret);

	ValueLocation result = ValueLocation::FromAPIObject(&location);
	BNFreeValueLocation(&location);
	return result;
}


vector<ValueLocation> CallingConvention::GetDefaultParameterLocations(BinaryView* view,
	const optional<ValueLocation>& returnValue, const vector<FunctionParameter>& params,
	const optional<set<uint32_t>>& permittedRegs)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	size_t locationCount = 0;
	BNValueLocation* locations;
	if (permittedRegs.has_value())
	{
		uint32_t* regs = new uint32_t[permittedRegs->size()];
		size_t i = 0;
		for (auto reg : *permittedRegs)
			regs[i++] = reg;
		locations = BNGetDefaultParameterLocations(m_object, view ? view->GetObject() : nullptr, retOpt, paramArray,
			params.size(), regs, permittedRegs->size(), &locationCount);
		delete[] regs;
	}
	else
	{
		locations = BNGetDefaultParameterLocationsDefaultPermittedArgs(
			m_object, view ? view->GetObject() : nullptr, retOpt, paramArray, params.size(), &locationCount);
	}

	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < params.size(); i++)
		FunctionParameter::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	vector<ValueLocation> result;
	result.reserve(locationCount);
	for (size_t i = 0; i < locationCount; i++)
		result.push_back(ValueLocation::FromAPIObject(&locations[i]));
	BNFreeValueLocationList(locations, locationCount);
	return result;
}


std::vector<Variable> CallingConvention::GetDefaultParameterOrderingForVariables(
	const std::map<Variable, Ref<Type>>& params)
{
	BNVariable* vars = new BNVariable[params.size()];
	const BNType** types = new const BNType*[params.size()];
	size_t i = 0;
	for (auto it = params.begin(); it != params.end(); ++it, ++i)
	{
		vars[i] = it->first;
		types[i] = it->second.GetPtr() ? it->second->GetObject() : nullptr;
	}

	size_t outCount = 0;
	auto outVars = BNGetDefaultParameterOrderingForVariables(m_object, vars, types, params.size(), &outCount);

	delete[] vars;
	delete[] types;

	vector<Variable> result;
	result.reserve(outCount);
	for (i = 0; i < outCount; i++)
		result.emplace_back(outVars[i]);
	BNFreeVariableList(outVars);
	return result;
}


int64_t CallingConvention::GetDefaultStackAdjustmentForLocations(const std::optional<ValueLocation>& returnValue,
	const std::vector<ValueLocation>& locations, const std::vector<Ref<Type>>& types)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	size_t count = locations.size();
	if (types.size() < count)
		count = types.size();
	BNValueLocation* locationArray = new BNValueLocation[count];
	for (size_t i = 0; i < count; i++)
		locationArray[i] = locations[i].ToAPIObject();
	const BNType** typeArray = new const BNType*[count];
	for (size_t i = 0; i < count; i++)
		typeArray[i] = types[i] ? types[i]->GetObject() : nullptr;

	int64_t result = BNGetDefaultStackAdjustmentForLocations(m_object, retOpt, locationArray, typeArray, count);
	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < count; i++)
		ValueLocation::FreeAPIObject(&locationArray[i]);
	delete[] locationArray;
	delete[] typeArray;
	return result;
}


std::map<uint32_t, int32_t> CallingConvention::GetDefaultRegisterStackAdjustments(
	const std::optional<ValueLocation>& returnValue, const std::vector<ValueLocation>& params)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	BNValueLocation* paramArray = new BNValueLocation[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	uint32_t* regs = nullptr;
	int32_t* adjust = nullptr;
	size_t count = BNGetCallingConventionDefaultRegisterStackAdjustments(
		m_object, retOpt, paramArray, params.size(), &regs, &adjust);

	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < params.size(); i++)
		ValueLocation::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	map<uint32_t, int32_t> result;
	for (size_t i = 0; i < count; i++)
		result[regs[i]] = adjust[i];
	BNFreeCallingConventionRegisterStackAdjustments(regs, adjust);
	return result;
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


vector<uint32_t> CoreCallingConvention::GetRequiredArgumentRegisters()
{
	size_t count;
	uint32_t* regs = BNGetRequiredArgumentRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetRequiredClobberedRegisters()
{
	size_t count;
	uint32_t* regs = BNGetRequiredClobberedRegisters(m_object, &count);
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
	vector<uint32_t> regs = GetGlobalPointerRegisters();
	if (regs.empty())
		return BN_INVALID_REGISTER;
	return regs[0];
}


vector<uint32_t> CoreCallingConvention::GetGlobalPointerRegisters()
{
	size_t count;
	uint32_t* regs = BNGetGlobalPointerRegisters(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
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


bool CoreCallingConvention::IsReturnTypeRegisterCompatible(BinaryView* view, Type* type)
{
	return BNIsReturnTypeRegisterCompatible(
		m_object, view ? view->GetObject() : nullptr, type ? type->GetObject() : nullptr);
}


Variable CoreCallingConvention::GetIndirectReturnValueLocation()
{
	return BNGetIndirectReturnValueLocation(m_object);
}


std::optional<Variable> CoreCallingConvention::GetReturnedIndirectReturnValuePointer()
{
	BNVariable var;
	if (BNGetReturnedIndirectReturnValuePointer(m_object, &var))
		return var;
	return std::nullopt;
}


bool CoreCallingConvention::IsArgumentTypeRegisterCompatible(BinaryView* view, Type* type)
{
	return BNIsArgumentTypeRegisterCompatible(
		m_object, view ? view->GetObject() : nullptr, type ? type->GetObject() : nullptr);
}


bool CoreCallingConvention::IsNonRegisterArgumentIndirect(BinaryView* view, Type* type)
{
	return BNIsNonRegisterArgumentIndirect(
		m_object, view ? view->GetObject() : nullptr, type ? type->GetObject() : nullptr);
}


bool CoreCallingConvention::AreStackArgumentsNaturallyAligned()
{
	return BNAreStackArgumentsNaturallyAligned(m_object);
}


bool CoreCallingConvention::AreStackArgumentsPushedLeftToRight()
{
	return BNAreStackArgumentsPushedLeftToRight(m_object);
}


CallLayout CoreCallingConvention::GetCallLayout(BinaryView* view, const ReturnValue& returnValue,
	const vector<FunctionParameter>& params, const optional<set<uint32_t>>& permittedRegs)
{
	BNReturnValue ret = returnValue.ToAPIObject();
	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	BNCallLayout layout;
	if (permittedRegs.has_value())
	{
		uint32_t* regs = new uint32_t[permittedRegs->size()];
		size_t i = 0;
		for (auto reg : *permittedRegs)
			regs[i++] = reg;
		layout = BNGetCallLayout(
			m_object, view ? view->GetObject() : nullptr, &ret, paramArray, params.size(), regs, permittedRegs->size());
		delete[] regs;
	}
	else
	{
		layout = BNGetCallLayoutDefaultPermittedArgs(
			m_object, view ? view->GetObject() : nullptr, &ret, paramArray, params.size());
	}

	ReturnValue::FreeAPIObject(&ret);
	for (size_t i = 0; i < params.size(); i++)
		FunctionParameter::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	CallLayout result = CallLayout::FromAPIObject(&layout);
	BNFreeCallLayout(&layout);
	return result;
}


ValueLocation CoreCallingConvention::GetReturnValueLocation(BinaryView* view, const ReturnValue& returnValue)
{
	BNReturnValue ret = returnValue.ToAPIObject();
	BNValueLocation location = BNGetReturnValueLocation(m_object, view ? view->GetObject() : nullptr, &ret);
	ReturnValue::FreeAPIObject(&ret);

	ValueLocation result = ValueLocation::FromAPIObject(&location);
	BNFreeValueLocation(&location);
	return result;
}


vector<ValueLocation> CoreCallingConvention::GetParameterLocations(BinaryView* view,
	const optional<ValueLocation>& returnValue, const vector<FunctionParameter>& params,
	const optional<set<uint32_t>>& permittedRegs)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	BNFunctionParameter* paramArray = new BNFunctionParameter[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	size_t locationCount = 0;
	BNValueLocation* locations;
	if (permittedRegs.has_value())
	{
		uint32_t* regs = new uint32_t[permittedRegs->size()];
		size_t i = 0;
		for (auto reg : *permittedRegs)
			regs[i++] = reg;
		locations = BNGetParameterLocations(m_object, view ? view->GetObject() : nullptr, retOpt, paramArray,
			params.size(), regs, permittedRegs->size(), &locationCount);
		delete[] regs;
	}
	else
	{
		locations = BNGetParameterLocationsDefaultPermittedArgs(
			m_object, view ? view->GetObject() : nullptr, retOpt, paramArray, params.size(), &locationCount);
	}

	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < params.size(); i++)
		FunctionParameter::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	vector<ValueLocation> result;
	result.reserve(locationCount);
	for (size_t i = 0; i < locationCount; i++)
		result.push_back(ValueLocation::FromAPIObject(&locations[i]));
	BNFreeValueLocationList(locations, locationCount);
	return result;
}


std::vector<Variable> CoreCallingConvention::GetParameterOrderingForVariables(
	BinaryView* view, const std::map<Variable, Ref<Type>>& params)
{
	BNVariable* vars = new BNVariable[params.size()];
	const BNType** types = new const BNType*[params.size()];
	size_t i = 0;
	for (auto it = params.begin(); it != params.end(); ++it, ++i)
	{
		vars[i] = it->first;
		types[i] = it->second.GetPtr() ? it->second->GetObject() : nullptr;
	}

	size_t outCount = 0;
	auto outVars = BNGetParameterOrderingForVariables(
		m_object, view ? view->GetObject() : nullptr, vars, types, params.size(), &outCount);

	delete[] vars;
	delete[] types;

	vector<Variable> result;
	result.reserve(outCount);
	for (i = 0; i < outCount; i++)
		result.emplace_back(outVars[i]);
	BNFreeVariableList(outVars);
	return result;
}


int64_t CoreCallingConvention::GetStackAdjustmentForLocations(BinaryView* view,
	const std::optional<ValueLocation>& returnValue, const std::vector<ValueLocation>& locations,
	const std::vector<Ref<Type>>& types)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	size_t count = locations.size();
	if (types.size() < count)
		count = types.size();
	BNValueLocation* locationArray = new BNValueLocation[count];
	for (size_t i = 0; i < count; i++)
		locationArray[i] = locations[i].ToAPIObject();
	const BNType** typeArray = new const BNType*[count];
	for (size_t i = 0; i < count; i++)
		typeArray[i] = types[i] ? types[i]->GetObject() : nullptr;

	int64_t result = BNGetStackAdjustmentForLocations(
		m_object, view ? view->GetObject() : nullptr, retOpt, locationArray, typeArray, count);
	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < count; i++)
		ValueLocation::FreeAPIObject(&locationArray[i]);
	delete[] locationArray;
	delete[] typeArray;
	return result;
}


std::map<uint32_t, int32_t> CoreCallingConvention::GetRegisterStackAdjustments(
	BinaryView* view, const std::optional<ValueLocation>& returnValue, const std::vector<ValueLocation>& params)
{
	BNValueLocation* retOpt = nullptr;
	BNValueLocation ret;
	if (returnValue.has_value())
	{
		ret = returnValue->ToAPIObject();
		retOpt = &ret;
	}
	BNValueLocation* paramArray = new BNValueLocation[params.size()];
	for (size_t i = 0; i < params.size(); i++)
		paramArray[i] = params[i].ToAPIObject();

	uint32_t* regs = nullptr;
	int32_t* adjust = nullptr;
	size_t count = BNGetCallingConventionRegisterStackAdjustments(
		m_object, view ? view->GetObject() : nullptr, retOpt, paramArray, params.size(), &regs, &adjust);

	if (retOpt)
		ValueLocation::FreeAPIObject(retOpt);
	for (size_t i = 0; i < params.size(); i++)
		ValueLocation::FreeAPIObject(&paramArray[i]);
	delete[] paramArray;

	map<uint32_t, int32_t> result;
	for (size_t i = 0; i < count; i++)
		result[regs[i]] = adjust[i];
	BNFreeCallingConventionRegisterStackAdjustments(regs, adjust);
	return result;
}
