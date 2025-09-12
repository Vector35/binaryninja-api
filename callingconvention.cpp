// Copyright (c) 2015-2025 Vector 35 Inc
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
	cc.getRegisterArgumentClasses = GetRegisterArgumentClassesCallback;
	cc.getRegisterArgumentClassLists = GetRegisterArgumentClassListsCallback;
	cc.getRegisterArgumentLists = GetRegisterArgumentListsCallback;
	cc.getRegisterArgumentListRegs = GetRegisterArgumentListRegsCallback;
	cc.getRegisterArgumentListKind = GetRegisterArgumentListKindCallback;
	cc.getVariablesForParameters = GetVariablesForParametersCallback;
	cc.freeVariableList = FreeVariableListCallback;

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


void CallingConvention::FreeVariableListCallback(void*, BNVariable* vars, size_t)
{
	delete[] vars;
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

vector<uint32_t> CallingConvention::GetRegisterArgumentClasses()
{
	/*
	This should return vector<uint32_t> {} when all architecture
	supports register class and register list.
	*/
	if (AreArgumentRegistersSharedIndex()) 
		return vector<uint32_t> {0};
	
	return vector<uint32_t> {0, 1};
}


vector<uint32_t> CallingConvention::GetRegisterArgumentClassLists(uint32_t classId)
{
	/*
	This should return vector<uint32_t> {} when all architecture
	supports register class and register list.
	*/
	if (AreArgumentRegistersSharedIndex()) {
		return vector<uint32_t> {0, 1};
	} else {
		if (0 == classId) {
			return vector<uint32_t> {0};
		} else if (1 == classId) {
			return vector<uint32_t> {1};
		}
	}
	return vector<uint32_t> {};
}


vector<uint32_t> CallingConvention::GetRegisterArgumentLists()
{
	vector<uint32_t> result;
	vector<uint32_t> classes = GetRegisterArgumentClasses();
	for(uint32_t classId : classes) 
	{
		vector<uint32_t> lists = GetRegisterArgumentClassLists(classId);
		result.insert(result.end(), lists.begin(), lists.end());
	}
	return result;
}


vector<uint32_t> CallingConvention::GetRegisterArgumentListRegs(uint32_t regListId)
{
	/*
	This should return vector<uint32_t> {} when all architecture
	supports register class and register list.
	
	Bridge implementation: use old APIs as fallback for architectures that haven't
	implemented the new register list/class APIs yet
	*/
	if (regListId == 0) {
		return GetIntegerArgumentRegisters();
	} else if (regListId == 1) {
		return GetFloatArgumentRegisters();
	}
	return vector<uint32_t>();
}


vector<Variable> CallingConvention::GetVariablesForParameters(
	const vector<FunctionParameter>& params, const std::optional<set<uint32_t>>& permittedRegs)
{
	vector<uint32_t> classes = GetRegisterArgumentClasses();
	
	// Build register lists for all classes
	// The order of iterators matter here, for register class and register list
	// we have assumed the INTEGER_SEMANTICS should be the first ones to be processed
	vector<vector<uint32_t>> allRegLists;
	vector<BNRegisterListKind> allListKinds;
	vector<vector<uint32_t>::iterator> allIterators;
	vector<vector<uint32_t>::iterator> allEndIterators;
	bool hasSharedIndex = false;
	
	for (uint32_t classId : classes)
	{
		vector<uint32_t> registerLists = GetRegisterArgumentClassLists(classId);
		if (registerLists.size() > 1)
			hasSharedIndex = true;
			
		for (uint32_t regListId : registerLists)
		{
			vector<uint32_t> regs = GetRegisterArgumentListRegs(regListId);
			BNRegisterListKind kind = GetRegisterArgumentListKind(regListId);
			
			allRegLists.push_back(regs);
			allListKinds.push_back(kind);
			allIterators.push_back(allRegLists.back().begin());
			allEndIterators.push_back(allRegLists.back().end());
		}
	}

	// Fallback to legacy API if no register classes defined
	if (allRegLists.empty())
	{
		vector<uint32_t> intArgs = GetIntegerArgumentRegisters();
		vector<uint32_t> floatArgs = GetFloatArgumentRegisters();
		
		if (!intArgs.empty())
		{
			allRegLists.push_back(intArgs);
			allListKinds.push_back(REGISTER_LIST_KIND_INTEGER_SEMANTICS);
			allIterators.push_back(allRegLists.back().begin());
			allEndIterators.push_back(allRegLists.back().end());
		}
		
		if (!floatArgs.empty())
		{
			allRegLists.push_back(floatArgs);
			allListKinds.push_back(REGISTER_LIST_KIND_FLOAT_SEMANTICS);
			allIterators.push_back(allRegLists.back().begin());
			allEndIterators.push_back(allRegLists.back().end());
		}
		
		hasSharedIndex = AreArgumentRegistersSharedIndex();
	}

	vector<Variable> result;
	size_t addrSize = GetArchitecture()->GetAddressSize();
	int64_t stackOffset = 0;
	
	if (GetArchitecture()->GetLinkRegister() == BN_INVALID_REGISTER)
		stackOffset = addrSize;
	if (IsStackReservedForArgumentRegisters())
	{
		// Count total registers for stack reservation
		size_t totalRegs = 0;
		for (const auto& list : allRegLists)
			totalRegs = std::max(totalRegs, list.size());
		stackOffset += totalRegs * addrSize;
	}

	// TODO: Structure in register and multi-reg parameters
	for (auto& param : params)
	{
		size_t width = param.type->GetWidth();

		if (!param.defaultLocation)
		{
			// Parameter not storage in a normal location, use custom variable
			result.push_back(param.location);
			
			if (param.location.type == RegisterVariableSourceType)
			{
				for (size_t i = 0; i < allIterators.size(); ++i)
				{
					if (allIterators[i] != allEndIterators[i] && *allIterators[i] == param.location.storage)
					{
						allIterators[i]++;
						
						// Advance all other iterators if shared index
						if (hasSharedIndex)
						{
							for (size_t j = i + 1; j < allIterators.size(); ++j)
							{
								if (allIterators[j] != allEndIterators[j])
									allIterators[j]++;
							}
						}
						break;
					}
				}
			}
			else if (param.location.type == StackVariableSourceType)
			{
				// Adjust next automatic stack location to after this one
				stackOffset = param.location.storage;
				if (width < addrSize)
					width = addrSize;
				else if ((width % addrSize) != 0)
					width += addrSize - (width % addrSize);
				stackOffset += width;
			}
			continue;
		}

		// Try to find a suitable register for this parameter
		bool paramPlaced = false;
		
		for (size_t i = 0; i < allIterators.size(); ++i)
		{
			if (allIterators[i] == allEndIterators[i])
				continue;
				
			// Check if this register is permitted
			if (permittedRegs.has_value() && permittedRegs.value().count(*allIterators[i]) == 0)
			{
				// Disallowed register parameter, mark this list as exhausted
				allIterators[i] = allEndIterators[i];
				if (hasSharedIndex)
				{
					// Mark all lists as exhausted when shared index
					for (size_t j = 0; j < allIterators.size(); ++j)
						allIterators[j] = allEndIterators[j];
				}
				continue;
			}
			
			// Check if the type matches the register semantics
			bool typeMatches = false;
			BNRegisterListKind kind = allListKinds[i];
			
			if (kind == REGISTER_LIST_KIND_INTEGER_SEMANTICS && !param.type->IsFloat())
				typeMatches = true;
			else if (kind == REGISTER_LIST_KIND_FLOAT_SEMANTICS && param.type->IsFloat())
				typeMatches = true;
			else if (kind == REGISTER_LIST_KIND_POINTER_SEMANTICS && param.type->IsPointer())
				typeMatches = true;
			
			if (typeMatches)
			{
				BNRegisterInfo regInfo = GetArchitecture()->GetRegisterInfo(*allIterators[i]);
				if (width <= regInfo.size)
				{
					result.emplace_back(RegisterVariableSourceType, 0, *allIterators[i]);
					allIterators[i]++;
					
					// Advance all other iterators if shared index
					if (hasSharedIndex)
					{
						for (size_t j = i + 1; j < allIterators.size(); ++j)
						{
							if (allIterators[j] != allEndIterators[j])
								allIterators[j]++;
						}
					}
					
					paramPlaced = true;
					break;
				}
			}
		}
		
		// If not placed in register, place on stack
		if (!paramPlaced)
		{
			result.emplace_back(StackVariableSourceType, 0, stackOffset);

			if (width < addrSize)
				width = addrSize;
			else if ((width % addrSize) != 0)
				width += addrSize - (width % addrSize);
			stackOffset += width;
		}
	}

	return result;
}


BNRegisterListKind CallingConvention::GetRegisterArgumentListKind(uint32_t regListId)
{
	// Default implementation: list 0 = integer, others = float
	return (regListId == 0) ? REGISTER_LIST_KIND_INTEGER_SEMANTICS : REGISTER_LIST_KIND_FLOAT_SEMANTICS;
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


vector<uint32_t> CoreCallingConvention::GetRegisterArgumentClasses()
{
	size_t count;
	uint32_t* classes = BNGetRegisterArgumentClasses(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), classes, &classes[count]);
	BNFreeRegisterList(classes);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetRegisterArgumentClassLists(uint32_t classId)
{
	size_t count;
	uint32_t* lists = BNGetRegisterArgumentClassLists(m_object, classId, &count);
	vector<uint32_t> result;
	result.insert(result.end(), lists, &lists[count]);
	BNFreeRegisterList(lists);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetRegisterArgumentLists()
{
	size_t count;
	uint32_t* lists = BNGetRegisterArgumentLists(m_object, &count);
	vector<uint32_t> result;
	result.insert(result.end(), lists, &lists[count]);
	BNFreeRegisterList(lists);
	return result;
}


vector<uint32_t> CoreCallingConvention::GetRegisterArgumentListRegs(uint32_t regListId)
{
	size_t count;
	uint32_t* regs = BNGetRegisterArgumentListRegs(m_object, regListId, &count);
	vector<uint32_t> result;
	result.insert(result.end(), regs, &regs[count]);
	BNFreeRegisterList(regs);
	return result;
}


BNRegisterListKind CoreCallingConvention::GetRegisterArgumentListKind(uint32_t regListId)
{
	return BNGetRegisterArgumentListKind(m_object, regListId);
}


vector<Variable> CoreCallingConvention::GetVariablesForParameters(const vector<FunctionParameter>& paramTypes,
	const std::optional<std::set<uint32_t>>& permittedRegs)
{
	BNFunctionParameter* params = new BNFunctionParameter[paramTypes.size()];
	for (size_t i = 0; i < paramTypes.size(); i++)
	{
		params[i].name = (char*)paramTypes[i].name.c_str();
		params[i].type = paramTypes[i].type->GetObject();
		params[i].typeConfidence = paramTypes[i].type.GetConfidence();
		params[i].defaultLocation = paramTypes[i].defaultLocation;
		params[i].location.type = paramTypes[i].location.type;
		params[i].location.index = paramTypes[i].location.index;
		params[i].location.storage = paramTypes[i].location.storage;
	}

	uint32_t* permittedRegsArray = nullptr;
	size_t permittedRegsCount = 0;
	if (permittedRegs.has_value())
	{
		permittedRegsCount = permittedRegs.value().size();
		permittedRegsArray = new uint32_t[permittedRegsCount];
		size_t j = 0;
		for (auto reg : permittedRegs.value())
			permittedRegsArray[j++] = reg;
	}

	size_t count;
	BNVariable* vars = BNGetVariablesForParameters(m_object, params, paramTypes.size(), 
		permittedRegsArray, permittedRegsCount, &count);
	
	vector<Variable> result;
	for (size_t i = 0; i < count; i++)
		result.push_back(vars[i]);
	BNFreeVariableList(vars);
	
	delete[] params;
	if (permittedRegsArray)
		delete[] permittedRegsArray;
	return result;
}


uint32_t* CallingConvention::GetRegisterArgumentClassesCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> classes = cc->GetRegisterArgumentClasses();
	*count = classes.size();

	uint32_t* result = new uint32_t[classes.size()];
	for (size_t i = 0; i < classes.size(); i++)
		result[i] = classes[i];
	return result;
}


uint32_t* CallingConvention::GetRegisterArgumentClassListsCallback(void* ctxt, uint32_t classId, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> lists = cc->GetRegisterArgumentClassLists(classId);
	*count = lists.size();

	uint32_t* result = new uint32_t[lists.size()];
	for (size_t i = 0; i < lists.size(); i++)
		result[i] = lists[i];
	return result;
}


uint32_t* CallingConvention::GetRegisterArgumentListsCallback(void* ctxt, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> lists = cc->GetRegisterArgumentLists();
	*count = lists.size();

	uint32_t* result = new uint32_t[lists.size()];
	for (size_t i = 0; i < lists.size(); i++)
		result[i] = lists[i];
	return result;
}


uint32_t* CallingConvention::GetRegisterArgumentListRegsCallback(void* ctxt, uint32_t regListId, size_t* count)
{
	CallbackRef<CallingConvention> cc(ctxt);
	vector<uint32_t> regs = cc->GetRegisterArgumentListRegs(regListId);
	*count = regs.size();

	uint32_t* result = new uint32_t[regs.size()];
	for (size_t i = 0; i < regs.size(); i++)
		result[i] = regs[i];
	return result;
}


BNRegisterListKind CallingConvention::GetRegisterArgumentListKindCallback(void* ctxt, uint32_t regListId)
{
	CallbackRef<CallingConvention> cc(ctxt);
	return cc->GetRegisterArgumentListKind(regListId);
}


BNVariable* CallingConvention::GetVariablesForParametersCallback(void* ctxt, const BNFunctionParameter* paramTypes, size_t paramCount, const uint32_t* permittedRegs, size_t permittedRegCount, size_t* resultCount)
{
	CallbackRef<CallingConvention> cc(ctxt);
	
	vector<FunctionParameter> params;
	for (size_t i = 0; i < paramCount; i++)
	{
		FunctionParameter param;
		param.name = paramTypes[i].name;
		param.type = Confidence<Ref<Type>>(new Type(BNNewTypeReference(paramTypes[i].type)), paramTypes[i].typeConfidence);
		param.defaultLocation = paramTypes[i].defaultLocation;
		param.location = paramTypes[i].location;
		params.push_back(param);
	}
	
	std::set<uint32_t> regsSet;
	std::optional<std::set<uint32_t>> permittedRegsSet;
	if (permittedRegs && permittedRegCount > 0)
	{
		for (size_t i = 0; i < permittedRegCount; i++)
			regsSet.insert(permittedRegs[i]);
		permittedRegsSet = regsSet;
	}
	
	vector<Variable> variables = cc->GetVariablesForParameters(params, permittedRegsSet);	
	*resultCount = variables.size();
	
	BNVariable* result = new BNVariable[variables.size()];
	for (size_t i = 0; i < variables.size(); i++)
		result[i] = variables[i];
	
	return result;
}
