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

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;


PluginCommandContext::PluginCommandContext()
{
	address = length = 0;
	instrIndex = BN_INVALID_EXPR;
}


PluginCommand::PluginCommand(const BNPluginCommand& cmd)
{
	m_command = cmd;
	m_command.name = BNAllocString(cmd.name);
	m_command.description = BNAllocString(cmd.description);
}


PluginCommand::PluginCommand(const PluginCommand& cmd)
{
	m_command = cmd.m_command;
	m_command.name = BNAllocString(cmd.m_command.name);
	m_command.description = BNAllocString(cmd.m_command.description);
}


PluginCommand::~PluginCommand()
{
	BNFreeString(m_command.name);
	BNFreeString(m_command.description);
}


PluginCommand& PluginCommand::operator=(const PluginCommand& cmd)
{
	BNFreeString(m_command.name);
	BNFreeString(m_command.description);
	m_command = cmd.m_command;
	m_command.name = BNAllocString(cmd.m_command.name);
	m_command.description = BNAllocString(cmd.m_command.description);
	return *this;
}


void PluginCommand::DefaultPluginCommandActionCallback(void* ctxt, BNBinaryView* view)
{
	RegisteredDefaultCommand* cmd = (RegisteredDefaultCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	cmd->action(viewObject);
}


void PluginCommand::AddressPluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr)
{
	RegisteredAddressCommand* cmd = (RegisteredAddressCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	cmd->action(viewObject, addr);
}


void PluginCommand::RangePluginCommandActionCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len)
{
	RegisteredRangeCommand* cmd = (RegisteredRangeCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	cmd->action(viewObject, addr, len);
}


void PluginCommand::FunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view, BNFunction* func)
{
	RegisteredFunctionCommand* cmd = (RegisteredFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<Function> funcObject = new Function(BNNewFunctionReference(func));
	cmd->action(viewObject, funcObject);
}


void PluginCommand::LowLevelILFunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
	BNLowLevelILFunction* func)
{
	RegisteredLowLevelILFunctionCommand* cmd = (RegisteredLowLevelILFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<LowLevelILFunction> funcObject = new LowLevelILFunction(BNNewLowLevelILFunctionReference(func));
	cmd->action(viewObject, funcObject);
}


void PluginCommand::LowLevelILInstructionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
	BNLowLevelILFunction* func, size_t instr)
{
	RegisteredLowLevelILInstructionCommand* cmd = (RegisteredLowLevelILInstructionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<LowLevelILFunction> funcObject = new LowLevelILFunction(BNNewLowLevelILFunctionReference(func));
	LowLevelILInstruction instrObject = funcObject->GetInstruction(instr);
	cmd->action(viewObject, instrObject);
}


void PluginCommand::MediumLevelILFunctionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
	BNMediumLevelILFunction* func)
{
	RegisteredMediumLevelILFunctionCommand* cmd = (RegisteredMediumLevelILFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<MediumLevelILFunction> funcObject = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(func));
	cmd->action(viewObject, funcObject);
}


void PluginCommand::MediumLevelILInstructionPluginCommandActionCallback(void* ctxt, BNBinaryView* view,
	BNMediumLevelILFunction* func, size_t instr)
{
	RegisteredMediumLevelILInstructionCommand* cmd = (RegisteredMediumLevelILInstructionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<MediumLevelILFunction> funcObject = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(func));
	MediumLevelILInstruction instrObject = funcObject->GetInstruction(instr);
	cmd->action(viewObject, instrObject);
}


bool PluginCommand::DefaultPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view)
{
	RegisteredDefaultCommand* cmd = (RegisteredDefaultCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	return cmd->isValid(viewObject);
}


bool PluginCommand::AddressPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr)
{
	RegisteredAddressCommand* cmd = (RegisteredAddressCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	return cmd->isValid(viewObject, addr);
}


bool PluginCommand::RangePluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, uint64_t addr, uint64_t len)
{
	RegisteredRangeCommand* cmd = (RegisteredRangeCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	return cmd->isValid(viewObject, addr, len);
}


bool PluginCommand::FunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view, BNFunction* func)
{
	RegisteredFunctionCommand* cmd = (RegisteredFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<Function> funcObject = new Function(BNNewFunctionReference(func));
	return cmd->isValid(viewObject, funcObject);
}


bool PluginCommand::LowLevelILFunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
	BNLowLevelILFunction* func)
{
	RegisteredLowLevelILFunctionCommand* cmd = (RegisteredLowLevelILFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<LowLevelILFunction> funcObject = new LowLevelILFunction(BNNewLowLevelILFunctionReference(func));
	return cmd->isValid(viewObject, funcObject);
}


bool PluginCommand::LowLevelILInstructionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
	BNLowLevelILFunction* func, size_t instr)
{
	RegisteredLowLevelILInstructionCommand* cmd = (RegisteredLowLevelILInstructionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<LowLevelILFunction> funcObject = new LowLevelILFunction(BNNewLowLevelILFunctionReference(func));
	LowLevelILInstruction instrObject = funcObject->GetInstruction(instr);
	return cmd->isValid(viewObject, instrObject);
}


bool PluginCommand::MediumLevelILFunctionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
	BNMediumLevelILFunction* func)
{
	RegisteredMediumLevelILFunctionCommand* cmd = (RegisteredMediumLevelILFunctionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<MediumLevelILFunction> funcObject = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(func));
	return cmd->isValid(viewObject, funcObject);
}


bool PluginCommand::MediumLevelILInstructionPluginCommandIsValidCallback(void* ctxt, BNBinaryView* view,
	BNMediumLevelILFunction* func, size_t instr)
{
	RegisteredMediumLevelILInstructionCommand* cmd = (RegisteredMediumLevelILInstructionCommand*)ctxt;
	Ref<BinaryView> viewObject = new BinaryView(BNNewViewReference(view));
	Ref<MediumLevelILFunction> funcObject = new MediumLevelILFunction(BNNewMediumLevelILFunctionReference(func));
	MediumLevelILInstruction instrObject = funcObject->GetInstruction(instr);
	return cmd->isValid(viewObject, instrObject);
}


void PluginCommand::Register(const string& name, const string& description,
                             const function<void(BinaryView* view)>& action)
{
	Register(name, description, action, [](BinaryView*) { return true; });
}


void PluginCommand::Register(const string& name, const string& description,
                             const function<void(BinaryView* view)>& action,
                             const function<bool(BinaryView* view)>& isValid)
{
	RegisteredDefaultCommand* cmd = new RegisteredDefaultCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommand(name.c_str(), description.c_str(), DefaultPluginCommandActionCallback,
	                        DefaultPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForAddress(const string& name, const string& description,
                                       const function<void(BinaryView* view, uint64_t addr)>& action)
{
	RegisterForAddress(name, description, action, [](BinaryView*, uint64_t) { return true; });
}


void PluginCommand::RegisterForAddress(const string& name, const string& description,
                                       const function<void(BinaryView* view, uint64_t addr)>& action,
                                       const function<bool(BinaryView* view, uint64_t addr)>& isValid)
{
	RegisteredAddressCommand* cmd = new RegisteredAddressCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForAddress(name.c_str(), description.c_str(), AddressPluginCommandActionCallback,
	                                  AddressPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForRange(const string& name, const string& description,
                                     const function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action)
{
	RegisterForRange(name, description, action, [](BinaryView*, uint64_t, uint64_t) { return true; });
}


void PluginCommand::RegisterForRange(const string& name, const string& description,
                                     const function<void(BinaryView* view, uint64_t addr, uint64_t len)>& action,
                                     const function<bool(BinaryView* view, uint64_t addr, uint64_t len)>& isValid)
{
	RegisteredRangeCommand* cmd = new RegisteredRangeCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForRange(name.c_str(), description.c_str(), RangePluginCommandActionCallback,
	                                RangePluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForFunction(const string& name, const string& description,
                                        const function<void(BinaryView* view, Function* func)>& action)
{
	RegisterForFunction(name, description, action, [](BinaryView*, Function*) { return true; });
}


void PluginCommand::RegisterForFunction(const string& name, const string& description,
                                        const function<void(BinaryView* view, Function* func)>& action,
                                        const function<bool(BinaryView* view, Function* func)>& isValid)
{
	RegisteredFunctionCommand* cmd = new RegisteredFunctionCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForFunction(name.c_str(), description.c_str(), FunctionPluginCommandActionCallback,
	                                   FunctionPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForLowLevelILFunction(const string& name, const string& description,
	const function<void(BinaryView* view, LowLevelILFunction* func)>& action)
{
	RegisterForLowLevelILFunction(name, description, action, [](BinaryView*, LowLevelILFunction*) { return true; });
}


void PluginCommand::RegisterForLowLevelILFunction(const string& name, const string& description,
	const function<void(BinaryView* view, LowLevelILFunction* func)>& action,
	const function<bool(BinaryView* view, LowLevelILFunction* func)>& isValid)
{
	RegisteredLowLevelILFunctionCommand* cmd = new RegisteredLowLevelILFunctionCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForLowLevelILFunction(name.c_str(), description.c_str(),
		LowLevelILFunctionPluginCommandActionCallback,
		LowLevelILFunctionPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForLowLevelILInstruction(const string& name, const string& description,
	const function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action)
{
	RegisterForLowLevelILInstruction(name, description, action,
		[](BinaryView*, const LowLevelILInstruction&) { return true; });
}


void PluginCommand::RegisterForLowLevelILInstruction(const string& name, const string& description,
	const function<void(BinaryView* view, const LowLevelILInstruction& instr)>& action,
	const function<bool(BinaryView* view, const LowLevelILInstruction& instr)>& isValid)
{
	RegisteredLowLevelILInstructionCommand* cmd = new RegisteredLowLevelILInstructionCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForLowLevelILInstruction(name.c_str(), description.c_str(),
		LowLevelILInstructionPluginCommandActionCallback,
		LowLevelILInstructionPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForMediumLevelILFunction(const string& name, const string& description,
	const function<void(BinaryView* view, MediumLevelILFunction* func)>& action)
{
	RegisterForMediumLevelILFunction(name, description, action,
		[](BinaryView*, MediumLevelILFunction*) { return true; });
}


void PluginCommand::RegisterForMediumLevelILFunction(const string& name, const string& description,
	const function<void(BinaryView* view, MediumLevelILFunction* func)>& action,
	const function<bool(BinaryView* view, MediumLevelILFunction* func)>& isValid)
{
	RegisteredMediumLevelILFunctionCommand* cmd = new RegisteredMediumLevelILFunctionCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForMediumLevelILFunction(name.c_str(), description.c_str(),
		MediumLevelILFunctionPluginCommandActionCallback,
		MediumLevelILFunctionPluginCommandIsValidCallback, cmd);
}


void PluginCommand::RegisterForMediumLevelILInstruction(const string& name, const string& description,
	const function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action)
{
	RegisterForMediumLevelILInstruction(name, description, action,
		[](BinaryView*, const MediumLevelILInstruction&) { return true; });
}


void PluginCommand::RegisterForMediumLevelILInstruction(const string& name, const string& description,
	const function<void(BinaryView* view, const MediumLevelILInstruction& instr)>& action,
	const function<bool(BinaryView* view, const MediumLevelILInstruction& instr)>& isValid)
{
	RegisteredMediumLevelILInstructionCommand* cmd = new RegisteredMediumLevelILInstructionCommand;
	cmd->action = action;
	cmd->isValid = isValid;
	BNRegisterPluginCommandForMediumLevelILInstruction(name.c_str(), description.c_str(),
		MediumLevelILInstructionPluginCommandActionCallback,
		MediumLevelILInstructionPluginCommandIsValidCallback, cmd);
}


vector<PluginCommand> PluginCommand::GetList()
{
	vector<PluginCommand> result;
	size_t count;
	BNPluginCommand* commands = BNGetAllPluginCommands(&count);
	result.reserve(count);
	for (size_t i = 0; i < count; i++)
		result.emplace_back(commands[i]);
	BNFreePluginCommandList(commands);
	return result;
}


vector<PluginCommand> PluginCommand::GetValidList(const PluginCommandContext& ctxt)
{
	vector<PluginCommand> commands = GetList();
	vector<PluginCommand> result;
	for (auto& i : commands)
	{
		if (i.IsValid(ctxt))
			result.push_back(i);
	}
	return result;
}


bool PluginCommand::IsValid(const PluginCommandContext& ctxt) const
{
	if (!ctxt.view)
		return false;

	switch (m_command.type)
	{
	case DefaultPluginCommand:
		if (!m_command.defaultIsValid)
			return true;
		return m_command.defaultIsValid(m_command.context, ctxt.view->GetObject());
	case AddressPluginCommand:
		if (!m_command.addressIsValid)
			return true;
		return m_command.addressIsValid(m_command.context, ctxt.view->GetObject(), ctxt.address);
	case RangePluginCommand:
		if (ctxt.length == 0)
			return false;
		if (!m_command.rangeIsValid)
			return true;
		return m_command.rangeIsValid(m_command.context, ctxt.view->GetObject(), ctxt.address, ctxt.length);
	case FunctionPluginCommand:
		if (!ctxt.function)
			return false;
		if (!m_command.functionIsValid)
			return true;
		return m_command.functionIsValid(m_command.context, ctxt.view->GetObject(), ctxt.function->GetObject());
	case LowLevelILFunctionPluginCommand:
		if (!ctxt.lowLevelILFunction)
			return false;
		if (!m_command.lowLevelILFunctionIsValid)
			return true;
		return m_command.lowLevelILFunctionIsValid(m_command.context, ctxt.view->GetObject(),
			ctxt.lowLevelILFunction->GetObject());
	case LowLevelILInstructionPluginCommand:
		if (!ctxt.lowLevelILFunction)
			return false;
		if (ctxt.instrIndex == BN_INVALID_EXPR)
			return false;
		if (!m_command.lowLevelILInstructionIsValid)
			return true;
		return m_command.lowLevelILInstructionIsValid(m_command.context, ctxt.view->GetObject(),
			ctxt.lowLevelILFunction->GetObject(), ctxt.instrIndex);
	case MediumLevelILFunctionPluginCommand:
		if (!ctxt.mediumLevelILFunction)
			return false;
		if (!m_command.mediumLevelILFunctionIsValid)
			return true;
		return m_command.mediumLevelILFunctionIsValid(m_command.context, ctxt.view->GetObject(),
			ctxt.mediumLevelILFunction->GetObject());
	case MediumLevelILInstructionPluginCommand:
		if (!ctxt.mediumLevelILFunction)
			return false;
		if (ctxt.instrIndex == BN_INVALID_EXPR)
			return false;
		if (!m_command.mediumLevelILInstructionIsValid)
			return true;
		return m_command.mediumLevelILInstructionIsValid(m_command.context, ctxt.view->GetObject(),
			ctxt.mediumLevelILFunction->GetObject(), ctxt.instrIndex);
	default:
		return false;
	}
}


void PluginCommand::Execute(const PluginCommandContext& ctxt) const
{
	if (!IsValid(ctxt))
		return;

	switch (m_command.type)
	{
	case DefaultPluginCommand:
		m_command.defaultCommand(m_command.context, ctxt.view->GetObject());
		break;
	case AddressPluginCommand:
		m_command.addressCommand(m_command.context, ctxt.view->GetObject(), ctxt.address);
		break;
	case RangePluginCommand:
		m_command.rangeCommand(m_command.context, ctxt.view->GetObject(), ctxt.address, ctxt.length);
		break;
	case FunctionPluginCommand:
		m_command.functionCommand(m_command.context, ctxt.view->GetObject(), ctxt.function->GetObject());
		break;
	case LowLevelILFunctionPluginCommand:
		m_command.lowLevelILFunctionCommand(m_command.context, ctxt.view->GetObject(),
			ctxt.lowLevelILFunction->GetObject());
		break;
	case LowLevelILInstructionPluginCommand:
		m_command.lowLevelILInstructionCommand(m_command.context, ctxt.view->GetObject(),
			ctxt.lowLevelILFunction->GetObject(), ctxt.instrIndex);
		break;
	case MediumLevelILFunctionPluginCommand:
		m_command.mediumLevelILFunctionCommand(m_command.context, ctxt.view->GetObject(),
			ctxt.mediumLevelILFunction->GetObject());
		break;
	case MediumLevelILInstructionPluginCommand:
		m_command.mediumLevelILInstructionCommand(m_command.context, ctxt.view->GetObject(),
			ctxt.mediumLevelILFunction->GetObject(), ctxt.instrIndex);
		break;
	default:
		break;
	}
}
