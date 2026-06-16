#include "DxeResolver.h"

bool DxeResolver::resolveProtocolGuid(Ref<Function> func, uint64_t addr, size_t guidParam)
{
	bool changed = false;
	auto hlils = GetCallExprs(HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr), addr);
	for (auto hlil : hlils)
	{
		auto params = hlil.GetParameterExprs();
		if (params.size() <= guidParam)
			continue;

		auto guidDataAddr = GetConstantDataAddress(params[guidParam]);
		if (!guidDataAddr || *guidDataAddr == 0)
			continue;

		EFI_GUID guid;
		if (m_view->Read(&guid, *guidDataAddr, 16) < 16)
			continue;

		auto info = Resolver::resolveProtocolGuid(guid, addr);
		if (defineGuidDataVariable(*guidDataAddr, info.guidName))
			changed = true;
	}
	if (changed)
		m_view->UpdateAnalysis();
	return changed;
}

bool DxeResolver::resolveProtocolInterfaces(
	Ref<Function> func, uint64_t addr, size_t guidParam, const vector<size_t>& interfaceParams)
{
	bool changed = false;
	auto hlils = GetCallExprs(HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr), addr);
	for (auto hlil : hlils)
	{
		auto params = hlil.GetParameterExprs();
		if (params.size() <= guidParam)
			continue;

		auto guidDataAddr = GetConstantDataAddress(params[guidParam]);
		if (!guidDataAddr || *guidDataAddr == 0)
			continue;

		EFI_GUID guid;
		if (m_view->Read(&guid, *guidDataAddr, 16) < 16)
			continue;

		auto info = Resolver::resolveProtocolGuid(guid, addr);
		if (defineGuidDataVariable(*guidDataAddr, info.guidName))
			changed = true;

		for (auto interfaceParam : interfaceParams)
		{
			if (params.size() <= interfaceParam)
				continue;
			if (applyProtocolInterface(func, params[interfaceParam], info, false))
				changed = true;
		}
	}
	if (changed)
		m_view->UpdateAnalysis();
	return changed;
}

bool DxeResolver::resolveProtocolInterfaceList(Ref<Function> func, uint64_t addr, size_t firstGuidParam)
{
	// InstallMultipleProtocolInterfaces and UninstallMultipleProtocolInterfaces take varargs shaped as:
	//   Handle, ProtocolGuid, Interface, ..., nullptr
	// The interface is the protocol implementation pointer itself, not an output parameter.
	bool changed = false;
	auto hlils = GetCallExprs(HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr), addr);
	for (auto hlil : hlils)
	{
		auto params = hlil.GetParameterExprs();
		for (size_t guidParam = firstGuidParam; guidParam + 1 < params.size(); guidParam += 2)
		{
			auto guidDataAddr = GetConstantDataAddress(params[guidParam]);
			if (!guidDataAddr || *guidDataAddr == 0)
				break;

			EFI_GUID guid;
			if (m_view->Read(&guid, *guidDataAddr, 16) < 16)
				continue;

			auto info = Resolver::resolveProtocolGuid(guid, addr);
			if (!defineGuidDataVariable(*guidDataAddr, info.guidName))
				continue;
			changed = true;

			if (applyProtocolInterface(func, params[guidParam + 1], info, false))
				changed = true;
		}
	}
	if (changed)
		m_view->UpdateAnalysis();
	return changed;
}

bool DxeResolver::resolveBootServices()
{
	SetProgressText("Resolving Boot Services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_BOOT_SERVICES"));
	// search reference of `EFI_BOOT_SERVICES` so that we can easily parse different services

	for (auto& ref : refs)
	{
		if (IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		size_t mlilSsaIdx = mlil->GetSSAInstructionIndex(mlilIdx);
		if (mlilSsaIdx >= mlilSsa->GetInstructionCount())
			continue;
		auto instr = mlilSsa->GetInstruction(mlilSsaIdx);

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();

			if (offset == 0x18 + m_width * 13)
			{
				// InstallProtocolInterface
				// Guid:1, Interface:3
				resolveProtocolInterfaces(ref.func, ref.addr, 1, {3});
			}
			else if (offset == 0x18 + m_width * 14)
			{
				// ReinstallProtocolInterface
				// Guid:1, OldInterface:2, NewInterface:3
				resolveProtocolInterfaces(ref.func, ref.addr, 1, {2, 3});
			}
			else if (offset == 0x18 + m_width * 15)
			{
				// UninstallProtocolInterface
				// Guid:1, Interface:2
				resolveProtocolInterfaces(ref.func, ref.addr, 1, {2});
			}
			else if (offset == 0x18 + m_width * 16 || offset == 0x18 + m_width * 32)
			{
				// HandleProtocol, OpenProtocol
				// Guid:1, Interface:2
				resolveGuidInterface(ref.func, ref.addr, 1, 2);
			}
			else if (offset == 0x18 + m_width * 18 || offset == 0x18 + m_width * 19)
			{
				// RegisterProtocolNotify, LocateHandle
				// Guid:0 for RegisterProtocolNotify, Guid:1 for LocateHandle
				resolveProtocolGuid(ref.func, ref.addr, offset == 0x18 + m_width * 18 ? 0 : 1);
			}
			else if (offset == 0x18 + m_width * 34 || offset == 0x18 + m_width * 36)
			{
				// OpenProtocolInformation, LocateHandleBuffer
				// Guid:1
				resolveProtocolGuid(ref.func, ref.addr, 1);
			}
			else if (offset == 0x18 + m_width * 37)
			{
				// LocateProtocol
				resolveGuidInterface(ref.func, ref.addr, 0, 2);
			}
			else if (offset == 0x18 + m_width * 38 || offset == 0x18 + m_width * 39)
			{
				// InstallMultipleProtocolInterfaces, UninstallMultipleProtocolInterfaces
				// Varargs start after the handle parameter.
				resolveProtocolInterfaceList(ref.func, ref.addr, 1);
			}
		}
	}
	return true;
}

bool DxeResolver::resolveRuntimeServices()
{
	SetProgressText("Resolving Runtime Services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_RUNTIME_SERVICES"));

	for (auto& ref : refs)
	{
		if (IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		size_t mlilSsaIdx = mlil->GetSSAInstructionIndex(mlilIdx);
		if (mlilSsaIdx >= mlilSsa->GetInstructionCount())
			continue;
		auto instr = mlilSsa->GetInstruction(mlilSsaIdx);

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();
			if (offset == 0x18 + m_width * 6 || offset == 0x18 + m_width * 8)
			{
				// TODO implement this
				// GetVariable and SetVariable
			}
		}
	}
	return true;
}

bool DxeResolver::resolveSmmTables(string serviceName, string tableName)
{
	SetProgressText("Defining MM tables...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName(serviceName));
	// both versions use the same type, so we only need to search for this one
	for (auto& ref : refs)
	{
		if (IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		size_t mlilSsaIdx = mlil->GetSSAInstructionIndex(mlilIdx);
		if (mlilSsaIdx >= mlilSsa->GetInstructionCount())
			continue;
		auto instr = mlilSsa->GetInstruction(mlilSsaIdx);

		if (instr.operation != MLIL_CALL_SSA && instr.operation != MLIL_TAILCALL_SSA)
			continue;

		auto destExpr = instr.GetDestExpr();
		if (destExpr.operation != MLIL_LOAD_STRUCT_SSA)
			continue;

		if (destExpr.GetOffset() != 8)
			continue;

		auto params = instr.GetParameterExprs();
		if (params.size() < 2)
			continue;

		auto smstAddr = params[1];
		if (smstAddr.operation != MLIL_CONST_PTR)
			continue;

		QualifiedNameAndType result;
		string errors;
		bool ok = m_view->ParseTypeString(tableName, result, errors);
		if (!ok)
			return false;
		m_view->DefineDataVariable(smstAddr.GetValue().value, result.type);
		m_view->DefineUserSymbol(new Symbol(DataSymbol, "gMmst", smstAddr.GetValue().value));
		m_view->UpdateAnalysis();
	}
	return true;
}

bool DxeResolver::resolveSmmServices()
{
	SetProgressText("Resolving MM services...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SYSTEM_TABLE"));
	auto refs_smm = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SYSTEM_TABLE2"));
	// These tables have same type information, we can just iterate once
	refs.insert(refs.end(), refs_smm.begin(), refs_smm.end());

	for (auto& ref : refs)
	{
		if (IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		size_t mlilSsaIdx = mlil->GetSSAInstructionIndex(mlilIdx);
		if (mlilSsaIdx >= mlilSsa->GetInstructionCount())
			continue;
		auto instr = mlilSsa->GetInstruction(mlilSsaIdx);

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;
			auto offset = dest.GetOffset();

			if (offset == 0x18 + m_width * 0x14)
			{
				// SmmHandleProtocol
				resolveGuidInterface(ref.func, ref.addr, 1, 2);
			}
			else if (offset == 0x18 + m_width * 0x17)
			{
				// SmmLocateProtocol
				resolveGuidInterface(ref.func, ref.addr, 0, 2);
			}
		}
	}
	return true;
}

bool DxeResolver::resolveSmiHandlers()
{
	SetProgressText("Resolving SMI Handlers...");
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SW_REGISTER"));
	auto refs_smm_sw = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SW_REGISTER2"));
	auto refs_mm_sx = m_view->GetCodeReferencesForType(QualifiedName("EFI_MM_SX_REGISTER"));
	auto refs_smm_sx = m_view->GetCodeReferencesForType(QualifiedName("EFI_SMM_SX_REGISTER2"));
	// Define them together

	refs.insert(refs.end(), refs_smm_sw.begin(), refs_smm_sw.end());
	refs.insert(refs.end(), refs_smm_sx.begin(), refs_smm_sx.end());
	refs.insert(refs.end(), refs_mm_sx.begin(), refs_mm_sx.end());

	for (auto& ref : refs)
	{
		if (IsCancelled())
			return false;

		auto func = ref.func;
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		size_t mlilSsaIdx = mlil->GetSSAInstructionIndex(mlilIdx);
		if (mlilSsaIdx >= mlilSsa->GetInstructionCount())
			continue;
		auto instr = mlilSsa->GetInstruction(mlilSsaIdx);

		if (instr.operation == MLIL_CALL_SSA || instr.operation == MLIL_TAILCALL_SSA)
		{
			auto dest = instr.GetDestExpr();
			if (dest.operation != MLIL_LOAD_STRUCT_SSA)
				continue;

			auto offset = dest.GetOffset();
			if (offset == 0)
			{
				auto parameters = instr.GetParameterExprs();
				if (parameters.size() < 4)
					continue;

				// TODO we should be able to parse registerContext, but it's normally an aliased variable
				//    and we have some issues relate to that
				auto dispatchFunction = parameters[1];
				if (dispatchFunction.operation != MLIL_CONST_PTR)
					continue;
				auto funcAddr = static_cast<uint64_t>(dispatchFunction.GetConstant());
				auto targetFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), funcAddr);
				if (!targetFunc)
				{
					uint64_t associatedFuncAddr = funcAddr;
					auto associatedPlatform = m_view->GetDefaultPlatform()->GetAssociatedPlatformByAddress(associatedFuncAddr);
					targetFunc = m_view->GetAnalysisFunction(associatedPlatform, associatedFuncAddr);
				}
				if (!targetFunc)
					continue;

				auto funcType = targetFunc->GetType();
				std::ostringstream ss;
				ss << "SmiHandler_" << std::hex << funcAddr;
				string funcName = ss.str();

				// typedef enum
				string handleTypeStr =
					"EFI_STATUS SmiHandler(EFI_HANDLE DispatchHandle, VOID* Context, VOID* CommBuffer, UINTN* "
					"CommBufferSize);";
				QualifiedNameAndType result;
				string errors;
				bool ok = m_view->ParseTypeString(handleTypeStr, result, errors);
				if (!ok)
					return false;
				targetFunc->SetUserType(result.type);
				m_view->DefineUserSymbol(new Symbol(FunctionSymbol, funcName, funcAddr));
				m_view->UpdateAnalysis();

				// After setting the type, we want to propagate the parameters' type
				TypePropagation propagator(m_view);
				propagator.propagateFuncParamTypes(targetFunc);
			}
		}
	}
	return true;
}

bool DxeResolver::resolveDxe()
{
	if (!resolveBootServices())
		return false;
	if (!resolveRuntimeServices())
		return false;
	return true;
}

bool DxeResolver::resolveSmm()
{
	if (!resolveSmmTables("EFI_SMM_GET_SMST_LOCATION2", "EFI_SMM_SYSTEM_TABLE2*"))
		return false;
	if (!resolveSmmTables("EFI_MM_GET_MMST_LOCATION", "EFI_MM_SYSTEM_TABLE*"))
		return false;
	if (!resolveSmmServices())
		return false;
	if (!resolveSmiHandlers())
		return false;
	return true;
}

DxeResolver::DxeResolver(Ref<BinaryView> view, Ref<BackgroundTask> task) : Resolver(view, task)
{
	initProtocolMapping();
}
