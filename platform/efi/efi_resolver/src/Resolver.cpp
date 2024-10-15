#include "Resolver.h"

string Resolver::nonConflictingName(const string& basename)
{
	int idx = 0;
	string name = basename;
	do
	{
		auto sym = m_view->GetSymbolByRawName(name);
		if (!sym)
			return name;
		else
		{
			name = basename + to_string(idx);
			idx += 1;
		}
	} while (true);
}

string Resolver::nonConflictingLocalName(Ref<Function> func, const string& basename)
{
	string name = basename;
	int idx = 0;
	while (true)
	{
		bool ok = true;
		for (const auto& varPair : func->GetVariables())
		{
			if (varPair.second.name == name)
			{
				ok = false;
				break;
			}
		}
		if (ok)
			break;
		name = basename + to_string(idx);
		idx += 1;
	}
	return name;
}

static string GetBundledEfiPath()
{
	string path = GetBundledPluginDirectory();
#if defined(_WIN32)
	return path + "..\\types\\efi.c";
#elif defined(__APPLE__)
	return path + "/../../Resources/types/efi.c";
#else
	return path + "../types/efi.c";
#endif
}

static string GetUserGuidPath()
{
	string path = GetUserDirectory();
#if defined(_WIN32)
	return path + "\\types\\efi-guids.json";
#elif defined(__APPLE__)
	return path + "/types/efi-guids.json";
#else
	return path + "/types/efi-guids.json";
#endif
}

static EFI_GUID parseGuid(const string& guidStr)
{
	EFI_GUID guid;
	istringstream iss(guidStr);
	string token;
	unsigned long value;

	getline(iss, token, ',');
	value = stoul(token, nullptr, 16);
	guid[0] = static_cast<uint8_t>(value);
	guid[1] = static_cast<uint8_t>(value >> 8);
	guid[2] = static_cast<uint8_t>(value >> 16);
	guid[3] = static_cast<uint8_t>(value >> 24);

	getline(iss, token, ',');
	value = stoul(token, nullptr, 16);
	guid[4] = static_cast<uint8_t>(value);
	guid[5] = static_cast<uint8_t>(value >> 8);

	getline(iss, token, ',');
	value = stoul(token, nullptr, 16);
	guid[6] = static_cast<uint8_t>(value);
	guid[7] = static_cast<uint8_t>(value >> 8);

	for (int i = 8; i < 16; i++)
	{
		getline(iss, token, ',');
		value = stoul(token, nullptr, 16);
		guid[i] = static_cast<uint8_t>(value);
	}
	return guid;
}

bool Resolver::parseProtocolMapping(const string& filePath)
{
	vector<pair<EFI_GUID, string>> guids;
	ifstream efiDefs;
	string line;

	m_protocol.clear();

	efiDefs.open(filePath.c_str());
	if (!efiDefs.is_open())
		return false;

	while (getline(efiDefs, line))
	{
		if (m_task->IsCancelled())
			return false;

		if (line.substr(0, 12) == "///@protocol")
		{
			string guid = line.substr(12);
			guid.erase(remove_if(guid.begin(), guid.end(), [](char c) { return c == '{' || c == '}' || c == ' '; }),
					   guid.end());
			guids.emplace_back(parseGuid(guid), "");
		}
		else if (line.substr(0, 11) == "///@binding")
		{
			istringstream iss(line.substr(11));
			string guidName, guid;
			iss >> guidName >> guid;
			guid.erase(remove_if(guid.begin(), guid.end(), [](char c) { return c == '{' || c == '}' || c == ' '; }),
					   guid.end());
			guids.emplace_back(parseGuid(guid), guidName);
		}
		else if (line.substr(0, 6) == "struct")
		{
			if (guids.empty())
				continue;
			istringstream iss(line.substr(6));
			string name;
			iss >> name;
			for (const auto& guidInfo : guids)
			{
				if (guidInfo.second.empty())
				{
					m_protocol[guidInfo.first] = make_pair(name, name + "_GUID");
				}
				else
				{
					m_protocol[guidInfo.first] = make_pair(name, guidInfo.second);
				}
			}
		}
		else
		{
			guids.clear();
		}
	}
	efiDefs.close();

	return true;
}

bool Resolver::parseUserGuidIfExists(const string& filePath)
{
	ifstream userJson(filePath);
	if (!userJson.is_open())
		return false;

	nlohmann::json jsonContent;
	userJson >> jsonContent;

	for (const auto& element : jsonContent.items())
	{
		if (m_task->IsCancelled())
			return false;

		const auto& guidName = element.key();
		auto guidBytes = element.value();
		if (guidBytes.size() != 11)
		{
			LogError("Error: GUID array size is incorrect for %s", guidName.c_str());
			return false;
		}
		EFI_GUID guid;
		guid[0] = static_cast<uint8_t>(int(guidBytes[0]));
		guid[1] = static_cast<uint8_t>(int(guidBytes[0]) >> 8);
		guid[2] = static_cast<uint8_t>(int(guidBytes[0]) >> 16);
		guid[3] = static_cast<uint8_t>(int(guidBytes[0]) >> 24);

		guid[4] = static_cast<uint8_t>(int(guidBytes[1]));
		guid[5] = static_cast<uint8_t>(int(guidBytes[1]) >> 8);

		guid[6] = static_cast<uint8_t>(int(guidBytes[2]));
		guid[7] = static_cast<uint8_t>(int(guidBytes[2]) >> 8);

		for (int i = 8; i < 16; i++)
			guid[i] = static_cast<uint8_t>(int(guidBytes[i - 5]));

		// Insert the GUID and its name into the map
		m_user_guids[guid] = guidName;
	}

	return true;
}

void Resolver::initProtocolMapping()
{
	if (!m_protocol.empty())
		return;
	auto fileName = GetBundledEfiPath();
	if (!parseProtocolMapping(fileName))
		LogAlert("Binary Ninja Version Too Low. Please upgrade to a new version.");

	fileName = GetUserGuidPath();
	parseUserGuidIfExists(fileName);
}

bool Resolver::setModuleEntry(EFIModuleType fileType)
{
	// Wait until initial analysis is finished
	m_view->UpdateAnalysisAndWait();

	uint64_t entry = m_view->GetEntryPoint();
	auto entryFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), entry);
	if (!entryFunc)
	{
		LogDebug("Entry func Not found... ");
		return false;
	}

	// TODO sometimes the parameter at callsite cannot be correctly recognized, #Vector35/binaryninja-api/4529
	//     temporary workaround for this issue, adjust callsite types in entry function if it doesn't has parameters

	// Note: we only adjust the callsite in entry function, this is just a temp fix and it cannot cover all cases
	auto callsites = entryFunc->GetCallSites();
	LogDebug("Checking callsites at 0x%llx", entryFunc->GetStart());
	LogDebug("callsite count : %zu", callsites.size());
	for (auto callsite : entryFunc->GetCallSites())
	{
		auto mlil = entryFunc->GetMediumLevelIL();
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), callsite.addr);
		auto instr = mlil->GetInstruction(mlilIdx);
		LogDebug("Checking Callsite at 0x%llx", callsite.addr);
		if (instr.operation == MLIL_CALL || instr.operation == MLIL_TAILCALL)
		{
			auto params = instr.GetParameterExprs();
			if (params.size() == 0)
			{
				// no parameter at call site, check whether it's correctly recognized
				auto constantPtr = instr.GetDestExpr();
				if (constantPtr.operation == MLIL_CONST_PTR)
				{
					auto addr = constantPtr.GetConstant();
					auto funcType = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr)->GetType();
					entryFunc->SetUserCallTypeAdjustment(m_view->GetDefaultArchitecture(), callsite.addr, funcType);
					m_view->UpdateAnalysisAndWait();
				}
				else
					LogDebug("Operation not ConstPtr: %d", constantPtr.operation);
			}
			else
				LogDebug("param size not zero");
		}
	}

	string errors;
	QualifiedNameAndType result;
	bool ok;

	string typeString;
	switch (fileType)
	{
	case PEI:
	{
		typeString = "EFI_STATUS _ModuleEntry(EFI_PEI_FILE_HANDLE FileHandle, EFI_PEI_SERVICES **PeiServices)";
		ok = m_view->ParseTypeString(typeString, result, errors, {}, true);
		break;
	}

	case DXE:
	{
		typeString = "EFI_STATUS _ModuleEntry(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE* SystemTable)";
		ok = m_view->ParseTypeString(typeString, result, errors, {}, true);
		break;
	}

	case UNKNOWN:
	{
		LogAlert("Could not identify EFI module type");
		return false;
	}
	}

	if (!ok)
		return false;

	// use UserType so that it would not be overwritten
	entryFunc->SetUserType(result.type);
	m_view->DefineUserSymbol(new Symbol(FunctionSymbol, "_ModuleEntry", entry));
	m_view->UpdateAnalysisAndWait();

	TypePropagation propagation = TypePropagation(m_view);
	return propagation.propagateFuncParamTypes(entryFunc);
}

vector<HighLevelILInstruction> Resolver::HighLevelILExprsAt(Ref<Function> func, Ref<Architecture> arch, uint64_t addr)
{
	auto llil = func->GetLowLevelIL();
	auto mlil = func->GetMediumLevelIL();
	auto hlil = func->GetHighLevelIL();

	size_t llilIdx = func->GetLowLevelILForInstruction(arch, addr);
	size_t llilExprIdx = llil->GetIndexForInstruction(llilIdx);
	auto mlilIdxes = llil->GetMediumLevelILExprIndexes(llilExprIdx);

	vector<HighLevelILInstruction> hlils;

	for (size_t mlilIdx : mlilIdxes)
	{
		auto hlilIdxes = mlil->GetHighLevelILExprIndexes(mlilIdx);
		for (auto hlilIdx : hlilIdxes)
		{
			auto hlilExpr = hlil->GetExpr(hlilIdx);
			hlils.push_back(hlilExpr);
		}
	}
	return hlils;
}

Ref<Type> Resolver::GetTypeFromViewAndPlatform(string typeName)
{
	QualifiedNameAndType result;
	string errors;
	bool ok = m_view->ParseTypeString(typeName, result, errors);
	if (!ok)
	{
		// TODO how to retrieve platform types?
		return nullptr;
	}
	return result.type;
}

bool Resolver::resolveGuidInterface(Ref<Function> func, uint64_t addr, int guidPos, int interfacePos)
{
	auto hlils = HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr);
	for (auto hlil : hlils)
	{
		if (hlil.operation != HLIL_CALL)
			continue;

		HighLevelILInstruction instr;
		if (hlil.GetParameterExprs().size() == 1 && hlil.GetParameterExprs()[0].operation == HLIL_CALL)
			instr = hlil.GetParameterExprs()[0];
		else
			instr = hlil;

		auto params = instr.GetParameterExprs();
		if (params.size() <= max(guidPos, interfacePos))
			continue;

		auto guidAddr = params[guidPos].GetValue();
		EFI_GUID guid;
		if (guidAddr.state == ConstantValue || guidAddr.state == ConstantPointerValue)
		{
			if (m_view->Read(&guid, guidAddr.value, 16) < 16)
				continue;
		}
		else if (guidAddr.state == StackFrameOffset)
		{
			auto mlil = instr.GetMediumLevelIL();
			int64_t offset = 0;
			vector<uint8_t> contentBytes;
			while (offset < 16)
			{
				auto var = mlil.GetVariableForStackLocation(guidAddr.value + offset);
				if (!func->GetVariableType(var))
					break;

				auto width = func->GetVariableType(var)->GetWidth();
				if (width == 0 || width > 8)
					break;

				auto value = mlil.GetStackContents(guidAddr.value + offset, width);
				int64_t content;
				if (value.state == ConstantValue || value.state == ConstantPointerValue)
					content = value.value;
				else
					break;

				for (auto i = 0; i < width; i++)
				{
					contentBytes.push_back(static_cast<uint8_t>(content >> (i * 8)));
				}
			}
			if (contentBytes.size() != 16)
				continue;

			memcpy(guid.data(), contentBytes.data(), 16);
		}
		else if (params[guidPos].operation == HLIL_VAR)
		{
			// want to check whether is a protocol wrapper
			auto ssa = params[guidPos].GetSSAForm();
			HighLevelILInstruction ssaExpr;
			if (ssa.operation != HLIL_VAR_SSA)
				continue;
			if (ssa.GetSSAVariable().version != 0)
			{
				auto incomming_def = func->GetHighLevelIL()->GetSSAVarDefinition(ssa.GetSSAVariable());
				if (!incomming_def)
					continue;
				auto incomming_def_ssa = func->GetHighLevelIL()->GetSSAForm()->GetExpr(incomming_def);
				if (incomming_def_ssa.operation != HLIL_VAR_INIT_SSA)
					continue;
				if (incomming_def_ssa.GetSourceExpr().operation != HLIL_VAR_SSA)
					continue;
				if (incomming_def_ssa.GetSourceExpr().GetSSAVariable().version != 0)
					continue;
				ssaExpr = incomming_def_ssa.GetSourceExpr();
			}
			else
				ssaExpr = ssa;

			auto funcParams = func->GetParameterVariables().GetValue();
			bool found = false;
			int incomingGuidIdx;
			for (int i = 0; i < funcParams.size(); i++)
			{
				if (funcParams[i] == ssaExpr.GetSSAVariable().var)
				{
					incomingGuidIdx = i;
					found = true;
					break;
				}
			}
			if (!found)
				continue;

			// see if output interface varible is an incoming parameter
			auto interfaceInstrSsa = params[interfacePos].GetSSAForm();
			if (interfaceInstrSsa.operation != HLIL_VAR_SSA)
				continue;

			if (interfaceInstrSsa.GetSSAVariable().version != 0)
			{
				auto incomingDef =
					func->GetHighLevelIL()->GetSSAForm()->GetSSAVarDefinition(interfaceInstrSsa.GetSSAVariable());
				auto defExpr = func->GetHighLevelIL()->GetSSAForm()->GetExpr(incomingDef);
				if (defExpr.operation != HLIL_VAR_INIT_SSA)
					continue;
				if (defExpr.GetSourceExpr().operation != HLIL_VAR_SSA)
					continue;
				if (defExpr.GetSourceExpr().GetSSAVariable().version != 0)
					continue;
				interfaceInstrSsa = defExpr.GetSourceExpr();
			}
			found = false;
			int incomingInstrIdx;
			for (int i = 0; i < funcParams.size(); i++)
			{
				if (funcParams[i] == interfaceInstrSsa.GetSSAVariable().var)
				{
					incomingInstrIdx = i;
					found = true;
					break;
				}
			}
			if (!found)
				continue;

			LogInfo("Found EFI Protocol wrapper at 0x%llx, checking reference to this function", addr);

			auto refs = m_view->GetCodeReferences(func->GetStart());
			for (auto& ref : refs)
				resolveGuidInterface(ref.func, ref.addr, incomingGuidIdx, incomingInstrIdx);
			continue;
		}

		if (guid.empty())
			continue;

		auto names = lookupGuid(guid);
		string protocol_name = names.first;
		string guidName = names.second;

		if (protocol_name.empty())
		{
			// protocol name is empty
			if (!guidName.empty())
			{
				// user added guid, check whether the user has added the protocol type
				string possible_protocol_type = guidName;
				size_t pos = possible_protocol_type.rfind("_GUID");
				if (pos != string::npos)
					possible_protocol_type.erase(pos, 5);

				// check whether `possible_protocol_type` is in bv.types
				QualifiedNameAndType result;
				string errors;
				bool ok = m_view->ParseTypeString(possible_protocol_type, result, errors);
				if (ok)
					protocol_name = possible_protocol_type;
			}
			else
			{
				// use UnknownProtocol as defult
				LogWarn("Unknown EFI Protocol referenced at 0x%llx", addr);
				guidName = nonConflictingName("UnknownProtocolGuid");
			}
		}

		// now we just need to rename the GUID and apply the protocol type
		auto sym = m_view->GetSymbolByAddress(guidAddr.value);
		auto guidVarName = guidName;
		if (sym)
			guidVarName = sym->GetRawName();

		QualifiedNameAndType result;
		string errors;
		bool ok = m_view->ParseTypeString("EFI_GUID", result, errors);
		if (!ok)
			return false;
		m_view->DefineDataVariable(guidAddr.value, result.type);
		m_view->DefineUserSymbol(new Symbol(DataSymbol, guidVarName, guidAddr.value));

		if (protocol_name.empty())
		{
			LogWarn("Found unknown protocol at 0x%llx", addr);
			protocol_name = "VOID*";
		}

		auto protocolType = GetTypeFromViewAndPlatform(protocol_name);
		if (!protocolType)
			continue;
		protocolType = Type::PointerType(m_view->GetDefaultArchitecture(), protocolType);
		auto interfaceParam = params[interfacePos];

		// TODO we need to check whether it is an aliased var, or it can probably overwrite the other interfaces

		if (interfaceParam.operation == HLIL_ADDRESS_OF)
		{
			interfaceParam = interfaceParam.GetSourceExpr();
			if (interfaceParam.operation == HLIL_VAR)
			{
				string interfaceName = guidName;
				if (guidName.substr(0, 19) == "UnknownProtocolGuid")
				{
					interfaceName.replace(0, 19, "UnknownProtocolInterface");
					interfaceName = nonConflictingLocalName(func, interfaceName);
				}
				else
				{
					interfaceName = nonConflictingLocalName(func, GetVarNameForTypeStr(guidName));
				}
				func->CreateUserVariable(interfaceParam.GetVariable(), protocolType, interfaceName);
			}
		}
		else if (interfaceParam.operation == HLIL_CONST_PTR)
		{
			auto dataVarAddr = interfaceParam.GetValue().value;
			m_view->DefineDataVariable(dataVarAddr, protocolType);
			string interfaceName = guidName;
			if (interfaceName.find("GUID") != interfaceName.npos)
			{
				interfaceName = interfaceName.replace(interfaceName.find("GUID"), 4, "INTERFACE");
				interfaceName = GetVarNameForTypeStr(interfaceName);
			}
			else if (guidName.substr(0, 19) == "UnknownProtocolGuid")
			{
				interfaceName.replace(15, 4, "Interface");
			}
			m_view->DefineUserSymbol(new Symbol(DataSymbol, interfaceName, dataVarAddr));
		}
		m_view->UpdateAnalysisAndWait();
	}

	return true;
}

bool Resolver::defineTypeAtCallsite(
	Ref<Function> func, uint64_t addr, const string typeName, int paramIdx, bool followFields)
{
	auto mlil = func->GetMediumLevelIL();
	size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), addr);
	auto instr = mlil->GetInstruction(mlilIdx);

	auto params = instr.GetParameterExprs();
	if (params.size() < paramIdx + 1)
		return false;

	auto param = params[paramIdx];
	if (param.operation != MLIL_CONST_PTR)
		return false;

	uint64_t varAddr = param.GetConstant();
	DataVariable datavar;
	auto ok = m_view->GetDataVariableAtAddress(varAddr, datavar);
	if (ok)
	{
		string datavarTypeName = datavar.type.GetValue()->GetTypeName().GetString();
		if (datavarTypeName.find(typeName) != datavarTypeName.npos)
			// the variable already has this type, return
			return false;
	}

	// Now we want to define the type at varAddr

	if (typeName == "EFI_GUID")
	{
		// If it's GUID, we want to define it with name
		defineAndLookupGuid(varAddr);
		// defining a GUID should never fail. Also it can not have fields
		return true;
	}

	QualifiedNameAndType result;
	string errors;
	ok = m_view->ParseTypeString(typeName, result, errors);
	if (!ok)
	{
		LogError("Cannot parse type %s when trying to define type at 0x%llx", typeName.c_str(), addr);
		return false;
	}

	m_view->DefineDataVariable(varAddr, result.type);

	if (!followFields)
		return true;

	// We want to define the Guid field and the Notify field, which are both pointers
	DataVariable structVar;
	ok = m_view->GetDataVariableAtAddress(varAddr, structVar);
	if (!ok)
		return false;

	if (!structVar.type.GetValue()->IsNamedTypeRefer())
		return false;

	auto structTypeId = structVar.type.GetValue()->GetNamedTypeReference()->GetTypeId();
	auto structStructureType = m_view->GetTypeById(structTypeId)->GetStructure();

	if (!structStructureType)
		return false;
	auto members = structStructureType->GetMembers();

	// we want to keep this name for renaming NotifyFunction
	string guidName;
	for (auto member : members)
	{
		auto memberOffset = member.offset;
		auto memberType = member.type.GetValue();
		auto memberName = member.name;

		// we only want to define pointers
		if (!memberType->IsPointer() && !(memberType->IsNamedTypeRefer() && memberName == "Notify"))
			continue;

		if (memberName == "Guid")
		{
			uint64_t guidAddr = 0;
			m_view->Read(&guidAddr, varAddr + memberOffset, m_view->GetAddressSize());
			auto name = defineAndLookupGuid(guidAddr);
			guidName = name.second;
		}
		else if (memberName == "Notify")
		{
			// Notify has the type EFI_NOTIFY_ENTRY_POINT
			// which is a NamedTypeRefer
			uint64_t funcAddr;
			m_view->Read(&funcAddr, varAddr + memberOffset, m_view->GetAddressSize());
			auto notifyFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), funcAddr);
			if (!notifyFunc)
				continue;

			string funcName = guidName;
			if (guidName.empty())
				funcName = nonConflictingName("UnknownNotify");
			else
				funcName = "Notify" + funcName.replace(funcName.find("GUID"), 4, "");

			string notifyTypeStr =
				"EFI_STATUS Notify(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* "
				"Ppi)";
			ok = m_view->ParseTypeString(notifyTypeStr, result, errors);
			notifyFunc->SetUserType(result.type);
			m_view->DefineUserSymbol(new Symbol(FunctionSymbol, funcName, funcAddr));
			m_view->UpdateAnalysisAndWait();

			TypePropagation propagator(m_view);
			propagator.propagateFuncParamTypes(notifyFunc);
		}
	}
	return true;
}

Resolver::Resolver(Ref<BinaryView> view, Ref<BackgroundTask> task)
{
	m_view = view;
	m_task = task;
	m_width = m_view->GetAddressSize();
}

pair<string, string> Resolver::lookupGuid(EFI_GUID guidBytes)
{
	auto it = m_protocol.find(guidBytes);
	if (it != m_protocol.end())
		return it->second;

	auto user_it = m_user_guids.find(guidBytes);
	if (user_it != m_user_guids.end())
		return make_pair(string(), user_it->second);

	return {};
}

pair<string, string> Resolver::defineAndLookupGuid(uint64_t addr)
{
	EFI_GUID guidBytes;
	try
	{
		auto readSize = m_view->Read(&guidBytes, addr, 16);
		if (readSize != 16)
			return make_pair(string(), string());
	}
	catch (ReadException)
	{
		LogError("Read GUID failed at 0x%llx", addr);
		return make_pair(string(), string());
	}
	auto namePair = lookupGuid(guidBytes);
	string protocolName = namePair.first;
	string guidName = namePair.second;

	QualifiedNameAndType result;
	string errors;
	// must use ParseTypeString,
	// m_view->GetTypeByName() doesn't return a NamedTypeReference and the DataRenderer doesn't applied
	bool ok = m_view->ParseTypeString("EFI_GUID", result, errors);
	if (!ok)
		return make_pair(string(""), string(""));
	m_view->DefineDataVariable(addr, result.type);
	if (guidName.empty())
	{
		m_view->DefineUserSymbol(new Symbol(DataSymbol, nonConflictingName("UnknownGuid"), addr));
		LogDebug("Found UnknownGuid at 0x%llx", addr);
	}
	else
	{
		m_view->DefineUserSymbol(new Symbol(DataSymbol, guidName, addr));
		LogDebug("Define %s at 0x%llx", guidName.c_str(), addr);
	}

	return namePair;
}
