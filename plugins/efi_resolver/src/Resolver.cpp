#include "Resolver.h"
#include <tuple>

static bool IsGeneratedName(const string& name, const string& basename)
{
	return name.starts_with(basename) && name.find_first_not_of("0123456789", basename.size()) == string::npos;
}

string Resolver::nonConflictingName(const string& basename, optional<uint64_t> target)
{
	auto available = [&](const string& name) {
		for (const auto& symbol : m_view->GetSymbolsByRawName(name))
		{
			if (!target || symbol->GetAddress() != *target)
				return false;
		}
		return true;
	};
	if (target)
	{
		auto symbol = m_view->GetSymbolByAddress(*target);
		if (symbol && IsGeneratedName(symbol->GetRawName(), basename) && available(symbol->GetRawName()))
			return symbol->GetRawName();
	}
	string name = basename;
	for (size_t idx = 0; !available(name); ++idx)
		name = basename + to_string(idx);
	return name;
}

string Resolver::nonConflictingLocalName(Ref<Function> func, const Variable& target, const string& basename)
{
	// User names are not reflected in GetVariables until analysis completes. Overlay the names assigned in this
	// resolver pass so multiple locals cannot claim the same name before reanalysis.
	auto& assignedNames = m_localNames[func];
	map<Variable, string> names;
	for (const auto& [var, info] : func->GetVariables())
		names[var] = info.name;
	for (const auto& [var, name] : assignedNames)
		names[var] = name;

	set<string> usedNames;
	for (const auto& [var, name] : names)
	{
		if (var != target)
			usedNames.insert(name);
	}

	// Preserve an available name from this naming family, including a previous numeric suffix.
	// This also keeps reruns stable if another local was deleted and a lower suffix is now available.
	auto current = names.find(target);
	if (current != names.end() && IsGeneratedName(current->second, basename) && !usedNames.count(current->second))
	{
		assignedNames[target] = current->second;
		return current->second;
	}

	string name = basename;
	for (size_t idx = 0; usedNames.count(name); ++idx)
		name = basename + to_string(idx);
	assignedNames[target] = name;
	return name;
}

static string GetBundledEfiPath()
{
	string path = GetBundledPluginDirectory();
#if defined(_WIN32)
	return path + "\\..\\types\\efi.c";
#elif defined(__APPLE__)
	return path + "/../../Resources/types/efi.c";
#else
	return path + "/../types/efi.c";
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
		if (IsCancelled())
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
		if (IsCancelled())
			return false;

		const auto& guidName = element.key();
		auto guidBytes = element.value();
		if (guidBytes.size() != 11)
		{
			LogErrorF("Error: GUID array size is incorrect for {}", guidName);
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
		LogAlertF("Binary Ninja Version Too Low. Please upgrade to a new version.");

	fileName = GetUserGuidPath();
	parseUserGuidIfExists(fileName);
}

bool Resolver::setModuleEntry(EFIModuleType fileType)
{
	uint64_t entry = m_view->GetEntryPoint();
	auto entryFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), entry);
	if (!entryFunc)
	{
		LogDebugF("Entry func Not found... ");
		return false;
	}

	// TODO sometimes the parameter at callsite cannot be correctly recognized, #Vector35/binaryninja-api/4529
	//     temporary workaround for this issue, adjust callsite types in entry function if it doesn't has parameters

	// Note: we only adjust the callsite in entry function, this is just a temp fix and it cannot cover all cases
	auto callsites = entryFunc->GetCallSites();
	LogDebugF("Checking callsites at {:#x}", entryFunc->GetStart());
	LogDebugF("callsite count : {}", callsites.size());
	for (auto callsite : entryFunc->GetCallSites())
	{
		auto mlil = entryFunc->GetMediumLevelIL();
		if (!mlil)
			continue;
		size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), callsite.addr);
		if (mlilIdx >= mlil->GetInstructionCount())
			continue;
		auto instr = mlil->GetInstruction(mlilIdx);
		LogDebugF("Checking Callsite at {:#x}", callsite.addr);
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
					auto targetFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), addr);
					if (!targetFunc)
					{
						uint64_t associatedAddr = addr;
						auto associatedPlatform = m_view->GetDefaultPlatform()->GetAssociatedPlatformByAddress(associatedAddr);
						targetFunc = m_view->GetAnalysisFunction(associatedPlatform, associatedAddr);
					}
					if (!targetFunc)
						continue;

					auto funcType = targetFunc->GetType();
					auto arch = m_view->GetDefaultArchitecture();
					m_updates.Apply([&]() { entryFunc->SetUserCallTypeAdjustment(arch, callsite.addr, funcType); });
				}
				else
					LogDebugF("Operation not ConstPtr: {}", constantPtr.operation);
			}
			else
				LogDebugF("param size not zero");
		}
	}

	string errors;
	QualifiedNameAndType result;
	bool ok = false;

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
		LogAlertF("Could not identify EFI module type");
		return false;
	}
	}

	if (!ok)
		return false;

	m_updates.Apply([&]() {
		entryFunc->SetUserType(result.type);
		m_view->DefineUserSymbol(new Symbol(FunctionSymbol, "_ModuleEntry", entry));
	});
	m_view->UpdateAnalysis();

	return true;
}

bool Resolver::propagateEntryTypes()
{
	uint64_t entry = m_view->GetEntryPoint();
	auto entryFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), entry);
	if (!entryFunc)
	{
		LogDebugF("Entry func Not found... ");
		return false;
	}

	m_propagation.QueueFunction(entryFunc);
	return true;
}

vector<HighLevelILInstruction> Resolver::HighLevelILExprsAt(Ref<Function> func, Ref<Architecture> arch, uint64_t addr)
{
	vector<HighLevelILInstruction> hlils;
	auto llil = func->GetLowLevelIL();
	auto mlil = func->GetMediumLevelIL();
	auto hlil = func->GetHighLevelIL();
	if (!llil || !mlil || !hlil)
		return hlils;

	size_t llilIdx = llil->GetInstructionStart(arch, addr);
	if (llilIdx >= llil->GetInstructionCount())
		return hlils;
	size_t llilExprIdx = llil->GetIndexForInstruction(llilIdx);
	if (llilExprIdx >= llil->GetExprCount())
		return hlils;
	auto mlilIdxes = llil->GetMediumLevelILExprIndexes(llilExprIdx);

	for (size_t mlilIdx : mlilIdxes)
	{
		if (mlilIdx >= mlil->GetExprCount())
			continue;
		auto hlilIdxes = mlil->GetHighLevelILExprIndexes(mlilIdx);
		for (auto hlilIdx : hlilIdxes)
		{
			if (hlilIdx >= hlil->GetExprCount())
				continue;
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

optional<uint64_t> Resolver::GetConstantDataAddress(const HighLevelILInstruction& expr)
{
	// HLIL represents "address of this global GUID/interface slot" in several ways depending on analysis state.
	// Normalize those shapes before reading GUID bytes or defining a data variable at the callsite.
	auto value = expr.GetValue();
	if (value.state == ConstantValue || value.state == ConstantPointerValue)
		return value.value;

	if (expr.operation == HLIL_CONST_PTR)
		return expr.GetConstant<HLIL_CONST_PTR>();

	if (expr.operation == HLIL_ADDRESS_OF)
		return GetConstantDataAddress(expr.GetSourceExpr<HLIL_ADDRESS_OF>());

	if (expr.operation == HLIL_EXTERN_PTR)
		return expr.GetConstant<HLIL_EXTERN_PTR>() + expr.GetOffset<HLIL_EXTERN_PTR>();

	return nullopt;
}

vector<HighLevelILInstruction> Resolver::GetCallExprs(const vector<HighLevelILInstruction>& exprs, uint64_t addr)
{
	vector<HighLevelILInstruction> calls;
	vector<HighLevelILInstruction> fallbackCalls;
	set<pair<HighLevelILFunction*, size_t>> visited;
	for (const auto& expr : exprs)
	{
		expr.VisitExprs([&](const HighLevelILInstruction& subExpr) {
			if (subExpr.operation == HLIL_CALL)
			{
				// Overlapping IL mappings may reach the same call more than once.
				if (!visited.emplace(subExpr.function, subExpr.exprIndex).second)
					return false;
				fallbackCalls.push_back(subExpr);
				if (subExpr.address == addr)
					calls.push_back(subExpr);
			}
			return true;
		});
	}
	// Lost source addresses are only safe to infer when there is one distinct call.
	// Otherwise a nested helper could be mistaken for the service being resolved.
	if (calls.empty() && fallbackCalls.size() == 1)
		return fallbackCalls;
	return calls;
}

Resolver::ProtocolGuidInfo Resolver::resolveProtocolGuid(
	const EFI_GUID& guid, uint64_t addr, optional<uint64_t> guidDataAddr)
{
	auto names = lookupGuid(guid);
	ProtocolGuidInfo info { names.first, names.second };

	if (!info.protocolName.empty())
		return info;

	if (!info.guidName.empty())
	{
		string possibleProtocolType = info.guidName;
		size_t pos = possibleProtocolType.rfind("_GUID");
		if (pos != string::npos)
			possibleProtocolType.erase(pos, 5);

		QualifiedNameAndType result;
		string errors;
		if (m_view->ParseTypeString(possibleProtocolType, result, errors))
			info.protocolName = possibleProtocolType;
		return info;
	}

	LogWarnF("Unknown EFI Protocol referenced at {:#x}", addr);
	// Use the GUID object's existing name before deriving interface names from it.
	if (auto symbol = guidDataAddr ? m_view->GetSymbolByAddress(*guidDataAddr) : nullptr)
		info.guidName = symbol->GetRawName();
	else
		info.guidName = nonConflictingName("UnknownProtocolGuid", guidDataAddr);
	return info;
}

bool Resolver::defineGuidDataVariable(uint64_t addr, const string& guidName)
{
	QualifiedNameAndType result;
	string errors;
	if (!m_view->ParseTypeString("EFI_GUID", result, errors))
		return false;

	auto sym = m_view->GetSymbolByAddress(addr);
	auto guidVarName = guidName;
	if (sym)
		guidVarName = sym->GetRawName();

	m_updates.Apply([&]() {
		m_view->DefineDataVariable(addr, result.type);
		m_view->DefineUserSymbol(new Symbol(DataSymbol, guidVarName, addr));
	});
	return true;
}

bool Resolver::applyProtocolInterface(Ref<Function> func, const HighLevelILInstruction& interfaceParam,
	const ProtocolGuidInfo& info, bool outputInterface)
{
	string protocolName = info.protocolName;
	string guidName = info.guidName;
	// A missing protocol definition requires a generic type, but the GUID can
	// still provide a useful interface name. Do not derive names from VOID.
	string localName;
	if (!protocolName.empty())
		localName = GetVarNameForTypeStr(protocolName);
	else if (guidName.starts_with("UnknownProtocolGuid"))
	{
		localName = guidName;
		localName.replace(0, 19, "UnknownProtocolInterface");
	}
	else
	{
		localName = guidName;
		if (localName.ends_with("_GUID"))
			localName.resize(localName.size() - 5);
		localName = GetVarNameForTypeStr(localName);
	}
	if (localName.empty())
		localName = "UnknownProtocolInterface";

	if (protocolName.empty())
	{
		LogWarnF("Found unknown protocol at {:#x}", interfaceParam.address);
		protocolName = "VOID";
	}

	auto protocolType = GetTypeFromViewAndPlatform(protocolName);
	if (!protocolType)
		return false;

	// Input arguments point to a protocol object; output arguments point to a
	// slot holding a protocol pointer. An address-of argument types that storage,
	// while a directly passed variable must retain the additional pointer level.
	auto storageType = outputInterface ? Type::PointerType(m_view->GetDefaultArchitecture(), protocolType) : protocolType;
	auto argumentType = Type::PointerType(m_view->GetDefaultArchitecture(), storageType);
	if (interfaceParam.operation == HLIL_ADDRESS_OF)
	{
		auto source = interfaceParam.GetSourceExpr<HLIL_ADDRESS_OF>();
		if (source.operation != HLIL_VAR)
			return false;

		auto interfaceName = nonConflictingLocalName(func, source.GetVariable(), localName);
		m_updates.CreateUserVariable(func, source.GetVariable(), storageType, interfaceName);
		return true;
	}

	if (interfaceParam.operation == HLIL_VAR)
	{
		auto interfaceName = nonConflictingLocalName(func, interfaceParam.GetVariable(), localName);
		m_updates.CreateUserVariable(func, interfaceParam.GetVariable(), argumentType, interfaceName);
		return true;
	}

	if (auto dataVarAddr = GetConstantDataAddress(interfaceParam))
	{
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
		m_updates.Apply([&]() {
			m_view->DefineDataVariable(*dataVarAddr, storageType);
			m_view->DefineUserSymbol(new Symbol(DataSymbol, interfaceName, *dataVarAddr));
		});
		return true;
	}

	return false;
}

bool Resolver::defineOutputAtCallsite(Ref<Function> func, uint64_t addr, int paramIdx, string typeName, string name)
{
	// Generic HLIL output-parameter annotator for service calls where the target is visible as either &local/global or a
	// data variable address. MLIL-specific fallbacks live in PeiResolver because their safety depends on PEI call shape.
	auto outputType = GetTypeFromViewAndPlatform(typeName);
	if (!outputType)
		return false;

	auto hlils = GetCallExprs(HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr), addr);
	for (auto hlil : hlils)
	{
		auto params = hlil.GetParameterExprs();
		if (params.size() <= paramIdx)
			continue;

		auto outputParam = params[paramIdx];
		if (outputParam.operation == HLIL_ADDRESS_OF)
			outputParam = outputParam.GetSourceExpr<HLIL_ADDRESS_OF>();

		auto dataVarAddr = GetConstantDataAddress(outputParam);
		if (dataVarAddr)
		{
			auto outputName = nonConflictingName(name, *dataVarAddr);
			m_updates.Apply([&]() {
				m_view->DefineDataVariable(*dataVarAddr, outputType);
				m_view->DefineUserSymbol(new Symbol(DataSymbol, outputName, *dataVarAddr));
			});
			m_view->UpdateAnalysis();
			return true;
		}
	}

	return false;
}

bool Resolver::resolveGuidInterface(Ref<Function> func, uint64_t addr, int guidPos, int interfacePos)
{
	// Keep discovery off the C++ call stack, and visit each interpretation of a
	// callsite once. A wrapper may be recursive or forward different argument pairs.
	vector<GuidInterfaceCallsite> pending {{func, addr, guidPos, interfacePos}};
	set<tuple<string, uint64_t, uint64_t, int, int>> visited;
	bool success = true;
	while (!pending.empty())
	{
		if (IsCancelled())
			return false;
		auto callsite = pending.back();
		pending.pop_back();
		if (!callsite.func)
			continue;
		if (!visited.emplace(callsite.func->GetPlatform()->GetName(), callsite.func->GetStart(),
			callsite.addr, callsite.guidPos, callsite.interfacePos).second)
			continue;
		success &= resolveGuidInterfaceAtCallsite(callsite, pending);
	}
	return success;
}

bool Resolver::resolveGuidInterfaceAtCallsite(const GuidInterfaceCallsite& callsite,
	vector<GuidInterfaceCallsite>& pending)
{
	// Resolve calls shaped like Service(..., Guid, ..., InterfaceOut).  The caller supplies the GUID and interface
	// parameter indexes because Boot Services, Runtime Services, and PEI services place them differently.
	const auto& [func, addr, guidPos, interfacePos] = callsite;
	auto hlils = GetCallExprs(HighLevelILExprsAt(func, m_view->GetDefaultArchitecture(), addr), addr);
	for (auto hlil : hlils)
	{
		if (IsCancelled())
			return false;
		auto instr = hlil;

		auto params = instr.GetParameterExprs();
		if (params.size() <= max(guidPos, interfacePos))
			continue;

		auto guidAddr = params[guidPos].GetValue();
		auto guidDataAddr = GetConstantDataAddress(params[guidPos]);
		EFI_GUID guid {};
		bool guidExtracted = false;
		if (guidDataAddr)
		{
			// Most calls pass a pointer to a GUID in a data segment; read the canonical bytes from the binary view.
			if (m_view->Read(&guid, *guidDataAddr, 16) < 16)
				continue;
			guidExtracted = true;
		}
		else if (guidAddr.state == StackFrameOffset)
		{
			// Some firmware constructs GUIDs on the stack immediately before the service call.  Reconstruct the 16 bytes
			// from MLIL's stack contents, walking the variables that cover the GUID-sized stack range.
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
				offset += width;
			}
			if (contentBytes.size() != 16)
				continue;

			memcpy(guid.data(), contentBytes.data(), 16);
			guidExtracted = true;
		}
		else if (params[guidPos].operation == HLIL_VAR)
		{
			// Wrapper functions often take (Guid, InterfaceOut) parameters and then call the real service internally.  If both
			// arguments are pass-through function parameters, visit this wrapper's callers using the caller-side indexes.
			auto hlil = func->GetHighLevelIL();
			if (!hlil)
				continue;
			auto hlilSsa = hlil->GetSSAForm();
			if (!hlilSsa)
				continue;

			auto ssa = params[guidPos].GetSSAForm();
			HighLevelILInstruction ssaExpr;
			if (ssa.operation != HLIL_VAR_SSA)
				continue;
			if (ssa.GetSSAVariable().version != 0)
			{
				auto incomming_def = hlil->GetSSAVarDefinition(ssa.GetSSAVariable());
				if (incomming_def >= hlilSsa->GetExprCount())
					continue;
				auto incomming_def_ssa = hlilSsa->GetExpr(incomming_def);
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

			// See if the output interface variable is also an incoming wrapper parameter.
			auto interfaceInstrSsa = params[interfacePos].GetSSAForm();
			if (interfaceInstrSsa.operation != HLIL_VAR_SSA)
				continue;

			if (interfaceInstrSsa.GetSSAVariable().version != 0)
			{
				auto incomingDef = hlilSsa->GetSSAVarDefinition(interfaceInstrSsa.GetSSAVariable());
				if (incomingDef >= hlilSsa->GetExprCount())
					continue;
				auto defExpr = hlilSsa->GetExpr(incomingDef);
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

			LogInfoF("Found EFI Protocol wrapper at {:#x}, checking reference to this function", addr);

			auto refs = m_view->GetCodeReferences(func->GetStart());
			SortCodeReferences(refs);
			// Reverse insertion preserves the sorted reference order when popping the worklist.
			for (auto ref = refs.rbegin(); ref != refs.rend(); ++ref)
			{
				if (IsCancelled())
					return false;
				pending.push_back({ref->func, ref->addr, incomingGuidIdx, incomingInstrIdx});
			}
			continue;
		}

		// A fixed-size GUID array is never empty. Only complete extraction supplies bytes for lookup and typing.
		if (!guidExtracted)
			continue;

		auto info = resolveProtocolGuid(guid, addr, guidDataAddr);
		if (guidDataAddr && !defineGuidDataVariable(*guidDataAddr, info.guidName))
			return false;
		applyProtocolInterface(func, params[interfacePos], info, true);
		m_view->UpdateAnalysis();
	}

	return true;
}

bool Resolver::defineTypeAtCallsite(
	Ref<Function> func, uint64_t addr, const string typeName, int paramIdx, bool followFields)
{
	auto mlil = func->GetMediumLevelIL();
	if (!mlil)
		return false;

	size_t mlilIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), addr);
	if (mlilIdx >= mlil->GetInstructionCount())
		return false;

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
		auto dataVarType = datavar.type.GetValue();
		if (!dataVarType)
			return false;

		string datavarTypeName = dataVarType->GetTypeName().GetString();
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
		LogErrorF("Cannot parse type {} when trying to define type at {:#x}", typeName, addr);
		return false;
	}

	m_updates.Apply([&]() { m_view->DefineDataVariable(varAddr, result.type); });

	if (!followFields)
		return true;

	// We want to define the Guid field and the Notify field, which are both pointers
	DataVariable structVar;
	ok = m_view->GetDataVariableAtAddress(varAddr, structVar);
	if (!ok)
		return false;

	auto structVarType = structVar.type.GetValue();
	if (!structVarType || !structVarType->IsNamedTypeRefer())
		return false;

	auto structTypeId = structVarType->GetNamedTypeReference()->GetTypeId();
	auto structType = m_view->GetTypeById(structTypeId);
	if (!structType)
		return false;

	auto structStructureType = structType->GetStructure();

	if (!structStructureType)
		return false;
	auto members = structStructureType->GetMembers();

	// we want to keep this name for renaming NotifyFunction
	string guidName;
	BinaryReader pointerReader(m_view, m_view->GetDefaultEndianness());
	for (auto member : members)
	{
		auto memberOffset = member.offset;
		auto memberType = member.type.GetValue();
		auto memberName = member.name;

		// we only want to define pointers
		if (!memberType)
			continue;
		if (!memberType->IsPointer() && !(memberType->IsNamedTypeRefer() && memberName == "Notify"))
			continue;

		if (memberName == "Guid")
		{
			uint64_t guidAddr = 0;
			pointerReader.Seek(varAddr + memberOffset);
			if (!pointerReader.TryReadPointer(guidAddr))
				continue;
			auto name = defineAndLookupGuid(guidAddr);
			guidName = name.second;
		}
		else if (memberName == "Notify")
		{
			// Notify has the type EFI_NOTIFY_ENTRY_POINT
			// which is a NamedTypeRefer
			uint64_t funcAddr = 0;
			pointerReader.Seek(varAddr + memberOffset);
			if (!pointerReader.TryReadPointer(funcAddr))
				continue;
			auto notifyFunc = m_view->GetAnalysisFunction(m_view->GetDefaultPlatform(), funcAddr);
			if (!notifyFunc)
				continue;

			string funcName = guidName;
			if (guidName.empty())
				funcName = nonConflictingName("UnknownNotify", funcAddr);
			else
			{
				auto guidPos = funcName.find("GUID");
				if (guidPos != string::npos)
					funcName.erase(guidPos, 4);
				funcName = "Notify" + funcName;
			}

			string notifyTypeStr =
				"EFI_STATUS Notify(EFI_PEI_SERVICES **PeiServices, EFI_PEI_NOTIFY_DESCRIPTOR* NotifyDescriptor, VOID* "
				"Ppi)";
			ok = m_view->ParseTypeString(notifyTypeStr, result, errors);
			if (!ok || !result.type)
			{
				LogErrorF("Cannot parse notify type at {:#x}: {}", funcAddr, errors);
				continue;
			}
			m_updates.Apply([&]() {
				notifyFunc->SetUserType(result.type);
				m_view->DefineUserSymbol(new Symbol(FunctionSymbol, funcName, funcAddr));
			});
			m_view->UpdateAnalysis();

			m_propagation.QueueFunction(notifyFunc);
		}
	}
	return true;
}

Resolver::Resolver(Ref<BinaryView> view, Ref<BackgroundTask> task, TypePropagation& propagation) :
	m_propagation(propagation), m_updates(propagation.GetUpdates())
{
	m_view = view;
	m_task = task;
	m_width = m_view->GetAddressSize();
}

bool Resolver::IsCancelled() const
{
	return m_task && m_task->IsCancelled();
}


void Resolver::SetProgressText(const string& text) const
{
	if (m_task)
		m_task->SetProgressText(text);
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
	catch (const ReadException&)
	{
		LogErrorF("Read GUID failed at {:#x}", addr);
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
	string symbolName;
	if (guidName.empty())
	{
		auto symbol = m_view->GetSymbolByAddress(addr);
		symbolName = symbol ? symbol->GetRawName() : nonConflictingName("UnknownGuid", addr);
		LogDebugF("Found UnknownGuid at {:#x}", addr);
	}
	else
	{
		symbolName = guidName;
		LogDebugF("Define {} at {:#x}", guidName.c_str(), addr);
	}
	m_updates.Apply([&]() {
		m_view->DefineDataVariable(addr, result.type);
		m_view->DefineUserSymbol(new Symbol(DataSymbol, symbolName, addr));
	});

	return namePair;
}
