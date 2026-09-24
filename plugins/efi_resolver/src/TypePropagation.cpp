#include "TypePropagation.h"
#include "highlevelilinstruction.h"

TypePropagation::TypePropagation(BinaryView* view, bool automatic) : m_view(view), m_updates(view, automatic)
{
}

const std::map<std::string, std::string> defaultName = {{"EFI_SYSTEM_TABLE", "gST"}, {"EFI_BOOT_SERVICES", "gBS"},
	{"EFI_RUNTIME_SERVICES", "gRT"}, {"EFI_MM_SYSTEM_TABLE", "gMmst"}, {"EFI_SMM_SYSTEM_TABLE2", "gSmmst"},
	{"EFI_HANDLE", "gHandle"}};

void TypePropagation::QueueFunction(Function* func)
{
	auto key = std::make_pair(func->GetPlatform()->GetName(), func->GetStart());
	if (std::find(m_queue.begin(), m_queue.end(), key) == m_queue.end())
		m_queue.push_back(key);
}

void TypePropagation::ProcessNextFunction()
{
	if (m_queue.empty())
		return;

	auto key = m_queue.front();
	m_queue.pop_front();
	m_processed.insert(key);
	if (auto platform = Platform::GetByName(key.first))
		if (auto func = m_view->GetAnalysisFunction(platform, key.second))
			propagateFuncParamTypes(func);
	// Callees whose types changed remain queued until the caller completes analysis.
}

Ref<Metadata> TypePropagation::SaveState() const
{
	auto serialize = [](const auto& keys) -> Ref<Metadata> {
		std::vector<Ref<Metadata>> functions;
		for (const auto& [platform, address] : keys)
		{
			functions.push_back(new Metadata(std::map<std::string, Ref<Metadata>> {
				{"platform", new Metadata(platform)}, {"address", new Metadata(address)}}));
		}
		return new Metadata(functions);
	};
	return new Metadata(std::map<std::string, Ref<Metadata>> {
		{"pending", serialize(m_queue)}, {"processed", serialize(m_processed)}});
}

void TypePropagation::RestoreState(Ref<Metadata> metadata)
{
	m_queue.clear();
	m_processed.clear();
	if (!metadata)
		return;
	auto deserialize = [](Ref<Metadata> function) {
		return FunctionKey {(*function)["platform"]->GetString(), (*function)["address"]->GetUnsignedInteger()};
	};
	for (const auto& function : (*metadata)["pending"]->GetArray())
		m_queue.push_back(deserialize(function));
	for (const auto& function : (*metadata)["processed"]->GetArray())
		m_processed.insert(deserialize(function));
}

bool TypePropagation::propagateFuncParamTypes(Function* func)
{
	LogDebugF("Propagating types from {:#x}", func->GetStart());
	bool update = false;
	// SetUserType schedules analysis; GetType may still return the old signature.
	// Share accumulated callee edits across all parameters and recursive SSA uses
	// in this pass. Analysis completes before the next worklist item is processed.
	PendingFunctionTypes pendingTypes;

	auto param_vars = func->GetParameterVariables().GetValue();
	for (auto var : param_vars)
	{
		bool propagate = false;
		auto var_type = func->GetVariableType(var).GetValue();
		if (!var_type)
			continue;

		if (var_type->IsPointer())
		{
			Ref<Type> target_type = var_type->GetChildType().GetValue();
			if (!target_type)
				continue;
			if (target_type->IsPointer() || target_type->IsNamedTypeRefer())
				propagate = true;
		}
		else if (var_type->IsNamedTypeRefer())
		{
			Ref<Type> target_type = m_view->GetTypeById(var_type->GetNamedTypeReference()->GetTypeId());
			if (!target_type)
				continue;
			if (target_type->IsPointer())
				propagate = true;
		}
		if (!propagate)
			continue;

		// Check whether the param is an aliased var. If it's an aliased var, it may not be directly used in the
		// function
		auto hlil = func->GetHighLevelIL();
		if (!hlil)
			continue;
		Ref<HighLevelILFunction> hlil_func_ssa = hlil->GetSSAForm();
		if (!hlil_func_ssa)
			continue;
		std::set<Variable> aliased_vars = func->GetHighLevelILAliasedVariables();

		auto it = aliased_vars.find(var);
		if (it == aliased_vars.end())
		{
			// not an aliaed var, use version 0
			update |= propagateFuncParamTypes(func, SSAVariable(var, 0), pendingTypes);
		}
		else
		{
			// this param is an aliased var, get the ssa_var
			auto uses = hlil->GetVariableUses(var);
			for (auto use : uses)
			{
				if (use >= hlil->GetExprCount())
					continue;
				auto hlil_instr = hlil->GetExpr(use);
				hlil_instr = hlil_instr.GetParent();
				if (hlil_instr.operation != HLIL_VAR_INIT)
					continue;
				SSAVariable ssa_var = hlil_instr.GetSSAForm().GetDestSSAVariable();
				update |= propagateFuncParamTypes(func, ssa_var, pendingTypes);
			}
		}
	}

	return update;
}

bool TypePropagation::propagateFuncParamTypes(Function* func, SSAVariable ssa_var, PendingFunctionTypes& pendingTypes)
{
	bool update = false;
	auto mlil = func->GetMediumLevelIL();
	if (!mlil)
		return false;
	auto mlil_func_ssa = mlil->GetSSAForm();
	if (!mlil_func_ssa)
		return false;

	auto uses = mlil_func_ssa->GetSSAVarUses(ssa_var);
	for (auto use : uses)
	{
		if (use >= mlil_func_ssa->GetInstructionCount())
			continue;

		auto instr = mlil_func_ssa->GetInstruction(use);
		switch (instr.operation)
		{
		case MLIL_CALL_SSA:
		case MLIL_TAILCALL_SSA:
		{
			// propagate variable type to sub function
			auto dest = instr.GetDestExpr();
			if (!dest.GetValue().IsConstant())
				continue;

			uint64_t target = dest.GetValue().value;
			Ref<Function> subfunc = m_view->GetAnalysisFunction(func->GetPlatform(), target);
			if (!subfunc)
			{
				uint64_t associatedTarget = target;
				Ref<Platform> associatedPlatform = func->GetPlatform()->GetAssociatedPlatformByAddress(associatedTarget);
				subfunc = m_view->GetAnalysisFunction(associatedPlatform, associatedTarget);
			}

			if (!subfunc)
				continue;

			FunctionKey subfuncKey {subfunc->GetPlatform()->GetName(), subfunc->GetStart()};
			auto pending = pendingTypes.find(subfuncKey);
			auto subfunc_type = pending != pendingTypes.end() ? pending->second : subfunc->GetType();
			auto subfunc_params = subfunc_type->GetParameters();

			auto instr_params = instr.GetParameterExprs();
			for (int i = 0; i < instr_params.size(); i++)
			{
				if (instr_params[i].operation != MLIL_VAR_SSA)
					continue;
				if (instr_params[i].GetSourceSSAVariable() != ssa_var)
					continue;
				if (i >= subfunc_params.size())
					break;
				auto ssa_var_type = func->GetVariableType(ssa_var.var).GetValue();
				if (!ssa_var_type)
					continue;

				auto typeName = GetOriginalTypeName(ssa_var_type);

				auto changeFuncType =
					[](BinaryView* bv, Ref<Type> funcType, std::string paramName, Ref<Type> paramType, int paramIdx) {
						auto newFuncType = TypeBuilder(funcType);
						auto adjustedParams = newFuncType.GetParameters();
						adjustedParams.at(paramIdx) = FunctionParameter(paramName, paramType);
						newFuncType.SetParameters(adjustedParams);
						return newFuncType.Finalize();
					};

				auto newType = changeFuncType(m_view, subfunc_type, GetVarNameForTypeStr(typeName), ssa_var_type, i);
				if (*newType == *subfunc_type)
				{
					// Traverse pretyped callees once, without looping around recursive edges.
					if (!m_processed.contains(subfuncKey))
						QueueFunction(subfunc);
					break;
				}
				m_updates.Apply([&]() { subfunc->SetUserType(newType); });
				pendingTypes[subfuncKey] = newType;
				QueueFunction(subfunc);
				update = true;
				break;
			}
			break;
		}

		case MLIL_STORE_SSA:
		{
			auto target = instr.GetDestExpr<MLIL_STORE_SSA>();
			if (!target.GetValue().IsConstant())
				continue;
			auto constant = target.GetValue().value;
			auto ssa_var_type = func->GetVariableType(ssa_var.var).GetValue();
			if (!ssa_var_type)
				continue;

			auto typeName = GetOriginalTypeName(ssa_var_type);

			auto it = defaultName.find(typeName);
			if (it != defaultName.end())
				typeName = it->second;

			m_updates.Apply([&]() {
				m_view->DefineDataVariable(constant, ssa_var_type);
				m_view->DefineUserSymbol(new Symbol(DataSymbol, typeName, constant));
			});

			update = true;
			break;
		}

		case MLIL_SET_VAR_SSA:
		{
			auto src = instr.GetSourceExpr<MLIL_SET_VAR_SSA>();
			auto dest = instr.GetDestSSAVariable<MLIL_SET_VAR_SSA>();

			auto dest_type = func->GetVariableType(dest.var);
			Confidence<Ref<Type>> src_type;
			switch (src.operation)
			{
			case MLIL_VAR_SSA:
				src_type = func->GetVariableType(src.GetSourceSSAVariable().var);
				break;

			case MLIL_LOAD_SSA:
			case MLIL_LOAD_STRUCT_SSA:
				src_type = src.GetType();
				break;

			default:
				continue;
			}

			if (src_type.GetValue() && src_type.GetValue() != dest_type.GetValue())
			{
				m_updates.CreateUserVariable(func, dest.var, src_type, func->GetVariableName(dest.var));
				update |= propagateFuncParamTypes(func, SSAVariable(dest.var, dest.version), pendingTypes);
			}
			break;
		}

		default:
			LogInfoF("Not handled case during type propagation. At {:#x}: {}", instr.address, instr.operation);
			break;
		}
	}
	return update;
}
