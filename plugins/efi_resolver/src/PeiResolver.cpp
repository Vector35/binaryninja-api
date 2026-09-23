#include "PeiResolver.h"

static bool IsPeiServicesType(Ref<Type> type)
{
	if (!type)
		return false;

	if (type->GetTypeName().GetString().find("EFI_PEI_SERVICES") != string::npos)
		return true;

	// Refreshed IL can carry the resolved structure instead of a named reference.
	if (auto name = type->GetRegisteredName(); name && name->GetName() == QualifiedName("EFI_PEI_SERVICES"))
		return true;

	if (!type->IsPointer())
		return false;

	return IsPeiServicesType(type->GetChildType().GetValue());
}

static bool IsPeiServicesExpr(Ref<Function> func, Ref<MediumLevelILFunction> mlilSsa, const MediumLevelILInstruction& expr,
	const set<SSAVariable>* knownPeiServicesVars = nullptr, size_t depth = 0)
{
	// This answers "does this expression probably evaluate to EFI_PEI_SERVICES*?" for the untyped MLIL shapes that
	// appear after indirect service-table calls have lost their original type references.  It intentionally follows
	// simple SSA definitions and pointer arithmetic, but keeps a small recursion limit so bad IL cycles cannot trap us.
	if (depth > 6)
		return false;

	if (IsPeiServicesType(expr.GetType().GetValue()))
		return true;

	switch (expr.operation)
	{
	case MLIL_VAR_SSA:
	{
		auto ssaVar = expr.GetSourceSSAVariable<MLIL_VAR_SSA>();
		// Only the exact SSA value used by a proven call inherits its provenance. Other lifetimes of the same
		// variable, or variables with similar display names, must be proven through their own definitions or types.
		if (knownPeiServicesVars && knownPeiServicesVars->find(ssaVar) != knownPeiServicesVars->end())
			return true;
		if (IsPeiServicesType(func->GetVariableType(ssaVar.var).GetValue()))
			return true;

		if (ssaVar.version == 0 || !mlilSsa)
			return false;

		auto def = mlilSsa->GetSSAVarDefinition(ssaVar);
		if (def >= mlilSsa->GetInstructionCount())
			return false;

		auto defExpr = mlilSsa->GetInstruction(def);
		if (defExpr.operation != MLIL_SET_VAR_SSA)
			return false;

		return IsPeiServicesExpr(func, mlilSsa, defExpr.GetSourceExpr<MLIL_SET_VAR_SSA>(), knownPeiServicesVars, depth + 1);
	}
	case MLIL_LOAD_SSA:
		return IsPeiServicesExpr(func, mlilSsa, expr.GetSourceExpr<MLIL_LOAD_SSA>(), knownPeiServicesVars, depth + 1);
	case MLIL_LOAD_STRUCT_SSA:
		return IsPeiServicesExpr(func, mlilSsa, expr.GetSourceExpr<MLIL_LOAD_STRUCT_SSA>(), knownPeiServicesVars, depth + 1);
	case MLIL_ADD:
	case MLIL_ADD_OVERFLOW:
		return IsPeiServicesExpr(func, mlilSsa, expr.GetLeftExpr(), knownPeiServicesVars, depth + 1)
			|| IsPeiServicesExpr(func, mlilSsa, expr.GetRightExpr(), knownPeiServicesVars, depth + 1);
	default:
		return false;
	}
}

static bool DefineOutputFromMlilParam(Ref<BinaryView> view, Ref<Function> func, Ref<MediumLevelILFunction> mlilSsa,
	const MediumLevelILInstruction& instr, int paramIdx, Ref<Type> outputType, const string& name,
	bool followAddressOfTemp = false)
{
	// Some service outputs are only visible in MLIL after HLIL has simplified a call too much for
	// defineOutputAtCallsite.  We only annotate explicit address-of parameters by default: renaming a plain pointer
	// temporary (for example a register holding &local) can be wrong if the stack slot is reused for another type.
	if (!outputType)
		return false;

	auto params = instr.GetParameterExprs();
	if (params.size() <= paramIdx)
		return false;

	auto outputParam = params[paramIdx];
	if (outputParam.operation == MLIL_ADDRESS_OF)
	{
		func->CreateUserVariable(outputParam.GetSourceVariable<MLIL_ADDRESS_OF>(), outputType,
			Resolver::nonConflictingLocalName(func, name));
		view->UpdateAnalysis();
		return true;
	}
	if (outputParam.operation == MLIL_ADDRESS_OF_FIELD)
	{
		// The output type describes the member, even at offset zero. Applying it to the source variable would
		// overwrite the containing structure's type and name, so decline this fallback without a member annotation.
		return false;
	}
	if (followAddressOfTemp && outputParam.operation == MLIL_VAR_SSA && mlilSsa)
	{
		// Safe narrow case: SSA tells us the exact argument temporary is defined as &local.  This is used for GetHobList,
		// where compilers commonly materialize the out-parameter address in a temp before the service call.
		auto ssaVar = outputParam.GetSourceSSAVariable<MLIL_VAR_SSA>();
		auto def = mlilSsa->GetSSAVarDefinition(ssaVar);
		if (def < mlilSsa->GetInstructionCount())
		{
			auto defExpr = mlilSsa->GetInstruction(def);
			if (defExpr.operation == MLIL_SET_VAR_SSA)
			{
				auto source = defExpr.GetSourceExpr<MLIL_SET_VAR_SSA>();
				if (source.operation == MLIL_ADDRESS_OF)
				{
					func->CreateUserVariable(source.GetSourceVariable<MLIL_ADDRESS_OF>(), outputType,
						Resolver::nonConflictingLocalName(func, name));
					view->UpdateAnalysis();
					return true;
				}
			}
		}
	}
	if (followAddressOfTemp && (outputParam.operation == MLIL_VAR_SSA || outputParam.operation == MLIL_VAR))
	{
		// Fallback for cases where non-SSA MLIL has the useful temp assignment but SSA lookup did not expose it.  We scan
		// forward to the current call and remember the last assignment to the argument temp, accepting only temp = &local.
		auto tempVar = outputParam.operation == MLIL_VAR_SSA ? outputParam.GetSourceSSAVariable<MLIL_VAR_SSA>().var
			: outputParam.GetSourceVariable<MLIL_VAR>();
		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			return false;

		optional<Variable> outputVar;
		for (size_t i = 0; i < mlil->GetInstructionCount(); i++)
		{
			auto cur = mlil->GetInstruction(i);
			if (cur.operation == MLIL_CALL || cur.operation == MLIL_TAILCALL)
			{
				if (cur.address == instr.address)
					break;
			}
			if (cur.operation != MLIL_SET_VAR || cur.GetDestVariable<MLIL_SET_VAR>() != tempVar)
				continue;

			auto source = cur.GetSourceExpr<MLIL_SET_VAR>();
			if (source.operation == MLIL_ADDRESS_OF)
				outputVar = source.GetSourceVariable<MLIL_ADDRESS_OF>();
			else
				outputVar.reset();
		}

		if (outputVar)
		{
			func->CreateUserVariable(*outputVar, outputType, Resolver::nonConflictingLocalName(func, name));
			view->UpdateAnalysis();
			return true;
		}
	}
	return false;
}

bool PeiResolver::resolvePeiIdt()
{
	string archName = m_view->GetDefaultArchitecture()->GetName();
	string intrinsicName;
	if (archName == "x86")
		intrinsicName = "IDTR32";
	else
		intrinsicName = "IDTR64";

	auto refs = m_view->GetCodeReferencesForType(QualifiedName(intrinsicName));
	SortCodeReferences(refs);
	for (auto ref : refs)
	{
		if (IsCancelled())
			return false;

		auto mlil = ref.func->GetMediumLevelIL();
		if (!mlil)
			continue;
		auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (instrIdx >= mlil->GetInstructionCount())
			continue;
		auto instr = mlil->GetInstruction(instrIdx);

		auto hlil = ref.func->GetHighLevelIL();
		auto hlils = HighLevelILExprsAt(ref.func, m_view->GetDefaultArchitecture(), ref.addr);

		for (auto expr : hlils)
		{
			if (expr.operation != HLIL_INTRINSIC || expr.GetParent().operation != HLIL_ASSIGN
				|| expr.GetParent().GetDestExpr<HLIL_ASSIGN>().operation != HLIL_STRUCT_FIELD
				|| expr.GetParent().GetDestExpr<HLIL_ASSIGN>().GetSourceExpr<HLIL_STRUCT_FIELD>().operation != HLIL_VAR)
				continue;

			auto var = expr.GetParent().GetDestExpr<HLIL_ASSIGN>().GetSourceExpr<HLIL_STRUCT_FIELD>().GetVariable();
			ref.func->CreateUserVariable(var, m_view->GetTypeByName(QualifiedName(intrinsicName)), intrinsicName);
		}

		if (instr.operation == MLIL_INTRINSIC)
		{
			// binja doesn't do type propagation on intrinsic instructions
			auto output_params = instr.GetOutputVariables<MLIL_INTRINSIC>();
			if (output_params.size() < 1)
				continue;
			ref.func->CreateUserVariable(
				output_params[0], m_view->GetTypeByName(QualifiedName(intrinsicName)), intrinsicName);
		}
		m_view->UpdateAnalysis();
	}

	return true;
}

bool PeiResolver::resolveServicePointers()
{
	auto archName = m_view->GetDefaultArchitecture()->GetName();
	if (archName != "x86" && archName != "x86-64")
		return true;

	// TODO There is an issue related to structure's type propagation, binja doesn't propagate indirect structure access
	// properly
	//   here is a temporary fix, should be removed after vector35/binaryninja/#749 got fixed
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));
	SortCodeReferences(refs);
	for (auto ref : refs)
	{
		if (IsCancelled())
			return false;

		auto mlil = ref.func->GetMediumLevelIL();
		if (!mlil)
			continue;
		auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (instrIdx >= mlil->GetInstructionCount())
			continue;
		auto instr = mlil->GetInstruction(instrIdx);

		if (instr.operation != MLIL_SET_VAR)
			continue;

		if (instr.GetSourceExpr<MLIL_SET_VAR>().operation != MLIL_LOAD_STRUCT)
			continue;

		auto sourceType = mlil->GetExprType(instr.GetSourceExpr<MLIL_SET_VAR>()).GetValue();
		if (!sourceType)
			continue;

		ref.func->CreateUserVariable(instr.GetDestVariable<MLIL_SET_VAR>(),
									 sourceType, nonConflictingLocalName(ref.func, "EfiPeiServices"));
		m_view->UpdateAnalysis();
	}

	return true;
}

bool PeiResolver::resolvePeiMrc()
{
	auto funcs = m_view->GetAnalysisFunctionList();
	SortAnalysisFunctions(funcs);
	for (auto func : funcs)
	{
		if (IsCancelled())
			return false;

		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;

		auto blocks = mlil->GetBasicBlocks();
		for (auto block : blocks)
		{
			for (size_t i = block->GetStart(); i < block->GetEnd(); i++)
			{
				if (i >= mlil->GetInstructionCount())
					continue;

				auto instr = mlil->GetInstruction(i);
				if (instr.operation != MLIL_INTRINSIC)
					continue;
				uint32_t intrinsicIdx = instr.GetIntrinsic<MLIL_INTRINSIC>();

				if (m_view->GetDefaultArchitecture()->GetIntrinsicName(intrinsicIdx) != "Coproc_GetOneWord")
					continue;
				auto intrinsicParams = instr.GetParameterExprs<MLIL_INTRINSIC>();
				if (intrinsicParams.size() != 5)
					continue;

				bool found = true;

				const int value[5] = {0xf, 0x0, 0xd, 0x0, 0x2};
				for (int j = 0; j < 5; j++)
				{
					auto param = intrinsicParams[j];
					if (param.operation != MLIL_CONST)
					{
						found = false;
						break;
					}

					if (param.GetConstant<MLIL_CONST>() != value[j])
					{
						found = false;
						break;
					}
				}

				if (!found)
					continue;

				// At this point, we can make sure this instruction fetches EFI_PEI_SERVICES
				auto output = instr.GetOutputVariables();
				if (output.size() > 0)
				{
					auto pointerType = Type::PointerType(m_view->GetDefaultArchitecture(),
														 Type::PointerType(m_view->GetDefaultArchitecture(),
																		   m_view->GetTypeByName(QualifiedName("EFI_PEI_SERVICES"))));
					func->CreateUserVariable(output[0], pointerType, nonConflictingLocalName(func, "PeiServices"));
					m_view->UpdateAnalysis();
				}
			}
		}
	}
	return true;
}

bool PeiResolver::resolvePeiMrs()
{
	// ideally we don't need this function, but since we don't support type propagation on intrinsic instructions
	// we have to manually propagate it
	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));
	SortCodeReferences(refs);
	for (auto ref : refs)
	{
		if (IsCancelled())
			return false;

		auto mlil = ref.func->GetMediumLevelIL();
		if (!mlil)
			continue;
		auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
		if (instrIdx >= mlil->GetInstructionCount())
			continue;
		auto instr = mlil->GetInstruction(instrIdx);
		if (instr.operation == MLIL_INTRINSIC)
		{
			auto params = instr.GetOutputVariables();
			if (params.size() < 1)
				continue;

			auto pointerType = Type::PointerType(m_view->GetDefaultArchitecture(),
												 Type::PointerType(
													 m_view->GetDefaultArchitecture(), m_view->GetTypeByName(QualifiedName("EFI_PEI_SERVICES"))));
			ref.func->CreateUserVariable(params[0], pointerType, nonConflictingLocalName(ref.func, "EfiPeiServices"));
			m_view->UpdateAnalysis();
		}
	}
	return true;
}

bool PeiResolver::resolvePlatformPointers()
{
	SetProgressText("Resolving PEI Services Pointers...");
	string archName = m_view->GetDefaultArchitecture()->GetName();
	string intrinsicTypeName;

	if (archName == "x86" || archName == "x86-64")
	{
		return resolvePeiIdt();
	}
	else if (archName == "arm" || archName == "thumb2")
	{
		return resolvePeiMrc();
	}
	else if (archName == "aarch64")
	{
		return resolvePeiMrs();
	}
	LogError("Not supported arch: %s", archName.c_str());
	return false;
}

bool PeiResolver::resolvePeiDescriptors()
{
	SetProgressText("Defining PEI Descriptors...");
	const string descriptorNames[2] = {"EFI_PEI_NOTIFY_DESCRIPTOR", "EFI_PEI_PPI_DESCRIPTOR"};
	for (auto descriptor : descriptorNames)
	{
		auto refs = m_view->GetCodeReferencesForType(QualifiedName(descriptor));
		SortCodeReferences(refs);
		for (auto ref : refs)
		{
			if (IsCancelled())
				return false;

			auto mlil = ref.func->GetMediumLevelIL();
			if (!mlil)
				continue;
			auto instrIdx = mlil->GetInstructionStart(m_view->GetDefaultArchitecture(), ref.addr);
			if (instrIdx >= mlil->GetInstructionCount())
				continue;
			auto instr = mlil->GetInstruction(instrIdx);

			if (instr.operation != MLIL_CALL && instr.operation != MLIL_TAILCALL)
				continue;

			auto destExpr = instr.GetDestExpr();
			if (destExpr.operation != MLIL_LOAD_STRUCT)
				continue;

			// at this point this instruction is probably a call to LocatPpi, InstallPpi or NotifyPpi
			auto destExprType = mlil->GetExprType(destExpr).GetValue();
			if (!destExprType || !destExprType->IsPointer())
				continue;

			auto funcType = destExprType->GetChildType().GetValue();
			if (!funcType)
				continue;
			auto params = funcType->GetParameters();
			int targetParamIdx = -1;
			for (int i = 0; i < params.size(); i++)
			{
				auto param = params[i];
				auto paramType = param.type.GetValue();
				if (!paramType || !paramType->IsPointer())
					continue;
				auto childType = paramType->GetChildType().GetValue();
				if (!childType)
					continue;
				auto paramTypeName = childType->GetTypeName().GetString();
				if (paramTypeName.find(descriptor) != paramTypeName.npos)
				{
					// this is the param
					targetParamIdx = i;
					break;
				}
			}
			if (targetParamIdx < 0)
				continue;

			// Now we are confident that this position is a call that pass Descriptor as a parameter
			defineTypeAtCallsite(ref.func, ref.addr, descriptor, targetParamIdx, true);
		}
	}
	return true;
}

bool PeiResolver::resolvePeiServices()
{
	SetProgressText("Resolving PPIs...");
	// SSA identities are local to an IL snapshot. Keep the snapshot alive and never carry cached provenance into
	// a different analysis revision (or a different function at the same address).
	map<Ref<MediumLevelILFunction>, set<SSAVariable>> knownPeiServicesVars;

	auto processCall = [this, &knownPeiServicesVars](
		Ref<Function> func, Ref<MediumLevelILFunction> mlilSsa, uint64_t addr, const MediumLevelILInstruction& instr, bool fromTypeRef) {
		auto& knownVars = knownPeiServicesVars[mlilSsa];
		auto dest = instr.GetDestExpr();
		bool typedServiceLoad = dest.operation == MLIL_LOAD_STRUCT_SSA;
		// Typed service loads are handled from actual EFI_PEI_SERVICES type references.  The whole-function scan below is
		// for untyped calls like [PeiServices + offset](...) and should not process every typed load a second time.
		if (typedServiceLoad && !fromTypeRef)
			return;
		bool provenPeiServices = false;
		optional<uint64_t> offset;
		if (typedServiceLoad)
		{
			auto sourceType = dest.GetSourceExpr<MLIL_LOAD_STRUCT_SSA>().GetType().GetValue();
			if (!IsPeiServicesType(sourceType))
				return;
			provenPeiServices = true;
			offset = dest.GetOffset();
		}
		else if (dest.operation == MLIL_LOAD_SSA)
		{
			// Untyped indirect service calls usually lower to load([base + offset])(...).  Recover the constant offset and
			// then prove that the base expression or first call parameter is a PEI services pointer before trusting it.
			auto source = dest.GetSourceExpr<MLIL_LOAD_SSA>();
			if (source.operation == MLIL_ADD || source.operation == MLIL_ADD_OVERFLOW)
			{
				auto left = source.GetLeftExpr();
				auto right = source.GetRightExpr();
				if (left.operation == MLIL_CONST || left.operation == MLIL_CONST_PTR)
				{
					offset = left.GetConstant();
					provenPeiServices = IsPeiServicesExpr(func, mlilSsa, right, &knownVars);
				}
				else if (right.operation == MLIL_CONST || right.operation == MLIL_CONST_PTR)
				{
					offset = right.GetConstant();
					provenPeiServices = IsPeiServicesExpr(func, mlilSsa, left, &knownVars);
				}
			}
		}

		if (!offset)
			return;
		if (!provenPeiServices)
		{
			auto params = instr.GetParameterExprs();
			if (params.size() > 0)
				provenPeiServices = IsPeiServicesExpr(func, mlilSsa, params[0], &knownVars);
		}

		if (*offset == 0x18 + m_width * 2)
		{
			// EFI_PEI_SERVICES starts with three non-service pointer-sized header fields after an 0x18-byte fixed prefix in
			// the relevant type layout.  Index 2 is LocatePpi, so the table offset is 0x18 + pointer_width * 2.
			// LocatePpi
			// A recognized GUID identifies the requested interface, not the receiver's service table.
			if (!provenPeiServices)
				return;
			auto params = instr.GetParameterExprs();
			if (params.size() > 0 && params[0].operation == MLIL_VAR_SSA)
			{
				knownVars.insert(params[0].GetSourceSSAVariable<MLIL_VAR_SSA>());
			}
			resolveGuidInterface(func, addr, 1, 4);
		}
		else if (*offset == 0x18 + m_width * 6)
		{
			// GetHobList has no GUID parameter, so require a proven PEI services receiver before naming its out parameter.
			if (!provenPeiServices)
				return;
			// GetHobList
			if (!defineOutputAtCallsite(func, addr, 1, "VOID*", "HobList"))
				DefineOutputFromMlilParam(m_view, func, mlilSsa, instr, 1, GetTypeFromViewAndPlatform("VOID*"), "HobList", true);
		}
		else if (*offset == 0x18 + m_width * 12)
		{
			// Allocation services also lack GUID validation.  Keep them provenance-gated and do not follow pointer temps;
			// otherwise reused stack slots can be mislabeled as Memory/Buffer and lose more precise types.
			if (!provenPeiServices)
				return;
			// AllocatePages
			if (!defineOutputAtCallsite(func, addr, 3, "EFI_PHYSICAL_ADDRESS", "Memory"))
				DefineOutputFromMlilParam(m_view, func, mlilSsa, instr, 3, GetTypeFromViewAndPlatform("EFI_PHYSICAL_ADDRESS"), "Memory");
		}
		else if (*offset == 0x18 + m_width * 13)
		{
			// Same constraints as AllocatePages: only annotate direct address-of outputs from proven service calls.
			if (!provenPeiServices)
				return;
			// AllocatePool
			if (!defineOutputAtCallsite(func, addr, 2, "VOID*", "Buffer"))
				DefineOutputFromMlilParam(m_view, func, mlilSsa, instr, 2, GetTypeFromViewAndPlatform("VOID*"), "Buffer");
		}
	};

	auto refs = m_view->GetCodeReferencesForType(QualifiedName("EFI_PEI_SERVICES"));
	SortCodeReferences(refs);
	for (auto ref : refs)
	{
		// First pass: use real type references.  These are the highest-confidence callsites because the service-table
		// access itself is typed as EFI_PEI_SERVICES.
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
			processCall(ref.func, mlilSsa, ref.addr, instr, true);
	}

	// Second pass: type references are not always present on the service-table pointer after staged analysis. Scan calls
	// directly to recover PEI service uses, requiring receiver provenance before annotating any service outputs.
	auto funcs = m_view->GetAnalysisFunctionList();
	SortAnalysisFunctions(funcs);
	for (auto func : funcs)
	{
		if (IsCancelled())
			return false;

		auto mlil = func->GetMediumLevelIL();
		if (!mlil)
			continue;
		auto mlilSsa = mlil->GetSSAForm();
		if (!mlilSsa)
			continue;

		for (size_t i = 0; i < mlilSsa->GetInstructionCount(); i++)
		{
			auto instr = mlilSsa->GetInstruction(i);
			if (instr.operation != MLIL_CALL_SSA && instr.operation != MLIL_TAILCALL_SSA)
				continue;
			processCall(func, mlilSsa, instr.address, instr, false);
		}
	}
	return true;
}

PeiResolver::PeiResolver(Ref<BinaryView> view, Ref<BackgroundTask> task, TypePropagation& propagation) : Resolver(view, task, propagation)
{
	initProtocolMapping();
}
