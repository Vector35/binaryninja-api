//
// Created by kat on 8/6/24.
//

// TODO We could use an LLIL/MLIL workflow to rewrite off-image value-loads
//  	(i.e. MLIL_VAR_LOAD.MLIL_DEREF.MLIL_CONST_PTR) to just read the value out of the cache and replace the load
// 		in stub regions.
//
// This is a pretty rough workflow and has huge room for improvements all around.

#include "SharedCacheWorkflow.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "../api/sharedcacheapi.h"
#include "thread"


struct GlobalWorkflowState
{
	std::mutex imageLoadMutex;
	bool autoLoadStubsAndDyldData = true;
	bool autoLoadObjCStubRequirements = true;
};

static std::unordered_map<uint64_t, GlobalWorkflowState*> globalWorkflowState;
std::mutex globalWorkflowStateMutex;

GlobalWorkflowState* GetGlobalWorkflowState(Ref<BinaryView> view)
{
	std::unique_lock<std::mutex> lock(globalWorkflowStateMutex);
	if (globalWorkflowState.find(view->GetFile()->GetSessionId()) == globalWorkflowState.end())
	{
		globalWorkflowState[view->GetFile()->GetSessionId()] = new GlobalWorkflowState();
		Ref<Settings> settings = view->GetLoadSettings(VIEW_NAME);
		bool autoLoadStubsAndDyldData = true;
		if (settings && settings->Contains("loader.dsc.autoLoadStubsAndDyldData"))
		{
			autoLoadStubsAndDyldData = settings->Get<bool>("loader.dsc.autoLoadStubsAndDyldData", view);
		}
		globalWorkflowState[view->GetFile()->GetSessionId()]->autoLoadStubsAndDyldData = autoLoadStubsAndDyldData;
		bool autoLoadObjC = true;
		if (settings && settings->Contains("loader.dsc.autoLoadObjCStubRequirements"))
		{
			autoLoadObjC = settings->Get<bool>("loader.dsc.autoLoadObjCStubRequirements", view);
		}
		globalWorkflowState[view->GetFile()->GetSessionId()]->autoLoadObjCStubRequirements = autoLoadObjC;
	}
	return globalWorkflowState[view->GetFile()->GetSessionId()];
}


std::vector<std::string> splitSelector(const std::string& selector) {
	std::vector<std::string> components;
	std::istringstream stream(selector);
	std::string component;

	while (std::getline(stream, component, ':')) {
		if (!component.empty()) {
			components.push_back(component);
		}
	}

	return components;
}

std::vector<std::string> generateArgumentNames(const std::vector<std::string>& components) {
	std::vector<std::string> argumentNames;

	for (const std::string& component : components) {
		size_t startPos = component.find_last_of(" ");
		std::string argumentName = (startPos == std::string::npos) ? component : component.substr(startPos + 1);
		argumentNames.push_back(argumentName);
	}

	return argumentNames;
}


void SharedCacheWorkflow::ProcessOffImageCall(Ref<AnalysisContext> ctx, Ref<Function> func, Ref<MediumLevelILFunction> mssa, const MediumLevelILInstruction dest, ExprId exprIndex,  bool applySymbolIfFoundToCurrentFunction)
{
	auto bv = func->GetView();
	WorkerPriorityEnqueue([bv=bv, dest=dest, func=func, applySymbolIfFoundToCurrentFunction]()
		{
			auto workflowState = GetGlobalWorkflowState(bv);
			Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(bv);
			if (!cache)
				return;
			if (dest.operation != MLIL_CONST_PTR && dest.operation != MLIL_CONST)
				return;
			if (workflowState->autoLoadStubsAndDyldData &&
					(cache->GetNameForAddress(dest.GetConstant()).find("dyld_shared_cache_branch_islands") != std::string::npos
						|| cache->GetNameForAddress(dest.GetConstant()).find("::_stubs") != std::string::npos
					)
				)

			{
				if (cache->LoadSectionAtAddress(dest.GetConstant()))
				{
					func->Reanalyze();
				}
			}
			else
			{
				if (applySymbolIfFoundToCurrentFunction)
					cache->FindSymbolAtAddrAndApplyToAddr(dest.GetConstant(), func->GetStart(), false);
				else
					cache->FindSymbolAtAddrAndApplyToAddr(dest.GetConstant(), dest.GetConstant(), false);
			}
	});
}


void SharedCacheWorkflow::FixupStubs(Ref<AnalysisContext> ctx)
{
	try
	{
		const auto func = ctx->GetFunction();
		const auto arch = func->GetArchitecture();

		const auto bv = func->GetView();

		auto workflowState = GetGlobalWorkflowState(bv);

		auto funcStart = func->GetStart();
		auto sectionExists = !bv->GetSectionsAt(funcStart).empty();
		if (!sectionExists)
			return;
		auto section = bv->GetSectionsAt(funcStart)[0];

		auto imageName = section->GetName();
		// remove everything after ::
		auto pos = imageName.find("::");
		if (pos != std::string::npos)
			imageName = imageName.substr(0, pos);

		const auto llil = ctx->GetLowLevelILFunction();
		if (!llil) {
			return;
		}
		const auto ssa = llil->GetSSAForm();
		if (!ssa) {
			return;
		}

		const auto mlil = ctx->GetMediumLevelILFunction();
		if (!mlil) {
			return;
		}
		const auto mssa = mlil->GetSSAForm();
		if (!mssa) {
			return;
		}

		// Processor that automatically loads the libObjC image when it encounters a stub (so we can do inlining).
		if (workflowState->autoLoadObjCStubRequirements && section->GetName().find("__objc_stubs") != std::string::npos)
		{
			auto firstInstruction = mlil->GetInstruction(0);
			if (firstInstruction.operation == MLIL_TAILCALL)
			{
				auto dest = firstInstruction.GetDestExpr<MLIL_TAILCALL>();
				if (dest.operation == MLIL_CONST_PTR)
				{
					// We're ready, everything is here
					func->SetAutoInlinedDuringAnalysis(true);
					return;
				}
			}
			for (const auto& block : mssa->GetBasicBlocks())
			{
				for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
				{
					auto instr = mssa->GetInstruction(i);
					// current_il_function.ssa_form.get_ssa_var_value(current_il_instruction.dest.var)
					if (instr.operation == MLIL_JUMP)
					{
						if (instr.GetDestExpr<MLIL_JUMP>().operation == MLIL_VAR_SSA)
						{
							auto dest = instr.GetDestExpr<MLIL_JUMP>();
							// RegisterValue value = mssa->GetSSAVarValue(instr.GetDestExpr().GetSourceSSAVariable())
							// ExprId def = mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable());
							// MLILInstruction defInstr = mssa->GetInstruction(mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable()));
							// targetOffset = mssa->GetInstruction(mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable())).GetSourceExpr().GetSourceExpr().GetConstant();
							auto value = mssa->GetSSAVarValue(dest.GetSourceSSAVariable());
							if (value.state == UndeterminedValue)
							{
								bool otherFunctionAlreadyRunning;
								{
									otherFunctionAlreadyRunning = !workflowState->imageLoadMutex.try_lock();
									if (!otherFunctionAlreadyRunning)
										workflowState->imageLoadMutex.unlock();
								}
								if (otherFunctionAlreadyRunning)
								{
									return;
								}

								std::unique_lock<std::mutex> lock(workflowState->imageLoadMutex);
								auto def = mssa->GetSSAVarDefinition(dest.GetSourceSSAVariable());
								auto defInstr = mssa->GetInstruction(def);
								auto targetOffset = defInstr.GetSourceExpr().GetSourceExpr().GetConstant();

								if (bv->IsValidOffset(targetOffset))
									return;

								Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(bv);

								if (!cache)
									return;
								if (!cache->GetImageNameForAddress(targetOffset).empty())
								{
									cache->LoadImageContainingAddress(targetOffset);
								}
								else
								{
									cache->LoadSectionAtAddress(targetOffset);
								}
								for (const auto &sectFunc : bv->GetAnalysisFunctionList())
								{
									if (section->GetStart() <= sectFunc->GetStart() && sectFunc->GetStart() < section->GetEnd())
									{
										func->Reanalyze();
									}
								}
							}
						}

						else if (instr.GetDestExpr<MLIL_JUMP>().operation == MLIL_CONST_PTR)
						{
							bool otherFunctionAlreadyRunning;
							{
								otherFunctionAlreadyRunning = !workflowState->imageLoadMutex.try_lock();
								if (!otherFunctionAlreadyRunning)
									workflowState->imageLoadMutex.unlock();
							}
							if (otherFunctionAlreadyRunning)
							{
								return;
							}

							std::unique_lock<std::mutex> lock(workflowState->imageLoadMutex);
							auto dest = instr.GetDestExpr<MLIL_JUMP>();
							auto targetOffset = dest.GetConstant();
							if (bv->IsValidOffset(targetOffset))
								return;

							Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(bv);

							if (!cache)
								return;

							if (!cache->GetImageNameForAddress(targetOffset).empty())
							{
								cache->LoadImageContainingAddress(targetOffset);
							}
							else
							{
								cache->LoadSectionAtAddress(targetOffset);
							}
							for (const auto &sectFunc : bv->GetAnalysisFunctionList())
							{
								if (section->GetStart() <= sectFunc->GetStart() && sectFunc->GetStart() < section->GetEnd())
								{
									func->Reanalyze();
								}
							}
						}
					}
				}
			}

			return;
		}

		if (section->GetName().find("::_stubs") != std::string::npos // Branch Islands (iOS 16)
			|| section->GetName().find("dyld_shared_cache_branch_islands") != std::string::npos // Branch Islands (iOS 11-?)
			|| section->GetName().find("::__stubs") != std::string::npos // Stubs (non arm64e)
			|| section->GetName().find("::__auth_stubs") != std::string::npos // Stubs (arm64e)
			)
		{
			auto firstInstruction = mlil->GetInstruction(0);
			if (firstInstruction.operation == MLIL_TAILCALL)
			{
				auto dest = firstInstruction.GetDestExpr<MLIL_TAILCALL>();
				if (dest.operation == MLIL_CONST_PTR)
				{
					if (auto symbol = bv->GetSymbolByAddress(dest.GetConstant()))
					{
						auto newSymbol = new Symbol(FunctionSymbol, "j_" + symbol->GetRawName(), func->GetStart());
						bv->DefineUserSymbol(newSymbol);
					}
				}
			}
			else if (firstInstruction.operation == MLIL_JUMP)
			{
				auto dest = firstInstruction.GetDestExpr<MLIL_JUMP>();
				if (dest.operation == MLIL_CONST_PTR)
				{
					if (!bv->IsValidOffset(dest.GetConstant()))
					{
						ProcessOffImageCall(ctx, func, mssa, dest, firstInstruction.GetSSAExprIndex(), true);
					}
				}

				else if (dest.operation == MLIL_LOAD)
				{
					if (dest.GetSourceExpr().operation == MLIL_CONST_PTR)
					{
						dest = dest.GetSourceExpr();
						if (!bv->IsValidOffset(dest.GetConstant()))
						{
							ProcessOffImageCall(ctx, func, mssa, dest, firstInstruction.GetSSAExprIndex());
						}
					}
				}
			}

			else
			{
				for (const auto& block : mssa->GetBasicBlocks())
				{
					for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
					{
						auto instr = mssa->GetInstruction(i);
						// current_il_function.ssa_form.get_ssa_var_value(current_il_instruction.dest.var)
						if (instr.operation == MLIL_JUMP)
						{
							if (instr.GetDestExpr<MLIL_JUMP>().operation == MLIL_VAR_SSA)
							{
								auto dest = instr.GetDestExpr<MLIL_JUMP>();
								// RegisterValue value = mssa->GetSSAVarValue(instr.GetDestExpr().GetSourceSSAVariable()) ExprId def = mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable());
								// MLILInstruction defInstr = mssa->GetInstruction(mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable()));
								// targetOffset = mssa->GetInstruction(mssa->GetSSAVarDefinition(instr.GetDestExpr().GetSourceSSAVariable())).GetSourceExpr().GetSourceExpr().GetConstant();
								auto value = mssa->GetSSAVarValue(dest.GetSourceSSAVariable());
								if (value.state == UndeterminedValue)
								{
									bool otherFunctionAlreadyRunning;
									{
										otherFunctionAlreadyRunning =
											!workflowState->imageLoadMutex.try_lock();
										if (!otherFunctionAlreadyRunning)
											workflowState->imageLoadMutex.unlock();
									}
									if (otherFunctionAlreadyRunning)
									{
										return;
									}

									std::unique_lock<std::mutex> lock(
										workflowState->imageLoadMutex);
									auto def = mssa->GetSSAVarDefinition(dest.GetSourceSSAVariable());
									auto defInstr = mssa->GetInstruction(def);
									auto targetOffset = defInstr.GetSourceExpr().GetSourceExpr().GetConstant();

									if (bv->IsValidOffset(targetOffset))
										return;

									Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(bv);

									if (!cache)
										return;

									if (!cache->GetImageNameForAddress(targetOffset).empty())
									{
										cache->LoadImageContainingAddress(targetOffset);
									}
									else
									{
										cache->LoadSectionAtAddress(targetOffset);
									}
									for (const auto &sectFunc : bv->GetAnalysisFunctionList())
									{
										if (section->GetStart() <= sectFunc->GetStart() && sectFunc->GetStart() < section->GetEnd())
										{
											func->Reanalyze();
										}
									}
								}
							}

						}
					}
				}
			}

			return;
		}

		for (const auto& block : mssa->GetBasicBlocks())
		{
			for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
			{
				auto instr = mssa->GetInstruction(i);
				if (instr.operation == MLIL_CALL_SSA)
				{
					if (instr.GetDestExpr<MLIL_CALL_SSA>().operation == MLIL_CONST_PTR)
					{
						auto dest = instr.GetDestExpr<MLIL_CALL_SSA>();
						if (!bv->IsValidOffset(dest.GetConstant()))
						{
							ProcessOffImageCall(ctx, func, mssa, dest, instr.GetSSAExprIndex());
						}
					}
				}
			}
		}
	}
	catch (...)
	{}
}


static constexpr auto workflowInfo = R"({
  "title": "Shared Cache Workflow",
  "description": "Shared Cache Workflow",
  "capabilities": []
})";


void fixObjCCallTypes(Ref<AnalysisContext> ctx)
{
	const auto func = ctx->GetFunction();
	const auto arch = func->GetArchitecture();
	const auto bv = func->GetView();

	const auto llil = ctx->GetLowLevelILFunction();
	if (!llil) {
		return;
	}
	const auto ssa = llil->GetSSAForm();
	if (!ssa) {
		return;
	}

	const auto rewriteIfEligible = [bv, ssa](size_t insnIndex) {
		auto insn = ssa->GetInstruction(insnIndex);

		if (insn.operation == LLIL_CALL_SSA)
		{
			// Filter out calls that aren't to `objc_msgSend`.
			auto callExpr = insn.GetDestExpr<LLIL_CALL_SSA>();
			bool isMessageSend = false;
			if (auto symbol = bv->GetSymbolByAddress(callExpr.GetValue().value))
				isMessageSend = symbol->GetRawName() == "_objc_msgSend";
			if (!isMessageSend)
				return;

			const auto llil = ssa->GetNonSSAForm();
			const auto insn = ssa->GetInstruction(insnIndex);
			const auto params = insn.GetParameterExprs<LLIL_CALL_SSA>();

			// The second parameter passed to the objc_msgSend call is the address of
			// either the selector reference or the method's name, which in both cases
			// is dereferenced to retrieve a selector.
			if (params.size() < 2)
				return;
			uint64_t rawSelector = 0;
			if (params[1].operation == LLIL_REG_SSA)
			{
				const auto selectorRegister = params[1].GetSourceSSARegister<LLIL_REG_SSA>();
				rawSelector = ssa->GetSSARegisterValue(selectorRegister).value;
			}
			else if (params[0].operation == LLIL_SEPARATE_PARAM_LIST_SSA)
			{
				if (params[0].GetParameterExprs<LLIL_SEPARATE_PARAM_LIST_SSA>().size() == 0)
				{
					return;
				}
				const auto selectorRegister = params[0].GetParameterExprs<LLIL_SEPARATE_PARAM_LIST_SSA>()[1].GetSourceSSARegister<LLIL_REG_SSA>();
				rawSelector = ssa->GetSSARegisterValue(selectorRegister).value;
			}
			if (!rawSelector || !bv->IsValidOffset(rawSelector))
				return;

			// -- Do callsite override
			auto reader = BinaryNinja::BinaryReader(bv);
			reader.Seek(rawSelector);
			auto selector = reader.ReadCString(500);
			auto additionalArgumentCount = std::count(selector.begin(), selector.end(), ':');

			auto retType = bv->GetTypeByName({ "id" });
			if (!retType)
				retType = BinaryNinja::Type::PointerType(ssa->GetArchitecture(), BinaryNinja::Type::VoidType());

			std::vector<BinaryNinja::FunctionParameter> callTypeParams;
			auto cc = bv->GetDefaultPlatform()->GetDefaultCallingConvention();

			callTypeParams.push_back({"self", retType, true, BinaryNinja::Variable()});

			auto selType = bv->GetTypeByName({ "SEL" });
			if (!selType)
				selType = BinaryNinja::Type::PointerType(ssa->GetArchitecture(), BinaryNinja::Type::IntegerType(1, true));
			callTypeParams.push_back({"sel", selType, true, BinaryNinja::Variable()});

			std::vector<std::string> selectorComponents = splitSelector(selector);
			std::vector<std::string> argumentNames = generateArgumentNames(selectorComponents);

			for (size_t i = 0; i < additionalArgumentCount; i++)
			{
				auto argType = BinaryNinja::Type::IntegerType(bv->GetAddressSize(), true);
				if (argumentNames.size() > i && !argumentNames[i].empty())
					callTypeParams.push_back({argumentNames[i], argType, true, BinaryNinja::Variable()});
				else
					callTypeParams.push_back({"arg" + std::to_string(i), argType, true, BinaryNinja::Variable()});
			}

			auto funcType = BinaryNinja::Type::FunctionType(retType, cc, callTypeParams);
			ssa->GetFunction()->SetAutoCallTypeAdjustment(ssa->GetFunction()->GetArchitecture(), insn.address, {funcType, BN_DEFAULT_CONFIDENCE});
			// --
		}
	};

	for (const auto& block : ssa->GetBasicBlocks())
		for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
			rewriteIfEligible(i);
}



void SharedCacheWorkflow::Register()
{
	Ref<Workflow> wf = BinaryNinja::Workflow::Instance("core.function.baseAnalysis")->Clone("core.function.dsc");
	wf->RegisterActivity(new BinaryNinja::Activity("core.analysis.dscstubs", &SharedCacheWorkflow::FixupStubs));
	wf->RegisterActivity(new BinaryNinja::Activity("core.analysis.fixObjCCallTypes", &fixObjCCallTypes));
	wf->Insert("core.function.analyzeTailCalls", "core.analysis.fixObjCCallTypes");
	wf->Insert("core.function.analyzeTailCalls", "core.analysis.dscstubs");

	BinaryNinja::Workflow::RegisterWorkflow(wf, workflowInfo);
}

extern "C"
{
	void RegisterSharedCacheWorkflow()
	{
		SharedCacheWorkflow::Register();
	}
}
