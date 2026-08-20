#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "mediumlevelilinstruction.h"
#include "KernelCacheController.h"
#include "KernelCacheWorkflow.h"

using namespace BinaryNinja;
using namespace BinaryNinja::KC;

namespace {

// Name a resolved stub with the j_ thunk convention. The target's symbol name is used when one
// exists. When it does not, the destination address is encoded (with the owning image when it can
// be resolved) so the j_ prefix still signals a cross-image thunk to an unnamed or unloaded target.
void IdentifyStub(BinaryView& view, KernelCacheController& controller, uint64_t stubAddr, uint64_t targetAddr)
{
	auto& cache = controller.GetCache();

	std::string name;
	if (auto symbol = cache.GetSymbolAt(targetAddr))
		name = "j_" + symbol->name;
	else if (auto image = cache.GetImageContaining(targetAddr))
		name = fmt::format("j_{}_{:x}", image->GetName(), targetAddr);
	else
		name = fmt::format("j_{:x}", targetAddr);

	view.DefineAutoSymbol(new Symbol(FunctionSymbol, name, stubAddr));
}

// Read the resolved branch target out of a stub's IL. Returns the destination address once data
// flow has folded the __auth_got load into a constant.
std::optional<uint64_t> ResolveStubTarget(MediumLevelILFunction& mlil, const MediumLevelILInstruction& dest)
{
	if (dest.operation == MLIL_CONST_PTR)
		return dest.GetConstant<MLIL_CONST_PTR>();
	if (dest.operation == MLIL_VAR_SSA)
	{
		auto value = mlil.GetSSAVarValue(dest.GetSourceSSAVariable());
		if (value.state == ConstantValue || value.state == ConstantPointerValue)
			return value.value;
	}
	return std::nullopt;
}

void AnalyzeStubFunction(Function& func, MediumLevelILFunction& mlil, KernelCacheController& controller)
{
	auto view = func.GetView();
	for (const auto& block : mlil.GetBasicBlocks())
	{
		for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
		{
			auto instr = mlil.GetInstruction(i);

			std::optional<uint64_t> target;
			if (instr.operation == MLIL_JUMP)
				target = ResolveStubTarget(mlil, instr.GetDestExpr<MLIL_JUMP>());
			else if (instr.operation == MLIL_TAILCALL_SSA)
				target = ResolveStubTarget(mlil, instr.GetDestExpr<MLIL_TAILCALL_SSA>());
			else
				continue;

			if (!target)
				continue;

			// Inline the thunk at its call sites when the target is mapped, matching how the
			// shared cache presents resolved stubs.
			if (view->IsValidOffset(*target))
				func.SetAutoInlinedDuringAnalysis(InlineUsingCallAddress);

			IdentifyStub(*view, controller, func.GetStart(), *target);
			return;
		}
	}
}

void AnalyzeFunction(Ref<AnalysisContext> ctx)
{
	auto func = ctx->GetFunction();
	auto view = func->GetView();
	auto mlil = ctx->GetMediumLevelILFunction();
	if (!mlil)
		return;
	auto mlilSsa = mlil->GetSSAForm();
	if (!mlilSsa)
		return;

	auto controller = KernelCacheController::FromView(*view);
	if (!controller)
		return;

	auto sections = view->GetSectionsAt(func->GetStart());
	if (sections.empty())
		return;
	auto sectionName = sections.front()->GetName();
	if (sectionName.find("__auth_stubs") == std::string::npos
		&& sectionName.find("__stubs") == std::string::npos)
		return;

	AnalyzeStubFunction(*func, *mlilSsa, *controller);
}

}  // namespace

void KernelCacheWorkflowRegister()
{
	auto workflow = Workflow::Get("core.function.metaAnalysis")->Clone("core.function.metaAnalysis");
	workflow->RegisterActivity(new Activity(R"({
	  "name": "core.analysis.kernelCache.analysis",
	  "eligibility": {
	    "predicates": [
	      {
	        "type": "viewType",
	        "operator": "in",
	        "value": [ "KCView" ]
	      }
	    ]
	  }
	})", &AnalyzeFunction));
	std::vector<std::string> inserted = { "core.analysis.kernelCache.analysis" };
	workflow->Insert("core.function.analyzeTailCalls", inserted);
	Workflow::RegisterWorkflow(workflow);
}

extern "C"
{
	void RegisterKernelCacheWorkflow()
	{
		KernelCacheWorkflowRegister();
	}
}
