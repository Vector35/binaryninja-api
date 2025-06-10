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
#include <shared_mutex>

#include "ObjCActivity.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

struct WorkflowState
{
	bool autoLoadStubsAndDyldData = true;
	bool autoLoadObjCStubRequirements = true;
};

std::shared_ptr<WorkflowState> GetWorkflowState(Ref<BinaryView> view)
{
	static std::shared_mutex globalWorkflowStateMutex;
	static std::unordered_map<uint64_t, std::shared_ptr<WorkflowState>> globalWorkflowState;

	std::shared_lock<std::shared_mutex> readLock(globalWorkflowStateMutex);
	const uint64_t viewId = view->GetFile()->GetSessionId();
	auto foundState = globalWorkflowState.find(viewId);
	if (foundState != globalWorkflowState.end())
		return foundState->second;
	readLock.unlock();

	std::unique_lock<std::shared_mutex> writeLock(globalWorkflowStateMutex);
	globalWorkflowState[viewId] = std::make_shared<WorkflowState>();
	Ref<Settings> settings = view->GetLoadSettings(VIEW_NAME);

	bool autoLoadStubsAndDyldData = true;
	if (settings && settings->Contains("loader.dsc.autoLoadStubsAndDyldData"))
		autoLoadStubsAndDyldData = settings->Get<bool>("loader.dsc.autoLoadStubsAndDyldData", view);
	globalWorkflowState[viewId]->autoLoadStubsAndDyldData = autoLoadStubsAndDyldData;

	bool autoLoadObjC = true;
	if (settings && settings->Contains("loader.dsc.autoLoadObjCStubRequirements"))
		autoLoadObjC = settings->Get<bool>("loader.dsc.autoLoadObjCStubRequirements", view);
	globalWorkflowState[viewId]->autoLoadObjCStubRequirements = autoLoadObjC;

	return globalWorkflowState[viewId];
}

// TODO: Add a type library cache to this workflow. (so we dont take global file lock)
Ref<TypeLibrary> TypeLibraryFromName(BinaryView& view, const std::string& name) {
	// Check to see if we have already loaded the type library.
	if (auto typeLib = view.GetTypeLibrary(name))
		return typeLib;

	// TODO: Use the functions platform instead.
	auto typeLibs = view.GetDefaultPlatform()->GetTypeLibrariesByName(name);
	if (!typeLibs.empty())
		return typeLibs.front();
	return nullptr;
}

// Rename and retype the stub function.
void IdentifyStub(BinaryView& view, const SharedCacheController& controller, uint64_t stubFuncAddr, uint64_t symbolAddr) {
	static const char* STUB_PREFIX = "j_";
	// Try and apply a version of the symbol address to the target address
	if (const auto symbol = view.GetSymbolByAddress(symbolAddr))
	{
		// A symbol already exists at the source location. Add a stub symbol at `targetLocation` based on the existing symbol.
		if (auto targetFunc = view.GetAnalysisFunction(view.GetDefaultPlatform(), stubFuncAddr))
			view.DefineAutoSymbol(new Symbol(FunctionSymbol, STUB_PREFIX + symbol->GetShortName(), stubFuncAddr));
		else
			view.DefineAutoSymbol(new Symbol(symbol->GetType(), STUB_PREFIX + symbol->GetShortName(), stubFuncAddr));
		return;
	}

	// No existing symbol located, try and search through the symbols of the cache.
	auto symbol = controller.GetSymbolAt(symbolAddr);
	if (!symbol.has_value())
		return;

	// TODO: The demangled type here is almost always wrong so we omit it for now.
	auto [demangledName, demangledType] = symbol->DemangledName(view);
	auto rawName = STUB_PREFIX + symbol->name;
	auto shortName = STUB_PREFIX + demangledName;

	// Try and retrieve a type for the stub function using type libraries.
	if (const auto targetFunc = view.GetAnalysisFunction(view.GetDefaultPlatform(), stubFuncAddr))
	{
		// NOTE: The type library name is expected to be the image name currently.
		// Try and pull the type from the associated type library (if there is one)
		// TODO: The demangled type here is missing a param
		// Ref<Type> selectedType = demangledType;
		Ref<Type> selectedType = nullptr;
		if (const auto image = controller.GetImageContaining(symbolAddr))
			if (auto typeLib = TypeLibraryFromName(view, image->name))
				if (Ref<Type> libraryType = view.ImportTypeLibraryObject(typeLib, {symbol->name}); libraryType)
					selectedType = libraryType;

		if (selectedType != nullptr)
			targetFunc->ApplyAutoDiscoveredType(selectedType);
	}

	// Define the new symbol!
	auto bnSymbol = new Symbol(symbol->type, shortName, shortName, rawName, stubFuncAddr, nullptr);
	view.DefineAutoSymbol(bnSymbol);
}

void AnalyzeStubFunction(Ref<Function> func, Ref<MediumLevelILFunction> mlil, SharedCacheController& controller, bool loadImage)
{
	// 1. Identify the load target and load the region, resolving the load to a const pointer.
	// 2. We _should_ have a proper call now to the appropriate external function (external to the current image)
	// 3. Rename and retype the current stub function to match the stub target (i.e. target is `foo`, sub function is `j_foo`)

	auto view = func->GetView();
	auto loadStubIslandRegion = [&](uint64_t regionAddr) {
		auto region = controller.GetRegionContaining(regionAddr);
		if (!region.has_value() || controller.IsRegionLoaded(*region))
			return false;
		// Only interested in non image regions, we DON'T want to implicitly load image regions (with functions presumably).
		if (region->type == SharedCacheRegionTypeImage)
			return false;
		// Adjust the new region semantics to read only, this helps analysis pickup constant loads in our stub functions.
		// NOTE: We do NOT do this for stub island as that contains CODE!
		if (region->type != SharedCacheRegionTypeStubIsland)
			region->flags = static_cast<BNSegmentFlag>(SegmentReadable | SegmentContainsData | SegmentDenyWrite);
		return controller.ApplyRegion(*view, *region);
	};

	// We allow the user to automatically load the directly referenced objc images as having the calls inlined is extremely useful for objc.
	auto loadTargetImage = [&](uint64_t imageAddr) {
		const auto image = controller.GetImageContaining(imageAddr);
		if (!image.has_value() || controller.IsImageLoaded(*image))
			return false;
		return controller.ApplyImage(*view, *image);
	};

	auto loadTarget = [&](uint64_t targetAddr) {
		// Skip if already loaded.
		if (view->IsValidOffset(targetAddr))
			return false;
		// If the stub function is allowed to load images (for inlining)
		if (loadImage && loadTargetImage(targetAddr))
			return true;
		return loadStubIslandRegion(targetAddr);
	};


	auto processJumpExpr = [&](MediumLevelILInstruction expr) {
		switch (expr.operation)
		{
		case MLIL_VAR_SSA:
			{
				const auto var = expr.GetSourceSSAVariable();
				const auto varValue = mlil->GetSSAVarValue(var);
				if (varValue.state != UndeterminedValue)
					return;
				// Analysis is not able to determine the jump location! We must load the target region and then
				// set the variables value.
				auto def = mlil->GetSSAVarDefinition(var);
				auto defInstr = mlil->GetInstruction(def);
				if (defInstr.operation != MLIL_SET_VAR_SSA)
					return;
				expr = defInstr.GetSourceExpr<MLIL_SET_VAR_SSA>();
				if (expr.operation != MLIL_LOAD_SSA)
					return;
				// Fallthrough to MLIL_LOAD_SSA.
			}
		case MLIL_LOAD_SSA:
			expr = expr.GetSourceExpr<MLIL_LOAD_SSA>();
			if (expr.operation != MLIL_CONST_PTR)
				return;
			// Fallthrough to MLIL_CONST_PTR.
		case MLIL_CONST_PTR:
			{
				// First load the stub island, if we _do_ load the stub island stop and reanalyze for constant propagation.'
				const auto islandPtr = expr.GetConstant<MLIL_CONST_PTR>();
				if (loadTarget(islandPtr))
					return;
				// We have been promoted to the target pointer here!
				const auto targetPtr = islandPtr;
				// Here we expect the pointer value to be the address of the resulting function.
				IdentifyStub(*view, controller, func->GetStart(), targetPtr);
			}
			break;
		default:
			break;
		}
	};

	auto processTailcallExpr = [&](const MediumLevelILInstruction& expr) {
		switch (expr.operation)
		{
		case MLIL_CONST_PTR:
			// NOTE: This runs every single function update.
			func->SetAutoInlinedDuringAnalysis(true);
			break;
		default:
			break;
		}
	};

	const auto basicBlocks = mlil->GetBasicBlocks();
	for (const auto& block : basicBlocks)
	{
		for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
		{
			auto instr = mlil->GetInstruction(i);
			switch (instr.operation)
			{
			case MLIL_JUMP:
				processJumpExpr(instr.GetDestExpr<MLIL_JUMP>());
				break;
			case MLIL_TAILCALL_SSA:
				processTailcallExpr(instr.GetDestExpr<MLIL_TAILCALL_SSA>());
				break;
			default:
				break;
			}
		}
	}
}

// Automatically load the stub regions.
void AnalyzeStandardFunction(Ref<Function> func, Ref<MediumLevelILFunction> mlil, SharedCacheController& controller)
{
	auto view = func->GetView();
	auto identifyUnmappedSymbol = [&](uint64_t symbolAddr) {
		// Skip if already loaded.
		if (view->IsValidOffset(symbolAddr) || view->GetSymbolByAddress(symbolAddr))
			return false;
		const auto symbol = controller.GetSymbolAt(symbolAddr);
		if (!symbol.has_value())
			return false;
		view->DefineAutoSymbol(symbol->GetBNSymbol(*view));
		return true;
	};

	auto loadStubIslandRegion = [&](uint64_t regionAddr) {
		// Skip if already loaded.
		if (view->IsValidOffset(regionAddr))
			return false;
		auto region = controller.GetRegionContaining(regionAddr);
		if (!region.has_value() || controller.IsRegionLoaded(*region))
			return false;
		// Only interested in non image regions, we DON'T want to implicitly load image regions (with functions presumably).
		if (region->type == SharedCacheRegionTypeImage)
			return false;
		// Adjust the new region semantics to read only, this helps analysis pickup constant loads in our stub functions.
		// NOTE: We do NOT do this for stub island as that contains CODE!
		if (region->type != SharedCacheRegionTypeStubIsland)
			region->flags = static_cast<BNSegmentFlag>(SegmentReadable | SegmentContainsData | SegmentDenyWrite);
		return controller.ApplyRegion(*view, *region);
	};

	// Use this to filter out constants that are impossible to be backed by a region.
	auto baseAddress = view->GetStart();

	// Promotes a constant to a constant pointer, if it's backed by a shared cache region.
	// Constants won't be eligible for symbol rendering so to get it to render we must rewrite the IL to make
	// it a constant pointer.
	auto promoteUnmappedPointerExpr = [&](MediumLevelILInstruction constExpr) {
		const auto unmappedAddr = constExpr.GetConstant<MLIL_CONST>();
		if (unmappedAddr < baseAddress || view->IsValidOffset(unmappedAddr))
			return false;
		if (!controller.GetRegionContaining(unmappedAddr))
			return false;
		// Replace the constant expr with a constant pointer expr
		const auto constSrcLoc = ILSourceLocation(constExpr.address, constExpr.sourceOperand);
		const auto constPtrExpr = mlil->ConstPointer(constExpr.size, unmappedAddr, constSrcLoc);
		// Force the expr type to a pointer as well
		const auto ptrType = Type::PointerType(func->GetArchitecture(), Type::VoidType()->WithConfidence(0))->WithConfidence(BN_HEURISTIC_CONFIDENCE);
		mlil->SetExprType(constPtrExpr, ptrType);
		constExpr.Replace(constPtrExpr);
		return true;
	};

	auto processUnmappedExpr = [&](const MediumLevelILInstruction& expr) {
		switch (expr.operation)
		{
		case MLIL_CONST_PTR:
			loadStubIslandRegion(expr.GetConstant<MLIL_CONST_PTR>());
			identifyUnmappedSymbol(expr.GetConstant<MLIL_CONST_PTR>());
			break;
		case MLIL_CONST:
			// Typically a direct expression load/store will have the constant be promoted to a constant pointer
			// however if an expression is only used as an address of and data flow does not fold it in, we won't get a
			// constant pointer promotion. This case handles that limitation, by checking to see if a constant falls in
			// an unmapped region.
			if (promoteUnmappedPointerExpr(expr))
			{
				// We have promoted a pointer, lets now try and identify its symbol.
				// We don't want to rely on this activity being re-invoked and going down the `MLIL_CONST_PTR` path
				// so instead we just call the `identifyUnmappedSymbol` after promotion, to ensure that the symbols are identified.
				identifyUnmappedSymbol(expr.GetConstant());
			}
			break;
		default:
			break;
		}
		return true;
	};

	// 1. Load all unmapped STUB regions / images that are called in this function.
	// 2. Identify loads & stores to unmapped regions and add their respective symbol.
	for (const auto& block : mlil->GetBasicBlocks())
		for (size_t i = block->GetStart(), end = block->GetEnd(); i < end; ++i)
			mlil->GetInstruction(i).VisitExprs(processUnmappedExpr);
}

void AnalyzeFunction(Ref<AnalysisContext> ctx)
{
	const auto func = ctx->GetFunction();
	const auto view = func->GetView();
	const auto mlil = ctx->GetMediumLevelILFunction();
	if (!mlil)
		return;
	const auto mlilSsa = mlil->GetSSAForm();
	if (!mlilSsa)
		return;

	auto workflowState = GetWorkflowState(view);
	auto controller = SharedCacheController::GetController(*view);
	if (!controller)
		return;

	// Get the containing section for section specific tasks.
	auto funcStart = func->GetStart();
	auto sections = view->GetSectionsAt(funcStart);
	if (sections.empty())
		return;
	const auto& section = sections.front();
	const auto sectionName = section->GetName();

	enum FunctionType
	{
		StandardFunction,
		StubFunction,
		ObjCStubFunction,
	};

	// Identify the current analysis function type. We perform different analysis depending on the type.
	FunctionType functionType = StandardFunction;
	if (sectionName.rfind("__objc_stubs") != std::string::npos)
		functionType = ObjCStubFunction;
	else if (sectionName.rfind("_stubs") != std::string::npos || sectionName.rfind("_branch_islands") != std::string::npos)
		functionType = StubFunction;

	switch (functionType)
	{
		case StandardFunction:
			AnalyzeStandardFunction(func, mlilSsa, *controller);
			break;
		case StubFunction:
			AnalyzeStubFunction(func, mlilSsa, *controller, false);
			break;
		case ObjCStubFunction:
			AnalyzeStubFunction(func, mlilSsa, *controller, workflowState->autoLoadObjCStubRequirements);
			break;
	}
}

void SharedCacheWorkflow::Register()
{
	Ref<Workflow> workflow = Workflow::Instance("core.function.metaAnalysis")->Clone("core.function.metaAnalysis");

	// Register and insert activities here.
	ObjCActivity::Register(*workflow);
	workflow->RegisterActivity(new Activity(R"({
	  "name": "core.analysis.sharedCache.analysis",
	  "eligibility": {
	    "predicates": [
	      {
	        "type": "viewType",
	        "operator": "in",
	        "value": [
	          "DSCView"
	        ]
	      }
	    ]
	  }
	})", &AnalyzeFunction));
	std::vector<std::string> inserted = { "core.analysis.sharedCache.analysis" };
	workflow->Insert("core.function.analyzeTailCalls", inserted);

	Workflow::RegisterWorkflow(workflow);
}

extern "C"
{
	void RegisterSharedCacheWorkflow()
	{
		SharedCacheWorkflow::Register();
	}
}
