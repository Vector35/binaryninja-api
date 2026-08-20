//
// Created by kat on 5/8/23.
//

#include "KernelCacheUINotifications.h"
#include <kernelcacheapi.h>
#include "mediumlevelilinstruction.h"
#include "ui/sidebar.h"
#include "ui/linearview.h"
#include "ui/viewframe.h"
#include "progresstask.h"

using namespace BinaryNinja;
using namespace KernelCacheAPI;

UINotifications* UINotifications::m_instance = nullptr;

// Resolve a stub function at `addr` to the constant target of its jump or tail call. Stub functions
// are identified by the `j_` symbol prefix that the kernel cache workflow applies when renaming them.
static std::optional<uint64_t> ResolveStubTarget(BinaryView& view, uint64_t addr)
{
	auto symbol = view.GetSymbolByAddress(addr);
	if (!symbol || symbol->GetShortName().rfind("j_", 0) != 0)
		return std::nullopt;

	auto func = view.GetAnalysisFunction(view.GetDefaultPlatform(), addr);
	if (!func)
		return std::nullopt;

	// Skip any function that is very clearly not a stub (not a single basic block with only a few instructions).
	const auto blocks = func->GetBasicBlocks();
	constexpr uint64_t maxStubLength = 0x20;
	if (blocks.size() != 1 || blocks[0]->GetLength() > maxStubLength)
		return std::nullopt;

	auto mlil = func->GetMediumLevelIL();
	if (!mlil)
		return std::nullopt;

	const auto mlilBlocks = mlil->GetBasicBlocks();
	if (mlilBlocks.size() != 1 || mlilBlocks[0]->GetEnd() == mlilBlocks[0]->GetStart())
		return std::nullopt;

	// The jump or tail call terminates the stub's single basic block, so it can only be the last instruction.
	const auto instr = mlil->GetInstruction(mlilBlocks[0]->GetEnd() - 1);
	if (instr.operation != MLIL_JUMP && instr.operation != MLIL_TAILCALL)
		return std::nullopt;

	const auto dest = instr.GetDestExpr();
	if (dest.operation != MLIL_CONST_PTR && dest.operation != MLIL_CONST)
		return std::nullopt;

	return dest.GetConstant();
}

// The address a token-based load action should operate on. A stub function's address is in an
// already-loaded image, so resolve it to its target and offer to load what the stub jumps to.
static uint64_t TokenAddress(const UIActionContext& ctx)
{
	uint64_t addr = ctx.token.token.value;
	if (!ctx.binaryView->GetSectionsAt(addr).empty())
	{
		if (auto target = ResolveStubTarget(*ctx.binaryView, addr))
			return *target;
	}
	return addr;
}

void UINotifications::init()
{
	m_instance = new UINotifications;
	UIContext::registerNotification(m_instance);
}

void UINotifications::OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
{
	if (!frame)
		return;

	auto view = frame->getCurrentBinaryView();
	if (!view || view->GetTypeName() != KC_VIEW_NAME)
		return;

	auto viewInt = frame->getCurrentViewInterface();
	if (!viewInt)
		return;

	auto ah = viewInt->actionHandler();
	// Check to see if we have already bound these actions.
	if (ah->isBoundAction("KC Load IMGHERE"))
		return;

	static auto loadImageAtAddr = [](BinaryView& view, uint64_t addr) {
		auto controller = KernelCacheController::GetController(view);
		if (!controller)
			return;
		if (auto foundImage = controller->GetImageContaining(addr))
		{
			// If we did not load the image, then we don't need to run analysis.
			if (!controller->ApplyImage(view, *foundImage))
				return;
			view.AddAnalysisOption("linearsweep");
			view.UpdateAnalysis();
		}
	};

	auto loadImageAddrAction = [](const UIActionContext& ctx) {
		uint64_t addr = 0;
		if (GetAddressInput(addr, "Address", "Address"))
		{
			BackgroundThread::create(ctx.context->mainWindow())
				->thenBackground([ctx, addr]() {
					loadImageAtAddr(*ctx.binaryView, addr);
				})->start();
		}
	};

	auto loadImageTokenAction = [](const UIActionContext& ctx) {
		uint64_t addr = TokenAddress(ctx);
		BackgroundThread::create(ctx.context->mainWindow())
			->thenBackground([ctx, addr](){ loadImageAtAddr(*ctx.binaryView, addr); })
			->start();
	};

	auto isValidUnloadedImageAction = [](const UIActionContext& ctx) {
		uint64_t addr = TokenAddress(ctx);
		// Check if the image is already loaded in the view.
		if (!ctx.binaryView->GetSectionsAt(addr).empty())
			return false;
		auto controller = KernelCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return false;
		return controller->GetImageContaining(addr).has_value();
	};

	ah->bindAction("KC Load Image by Address", UIAction(loadImageAddrAction));
	ah->setActionDisplayName("KC Load Image by Address", "Load Image by Address");

	ah->bindAction("KC Load IMGHERE", UIAction(loadImageTokenAction, isValidUnloadedImageAction));

	ah->setActionDisplayName("KC Load IMGHERE", [](const UIActionContext& ctx) {
		auto controller = KernelCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return QString("NO CONTROLLER");
		uint64_t addr = TokenAddress(ctx);
		auto image = controller->GetImageContaining(addr);
		if (!image)
			return QString("NO IMAGE");
		return QString("Load ") + image->name.c_str();
	});

	// Finally add the actions to the context menu.
	if (auto linearView = qobject_cast<LinearView*>(viewInt->widget()))
	{
		constexpr auto groupOneName = KC_VIEW_NAME;
		constexpr auto groupTwoName = KC_VIEW_NAME "2";
		linearView->contextMenu().addAction("KC Load IMGHERE", groupOneName);
		linearView->contextMenu().addAction("KC Load Image by Address", groupTwoName);
		linearView->contextMenu().setGroupOrdering(groupOneName, 0);
		linearView->contextMenu().setGroupOrdering(groupTwoName, 1);
	}
}

void UINotifications::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}
