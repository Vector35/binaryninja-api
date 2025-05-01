//
// Created by kat on 5/8/23.
//

#include "SharedCacheUINotifications.h"
#include <sharedcacheapi.h>
#include "ui/sidebar.h"
#include "ui/linearview.h"
#include "ui/viewframe.h"
#include "dscpicker.h"
#include "progresstask.h"

using namespace BinaryNinja;
using namespace SharedCacheAPI;

UINotifications* UINotifications::m_instance = nullptr;

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
	if (!view || view->GetTypeName() != VIEW_NAME)
		return;

	auto viewInt = frame->getCurrentViewInterface();
	if (!viewInt)
		return;

	auto ah = viewInt->actionHandler();
	// Check to see if we have already bound these actions.
	if (ah->isBoundAction("Load Image by Name"))
		return;

	static auto loadRegionAtAddr = [](BinaryView& view, uint64_t addr) {
		auto controller = SharedCacheController::GetController(view);
		if (!controller)
			return;
		if (auto foundRegion = controller->GetRegionContaining(addr))
		{
			// If we did not load the region, then we don't need to run analysis.
			if (!controller->ApplyRegion(view, *foundRegion))
				return;
			view.AddAnalysisOption("linearsweep");
			view.UpdateAnalysis();
		}
	};

	static auto loadImageAtAddr = [](BinaryView& view, uint64_t addr) {
		auto controller = SharedCacheController::GetController(view);
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

	auto loadImageNameAction = [](const UIActionContext& ctx) {
		DisplayDSCPicker(ctx.context, ctx.binaryView);
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

	auto loadSectionAddrAction = [](const UIActionContext& ctx) {
		uint64_t addr = 0;
		if (GetAddressInput(addr, "Address", "Address"))
		{
			BackgroundThread::create(ctx.context->mainWindow())
				->thenBackground([ctx, addr](){ loadRegionAtAddr(*ctx.binaryView, addr); })
				->start();
		}
	};

	auto loadRegionTokenAction = [](const UIActionContext& ctx) {
		BackgroundThread::create(ctx.context->mainWindow())
			->thenBackground([ctx](){ loadRegionAtAddr(*ctx.binaryView, ctx.token.token.value); })
			->start();
	};

	auto loadImageTokenAction = [](const UIActionContext& ctx) {
		BackgroundThread::create(ctx.context->mainWindow())
			->thenBackground([ctx](){ loadImageAtAddr(*ctx.binaryView, ctx.token.token.value); })
			->start();
	};

	auto isValidUnloadedRegionAction = [](const UIActionContext& ctx) {
		uint64_t addr = ctx.token.token.value;
		// Check if the region is already loaded in the view.
		if (!ctx.binaryView->GetSectionsAt(addr).empty())
			return false;
		auto controller = SharedCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return false;
		return controller->GetRegionContaining(addr).has_value();
	};

	auto isValidUnloadedImageAction = [](const UIActionContext& ctx) {
		uint64_t addr = ctx.token.token.value;
		// Check if the image is already loaded in the view.
		if (!ctx.binaryView->GetSectionsAt(addr).empty())
			return false;
		auto controller = SharedCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return false;
		return controller->GetImageContaining(addr).has_value();
	};

	ah->bindAction("Load Image by Name", UIAction(loadImageNameAction));
	ah->bindAction("Load Image by Address", UIAction(loadImageAddrAction));
	ah->bindAction("Load Section by Address", UIAction(loadSectionAddrAction));

	ah->bindAction("Load ADDRHERE", UIAction(loadRegionTokenAction, isValidUnloadedRegionAction));
	ah->bindAction("Load IMGHERE", UIAction(loadImageTokenAction, isValidUnloadedImageAction));

	ah->setActionDisplayName("Load ADDRHERE", [](const UIActionContext& ctx) {
		auto controller = SharedCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return QString("NO CONTROLLER");
		uint64_t addr = ctx.token.token.value;
		auto region = controller->GetRegionContaining(addr);
		if (!region)
			return QString("NO REGION");
		return QString("Load ") + region->name.c_str();
	});

	ah->setActionDisplayName("Load IMGHERE", [](const UIActionContext& ctx) {
		auto controller = SharedCacheController::GetController(*ctx.binaryView);
		if (!controller)
			return QString("NO CONTROLLER");
		uint64_t addr = ctx.token.token.value;
		auto image = controller->GetImageContaining(addr);
		if (!image)
			return QString("NO IMAGE");
		return QString("Load ") + image->name.c_str();
	});

	// Finally add the actions to the context menu.
	if (auto linearView = qobject_cast<LinearView*>(viewInt->widget()))
	{
		constexpr auto groupOneName = VIEW_NAME;
		constexpr auto groupTwoName = VIEW_NAME "2";
		linearView->contextMenu().addAction("Load ADDRHERE", groupOneName);
		linearView->contextMenu().addAction("Load IMGHERE", groupOneName);
		linearView->contextMenu().addAction("Load Image by Name", groupTwoName);
		linearView->contextMenu().addAction("Load Image by Address", groupTwoName);
		linearView->contextMenu().addAction("Load Section by Address", groupTwoName);
		linearView->contextMenu().setGroupOrdering(groupOneName, 0);
		linearView->contextMenu().setGroupOrdering(groupTwoName, 1);
	}
}

void UINotifications::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}
