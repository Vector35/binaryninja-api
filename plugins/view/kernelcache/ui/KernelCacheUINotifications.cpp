//
// Created by kat on 5/8/23.
//

#include "KernelCacheUINotifications.h"
#include <QLayout>
#include <kernelcacheapi.h>
#include "ui/sidebar.h"
#include "ui/linearview.h"
#include "ui/viewframe.h"
#include "progresstask.h"

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

	// FIXME there is a bv func for this
	static std::function<bool(Ref<BinaryView>, uint64_t)> isAddrMapped = [](Ref<BinaryView> view, uint64_t addr) {
		if (view && view->GetTypeName() == KC_VIEW_NAME)
		{
			for (const auto& seg : view->GetSegments())
			{
				if (seg->GetStart() <= addr && seg->GetEnd() > addr)
					return true;
			}
		}
		return false;
	};

	auto view = frame->getCurrentBinaryView();
	if (view && view->GetTypeName() == KC_VIEW_NAME)
	{
		if (auto viewInt = frame->getCurrentViewInterface())
		{
			auto ah = viewInt->actionHandler();
			if (!ah->isBoundAction("KC Load IMGHERE"))
			{
				ah->bindAction("KC Load IMGHERE",
					UIAction(
						[](const UIActionContext& ctx) {
							Ref<BinaryView> view = ctx.binaryView;
							Ref<KernelCacheAPI::KernelCache> cache = new KernelCacheAPI::KernelCache(view);
							uint64_t addr = ctx.token.token.value;
							if (addr)
							{
								BackgroundThread::create(ctx.context->mainWindow())->thenBackground(
								[cache=cache, addr=addr]() {
									cache->LoadImageContainingAddress(addr);
								})->start();
							}
						},
						[](const UIActionContext& ctx) {
							Ref<KernelCacheAPI::KernelCache> cache = new KernelCacheAPI::KernelCache(ctx.binaryView);
							uint64_t addr = ctx.token.token.value;
							if (isAddrMapped(ctx.binaryView, addr))
								return false;
							return addr && cache->GetImageNameForAddress(addr) != "";  // bool
						}));
				ah->setActionDisplayName("KC Load IMGHERE", [](const UIActionContext& ctx) {
					Ref<KernelCacheAPI::KernelCache> cache = new KernelCacheAPI::KernelCache(ctx.binaryView);
					uint64_t addr = ctx.token.token.value;
					if (addr)
						return QString("Load ") + cache->GetImageNameForAddress(addr).c_str();
					return QString("Error");
				});
				if (auto linearView = qobject_cast<LinearView*>(viewInt->widget()))
				{
					linearView->contextMenu().addAction("KC Load IMGHERE", KC_VIEW_NAME);
					linearView->contextMenu().setGroupOrdering(KC_VIEW_NAME, 0);
				}
			}
		}
	}
}
void UINotifications::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	if (frame->getCurrentBinaryView())
	{
		// Register BD notifications. We dont use them right now.
	}
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}
