//
// Created by kat on 5/8/23.
//

#include "SharedCacheUINotifications.h"
#include <QLayout>
#include <sharedcacheapi.h>
#include "ui/sidebar.h"
#include "ui/linearview.h"
#include "ui/viewframe.h"
#include "dscpicker.h"
#include "progresstask.h"
#include "SharedCacheBDNotifications.h"

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
		if (view && view->GetTypeName() == VIEW_NAME)
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
	if (view && view->GetTypeName() == VIEW_NAME)
	{
		if (auto viewInt = frame->getCurrentViewInterface())
		{
			auto ah = viewInt->actionHandler();
			if (!ah->isBoundAction("Load Image by Name"))
			{
				ah->bindAction("Load Image by Name", UIAction([view = view](const UIActionContext& ctx) {
					Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(view);
					DisplayDSCPicker(ctx.context, view);
				}));
				ah->bindAction("Load Section by Address", UIAction([view = view](const UIActionContext& ctx) {
					Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
					uint64_t addr = 0;
					bool gotAddr = GetAddressInput(addr, "Address", "Address");
					if (gotAddr)
					{
						BackgroundThread::create(ctx.context->mainWindow())->thenBackground(
						[cache=cache, addr=addr]() {
							cache->LoadSectionAtAddress(addr);
						})->start();
					}
				}));
				ah->bindAction("Load ADDRHERE",
					UIAction(
						[](const UIActionContext& ctx) {
							Ref<BinaryView> view = ctx.binaryView;
							Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
							uint64_t addr = ctx.token.token.value;
							if (addr)
							{
								BackgroundThread::create(ctx.context->mainWindow())->thenBackground(
								[cache=cache, addr=addr]() {
									cache->LoadSectionAtAddress(addr);
								})->start();
							}
						},
						[](const UIActionContext& ctx) {
							Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
							uint64_t addr = ctx.token.token.value;
							if (isAddrMapped(ctx.binaryView, addr))
								return false;
							return addr && cache->GetNameForAddress(addr) != "";	 // bool
						}));
				ah->bindAction("Load IMGHERE",
					UIAction(
						[](const UIActionContext& ctx) {
							Ref<BinaryView> view = ctx.binaryView;
							Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(view);
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
							Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
							uint64_t addr = ctx.token.token.value;
							if (isAddrMapped(ctx.binaryView, addr))
								return false;
							return addr && cache->GetImageNameForAddress(addr) != "";  // bool
						}));
				ah->setActionDisplayName("Load ADDRHERE", [](const UIActionContext& ctx) {
					Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
					uint64_t addr = ctx.token.token.value;
					if (addr)
						return QString("Load ") + cache->GetNameForAddress(addr).c_str();
					return QString("Error");
				});
				ah->setActionDisplayName("Load IMGHERE", [](const UIActionContext& ctx) {
					Ref<SharedCacheAPI::SharedCache> cache = new SharedCacheAPI::SharedCache(ctx.binaryView);
					uint64_t addr = ctx.token.token.value;
					if (addr)
						return QString("Load ") + cache->GetImageNameForAddress(addr).c_str();
					return QString("Error");
				});
				if (auto linearView = qobject_cast<LinearView*>(viewInt->widget()))
				{
					linearView->contextMenu().addAction("Load ADDRHERE", VIEW_NAME);
					linearView->contextMenu().addAction("Load IMGHERE", VIEW_NAME);
					linearView->contextMenu().addAction("Load Image by Name", "DSCView2");
					linearView->contextMenu().addAction("Load Section by Address", "DSCView2");
					linearView->contextMenu().setGroupOrdering(VIEW_NAME, 0);
					linearView->contextMenu().setGroupOrdering("DSCView2", 1);
				}
			}
		}
	}
}
void UINotifications::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	if (frame->getCurrentBinaryView())
	{
		auto listener = new SharedCacheBDNotifications(frame->getCurrentBinaryView());
		frame->getCurrentBinaryView()->RegisterNotification(listener);
	}
	UIContextNotification::OnAfterOpenFile(context, file, frame);
}
