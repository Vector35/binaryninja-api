//
// Created by kat on 8/22/24.
//

#include "SharedCacheBDNotifications.h"


SharedCacheBDNotifications::SharedCacheBDNotifications(Ref<BinaryView> view)
	: BinaryDataNotification(FunctionUpdates | DataVariableUpdates)
{
}

void SharedCacheBDNotifications::OnAnalysisFunctionAdded(BinaryView* view, Function* func)
{
	//
	// We just cannot do this until one of:
	// "Component::AddAutoFunction"
	// BinaryView::BeginIgnoredUndoActions
	// some similar fix

	/*
	if (view->GetTypeName() == VIEW_NAME)
	{
		auto sections = view->GetSectionsAt(func->GetStart());
		if (sections.size() > 0)
		{
			auto section = sections[0];
			auto imageName = section->GetName().substr(0, section->GetName().find("::"));
			auto id = view->BeginUndoActions();
			auto comp = view->GetComponentByPath(imageName);
			if (!comp)
			{
				comp = view->CreateComponentWithName(imageName);
			}
			comp.value()->AddFunction(func);
			view->ForgetUndoActions(id);
		}
	}
	 */
}


void SharedCacheBDNotifications::OnSectionAdded(BinaryView* data, Section* section)
{

}


void SharedCacheBDNotifications::OnDataVariableAdded(BinaryView* view, const DataVariable& var)
{
	/*
	if (view->GetTypeName() == VIEW_NAME)
	{
		auto sections = view->GetSectionsAt(var.address);
		if (sections.size() > 0)
		{
			auto section = sections[0];
			auto imageName = section->GetName().substr(0, section->GetName().find("::"));
			auto comp = view->GetComponentByPath(imageName);
			auto id = view->BeginUndoActions();
			if (!comp)
			{
				comp = view->CreateComponentWithName(imageName);
			}
			comp.value()->AddDataVariable(var);
			view->ForgetUndoActions(id);
		}
	}*/
}
