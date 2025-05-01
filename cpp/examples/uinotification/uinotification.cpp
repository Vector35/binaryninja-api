#include "inttypes.h"
#include "uinotification.h"
#include "filecontext.h"
#include "viewframe.h"
#include <QtWidgets/QMessageBox>
#include <QtCore/QFileInfo>

using namespace BinaryNinja;

NotificationListener* NotificationListener::m_instance = nullptr;

void NotificationListener::init()
{
	m_instance = new NotificationListener;
	UIContext::registerNotification(m_instance);
}


void NotificationListener::OnContextOpen(UIContext* context)
{
	LogInfo("OnContextOpen");
}


void NotificationListener::OnContextClose(UIContext* context)
{
	LogInfo("OnContextClose");
}


bool NotificationListener::OnBeforeOpenDatabase(UIContext* context, FileMetadataRef metadata)
{
	LogInfo("OnBeforeOpenDatabase");
	return QMessageBox::question(context->mainWindow(), "OnBeforeOpenDatabase", "OnBeforeOpenDatabase")
	       == QMessageBox::StandardButton::Yes;
}


bool NotificationListener::OnAfterOpenDatabase(UIContext* context, FileMetadataRef metadata, BinaryViewRef data)
{
	LogInfo("OnAfterOpenDatabase");
	return QMessageBox::question(context->mainWindow(), "OnAfterOpenDatabase", "OnAfterOpenDatabase")
	       == QMessageBox::StandardButton::Yes;
}


bool NotificationListener::OnBeforeOpenFile(UIContext* context, FileContext* file)
{
	LogInfo("OnBeforeOpenFile");
	return QMessageBox::question(context->mainWindow(), "OnBeforeOpenFile", "OnBeforeOpenFile")
	       == QMessageBox::StandardButton::Yes;
}


void NotificationListener::OnAfterOpenFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	LogInfo("OnAfterOpenFile");
}


bool NotificationListener::OnBeforeSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	LogInfo("OnBeforeSaveFile");
	return QMessageBox::question(context->mainWindow(), "OnBeforeSaveFile", "OnBeforeSaveFile")
	       == QMessageBox::StandardButton::Yes;
}


void NotificationListener::OnAfterSaveFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	LogInfo("OnAfterSaveFile");
}


bool NotificationListener::OnBeforeCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	LogInfo("OnBeforeCloseFile");
	return QMessageBox::question(context->mainWindow(), "OnBeforeCloseFile", "OnBeforeCloseFile")
	       == QMessageBox::StandardButton::Yes;
}


void NotificationListener::OnAfterCloseFile(UIContext* context, FileContext* file, ViewFrame* frame)
{
	LogInfo("OnAfterCloseFile");
}


void NotificationListener::OnViewChange(UIContext* context, ViewFrame* frame, const QString& type)
{
	LogInfo("OnViewChange");
}


void NotificationListener::OnAddressChange(
    UIContext* context, ViewFrame* frame, View* view, const ViewLocation& location)
{
	LogInfo("OnAddressChange: 0x%" PRIx64, location.getOffset());
}


bool NotificationListener::GetNameForFile(UIContext* context, FileContext* file, QString& name)
{
	LogInfo("GetNameForFile");
	name = file->getFilename() + " Foo";
	return true;
}


bool NotificationListener::GetNameForPath(UIContext* context, const QString& path, QString& name)
{
	QFileInfo info(path);
	LogInfo("GetNameForPath");
	name = info.baseName() + " Foo";
	return true;
}


extern "C"
{
	BN_DECLARE_UI_ABI_VERSION

	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		NotificationListener::init();
		return true;
	}
}
