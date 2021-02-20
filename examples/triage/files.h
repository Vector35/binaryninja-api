#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QTreeView>
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
#include <QtWidgets/QFileSystemModel>
#else
#include <QtGui/QFileSystemModel>
#endif
#include "action.h"
#include "menus.h"


class TriageFilePicker: public QWidget
{
	UIContext* m_context;
	UIActionHandler m_actionHandler;
	Menu m_contextMenu;
	ContextMenuManager m_contextMenuManager;

	QFileSystemModel* m_model;
	QTreeView* m_tree;

	void openSelectedFiles();
	bool areFilesSelected();

public:
	TriageFilePicker(UIContext* context);

protected:
	virtual void contextMenuEvent(QContextMenuEvent*) override;

private Q_SLOTS:
	void onDoubleClick(const QModelIndex& idx);
};
