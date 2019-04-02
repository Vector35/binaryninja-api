#pragma once

#include <QtWidgets/QWidget>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QFileSystemModel>
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
