#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QFrame>
#include <QtCore/QPointer>
#include <QtWidgets/QStyledItemDelegate>
#include <vector>
#include "action.h"

struct BINARYNINJAUIAPI CommandListItem
{
	enum CommandListItemType
	{
		OpenTab,
		UIAction,
	};

	CommandListItemType type;
	QString name;
	QString shortcut;
	QVariant action;
};

class CommandPalette;
class CommandListFilter;


class BINARYNINJAUIAPI CommandListDelegate: public QStyledItemDelegate
{
	Q_OBJECT
	QFont m_font;
	int m_height;

public:
	CommandListDelegate(QWidget* parent);
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

class BINARYNINJAUIAPI CommandListModel: public QAbstractItemModel
{
	Q_OBJECT

	std::vector<CommandListItem> m_items;
	std::vector<CommandListItem> m_allItems;

	std::vector<QString> m_recentItems;
	size_t m_maxRecentItems;

	bool isFilterMatch(const QString& name, const QString& filter);
	int getFilterMatchScore(const QString& name, const QString& filter);

public:
	CommandListModel(QWidget* parent, const std::vector<CommandListItem>& items);

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;

	CommandListItem getItem(int row);
	void setFilterText(const QString& text);
	size_t getRecentPosition(const QString& name) const;
	void addRecentItem(const QString& name);
};

class BINARYNINJAUIAPI CommandList: public QListView
{
	Q_OBJECT

	CommandPalette* m_palette;
	CommandListModel* m_model;
	CommandListFilter* m_filter;

public:
	CommandList(CommandPalette* parent, const std::vector<CommandListItem>& items);
	void setFilter(CommandListFilter* filter) { m_filter = filter; }
	void setFilterText(const QString& text);

	CommandListItem getItem(int row);

	QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const;
	void addRecentItem(const QString& name);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
};

class BINARYNINJAUIAPI CommandListFilter: public QLineEdit
{
	Q_OBJECT

	CommandPalette* m_palette;
	CommandList* m_list;

public:
	CommandListFilter(CommandPalette* parent, CommandList* list);

protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
};

class BINARYNINJAUIAPI CommandPalette: public QFrame
{
	Q_OBJECT

	UIActionHandler* m_handler;
	UIActionContext m_context;
	QPointer<QWidget> m_previousWidget;

	CommandListFilter* m_filter;
	CommandList* m_list;

	bool m_executing;

	std::vector<CommandListItem> getCommandList();
	void init();

public:
	CommandPalette(QWidget* parent, UIActionHandler* handler);
	CommandPalette(QWidget* parent, UIActionHandler* handler, const UIActionContext& context);

	void focusInput();
	void activateFirstItem();
	void selectFirstItem();
	void close();

private Q_SLOTS:
	void itemClicked(const QModelIndex& idx);
	void filterChanged(const QString& text);
};
