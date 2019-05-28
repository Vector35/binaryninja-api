#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtWidgets/QTableView>
#include <QtWidgets/QItemDelegate>
#include <QtWidgets/QDialog>
#include <QtWidgets/QComboBox>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"


class BINARYNINJAUIAPI TagTypeListModel: public QAbstractItemModel
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<TagTypeRef> m_refs;

public:
	TagTypeListModel(QWidget* parent, BinaryViewRef data);

	TagTypeRef& GetRef(int index) { return m_refs[index]; }
	const TagTypeRef& GetRef(int index) const { return m_refs[index]; }

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual bool setData(const QModelIndex& i, const QVariant& value, int role = Qt::EditRole) override;
	virtual void sort(int column, Qt::SortOrder order) override;
	virtual Qt::ItemFlags flags(const QModelIndex& i) const override;

	bool setModelData(const std::vector<TagTypeRef>& refs, QItemSelectionModel* selectionModel, int sortColumn, Qt::SortOrder sortOrder, bool& selectionUpdated);
};


class BINARYNINJAUIAPI TagTypeItemDelegate: public QItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	void initFont();

public:
	TagTypeItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void setEditorData(QWidget* editor, const QModelIndex& index) const override;
	virtual bool editorEvent(QEvent *event, QAbstractItemModel *model, const QStyleOptionViewItem &option, const QModelIndex &index) override;
};


class BINARYNINJAUIAPI TagTypeList: public QTableView, public DockContextHandler, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	ViewFrame* m_view;
	TagTypeListModel* m_list;
	TagTypeItemDelegate* m_itemDelegate;
	BinaryViewRef m_data;
	UIActionHandler* m_handler;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	Menu* m_menu;

	QTimer* m_updateTimer;
	bool m_needsUpdate;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

	virtual void OnDataMetadataUpdated(BinaryNinja::BinaryView*, uint64_t) override;

private:
	void createTagType();
	void removeTagType();

private Q_SLOTS:
	void updateTimerEvent();

public:
	TagTypeList(QWidget* parent, ViewFrame* view, BinaryViewRef data, Menu* menu = nullptr);
	virtual ~TagTypeList();
	virtual void notifyFontChanged() override;

	static void registerActions();

	void updateData();
	bool hasSelection();
};

class BINARYNINJAUIAPI TagTypeDialogModel: public QAbstractItemModel
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<TagTypeRef> m_refs;

public:
	TagTypeDialogModel(QWidget* parent, BinaryViewRef data);

	TagTypeRef& GetRef(int index) { return m_refs[index]; }
	const TagTypeRef& GetRef(int index) const { return m_refs[index]; }

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
};

class BINARYNINJAUIAPI TagTypeSelectDialog: public QDialog
{
	Q_OBJECT

	BinaryViewRef m_data;
	TagTypeDialogModel* m_model;
	QComboBox* m_tagTypeList;

private Q_SLOTS:
	void select();

public:
	TagTypeSelectDialog(QWidget* parent, BinaryViewRef data);

Q_SIGNALS:
	void selected(TagTypeRef tagType);
};
