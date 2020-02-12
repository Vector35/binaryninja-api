#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtWidgets/QListView>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QTreeView>
#include <QtGui/QImage>
#include <vector>
#include <memory>

#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"


class XrefItem
{
public:
	enum XrefDirection
	{
		Forward, // current address is addressing another address
		Backward // current address is being referenced by another address
	};

	enum XrefType
	{
		DataXrefType,
		CodeXrefType,
		VariableXrefType
	};

protected:
	FunctionRef m_func;
	ArchitectureRef m_arch;
	uint64_t m_addr;
	XrefType m_type;
	XrefDirection m_direction;

	std::vector<std::shared_ptr<XrefItem>> m_childItems;
	std::weak_ptr<XrefItem> m_parentItem;

public:
	XrefItem();
	XrefItem(FunctionRef func);
	XrefItem(FunctionRef func, ArchitectureRef arch, uint64_t addr, XrefType type, XrefDirection direction);
	XrefItem(BinaryNinja::ReferenceSource referenceSource, XrefType type, XrefDirection direction);
	virtual ~XrefItem();

	void appendChild(std::shared_ptr<XrefItem> child, std::shared_ptr<XrefItem> parent);
	std::shared_ptr<XrefItem> child(size_t row) const;
	size_t childCount() const { return m_childItems.size(); }
	size_t columnCount() const { return 1; }
	size_t row() const;
	std::weak_ptr<XrefItem> parentItem() const { return m_parentItem; }
	XrefDirection direction() const { return m_direction; }
	FunctionRef func() const { return m_func; }
	ArchitectureRef arch() const { return m_arch; }
	uint64_t addr() const { return m_addr; }
	XrefType type() const { return m_type; }

	bool operator==(const XrefItem& other)
	{
		if (!((m_direction == other.m_direction) &&
				(m_addr == other.m_addr) &&
				(m_type == other.m_type)))
			return false;

		if (!m_func && !other.m_func)
			return true;

		return (m_func->GetStart() == other.m_func->GetStart());
	}

	bool operator!=(const XrefItem& other)
	{
		return !(*this == other);
	}
};


class XrefHeader: public XrefItem
{
	QString m_name;
public:
	XrefHeader() {}
	XrefHeader(const QString& name);
	virtual ~XrefHeader() {}
	virtual QString name() const { return m_name; }
};


class XrefFunctionHeader: public XrefItem
{
public:
	XrefFunctionHeader() {}
	XrefFunctionHeader(FunctionRef func) : XrefItem(func) {};
	virtual ~XrefFunctionHeader() {}
};


class BINARYNINJAUIAPI CrossReferenceListModel : public QAbstractItemModel
{
	Q_OBJECT

	std::shared_ptr<XrefHeader> m_rootItem;
	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<std::shared_ptr<XrefItem>> m_refs;

public:
	CrossReferenceListModel(QWidget* parent, BinaryViewRef data);
	virtual ~CrossReferenceListModel() {}

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex nextValidIndex(const QModelIndex& current) const;
	QModelIndex prevValidIndex(const QModelIndex& current) const;
	bool selectRef(XrefItem* ref, XrefItem* root, QItemSelectionModel* selectionModel);

	bool setModelData(std::vector<std::shared_ptr<XrefItem>>& refs, QItemSelectionModel* selectionModel, bool& selectionUpdated);
};


class BINARYNINJAUIAPI CrossReferenceItemDelegate: public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;
	QImage m_xrefTo, m_xrefFrom;

	void initFont();

public:
	CrossReferenceItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
};

class BINARYNINJAUIAPI CrossReferenceList: public QTreeView, public DockContextHandler
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	ViewFrame* m_view;
	CrossReferenceListModel* m_tree;
	CrossReferenceItemDelegate* m_itemDelegate;
	BinaryViewRef m_data;

	QTimer* m_hoverTimer;
	QPoint m_hoverPos;

	uint64_t m_curRefTarget = 0;
	bool m_navigating = false;
	bool m_navToNextOrPrevStarted = false;

protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual void mouseMoveEvent(QMouseEvent* e) override;
	virtual void mousePressEvent(QMouseEvent* e) override;
	virtual void mouseDoubleClickEvent(QMouseEvent *event) override;
	virtual void notifyFontChanged() override;
	virtual bool shouldBeVisible(ViewFrame* frame) override;
	virtual void wheelEvent(QWheelEvent* e) override;
	virtual void drawRow(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
	void goToReference(const QModelIndex& idx);

private Q_SLOTS:
	void hoverTimerEvent();
	void referenceActivated(const QModelIndex& idx);

public:
	CrossReferenceList(ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceList();

	void setCurrentSelection(uint64_t begin, uint64_t end);
	void navigateToNext();
	void navigateToPrev();

	bool hasSelection();
};
