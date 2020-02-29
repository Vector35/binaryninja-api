#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QModelIndex>
#include <QtGui/QImage>
#include <QtCore/QParallelAnimationGroup>
#include <QtWidgets/QListView>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QTableView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QToolButton>

#include <vector>
#include <deque>
#include <memory>

#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "viewframe.h"
#include "fontsettings.h"

class XrefHeader;
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
	mutable XrefHeader* m_parentItem;
	mutable int m_size;


public:
	explicit XrefItem();
	explicit XrefItem(XrefHeader* parent, XrefType type, FunctionRef func);
	explicit XrefItem(BinaryNinja::ReferenceSource referenceSource, XrefType type, XrefDirection direction);
	XrefItem(const XrefItem& ref);
	virtual ~XrefItem();

	XrefDirection direction() const { return m_direction; }
	FunctionRef func() const { return m_func; }
	ArchitectureRef arch() const { return m_arch; }
	uint64_t addr() const { return m_addr; }
	XrefType type() const { return m_type; }
	int size() const { return m_size; }
	void setSize(int size) const { m_size = size; }
	void setParent(XrefHeader* parent) const;
	virtual XrefItem* parent() const { return (XrefItem*)m_parentItem; }
	virtual XrefItem* child(int) const { return nullptr; }
	virtual int childCount() const { return 0; }

	int row() const;
	bool operator==(const XrefItem& other) const;
	bool operator!=(const XrefItem& other) const;
};


class XrefHeader: public XrefItem
{
protected:
	QString m_name;
public:
	XrefHeader();
	XrefHeader(const QString& name, XrefItem::XrefType type, XrefHeader* parent, FunctionRef func);
	virtual ~XrefHeader() {}

	virtual QString name() const { return m_name; }
	XrefItem::XrefType type() const { return m_type; }

	virtual void appendChild(XrefItem* ref) = 0;
	virtual int row(const XrefItem* item) const = 0;
	virtual XrefItem* child(int i) const = 0;
	virtual int childCount() const = 0;
};


class XrefFunctionHeader : public XrefHeader
{
	std::deque<XrefItem*> m_refs;
public:
	XrefFunctionHeader();
	XrefFunctionHeader(FunctionRef func, XrefHeader* parent, XrefItem* child);
	XrefFunctionHeader(const XrefFunctionHeader& header);
	virtual int childCount() const override { return m_refs.size(); }
	virtual uint64_t addr() const { return m_func->GetStart(); }
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};


class XrefCodeReferences: public XrefHeader
{
	std::map<FunctionRef, XrefFunctionHeader*> m_refs;
	std::deque<XrefFunctionHeader*> m_refList;
public:
	XrefCodeReferences(XrefHeader* parent);
	virtual ~XrefCodeReferences();
	virtual int childCount() const override { return m_refs.size(); }
	virtual void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref) const;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};


class XrefDataReferences: public XrefHeader
{
	std::deque<XrefItem*> m_refs;
public:
	XrefDataReferences(XrefHeader* parent);
	virtual ~XrefDataReferences();
	virtual int childCount() const override { return m_refs.size(); };
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};


class XrefRoot: public XrefHeader
{
	std::map<int, XrefHeader*> m_refs;
public:
	XrefRoot();
	XrefRoot(XrefRoot&& root);
	~XrefRoot();
	virtual int childCount() const override { return m_refs.size(); }
	void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref);
	virtual int row(const XrefItem* item) const override;
	virtual XrefHeader* child(int i) const override;
};

class BINARYNINJAUIAPI CrossReferenceTreeModel : public QAbstractItemModel
{
	Q_OBJECT

	XrefRoot* m_rootItem;
	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<XrefItem> m_refs;

public:
	CrossReferenceTreeModel(QWidget* parent, BinaryViewRef data);
	virtual ~CrossReferenceTreeModel() {}

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override;
	QModelIndex nextValidIndex(const QModelIndex& current) const;
	QModelIndex prevValidIndex(const QModelIndex& current) const;
	bool selectRef(XrefItem* ref, QItemSelectionModel* selectionModel);
	XrefRoot* getRoot() { return m_rootItem; }
	bool setModelData(std::vector<XrefItem>& refs, QItemSelectionModel* selectionModel, bool& selectionUpdated);
	int leafCount() const;
};


class BINARYNINJAUIAPI CrossReferenceTableModel : public QAbstractTableModel
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	std::vector<XrefItem> m_refs;
public:
	enum ColumnHeaders
	{
		Direction = 0,
		Address = 1,
		Function = 2,
		Preview = 3
	};

	CrossReferenceTableModel(QWidget* parent, BinaryViewRef data);
	virtual ~CrossReferenceTableModel() {}

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override { (void)parent; return m_refs.size(); };
	virtual QModelIndex parent(const QModelIndex& i) const override { (void)i; return QModelIndex(); }
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override { (void) parent; return 4;};
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	virtual bool hasChildren(const QModelIndex&) const override { return false; }
	bool setModelData(std::vector<XrefItem>& refs, QItemSelectionModel* selectionModel, bool& selectionUpdated);
	const XrefItem& getRow(int idx);
};


class BINARYNINJAUIAPI CrossReferenceItemDelegate: public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;
	QImage m_xrefTo, m_xrefFrom;
	bool m_table;

public:
	CrossReferenceItemDelegate(QWidget* parent, bool table);

	void updateFonts();
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paintTreeRow(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	virtual void paintTableRow(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	virtual QImage DrawArrow(bool direction) const;
};


class BINARYNINJAUIAPI CrossReferenceFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

	bool m_showData = true;
	bool m_showCode = true;
	bool m_showIncoming = true;
	bool m_showOutgoing = true;
	bool m_table;

public:
	CrossReferenceFilterProxyModel(QObject* parent, bool table);
protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
	virtual bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
public Q_SLOTS:
	void directionChanged(int index);
	void typeChanged(int index);
};

class CrossReferenceWidget;
class BINARYNINJAUIAPI CrossReferenceContainer
{
protected:
	ViewFrame* m_view;
	CrossReferenceWidget* m_parent;
	BinaryViewRef m_data;
	UIActionHandler m_actionHandler;
public:
	CrossReferenceContainer(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceContainer() {}
	virtual QModelIndex translateIndex(const QModelIndex& idx) const = 0;
	virtual bool getReference(const QModelIndex& idx, FunctionRef& func, uint64_t& addr) const = 0;
	virtual QModelIndex nextIndex() = 0;
	virtual QModelIndex prevIndex() = 0;
	virtual QModelIndexList selectedRows() const = 0;
	virtual bool hasSelection() const = 0;
	virtual void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget) = 0;
	virtual void updateFonts() = 0;
	virtual int leafCount() const = 0;
	virtual int filteredCount() const = 0;
};


class BINARYNINJAUIAPI CrossReferenceTree: public QTreeView, public CrossReferenceContainer
{
	Q_OBJECT

	CrossReferenceTreeModel* m_tree;
	CrossReferenceFilterProxyModel* m_model;
	CrossReferenceItemDelegate* m_itemDelegate;

protected:
	void drawBranches(QPainter *painter, const QRect &rect, const QModelIndex &index) const override;
	virtual bool getReference(const QModelIndex& idx, FunctionRef& func, uint64_t& addr) const override;

public:
	CrossReferenceTree(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceTree();

	void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget) override;
	virtual QModelIndex nextIndex() override;
	virtual QModelIndex prevIndex() override;
	virtual bool hasSelection() const override { return selectionModel()->selectedRows().size() != 0; }
	virtual void mouseMoveEvent(QMouseEvent* e) override;
	virtual void mousePressEvent(QMouseEvent* e) override;
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual bool event(QEvent* event) override;
	virtual QModelIndexList selectedRows() const override { return selectionModel()->selectedRows(); }
	virtual QModelIndex translateIndex(const QModelIndex& idx) const override { return m_model->mapToSource(idx); }
	virtual void updateFonts() override;
	virtual int leafCount() const override;
	virtual int filteredCount() const override;
	void updateTextFilter(const QString& filterText);

Q_SIGNALS:
	void newSelection();
};


class BINARYNINJAUIAPI CrossReferenceTable: public QTableView, public CrossReferenceContainer
{
	Q_OBJECT

	CrossReferenceTableModel* m_table;
	CrossReferenceItemDelegate* m_itemDelegate;
	CrossReferenceFilterProxyModel* m_model;

	int m_charWidth = 0;
	int m_charHeight = 0;
	int m_maxWidthAddress = 0;
	int m_maxWidthFunction = 0;
	int m_maxWidthPreview = 0;
public:
	CrossReferenceTable(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceTable();

	void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget) override;
	virtual QModelIndex nextIndex() override;
	virtual QModelIndex prevIndex() override;
	virtual bool hasSelection() const override { return selectionModel()->selectedRows().size() != 0; }
	virtual QModelIndexList selectedRows() const override { return selectionModel()->selectedRows(); }
	virtual bool getReference(const QModelIndex& idx, FunctionRef& func, uint64_t& addr) const override;
	virtual void mouseMoveEvent(QMouseEvent* e) override;
	virtual void mousePressEvent(QMouseEvent* e) override;
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual bool event(QEvent* event) override;
	virtual QModelIndex translateIndex(const QModelIndex& idx) const override { return m_model->mapToSource(idx); }
	virtual void updateFonts() override;
	virtual int leafCount() const override;
	virtual int filteredCount() const override;
public Q_SLOTS:
	void updateTextFilter(const QString& filterText);
Q_SIGNALS:
	void newSelection();
};

class ExpandableGroup;
class BINARYNINJAUIAPI CrossReferenceWidget: public QWidget, public DockContextHandler
{
	Q_OBJECT
	Q_INTERFACES(DockContextHandler)

	ViewFrame* m_view;
	BinaryViewRef m_data;
	QAbstractItemView* m_object;
	QLabel* m_label;
	QCheckBox* m_pinRefs;
	QComboBox* m_direction, *m_type;
	CrossReferenceTable* m_table;
	CrossReferenceTree* m_tree;
	CrossReferenceContainer* m_container;
	bool m_useTableView;

	QTimer* m_hoverTimer;
	QPoint m_hoverPos;
	QStringList m_historyEntries;
	int m_historySize;
	QLineEdit* m_lineEdit;
	ExpandableGroup* m_group;

	uint64_t m_curRefTarget = 0;
	uint64_t m_curRefTargetEnd = 0;
	uint64_t m_newRefTarget = 0;
	uint64_t m_newRefTargetEnd = 0;
	bool m_navigating = false;
	bool m_navToNextOrPrevStarted = false;
	bool m_pinned;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void wheelEvent(QWheelEvent* e) override;

public:
	CrossReferenceWidget(ViewFrame* view, BinaryViewRef data, bool pinned);
	virtual void notifyFontChanged() override;
	virtual bool shouldBeVisible(ViewFrame* frame) override;

	virtual void setCurrentSelection(uint64_t begin, uint64_t end);
	virtual void setCurrentPinnedSelection(uint64_t begin, uint64_t end);
	void updatePinnedSelection();
	virtual void navigateToNext();
	virtual void navigateToPrev();
	virtual bool selectFirstRow();
	virtual bool hasSelection() const;
	virtual void goToReference(const QModelIndex& idx);

	virtual void restartHoverTimer(QMouseEvent* e);
	virtual void startHoverTimer(QMouseEvent* e);
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual bool keyPressHandler(QKeyEvent* e);
	void useTableView(bool tableView, bool init);
	bool tableView() const { return m_useTableView; }

private Q_SLOTS:
	void hoverTimerEvent();

public Q_SLOTS:
	void referenceActivated(const QModelIndex& idx);
	void pinnedStateChanged(bool state);
	void selectionChanged();
	void typeChanged(int change);
	void directionChanged(int change);
};


class BINARYNINJAUIAPI ExpandableGroup : public QWidget
{
	Q_OBJECT

private:
	QToolButton* m_button;
	QParallelAnimationGroup* m_animation;
	QScrollArea* m_content;
	int m_duration = 100;

public Q_SLOTS:
	void toggle(bool collapsed);

public:
	explicit ExpandableGroup(const QString& title = "", QWidget* parent = nullptr);
	void setContentLayout(QLayout* contentLayout);
	void setTitle(const QString& title) { m_button->setText(title); }
};