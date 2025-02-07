#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QModelIndex>
#include <QtGui/QImage>
#include <QtCore/QTimer>
#include <QtWidgets/QListView>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QTableView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>

#include <vector>
#include <deque>
#include <memory>

#include "binaryninjaapi.h"
#include "sidebar.h"
#include "viewframe.h"
#include "fontsettings.h"
#include "expandablegroup.h"

class XrefHeader;

/*!

	\defgroup xreflist XrefList
 	\ingroup uiapi
*/

/*!

	\ingroup xreflist
*/
class XrefItem
{
  public:
	enum XrefDirection
	{
		Forward,  // current address is addressing another address
		Backward  // current address is being referenced by another address
	};

	enum XrefType
	{
		DataXrefType,
		CodeXrefType,
		VariableXrefType,
		TypeXrefType
	};

	enum XrefQueryKind
	{
		AddressXrefQuery,
		TypeXrefQuery,
		TypeFieldXrefQuery,
		LocalVarXrefQuery
	};

  protected:
	FunctionRef m_func;
	ArchitectureRef m_arch;
	uint64_t m_addr;
	BinaryNinja::QualifiedName m_typeName;
	uint64_t m_offset;
	BinaryNinja::Variable m_var;
	BNFunctionGraphType m_ilType;
	size_t m_instrId;
	XrefType m_type;
	XrefQueryKind m_queryKind;
	XrefDirection m_direction;
	mutable std::vector<BinaryNinja::InstructionTextToken> m_cachedTokens;
	mutable XrefHeader* m_parentItem;
	mutable int m_size;

  public:
	explicit XrefItem();
	explicit XrefItem(XrefHeader* parent, XrefType type, FunctionRef func);
	// The four constructors are used for code/data/type/variable references, respectively
	explicit XrefItem(BinaryNinja::ReferenceSource ref, XrefType type, XrefDirection direction,
			XrefQueryKind kind);
	explicit XrefItem(uint64_t addr, XrefType type, XrefDirection direction, XrefQueryKind kind);
	explicit XrefItem(BinaryNinja::TypeReferenceSource ref, XrefType type, XrefDirection direction,
			XrefQueryKind kind);
	explicit XrefItem(BinaryNinja::Variable var, BinaryNinja::ILReferenceSource ref, XrefType type,
			XrefDirection direction, XrefQueryKind kind);
	XrefItem(const XrefItem& ref);
	virtual ~XrefItem();

	XrefDirection direction() const { return m_direction; }
	const FunctionRef& func() const { return m_func; }
	const ArchitectureRef& arch() const { return m_arch; }
	uint64_t addr() const { return m_addr; }
	BinaryNinja::QualifiedName typeName() const { return m_typeName; }
	uint64_t offset() const { return m_offset; }
	BinaryNinja::Variable variable() const { return m_var; }
	BNFunctionGraphType ilType() const { return m_ilType; }
	size_t instrId() const { return m_instrId; }
	XrefType type() const { return m_type; }
	XrefQueryKind kind() const { return m_queryKind; }
	int size() const { return m_size; }
	void setSize(int size) const { m_size = size; }
	void setParent(XrefHeader* parent) const;
	void setCachedTokens(const std::vector<BinaryNinja::InstructionTextToken>& cachedTokens) const { m_cachedTokens = cachedTokens; }
	std::vector<BinaryNinja::InstructionTextToken> cachedTokens() const { return m_cachedTokens; }
	bool hasCachedTokens() const { return m_cachedTokens.size() > 0; }
	virtual XrefItem* parent() const { return (XrefItem*)m_parentItem; }
	virtual XrefItem* child(int) const { return nullptr; }
	virtual int childCount() const { return 0; }

	int row() const;
	bool operator==(const XrefItem& other) const;
	bool operator!=(const XrefItem& other) const;
	size_t operator()(const XrefItem& item) const
	{
		size_t hash = std::hash<uint64_t>()(item.addr());
		hash ^= std::hash<int>()(item.type()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		hash ^= std::hash<int>()(item.direction()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		hash ^= std::hash<int>()(item.kind()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		hash ^= std::hash<size_t>()(item.instrId()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		hash ^= std::hash<uint64_t>()(item.func() ? item.func()->GetStart() : 0) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		hash ^= std::hash<int>()(item.ilType()) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
		return hash;
	}
};

/*!

	\ingroup xreflist
*/
class XrefHeader : public XrefItem
{
  protected:
	QString m_name;

  public:
	XrefHeader();
	XrefHeader(const QString& name, XrefItem::XrefType type, XrefHeader* parent, FunctionRef func);
	virtual ~XrefHeader();

	virtual QString name() const { return m_name; }
	XrefItem::XrefType type() const { return m_type; }

	virtual void appendChild(XrefItem* ref) = 0;
	virtual int row(const XrefItem* item) const = 0;
	virtual XrefItem* child(int i) const = 0;
	virtual int childCount() const = 0;
};

/*!

	\ingroup xreflist
*/
class XrefFunctionHeader : public XrefHeader
{
	std::deque<XrefItem*> m_refs;

  public:
	XrefFunctionHeader();
	XrefFunctionHeader(FunctionRef func, XrefHeader* parent, XrefItem* child);
	XrefFunctionHeader(const XrefFunctionHeader& header);
	virtual int childCount() const override { return (int)m_refs.size(); }
	virtual uint64_t addr() const { return m_func->GetStart(); }
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefTypeHeader : public XrefHeader
{
	std::deque<XrefItem*> m_refs;

  public:
	XrefTypeHeader();
	XrefTypeHeader(BinaryNinja::QualifiedName name, XrefHeader* parent, XrefItem* child);
	XrefTypeHeader(const XrefTypeHeader& header);
	virtual int childCount() const override { return (int)m_refs.size(); }
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefVariableHeader : public XrefHeader
{
	std::deque<XrefItem*> m_refs;

  public:
	XrefVariableHeader();
	XrefVariableHeader(XrefHeader* parent, XrefItem* child);
	XrefVariableHeader(const XrefVariableHeader& header);
	virtual int childCount() const override { return (int)m_refs.size(); }
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefCodeReferences : public XrefHeader
{
	std::map<FunctionRef, XrefFunctionHeader*> m_refs;
	std::deque<XrefFunctionHeader*> m_refList;

  public:
	XrefCodeReferences(XrefHeader* parent);
	virtual ~XrefCodeReferences();
	virtual int childCount() const override { return (int)m_refs.size(); }
	virtual void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref) const;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefDataReferences : public XrefHeader
{
	std::deque<XrefItem*> m_refs;

  public:
	XrefDataReferences(XrefHeader* parent);
	virtual ~XrefDataReferences();
	virtual int childCount() const override { return (int)m_refs.size(); };
	virtual void appendChild(XrefItem* ref) override;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefTypeReferences : public XrefHeader
{
	std::map<BinaryNinja::QualifiedName, XrefTypeHeader*> m_refs;
	std::deque<XrefTypeHeader*> m_refList;

  public:
	XrefTypeReferences(XrefHeader* parent);
	virtual ~XrefTypeReferences();
	virtual int childCount() const override { return (int)m_refs.size(); };
	virtual void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref) const;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefVariableReferences : public XrefHeader
{
	std::map<BinaryNinja::Variable, XrefVariableHeader*> m_refs;
	std::deque<XrefVariableHeader*> m_refList;

  public:
	XrefVariableReferences(XrefHeader* parent);
	virtual ~XrefVariableReferences();
	virtual int childCount() const override { return (int)m_refs.size(); };
	virtual void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref) const;
	virtual int row(const XrefItem* item) const override;
	virtual XrefItem* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class XrefRoot : public XrefHeader
{
	std::map<XrefItem::XrefType, XrefHeader*> m_refs;

  public:
	XrefRoot();
	XrefRoot(XrefRoot&& root);
	~XrefRoot();
	virtual int childCount() const override { return (int)m_refs.size(); }
	void appendChild(XrefItem* ref) override;
	XrefHeader* parentOf(XrefItem* ref);
	virtual int row(const XrefItem* item) const override;
	virtual XrefHeader* child(int i) const override;
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceTreeModel : public QAbstractItemModel
{
	Q_OBJECT

	XrefRoot* m_rootItem;
	QWidget* m_owner;
	BinaryViewRef m_data;
	ViewFrame* m_view;
	std::vector<XrefItem> m_refs;
	size_t m_maxUIItems;
	std::optional<BinaryNinja::FunctionViewType> m_graphType;
	SelectionInfoForXref m_curRef;
	QTimer* m_updateTimer;

  public:
	CrossReferenceTreeModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
	virtual ~CrossReferenceTreeModel();

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
	bool setModelData(std::vector<XrefItem>& refs, QItemSelectionModel* selectionModel, bool& selectionUpdated, const SelectionInfoForXref& ref);
	int leafCount() const;
	ViewFrame* getView() const { return m_view; }
	virtual void updateMaxUIItems(size_t value) { m_maxUIItems = value; }
	size_t getMaxUIItems() const { return m_maxUIItems; }
	void setGraphType(const BinaryNinja::FunctionViewType& type);
	void requestAdvancedAnalysis();

 Q_SIGNALS:
	void needRepaint();

 public Q_SLOTS:
	void startUpdateTimer(FunctionRef func);

};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceTableModel : public QAbstractTableModel
{
	Q_OBJECT

	QWidget* m_owner;
	BinaryViewRef m_data;
	ViewFrame* m_view;
	std::vector<XrefItem> m_refs;
	size_t m_maxUIItems;
	std::optional<BinaryNinja::FunctionViewType> m_graphType;
	SelectionInfoForXref m_curRef;
	QTimer* m_updateTimer;

  public:
	enum ColumnHeaders
	{
		Direction = 0,
		Address = 1,
		Function = 2,
		Preview = 3
	};

	CrossReferenceTableModel(QWidget* parent, BinaryViewRef data, ViewFrame* view);
	virtual ~CrossReferenceTableModel() {}

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	Qt::ItemFlags flags(const QModelIndex& index) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_refs.size();
	};
	virtual QModelIndex parent(const QModelIndex& i) const override
	{
		(void)i;
		return QModelIndex();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 4;
	};
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	virtual bool hasChildren(const QModelIndex&) const override { return false; }
	bool setModelData(std::vector<XrefItem>& refs, QItemSelectionModel* selectionModel, bool& selectionUpdated, const SelectionInfoForXref& ref);
	const XrefItem& getRow(int idx);
	ViewFrame* getView() const { return m_view; }
	virtual void updateMaxUIItems(size_t value) { m_maxUIItems = value; }
	size_t getMaxUIItems() const { return m_maxUIItems; }
	void setGraphType(const BinaryNinja::FunctionViewType& type);
	void requestAdvancedAnalysis();
 Q_SIGNALS:
	void needRepaint();

 public Q_SLOTS:
	void startUpdateTimer(FunctionRef func);
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;
	QImage m_xrefTo, m_xrefFrom;
	bool m_table;
	size_t m_maxUIItems;

  public:
	CrossReferenceItemDelegate(QWidget* parent, bool table);

	void updateFonts();
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paintTreeRow(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	virtual void paintTableRow(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
	virtual QImage DrawArrow(bool direction) const;
	void updateMaxUIItems(size_t count);
	size_t getMaxUIItems() const { return m_maxUIItems; }
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

	bool m_showData = true;
	bool m_showCode = true;
	bool m_showType = true;
	bool m_showVariable = true;
	bool m_showIncoming = true;
	bool m_showOutgoing = true;
	bool m_table;

  public:
	CrossReferenceFilterProxyModel(QObject* parent, bool table);
	QModelIndex nextValidIndex(const QModelIndex& current) const;
	QModelIndex getFirstLeaf(const QModelIndex& index) const;
	QModelIndex prevValidIndex(const QModelIndex& current) const;
	QModelIndex getLastLeaf(const QModelIndex& index) const;

  protected:
	virtual bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;
	virtual bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;
	virtual QVariant data(const QModelIndex& index, int role) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;

  public Q_SLOTS:
	void directionChanged(int index, bool checked);
	void typeChanged(int index, bool checked);
};

class CrossReferenceWidget;

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceContainer
{
  protected:
	ViewFrame* m_view;
	CrossReferenceWidget* m_parent;
	BinaryViewRef m_data;
	UIActionHandler m_actionHandler;
	SelectionInfoForXref m_curRef;

  public:
	CrossReferenceContainer(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceContainer();
	virtual QModelIndex translateIndex(const QModelIndex& idx) const = 0;
	virtual bool getReference(const QModelIndex& idx, XrefItem** refPtr) const = 0;
	virtual QModelIndex nextIndex() = 0;
	virtual QModelIndex prevIndex() = 0;
	virtual QModelIndexList selectedRows() const = 0;
	virtual bool hasSelection() const = 0;
	virtual void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget, const SelectionInfoForXref& ref) = 0;
	virtual void updateFonts() = 0;
	virtual int leafCount() const = 0;
	virtual int filteredCount() const = 0;
	virtual void updateMaxUIItems(size_t value) = 0;
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceTree : public QTreeView, public CrossReferenceContainer, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	CrossReferenceTreeModel* m_tree;
	CrossReferenceFilterProxyModel* m_model;
	CrossReferenceItemDelegate* m_itemDelegate;

  protected:
	void drawBranches(QPainter* painter, const QRect& rect, const QModelIndex& index) const override;
	virtual bool getReference(const QModelIndex& idx, XrefItem** refPtr) const override;
	virtual void scrollContentsBy(int dx, int dy) override;

public:
	CrossReferenceTree(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceTree();

	void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget, const SelectionInfoForXref& ref) override;
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
	virtual void updateMaxUIItems(size_t count) override;
	void setGraphType(const BinaryNinja::FunctionViewType& type) { m_tree->setGraphType(type); }
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;

  Q_SIGNALS:
	void newSelection();
	void modelUpdated();
	void functionUpdated(FunctionRef func);

  public Q_SLOTS:
	void doRepaint();
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceTable : public QTableView, public CrossReferenceContainer, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	CrossReferenceTableModel* m_table;
	CrossReferenceItemDelegate* m_itemDelegate;
	CrossReferenceFilterProxyModel* m_model;

  public:
	CrossReferenceTable(CrossReferenceWidget* parent, ViewFrame* view, BinaryViewRef data);
	virtual ~CrossReferenceTable();

	void updateFontAndHeaderSize();
	void setNewSelection(std::vector<XrefItem>& refs, bool newRefTarget, const SelectionInfoForXref& ref) override;
	virtual QModelIndex nextIndex() override;
	virtual QModelIndex prevIndex() override;
	virtual bool hasSelection() const override { return selectionModel()->selectedRows().size() != 0; }
	virtual QModelIndexList selectedRows() const override { return selectionModel()->selectedRows(); }
	virtual bool getReference(const QModelIndex& idx, XrefItem** refPtr) const override;
	virtual void mouseMoveEvent(QMouseEvent* e) override;
	virtual void mousePressEvent(QMouseEvent* e) override;
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual bool event(QEvent* event) override;
	virtual QModelIndex translateIndex(const QModelIndex& idx) const override { return m_model->mapToSource(idx); }
	virtual void updateFonts() override;
	virtual int leafCount() const override;
	virtual int filteredCount() const override;
	virtual void updateMaxUIItems(size_t count) override;
	void setGraphType(const BinaryNinja::FunctionViewType& type) { m_table->setGraphType(type); }
	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;

  public Q_SLOTS:
	void doRepaint();
	void updateTextFilter(const QString& filterText);

  Q_SIGNALS:
	void newSelection();
	void modelUpdated();
	void functionUpdated(FunctionRef func);
};

class ExpandableGroup;
class QCheckboxCombo;

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceWidget : public SidebarWidget, public UIContextNotification
{
	Q_OBJECT

	ViewFrame* m_view;
	BinaryViewRef m_data;
	QAbstractItemView* m_object;
	QLabel* m_label;
	QCheckBox* m_pinRefs;
	QCheckboxCombo *m_direction, *m_type;
	CrossReferenceTable* m_table;
	CrossReferenceTree* m_tree;
	CrossReferenceContainer* m_container;
	bool m_useTableView;
	Qt::Orientation m_primaryOrientation;
	std::optional<BinaryNinja::FunctionViewType> m_graphType;

	QTimer* m_hoverTimer;
	QPoint m_hoverPos;
	QStringList m_historyEntries;
	int m_historySize;
	QLineEdit* m_lineEdit;
	ExpandableGroup* m_group;

	bool m_curRefTargetValid = false;
	SelectionInfoForXref m_curRef;
	SelectionInfoForXref m_newRef;
	bool m_navigating = false;
	bool m_navToNextOrPrevStarted = false;
	bool m_pinned;
	bool m_uiMaxItemsExceeded = false;

	QWidget* m_header = nullptr;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void wheelEvent(QWheelEvent* e) override;

  public:
	CrossReferenceWidget(ViewFrame* view, BinaryViewRef data, bool pinned);
	virtual ~CrossReferenceWidget();
	virtual void notifyFontChanged() override;

	virtual QString getHeaderText(SelectionInfoForXref selectionInfo);
	virtual void setCurrentSelection(SelectionInfoForXref selectionInfo);
	virtual void updateCrossReferences();
	virtual void setCurrentPinnedSelection(SelectionInfoForXref selectionInfo);
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
	void showEvent(QShowEvent* event) override;
	void useTableView(bool tableView, bool init, bool updateSetting);
	bool tableView() const { return m_useTableView; }
	bool uiMaxItemsExceeded() const { return m_uiMaxItemsExceeded; }
	void setUIMaxItemsExceeded(bool value) { m_uiMaxItemsExceeded = value; }
	void setGraphType(const BinaryNinja::FunctionViewType& type);

	virtual void focus() override;

	virtual void OnNewSelectionForXref(
	    UIContext* context, ViewFrame* frame, View* view, const SelectionInfoForXref& selection) override;

	virtual QWidget* headerWidget() override { return m_header; }
	virtual void setPrimaryOrientation(Qt::Orientation orientation) override;

private Q_SLOTS:
	void hoverTimerEvent();
	void newPinnedPane();

  public Q_SLOTS:
	void referenceActivated(const QModelIndex& idx);
	void pinnedStateChanged(bool state);
	void selectionChanged();
	void typeChanged(int index, bool checked);
	void directionChanged(int change, bool checked);
};

/*!

	\ingroup xreflist
*/
class BINARYNINJAUIAPI CrossReferenceSidebarWidgetType : public SidebarWidgetType
{
  public:
	CrossReferenceSidebarWidgetType();
	virtual bool isInReferenceArea() const override { return true; }
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
};


// https://github.com/CuriousCrow/QCheckboxCombo
/*! QCheckboxCombo is a combobox widget that contains items with checkboxes.

	User can select proper items by checking corresponding checkboxes.
	Resulting text will contain list of selected items separated by delimiter (", " by default)

 	\ingroup xreflists
*/
class BINARYNINJAUIAPI QCheckboxCombo : public QComboBox
{
	Q_OBJECT

  public:
	explicit QCheckboxCombo(QWidget* parent = nullptr);
	bool eventFilter(QObject* watched, QEvent* event);
	void hidePopup();
	void showPopup();
	void addItem(const QString& text, bool checked = true);

  Q_SIGNALS:
	void selectionChanged(const QString& text);
	void itemToggled(int index, bool checked);

  private:
	bool m_popupVisible = false;
	bool m_editable = false;
	QString m_selectionString;
	const QString m_delimiter = ", ";
};
