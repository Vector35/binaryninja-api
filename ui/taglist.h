#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QDialog>
#include "binaryninjaapi.h"
#include "sidebar.h"
#include "viewframe.h"
#include "filter.h"
#include "tagtypelist.h"

/*!

	\defgroup taglist TagList
 	\ingroup uiapi
*/

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagListModel : public QAbstractItemModel
{
	Q_OBJECT

  protected:
	QWidget* m_owner;
	BinaryViewRef m_data;
	std::map<TagTypeRef, size_t> m_typeIndexes;
	std::vector<std::pair<TagTypeRef, std::vector<BinaryNinja::TagReference>>> m_refs;
	std::map<int, QSize> m_sectionSizeHints;
	DisassemblySettingsRef m_settings;

  private:
	void AddDisassemblyTokens(QList<QVariant>& line, std::vector<BinaryNinja::InstructionTextToken> tokens) const;

	void TrimLeadingWhitespace(QList<QVariant>& line) const;

	QVariant GetIconColumn(const BinaryNinja::TagReference& ref) const;
	QVariant GetLocationColumn(const BinaryNinja::TagReference& ref) const;
	QVariant GetDataColumn(const BinaryNinja::TagReference& ref) const;
	QVariant GetPreviewColumn(const BinaryNinja::TagReference& ref) const;

	QVariant GetIconColumn(const TagTypeRef& ref) const;
	QVariant GetLocationColumn(const TagTypeRef& ref) const;
	QVariant GetDataColumn(const TagTypeRef& ref) const;
	QVariant GetPreviewColumn(const TagTypeRef& ref) const;

  public:
	TagListModel(QWidget* parent, BinaryViewRef data);

	BinaryNinja::TagReference& GetRef(const QModelIndex& index);
	const BinaryNinja::TagReference& GetRef(const QModelIndex& index) const;

	void SetSectionSizeHints(const std::map<int, QSize>& sizes) { m_sectionSizeHints = sizes; }

	TagTypeRef GetTypeRef(const QModelIndex& index);
	const TagTypeRef GetTypeRef(const QModelIndex& index) const;

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual bool setData(const QModelIndex& i, const QVariant& value, int role = Qt::EditRole) override;
	virtual Qt::ItemFlags flags(const QModelIndex& i) const override;
	virtual void sort(int column, Qt::SortOrder order) override;

	bool setModelData(const std::vector<std::pair<TagTypeRef, std::vector<BinaryNinja::TagReference>>>& refs,
	    QItemSelectionModel* selectionModel, int sortColumn, Qt::SortOrder sortOrder, bool& selectionUpdated);
};

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

  protected:
	QFont m_font, m_monospaceFont, m_emojiFont;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	void initFont();

  public:
	TagItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void setEditorData(QWidget* editor, const QModelIndex& index) const override;
};

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagList : public QTreeView, public BinaryNinja::BinaryDataNotification, public FilterTarget
{
	Q_OBJECT

	ViewFrame* m_view;
	class TagListWidget* m_listWidget;
	TagListModel* m_list;
	TagItemDelegate* m_itemDelegate;
	BinaryViewRef m_data;
	UIActionHandler* m_handler;
	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager;
	FilteredView* m_filterView;
	Menu* m_menu;
	std::unordered_map<std::string, bool> m_expandedItems;

  public:
	typedef std::function<bool(const BinaryNinja::TagReference&)> FilterFn;

  private:
	bool m_hasFilter;
	FilterFn m_filter;
	std::string m_searchFilter;

	QTimer* m_hoverTimer;
	QTimer* m_updateTimer;
	QPoint m_hoverPos;

	uint64_t m_curRefTarget = 0;
	bool m_needsUpdate;
	bool m_navToNextOrPrevStarted = false;

  protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* e) override;
	virtual void mouseMoveEvent(QMouseEvent* e) override;
	virtual void mousePressEvent(QMouseEvent* e) override;
	virtual void wheelEvent(QWheelEvent* e) override;
	virtual void resizeEvent(QResizeEvent* event) override;
	void goToReference(const QModelIndex& idx);

	void setFilter(const std::string& filter) override;

	virtual void OnAnalysisFunctionUpdated(BinaryNinja::BinaryView* view, BinaryNinja::Function* func) override;
	virtual void OnTagAdded(BinaryNinja::BinaryView*, const BinaryNinja::TagReference&) override;
	virtual void OnTagUpdated(BinaryNinja::BinaryView*, const BinaryNinja::TagReference&) override;
	virtual void OnTagRemoved(BinaryNinja::BinaryView*, const BinaryNinja::TagReference&) override;
	virtual void OnTagTypeUpdated(BinaryNinja::BinaryView*, TagTypeRef) override;

	virtual void showEvent(QShowEvent* event) override;
	virtual void hideEvent(QHideEvent* event) override;

  private Q_SLOTS:
	void hoverTimerEvent();
	void updateTimerEvent();
	void referenceActivated(const QModelIndex& idx);

	void saveExpanded();
	void restoreExpanded();

  public Q_SLOTS:
	void showContextMenu();

  public:
	TagList(QWidget* parent, ViewFrame* view, BinaryViewRef data, TagListModel* model = nullptr, Menu* menu = nullptr);
	virtual ~TagList();

	static void registerActions();
	virtual void setModel(QAbstractItemModel* model) override;

	void notifyFontChanged();
	void removeSelection();

	void clearFilter();
	void setFilter(FilterFn filter);
	void setFilterView(FilteredView* filterView) { m_filterView = filterView; }

	void updateTags();

	bool hasSelection();
	void navigateToNext();
	void navigateToPrev();

	void scrollToFirstItem() override;
	void scrollToCurrentItem() override;
	void selectFirstItem() override;
	void activateFirstItem() override;
};

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagListWidget : public SidebarWidget
{
	Q_OBJECT

	ViewFrame* m_view;
	QTabWidget* m_tabs;

	TagList* m_notificationList;
	FilteredView* m_notificationFilter;
	QWidget* m_header;

	FilterEdit* m_filterEdit;

	TagTypeList* m_typeList;

	BinaryViewRef m_data;
	UIActionHandler* m_handler;

  protected:
	virtual void notifyFontChanged() override;

  private Q_SLOTS:
	void showContextMenu();
	void onTabChanged(int which);

  public:
	TagList* GetList();
	void editTag(TagRef tag);
	TagList* getNotificationList() { return m_notificationList; }
	FilteredView* getNotificationFilter() { return m_notificationFilter; }

	TagListWidget(ViewFrame* view, BinaryViewRef data);
	virtual ~TagListWidget();

	virtual void focus() override;
	virtual QWidget* headerWidget() override { return m_header; }
};

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagListDialog : public QDialog
{
	Q_OBJECT

  public:
	typedef std::function<void(const TagRef&)> AddFn;

  private:
	BinaryViewRef m_data;
	TagList* m_list;
	FilteredView* m_filter;

	AddFn m_addFn;

	QPushButton* m_removeButton;

  public:
	TagListDialog(QWidget* parent, ViewFrame* frame, BinaryViewRef data, AddFn addFn);
	void setFilter(TagList::FilterFn filter);

  private Q_SLOTS:
	void updateActive(const QItemSelection&, const QItemSelection&);
	void createTag();
	void createTagAccept(TagTypeRef tt);
	void removeTag();
};

/*!

    \ingroup taglist
*/
class BINARYNINJAUIAPI TagListSidebarWidgetType : public SidebarWidgetType
{
  public:
	TagListSidebarWidgetType();
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
};
