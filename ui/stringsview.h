#pragma once

#include <QtCore/QSettings>
#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QAbstractScrollArea>
#include <mutex>
#include "viewframe.h"
#include "render.h"
#include "filter.h"
#include "uicontext.h"

#define STRINGS_LIST_UPDATE_INTERVAL 250

/*!

	\defgroup stringsview StringsView
 	\ingroup uiapi
*/

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringsListModel : public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	struct StringUpdateEvent
	{
		BNStringReference ref;
		bool added;
	};

	QWidget* m_stringsList;
	BinaryViewRef m_data;
	std::vector<BNStringReference> m_allStrings;
	std::vector<BNStringReference> m_strings;
	std::string m_filter;

	size_t m_filteredByOptions;

	std::mutex m_updateMutex;
	std::vector<StringUpdateEvent> m_updates;

	bool m_includeStringsOverlappingCode;
	bool m_includeOnlyReferenced;
	bool m_includeOnlyFromCurrentFunction;

	static bool stringComparison(const BNStringReference& a, const BNStringReference& b);
	bool matchString(const BNStringReference& stringRef);

	std::vector<StringUpdateEvent> getQueuedStringUpdates();

  public:
	enum {
		COL_ADDRESS = 0,
		COL_TYPE,
		COL_VALUE,
		COLUMN_COUNT,
	};

	StringsListModel(QWidget* parent, BinaryViewRef data);
	virtual ~StringsListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

	BNStringReference getStringAt(const QModelIndex& i);
	QModelIndex findString(const BNStringReference& ref);

	virtual void OnStringFound(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;
	virtual void OnStringRemoved(BinaryNinja::BinaryView* data, BNStringType type, uint64_t offset, size_t len) override;
	void updateStrings();

	virtual void sort(int col, Qt::SortOrder order) override;

	void setFilter(const std::string& filter);

	void updateFilter() { setFilter(m_filter); };

	size_t getFilteredStringCount() const { return m_filteredByOptions; }
	size_t getStringCount() const { return m_strings.size(); }

	void toggleIncludeStringsOverlappingCode() { m_includeStringsOverlappingCode = !m_includeStringsOverlappingCode; };
	void toggleIncludeOnlyReferenced() { m_includeOnlyReferenced = !m_includeOnlyReferenced; };
	void toggleIncludeOnlyFromCurrentFunction() { m_includeOnlyFromCurrentFunction = !m_includeOnlyFromCurrentFunction; };

	void includeStringsOverlappingCode(bool exclude) { m_includeStringsOverlappingCode = exclude; };
	void includeOnlyReferenced(bool exclude) { m_includeOnlyReferenced = exclude; };
	void includeOnlyFromCurrentFunction(bool exclude) { m_includeOnlyFromCurrentFunction = exclude; };

	bool getIncludeStringsOverlappingCode() const { return m_includeStringsOverlappingCode; };
	bool getIncludeOnlyReferenced() const { return m_includeOnlyReferenced; };
	bool getIncludeOnlyFromCurrentFunction() const { return m_includeOnlyFromCurrentFunction; };
};

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QWidget* m_owner;
	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	void initFont();

  public:
	StringItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	QFont getFont() const { return m_font; }
};

class StringsContainer;
class StringsViewSidebarWidget;

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringsView : public QTableView, public View, public FilterTarget
{
	Q_OBJECT

	BinaryViewRef m_data;
	StringsContainer* m_container;

	RenderContext m_render;
	QSettings m_settings;
	StringsListModel* m_list;
	StringItemDelegate* m_itemDelegate;
	QTimer* m_updateTimer;

	uint64_t m_selectionBegin, m_selectionEnd;
	uint64_t m_currentlySelectedDataAddress;

  public:
	StringsView(BinaryViewRef data, StringsContainer* container);

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual BNAddressRange getSelectionOffsets() override;
	virtual void setSelectionOffsets(BNAddressRange range) override;
	virtual bool navigate(uint64_t offset) override;

	virtual void updateFonts() override;

	virtual StatusBarWidget* getStatusBarWidget() override;

	virtual void selectionChanged(const QItemSelection& selected, const QItemSelection& deselected) override;

	virtual void setFilter(const std::string& filter) override;
	virtual void scrollToFirstItem() override;
	virtual void scrollToCurrentItem() override;
	virtual void selectFirstItem() override;
	virtual void activateFirstItem() override;
	virtual QFont getFont() override { return m_itemDelegate->getFont(); }

	bool getIncludeStringsOverlappingCode() const { return m_list->getIncludeStringsOverlappingCode(); };
	bool getIncludeOnlyReferenced() const { return m_list->getIncludeOnlyReferenced(); };
	bool getIncludeOnlyFromCurrentFunction() const { return m_list->getIncludeOnlyFromCurrentFunction(); };

	void toggleIncludeStringsOverlappingCode() const { m_list->toggleIncludeStringsOverlappingCode(); };
	void toggleIncludeOnlyReferenced() const { m_list->toggleIncludeOnlyReferenced(); };
	void toggleIncludeOnlyFromCurrentFunction() const { m_list->toggleIncludeOnlyFromCurrentFunction(); };

	void resetFilterOptions();

	void copyText();
	virtual bool canCopy() override;

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void mouseMoveEvent(QMouseEvent* event) override;
	virtual void mousePressEvent(QMouseEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
	virtual bool event(QEvent* event) override;

  private Q_SLOTS:
	void goToString(const QModelIndex& idx);
	void updateTimerEvent();
};

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringsContainer : public QWidget, public ViewContainer
{
	Q_OBJECT

	friend class StringsView;

	StringsView* m_strings;
	FilteredView* m_filter;
	FilterEdit* m_separateEdit = nullptr;
	StringsViewSidebarWidget* m_widget;

  public:
	StringsContainer(BinaryViewRef data, StringsViewSidebarWidget* parent, bool separateEdit = false);
	virtual View* getView() override { return m_strings; }

	StringsView* getStringsView() { return m_strings; }
	FilteredView* getFilter() { return m_filter; }
	FilterEdit* getSeparateFilterEdit() { return m_separateEdit; }

  protected:
	virtual void focusInEvent(QFocusEvent* event) override;
};

/*!

    \ingroup stringsview
*/
class StringsViewType : public ViewType
{
	static StringsViewType* m_instance;

  public:
	StringsViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringsViewSidebarWidget : public SidebarWidget
{
	Q_OBJECT

	friend class StringsView;

	QWidget* m_header;
	StringsContainer* m_container;

  public:
	StringsViewSidebarWidget(BinaryViewRef data);
	virtual QWidget* headerWidget() override { return m_header; }
	virtual void focus() override;

  protected:
	virtual void contextMenuEvent(QContextMenuEvent* event) override;

  private Q_SLOTS:
	void showContextMenu();
};

/*!

    \ingroup stringsview
*/
class BINARYNINJAUIAPI StringsViewSidebarWidgetType : public SidebarWidgetType
{
public:
	StringsViewSidebarWidgetType();
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return PerViewTypeSidebarContext; }
	virtual SidebarWidget* createWidget(ViewFrame* frame, BinaryViewRef data) override;
	virtual bool canUseAsPane(SplitPaneWidget*, BinaryViewRef) const override { return true; }
	virtual Pane* createPane(SplitPaneWidget* panes, BinaryViewRef data) override;
};
