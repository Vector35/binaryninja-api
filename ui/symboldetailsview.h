#pragma once

#include <QtWidgets/QTableView>
#include <QtWidgets/QStyledItemDelegate>
#include <mutex>
#include "viewframe.h"
#include "filter.h"
#include "uicontext.h"

#define SYMBOLS_LIST_UPDATE_INTERVAL 250

class BINARYNINJAUIAPI SymbolDetailsListModel: public QAbstractItemModel, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	struct SymbolUpdateEvent
	{
		SymbolRef ref;
		bool added;
	};

	QWidget* m_symbolsList;
	BinaryViewRef m_data;
	std::vector<SymbolRef> m_allSymbols;
	std::vector<SymbolRef> m_symbols;
	std::string m_filter;

	std::mutex m_updateMutex;
	std::vector<SymbolUpdateEvent> m_updates;

	static bool symbolComparison(const SymbolRef& a, const SymbolRef& b);
	bool matchSymbol(const SymbolRef& symbol);

	std::vector<SymbolUpdateEvent> getQueuedSymbolUpdates();

public:
	SymbolDetailsListModel(QWidget* parent, BinaryViewRef data);
	virtual ~SymbolDetailsListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;

	SymbolRef getSymbolAt(const QModelIndex& i);
	QModelIndex findSymbol(const SymbolRef& ref);

	void updateSymbols();

	void setFilter(const std::string& filter);
};

class BINARYNINJAUIAPI SymbolItemDelegate: public QStyledItemDelegate
{
	Q_OBJECT

	QWidget* m_owner;
	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

	void initFont();

public:
	SymbolItemDelegate(QWidget* parent);

	void updateFonts();

	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	QFont getFont() const { return m_font; }
};

class SymbolDetailsContainer;

class BINARYNINJAUIAPI SymbolDetailsView: public QTableView, public View, public FilterTarget
{
	Q_OBJECT

	BinaryViewRef m_data;
	ViewFrame* m_view;
	SymbolDetailsContainer* m_container;

	SymbolDetailsListModel* m_list;
	SymbolItemDelegate* m_itemDelegate;
	QTimer* m_updateTimer;

	uint64_t m_selectionBegin;

public:
	SymbolDetailsView(BinaryViewRef data, ViewFrame* view, SymbolDetailsContainer* container);

	virtual BinaryViewRef getData() override { return m_data; }
	virtual uint64_t getCurrentOffset() override;
	virtual void getSelectionOffsets(uint64_t& begin, uint64_t& end) override;
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
protected:
	virtual void keyPressEvent(QKeyEvent* event) override;

private Q_SLOTS:
	void goToSymbol(const QModelIndex& idx);
	void updateTimerEvent();
};

class BINARYNINJAUIAPI SymbolDetailsContainer: public QWidget, public ViewContainer
{
	Q_OBJECT

	ViewFrame* m_view;
	SymbolDetailsView* m_symbols;
	FilteredView* m_filter;

public:
	SymbolDetailsContainer(BinaryViewRef data, ViewFrame* view);
	virtual View* getView() override { return m_symbols; }

	SymbolDetailsView* getSymbolDetailsView() { return m_symbols; }
	FilteredView* getFilter() { return m_filter; }

protected:
	virtual void focusInEvent(QFocusEvent* event) override;
};

class SymbolDetailsViewType: public ViewType
{
	static SymbolDetailsViewType* m_instance;

public:
	SymbolDetailsViewType();
	virtual int getPriority(BinaryViewRef data, const QString& filename);
	virtual QWidget* create(BinaryViewRef data, ViewFrame* viewFrame);
	static void init();
};
