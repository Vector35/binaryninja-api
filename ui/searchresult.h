#pragma once

#include <QtCore/QAbstractItemModel>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QSortFilterProxyModel>
#include <QtCore/QModelIndex>
#include <QtCore/QThread>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QDialog>
#include <QtWidgets/QProgressBar>
#include <QtWidgets/QToolButton>
#include "binaryninjaapi.h"
#include "dockhandler.h"
#include "filter.h"
#include "expandablegroup.h"

#define FIND_RESULT_LIST_UPDATE_INTERVAL 250
#define COLUMN_MIN_WIDTH_IN_CHAR         10
#define COLUMN_MAX_WIDTH_IN_CHAR         30

class CachedTokens
{
  public:
	QVariant tokens;
	QVariant flattenedTokens;
	bool valid;

	CachedTokens() : valid(false) {}
	CachedTokens(const CachedTokens& other) :
	    tokens(other.tokens), flattenedTokens(other.flattenedTokens), valid(other.valid)
	{}
};


class SearchResultItem
{
  private:
	uint64_t m_addr;
	BinaryNinja::DataBuffer m_buffer;
	FunctionRef m_func;
	CachedTokens m_tokensCache[4];

  public:
	SearchResultItem();
	SearchResultItem(uint64_t addr, const BinaryNinja::DataBuffer& buffer, FunctionRef func);
	SearchResultItem(uint64_t addr, const BinaryNinja::DataBuffer& buffer, FunctionRef func,
	    const BinaryNinja::DisassemblyTextLine& line, QWidget* owner);
	SearchResultItem(const SearchResultItem& other);
	uint64_t addr() const { return m_addr; }
	BinaryNinja::DataBuffer buffer() const { return m_buffer; }
	FunctionRef func() const { return m_func; }
	bool operator==(const SearchResultItem& other) const { return m_addr == other.addr(); }
	bool operator!=(const SearchResultItem& other) const { return m_addr != other.addr(); }
	bool operator<(const SearchResultItem& other) const { return m_addr < other.addr(); }

	CachedTokens getCachedTokens(size_t i) const;
	CachedTokens& getCachedTokens(size_t i);
	void setCachedTokens(size_t i, QVariant tokens, QVariant flattenedTokens);
};

Q_DECLARE_METATYPE(SearchResultItem);


class BINARYNINJAUIAPI SearchResultModel : public QAbstractTableModel
{
	Q_OBJECT

  protected:
	QWidget* m_owner;
	BinaryViewRef m_data;
	BinaryNinja::FindParameters m_params;
	std::vector<SearchResultItem> m_refs;
	mutable size_t m_columnWidths[4];
	// if this value is true, it means the user has overriden the automatically calculated width
	// of the coumn, and we should not resize it anymore
	bool m_userColumnWidth[4];

	std::mutex m_updateMutex;
	std::set<SearchResultItem> m_pendingSearchResults;

  public:
	enum ColumnHeaders
	{
		AddressColumn = 0,
		DataColumn = 1,
		FunctionColumn = 2,
		PreviewColumn = 3,
		EndOfColumn = 4
	};

	SearchResultModel(QWidget* parent, BinaryViewRef data);
	virtual ~SearchResultModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const override;

	void reset();
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return (int)m_refs.size();
	}
	virtual int columnCount(const QModelIndex& parent = QModelIndex()) const override
	{
		(void)parent;
		return 4;
	}
	SearchResultItem getRow(int row) const;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual QVariant headerData(int column, Qt::Orientation orientation, int role) const override;
	void addItem(const SearchResultItem& addr);
	void clear();
	void updateFindParameters(const BinaryNinja::FindParameters params);
	void updateSearchResults();

	size_t getColumnWidth(size_t column) const;
	// This function is marked as const, but it actually modifies the mutable member m_columnWidths.
	// It is called in SearchResultModel::data(), which is const. So it has to be const as well.
	void updateColumnWidth(size_t column, size_t size) const;
	void resetColumnWidth();

	bool isUserColumnWidth(size_t column) const;
	void setUserColumnWidth(size_t column);
};


class BINARYNINJAUIAPI SearchResultFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT

  public:
	SearchResultFilterProxyModel(QObject* parent);
	virtual bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;
	virtual bool lessThan(const QModelIndex& left, const QModelIndex& right) const override;
	virtual QVariant data(const QModelIndex& idx, int role) const override;
};


class BINARYNINJAUIAPI SearchResultItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QFont m_font;
	int m_baseline, m_charWidth, m_charHeight, m_charOffset;

  public:
	SearchResultItemDelegate(QWidget* parent);
	void updateFonts();
	void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const;
};

class SearchResultWidget;
class BINARYNINJAUIAPI SearchResultTable : public QTableView
{
	Q_OBJECT

	SearchResultModel* m_table;
	SearchResultFilterProxyModel* m_model;
	SearchResultItemDelegate* m_itemDelegate;
	BinaryViewRef m_data;
	BinaryNinja::FindParameters m_params;
	UIActionHandler m_actionHandler;
	QTimer* m_updateTimer;

	int m_charWidth, m_charHeight;

	bool m_cacheThreadShouldExit;

  public:
	SearchResultTable(SearchResultWidget* parent, BinaryViewRef data);
	virtual ~SearchResultTable();

	void addSearchResult(const SearchResultItem& addr);
	void updateFindParameters(const BinaryNinja::FindParameters& params);
	void clearSearchResult();

	void updateFonts();
	void updateHeaderFontAndSize();

	virtual void keyPressEvent(QKeyEvent* e) override;

	virtual bool hasSelection() const { return selectionModel()->selectedRows().size() != 0; }
	virtual QModelIndexList selectedRows() const { return selectionModel()->selectedRows(); }

	void goToResult(const QModelIndex& idx);

	int rowCount() const;
	int filteredCount() const;

	void updateColumnWidth();
	void resetColumnWidth();

	void cacheTokens();
	void terminateCacheThread() { m_cacheThreadShouldExit = true; }

	SearchResultModel* model() const { return m_table; }

  public Q_SLOTS:
	void resultActivated(const QModelIndex& idx);
	void updateFilter(const QString& filterText);
	void updateTimerEvent();
	void columnResized(int logicalIndex, int oldSize, int newSize);

  Q_SIGNALS:
	void newSelection();
};

class SearchProgressBar;
class BINARYNINJAUIAPI SearchResultWidget : public QWidget
{
	Q_OBJECT

	UIActionHandler m_actionHandler;
	ContextMenuManager* m_contextMenuManager = nullptr;
	Menu* m_menu = nullptr;

	BinaryViewRef m_data;
	SearchResultTable* m_table;
	QLabel* m_label;
	QLineEdit* m_lineEdit;
	ExpandableGroup* m_group;
	SearchProgressBar* m_progress;
	BinaryNinja::FindParameters m_params;
	QThread* m_tokenCacheThread = nullptr;

	virtual void contextMenuEvent(QContextMenuEvent* event) override;

  public:
	SearchResultWidget(BinaryViewRef data);
	~SearchResultWidget();

	void notifyFontChanged();

	void startNewFind(const BinaryNinja::FindParameters& params);
	virtual QString getHeaderText();

	void addSearchResult(uint64_t addr, const BinaryNinja::DataBuffer& match);
	void addSearchResult(
	    uint64_t addr, const BinaryNinja::DataBuffer& match, const BinaryNinja::LinearDisassemblyLine& line);
	void clearSearchResult();
	bool updateProgress(uint64_t cur, uint64_t total);
	void notifySearchCompleted();
	void cacheTokens();
	void terminateCacheThread();
	bool isSearchActive() const;

  public Q_SLOTS:
	void updateTotal();
};


class BINARYNINJAUIAPI SearchProgressBar : public QWidget
{
	Q_OBJECT

  private:
	QProgressBar* m_progress;
	QToolButton* m_cancel;
	bool m_maxSet;
	bool m_running;
	// The minimal duration (in milliseconds) the progress bar must last, before it is displayed
	int m_minimalDuration;
	std::chrono::steady_clock::time_point m_lastUpdate;

  public:
	explicit SearchProgressBar(QWidget* parent = nullptr);
	bool updateProgress(uint64_t cur, uint64_t total);
	void init();
	void reset();
	void show();
	bool isRunning() const { return m_running; }
};
