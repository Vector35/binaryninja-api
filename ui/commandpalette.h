#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QAbstractItemModel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QFrame>
#include <QtCore/QPointer>
#include <QtCore/QThread>
#include <QtWidgets/QStyledItemDelegate>
#include <vector>
#include "action.h"

/*!

	\defgroup commandpalette CommandPalette
 	\ingroup uiapi
*/

/*!

    \ingroup commandpalette
*/
struct BINARYNINJAUIAPI CommandListItem
{
	enum CommandListItemType
	{
		// Index is serialized so only to add to the end
		Help,
		UIAction,
		OpenTab,
		NavigationHistory,
		RecentFile,
		RecentProject,
		ProjectFile,
		Expression,
		RecentExpression,
		Function,
		Symbol,
		Type,
		String,
		DerivedString,
		LastItemType
	};

	CommandListItemType type;
	QString name;
	QString secondary;
	QString shortcut;
	QString extraSearchableText;
	QVariant action;
	Qt::TextElideMode secondaryElide = Qt::ElideRight;
	int score = 0;
	bool addToRecents = true;
	bool includeUnfiltered = true;
	bool scoreFast = false;
};


/*!

	\ingroup commandpalette
*/
struct BINARYNINJAUIAPI CommandListItemSearchInfo
{
	std::unordered_set<CommandListItem::CommandListItemType> types;
	QString name;
	QString searchName;
	std::string prefix;
	QKeySequence shortcut;

	static std::vector<CommandListItemSearchInfo> GetSearchTypes();
};


class CommandPalette;
class CommandListFilter;

class CommandListGenerateWorker : public QObject
{
	Q_OBJECT

	BinaryViewRef m_view;
	bool m_aborted;
	int m_request;
	std::shared_ptr<std::atomic_int> m_latestRequest;

	bool m_pending;
	std::vector<CommandListItem> m_pendingItems;
	std::mutex m_pendingItemsMutex;

public:
	explicit CommandListGenerateWorker(QObject* parent, std::shared_ptr<std::atomic_int> request, const UIActionContext& context);
	virtual ~CommandListGenerateWorker();

Q_SIGNALS:
	void dataFetched(int request, const std::vector<CommandListItem>& items);
	void noMoreDataToFetch(int request);
	void workFinished(int request);

public Q_SLOTS:
	void fetchMore();
	void start();
	void abort();
};


class CommandListScoreWorker : public QObject
{
public:
	enum OrderStrategy
	{
		DefaultOrder,
		ScoreOrder
	};

private:
	Q_OBJECT

	bool m_aborted;
	int m_request;
	std::shared_ptr<std::atomic_int> m_latestRequest;
	QString m_filter;
	std::shared_ptr<std::vector<CommandListItem>> m_items;
	std::vector<int> m_oldItemScores;
	OrderStrategy m_strategy;

	bool m_pending;
	std::vector<std::pair<CommandListItem*, int>> m_pendingItems;
	std::mutex m_pendingItemsMutex;

public:
	explicit CommandListScoreWorker(
		QObject* parent,
		std::shared_ptr<std::atomic_int> request,
		QString filter,
		std::shared_ptr<std::vector<CommandListItem>> items,
		OrderStrategy orderStrategy
	);
	virtual ~CommandListScoreWorker();

	static int scoreItem(const CommandListItem* item, const std::string& strippedFilter);

Q_SIGNALS:
	void dataFetched(int request, const std::vector<std::pair<CommandListItem*, int>>& items);
	void noMoreDataToFetch(int request);
	void workFinished(int request);

public Q_SLOTS:
	void fetchMore();
	void start();
	void abort();
};


/*!

    \ingroup commandpalette
*/
class BINARYNINJAUIAPI CommandListDelegate : public QStyledItemDelegate
{
	Q_OBJECT
	QFont m_font;
	int m_height;

  public:
	CommandListDelegate(QWidget* parent);
	virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
	virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;
};

/*!

    \ingroup commandpalette
*/
class BINARYNINJAUIAPI CommandListModel : public QAbstractItemModel
{
	Q_OBJECT

	UIActionHandler* m_handler;
	UIActionContext m_context;

	std::shared_ptr<std::vector<CommandListItem>> m_allItems;
	std::vector<CommandListItem*> m_displayItems; // pointers into m_allItems
	QString m_filterText;
	bool m_updatesPaused;

	std::vector<CommandListItem> m_recentItems;

	QThread m_generateWorkerThread;
	CommandListGenerateWorker* m_generateWorker;
	std::shared_ptr<std::atomic_int> m_generateWorkerRequest;
	QTimer m_generateFetchTimer;
	bool m_generateMoreToFetch;

	QTimer m_scoreTimer;
	QMetaObject::Connection m_scoreTimerConnection;

	QThread m_scoreWorkerThread;
	CommandListScoreWorker* m_scoreWorker;
	std::shared_ptr<std::atomic_int> m_scoreWorkerRequest;
	QTimer m_scoreFetchTimer;
	bool m_scoreMoreToFetch;

	void loadRecentItems();
	std::vector<CommandListItem> generateFastCommandList();
	void scoreFastCommandList();
	void sortCommandList(std::vector<CommandListItem>& list);
	void mergeCommandList(std::vector<CommandListItem>& output, std::vector<CommandListItem>&& input);
	void startScoreListThread();

public:
	CommandListModel(QWidget* parent);
	~CommandListModel();

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent = QModelIndex()) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;

	CommandListItem getItem(int row);
	void setFilterText(const QString& text);
	size_t getRecentPosition(const CommandListItem& item) const;
	void addRecentItem(const CommandListItem& item);

	void clearCommandList();
	void generateCommandList(UIActionHandler* handler, const UIActionContext& context);
	void cancelGenerateCommandList();

	void scoreCommandList(CommandListScoreWorker::OrderStrategy strategy);
	void cancelScoreCommandList();

	void pauseCommandListUpdates();
	void unpauseCommandListUpdates();

	void updateDisplayedItems();

private Q_SLOTS:
	void generateFetch();
	void itemsGenerated(int request, const std::vector<CommandListItem>& items);
	void itemsFinishedGenerating(int request);
	void generateWorkFinished(int request);

	void scoreFetch();
	void itemsScored(int request, const std::vector<std::pair<CommandListItem*, int>>& items);
	void itemsFinishedScoring(int request);
	void scoreWorkFinished(int request);
};

/*!

    \ingroup commandpalette
*/
class BINARYNINJAUIAPI CommandList : public QListView
{
	Q_OBJECT

	CommandPalette* m_palette;
	CommandListModel* m_model;
	CommandListFilter* m_filter;

  public:
	CommandList(CommandPalette* parent);
	void setFilter(CommandListFilter* filter) { m_filter = filter; }
	void setFilterText(const QString& text);

	CommandListItem getItem(int row);

	QModelIndex index(int row, int col, const QModelIndex& parent = QModelIndex()) const;
	void addRecentItem(const CommandListItem& item);

	void clearCommandList();
	void generateCommandList(UIActionHandler* handler, const UIActionContext& context);
	void cancelGenerateCommandList();

	void pauseCommandListUpdates();
	void unpauseCommandListUpdates();

  protected:
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
};

/*!

    \ingroup commandpalette
*/
class BINARYNINJAUIAPI CommandListFilter : public QLineEdit
{
	Q_OBJECT

	CommandPalette* m_palette;
	CommandList* m_list;

	//! Focus the next or previous results list item.
	bool cycleSelection(bool forward = true);

  public:
	CommandListFilter(CommandPalette* parent, CommandList* list);

  protected:
	bool event(QEvent* event) override;
	virtual void keyPressEvent(QKeyEvent* event) override;
	virtual void focusInEvent(QFocusEvent* event) override;
	virtual void focusOutEvent(QFocusEvent* event) override;
	virtual void paintEvent(QPaintEvent* event) override;
};

/*!

    \ingroup commandpalette
*/
class BINARYNINJAUIAPI CommandPalette : public QFrame
{
	Q_OBJECT

	UIActionHandler* m_handler;
	UIActionContext m_context;

	QPointer<QWidget> m_previousWidget;

	CommandListFilter* m_filter;
	CommandList* m_list;
	std::optional<CommandListItem> m_savedTop;

	bool m_executing;

	void init();

  public:
	CommandPalette(QWidget* parent);

	void openWithInput(const QString& text);
	void focusInput();

	void clearCommandList();
	void generateCommandList(UIActionHandler* handler, const UIActionContext& context);

	//! Activate the focused item, or topmost item if there is no selection.
	void activateFocusedItem();
	void selectFirstItem();
	void close(bool restoreFocus = true);
	void activateItem(const CommandListItem& item);

  private Q_SLOTS:
	void itemClicked(const QModelIndex& idx);
	void filterChanged(const QString& text);
};
