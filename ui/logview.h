#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QItemSelection>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QLabel>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QLineEdit>
#include <QtCore/QSortFilterProxyModel>
#include <QtWidgets/QStackedWidget>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "binaryninjaapi.h"
#include "action.h"
#include "globalarea.h"
#include "render.h"
#include "filter.h"

#define LOG_UPDATE_INTERVAL 100

class LogStatus;
class View;
class ViewFrame;

/*!

	\defgroup logview LogView
 	\ingroup uiapi
*/

/*!

    \ingroup logview
*/
struct BINARYNINJAUIAPI LogTokenList
{
	std::vector<std::pair<int, int>> tokens;
};


struct BINARYNINJAUIAPI LogListItem
{
	size_t sessionId;
	BNLogLevel level;
	std::string text;
	LogTokenList tokens;
	bool selected;
	std::string logger;
	size_t threadId{0};

	LogListItem(size_t sessionId, BNLogLevel level, std::string text, const std::string& logger_name = "", size_t tid = 0);
};

/*!

    \ingroup logview
*/
enum LoggingScope
{
	CurrentTabOnly,
	CurrentTabAndGlobal,
	GlobalOnly,
	AllTabs
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogListFilterProxyModel : public QSortFilterProxyModel
{
	Q_OBJECT
		QString m_loggerName;
		size_t m_sessionId {0};
		LoggingScope m_scope;

	public:
		LogListFilterProxyModel(QObject* parent);
		virtual bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override;
		virtual QVariant data(const QModelIndex& idx, int role) const override;
		void setScope(LoggingScope scope);
		LoggingScope getScope() const { return m_scope; }
	public Q_SLOTS:
		void updateSession(size_t sessionId);
		void updateLogger(QString loggerName);
		void updateFilter();
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogListModel : public QAbstractItemModel, BinaryNinja::LogListener
{
	Q_OBJECT

	QWidget* m_owner;
	std::deque<LogListItem> m_items;

	std::vector<LogListItem> m_pendingItems;
	mutable std::mutex m_mutex;
	std::mutex m_pendingMutex;
	std::string m_logger;
	size_t m_sessionId {0};

	bool m_showSessionId {false};
	bool m_showThreadId {false};
	bool m_showLoggerName {false};
	bool m_showLogLevel {false};

	public:
		static constexpr int Level = Qt::UserRole + 1;
		static constexpr int Logger = Qt::UserRole + 2;
		static constexpr int ThreadId = Qt::UserRole + 3;
		static constexpr int Message = Qt::UserRole + 4;
		static constexpr int Session = Qt::UserRole + 5;
		static constexpr int FormattedMessage = Qt::UserRole + 6;
		static constexpr int Tokens = Qt::UserRole + 7;

		LogListModel(QWidget* parent);
		~LogListModel();

		void addPendingItems();
		void clear();

		virtual void LogMessage(size_t sessionId, BNLogLevel level, const std::string& msg, const std::string& loggerName = "", size_t tid = 0) override;
		virtual BNLogLevel GetLogLevel() override;

		QString getFormattedMessage(const LogListItem& item) const;
		void updateTokens();

		virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
		virtual QModelIndex parent(const QModelIndex& i) const override;
		virtual bool hasChildren(const QModelIndex& parent) const override;
		virtual int rowCount(const QModelIndex& parent) const override;
		virtual int columnCount(const QModelIndex& parent) const override;
		virtual QVariant data(const QModelIndex& i, int role) const override;

		void setDisplaySessionId(bool value);
		void setDisplayThreadId(bool value);
		void setDisplayLoggerName(bool value);
		void setDisplayLogLevel(bool value);
		void setMinLogLevel(BNLogLevel level);
		void setMaxLogLength(size_t length);

		size_t getSessionId() const { return m_sessionId; }
		bool getDisplaySessionId() const { return m_showSessionId; }
		bool getDisplayThreadId() const { return m_showThreadId; }
		bool getDisplayLoggerName() const { return m_showLoggerName; }
		bool getDisplayLogLevel() const { return m_showLogLevel; }
	Q_SIGNALS:
		void settingsUpdated();

	public Q_SLOTS:
		void notifySessionChanged(size_t sessionId);
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogItemDelegate : public QStyledItemDelegate, public BinaryNinja::BinaryDataNotification
{
	Q_OBJECT

	QWidget* m_owner;
	ViewFrame* m_viewFrame = nullptr;
	View* m_view = nullptr;
	BinaryViewRef m_data;
	std::vector<std::pair<uint64_t, uint64_t>> m_validRanges;
	QFont m_font;
	int m_height;

	bool isNavigable(const QString& str, const std::pair<int, int>& offsetLen, uint64_t& value, bool highlight) const;
	void cacheValidRanges();
	bool isAddressValid(uint64_t addr) const;


	public:
		LogItemDelegate(QWidget* parent);

		void updateFonts();
		virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
		virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
		virtual void OnSegmentAdded(BinaryNinja::BinaryView*, BinaryNinja::Segment*) override { cacheValidRanges(); }
		virtual void OnSegmentRemoved(BinaryNinja::BinaryView*, BinaryNinja::Segment*) override { cacheValidRanges(); }
		virtual void OnSegmentUpdated(BinaryNinja::BinaryView*, BinaryNinja::Segment*) override { cacheValidRanges(); }
	protected:
		bool editorEvent(QEvent* event, QAbstractItemModel* model, const QStyleOptionViewItem& option,
			const QModelIndex& index) override;

	Q_SIGNALS:
		void notifySessionChanged(size_t sessionId);

	public Q_SLOTS:
		void viewChanged(QWidget* frame);
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogViewComboBox : public QComboBox
{
	Q_OBJECT

	public:
		LogViewComboBox(QWidget* parent);
		void updateLoggers();
		void showPopup();
	public Q_SLOTS:
		void signalItemSelected(size_t);
	Q_SIGNALS:
		void itemSelected(QString text);
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogView : public SidebarWidget, public FilterTarget
{
	Q_OBJECT

	QPointer<LogStatus> m_logStatus;
	std::vector<std::pair<QAction*, bool>> m_actionEnableList;
	QListView* m_list;
	LogListModel* m_listModel;
	LogListFilterProxyModel* m_model;
	LogItemDelegate* m_itemDelegate;
	QTimer* m_updateTimer;

	LogViewComboBox* m_comboBox;
	FilteredView* m_filteredView;
	QWidget* m_filterWidget;
	RenderContext m_render;

	bool m_doClear;
	bool m_scrolledToEnd;
	bool m_hasSelection = false;
	bool m_isRestored = false;

	public:
		LogView(LogStatus* logStatus);

		virtual void copy();
		virtual bool canCopy();

		static void setLogLevel(BNLogLevel level);
		static void setLogSize(size_t maxSize);
		static bool IsHexString(const QString& str, std::pair<int, int> offsetLen);
		static bool StartsWith0x(const QString& str, std::pair<int, int> offsetLen);

		void notifyFontChanged() override;
		void notifyThemeChanged() override;
		void notifyViewChanged(ViewFrame* frame) override;
		void focus() override;

		LogListModel* model() { return m_listModel; }
		void setFilter(const std::string& filter) override;
		LoggingScope getScope() const { return m_model->getScope(); }
		void setScope(LoggingScope scope) { m_model->setScope(scope); }

		QWidget* headerWidget() override { return m_filterWidget; }

		void scrollToFirstItem() override;
		void scrollToCurrentItem() override;
		void selectFirstItem() override;
		void activateFirstItem() override {}
		void closeFilter() override;

		// std::pair<size_t, size_t> GetSelectionIndexAndOffsetFromPosition(const QPoint& position) const;
		// virtual void mousePressEvent(QMouseEvent* event) override;
		// virtual void mouseReleaseEvent(QMouseEvent* event) override;
		// virtual void mouseMoveEvent(QMouseEvent* event) override;

		// bool IsInSubSelectionMode() const { return m_subSelectionMode; }
		// std::pair<size_t, size_t> GetSelectionIndicies() const { return {m_baseSelectionOffset, m_currentSelectionOffset}; }

	protected:
		void contextMenuEvent(QContextMenuEvent* event) override;

	Q_SIGNALS:
		void notifyUiStatus();
		void viewChanged(QWidget* frame);

	public Q_SLOTS:
		void clear();

	private Q_SLOTS:
		void scrollRangeChanged(int minimum, int maximum);
		void scrollValueChanged(int value);
		void updateSelection(const QItemSelection& selected, const QItemSelection& deselected);
		void updateTimerEvent();
		void updateUiStatus();
		void showContextMenu();
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogStatus : public QWidget
{
	Q_OBJECT

	QToolButton* m_errorIndicator;
	QToolButton* m_warnIndicator;
	ContextMenuManager* m_contextMenuManager;
	QMenu* m_menu;

	std::mutex m_countMutex;
	std::map<uint64_t, int> m_sessionErrorCount;
	std::map<uint64_t, int> m_sessionWarnCount;
	size_t m_sessionId {0};
	LogView* m_logView;

	public:
		LogStatus(QWidget* parent);
		void setLogView(LogView* view) { m_logView = view; }
		void incrementErrorCount(uint64_t session, int count);
		void incrementWarningCount(uint64_t session, int count);
		void checkForErrors();
		void focusTab(UIContext* context, QWidget* tab, size_t m_sessionId);
		void clearIndicators();
		void updateTheme();
	public Q_SLOTS:
		void notifySessionChanged(size_t sessionId);
	public Q_SLOTS:
		void clicked(bool error);
};

/*!

    \ingroup logview
*/
class BINARYNINJAUIAPI LogViewSidebarWidgetType : public SidebarWidgetType
{
public:
	LogViewSidebarWidgetType();
	SidebarWidgetLocation defaultLocation() const override { return SidebarWidgetLocation::RightBottom; }
	SidebarContextSensitivity contextSensitivity() const override { return GlobalSidebarContext; }
};
