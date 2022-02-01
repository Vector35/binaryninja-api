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

#define LOG_UPDATE_INTERVAL 100

class LogStatus;
class View;
class ViewFrame;

struct BINARYNINJAUIAPI LogListItem
{
	size_t sessionId;
	BNLogLevel level;
	std::string text;
	bool selected;
	std::string logger;
	size_t threadId{0};

	LogListItem(size_t sessionId, BNLogLevel level, std::string text, bool selected = false, const std::string& logger_name = "", size_t tid = 0);
};

enum LoggingScope
{
	CurrentTabOnly,
	CurrentTabAndGlobal,
	GlobalOnly,
	AllTabs
};

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
		void updateLogger(const QString & loggerName);
		void updateFilter();
};


class BINARYNINJAUIAPI LogListModel : public QAbstractItemModel, public BinaryNinja::LogListener
{
	Q_OBJECT

	QWidget* m_owner;
	std::deque<LogListItem> m_items;
	std::deque<LogListItem> m_visibleItems;

	std::vector<LogListItem> m_pendingItems;
	std::mutex m_mutex;
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

		LogListModel(QWidget* parent);
		~LogListModel();

		void addPendingItems();
		void clear();
		std::vector<LogListItem> getSelectedItems();
		bool hasSelectedItems();

		virtual void LogMessage(size_t sessionId, BNLogLevel level, const std::string& msg, const std::string& loggerName = "", size_t tid = 0) override;
		virtual BNLogLevel GetLogLevel() override;

		virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
		virtual QModelIndex parent(const QModelIndex& i) const override;
		virtual bool hasChildren(const QModelIndex& parent) const override;
		virtual int rowCount(const QModelIndex& parent) const override;
		virtual int columnCount(const QModelIndex& parent) const override;
		virtual QVariant data(const QModelIndex& i, int role) const override;
		virtual bool setData(const QModelIndex& i, const QVariant& value, int role) override;

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


class BINARYNINJAUIAPI LogItemDelegate : public QStyledItemDelegate
{
	Q_OBJECT

	QWidget* m_owner;
	ViewFrame* m_viewFrame = nullptr;
	View* m_view = nullptr;
	BinaryViewRef m_data;

	QFont m_font;
	int m_height;

	bool IsNavigable(const QString& str, const std::pair<int, int>& offsetLen, uint64_t& value, bool highlight) const;

	public:
		LogItemDelegate(QWidget* parent);

		void updateFonts();
		virtual QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& idx) const override;
		virtual void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& idx) const override;

	protected:
		bool editorEvent(QEvent* event, QAbstractItemModel* model, const QStyleOptionViewItem& option,
			const QModelIndex& index) override;

	Q_SIGNALS:
		void notifySessionChanged(size_t sessionId);

	public Q_SLOTS:
		void viewChanged(QWidget* frame);
};


class BINARYNINJAUIAPI LogView : public GlobalAreaWidget
{
	Q_OBJECT

	QPointer<LogStatus> m_logStatus;
	std::vector<std::pair<QAction*, bool>> m_actionEnableList;
	QListView* m_list;
	LogListModel* m_listModel;
	LogListFilterProxyModel* m_model;
	LogItemDelegate* m_itemDelegate;
	QTimer* m_updateTimer;

	QComboBox* m_comboBox;
	QLineEdit* m_lineEdit;
	QWidget* m_filterWidget;
	RenderContext m_render;

	bool m_doClear;
	bool m_scrolledToEnd;
	bool m_hasSelection = false;

	// bool m_subSelectionMode;
	// size_t m_baseSelectionIndex;
	// size_t m_baseSelectionOffset;
	// size_t m_currentSelectionIndex;
	// size_t m_currentSelectionOffset;
	// size_t m_visibleRows {1};
	// size_t m_topLine {0};
	// size_t m_selectCount {0};

	public:
		LogView(LogStatus* logStatus);
		void adjustSize(int width, int height);

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
		void updateFilter(const QString& filterText);
		LoggingScope getScope() const { return m_model->getScope(); }

		// std::pair<size_t, size_t> GetSelectionIndexAndOffsetFromPosition(const QPoint& position) const;
		// virtual void mousePressEvent(QMouseEvent* event) override;
		// virtual void mouseReleaseEvent(QMouseEvent* event) override;
		// virtual void mouseMoveEvent(QMouseEvent* event) override;

		// bool IsInSubSelectionMode() const { return m_subSelectionMode; }
		// std::pair<size_t, size_t> GetSelectionIndicies() const { return {m_baseSelectionOffset, m_currentSelectionOffset}; }

	protected:
		void contextMenuEvent(QContextMenuEvent* event) override;
		virtual void resizeEvent(QResizeEvent* event) override;

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


class BINARYNINJAUIAPI LogStatus : public QWidget
{
	Q_OBJECT

	QToolButton* m_errorIndicator;
	QToolButton* m_warnIndicator;
	ContextMenuManager* m_contextMenuManager;
	QMenu* m_menu;

	std::mutex m_countMutex;
	int m_totalErrorCount = 0;
	int m_totalWarnCount = 0;
	std::map<uint64_t, int> m_sessionErrorCount;
	std::map<uint64_t, int> m_sessionWarnCount;
	size_t m_sessionId {0};
	LogView* m_logView;
	std::map<size_t, QString> getSessionToNameMap();

	public:
		LogStatus(QWidget* parent);
		void setLogView(LogView* view) { m_logView = view; }
		void incrementErrorCount(uint64_t session, int count);
		void incrementWarningCount(uint64_t session, int count);
		void clearIndicators(bool warnings, bool errors);
		void checkForErrors();
		void focusTab(QString tabName);

		void updateTheme();
	public Q_SLOTS:
		void notifySessionChanged(size_t sessionId);
	private Q_SLOTS:
		void clearStatus(bool error);
};
