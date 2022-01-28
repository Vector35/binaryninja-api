#pragma once

#include <QtWidgets/QListView>
#include <QtCore/QItemSelection>
#include <QtCore/QPointer>
#include <QtCore/QTimer>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QLabel>
#include <QtWidgets/QToolButton>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "binaryninjaapi.h"
#include "action.h"
#include "globalarea.h"

#define LOG_UPDATE_INTERVAL 100

class LogStatus;
class View;
class ViewFrame;

struct BINARYNINJAUIAPI LogListItem
{
	BNLogLevel level;
	std::string text;
	bool selected;

	LogListItem(BNLogLevel level, std::string text, bool selected = false) :
	    level(level), text(text), selected(selected) {};
};


class BINARYNINJAUIAPI LogListModel : public QAbstractItemModel, public BinaryNinja::LogListener
{
	Q_OBJECT

	QWidget* m_owner;
	std::deque<LogListItem> m_items;
	std::deque<LogListItem> m_visibleItems;
	int64_t m_maxSize;

	std::vector<LogListItem> m_pendingItems;
	std::mutex m_mutex;
	std::mutex m_pendingMutex;

  public:
	LogListModel(QWidget* parent);
	~LogListModel();

	void addPendingItems();
	void clear();
	std::vector<LogListItem> getSelectedItems();
	bool hasSelectedItems();

	virtual void LogMessage(BNLogLevel level, const std::string& msg) override;
	virtual BNLogLevel GetLogLevel() override;

	virtual QModelIndex index(int row, int col, const QModelIndex& parent) const override;
	virtual QModelIndex parent(const QModelIndex& i) const override;
	virtual bool hasChildren(const QModelIndex& parent) const override;
	virtual int rowCount(const QModelIndex& parent) const override;
	virtual int columnCount(const QModelIndex& parent) const override;
	virtual QVariant data(const QModelIndex& i, int role) const override;
	virtual bool setData(const QModelIndex& i, const QVariant& value, int role) override;

  public Q_SLOTS:
	void notifyDataChanged();
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
	void notifyDataChanged();

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
	LogItemDelegate* m_itemDelegate;
	QTimer* m_updateTimer;

	bool m_doClear;
	bool m_scrolledToEnd;
	bool m_hasSelection = false;

  public:
	LogView(LogStatus* logStatus);

	virtual void copy();
	virtual bool canCopy();

	static void SetLogLevel(BNLogLevel level);
	static void SetLogSize(size_t maxSize);
	static bool IsHexString(const QString& str, std::pair<int, int> offsetLen);
	static bool StartsWith0x(const QString& str, std::pair<int, int> offsetLen);

	void notifyFontChanged() override;
	void notifyThemeChanged() override;
	void notifyViewChanged(ViewFrame* frame) override;
	void focus() override;

	LogListModel* model() { return m_listModel; }

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
};


class BINARYNINJAUIAPI LogStatus : public QWidget
{
	Q_OBJECT

	QToolButton* m_errorIndicator;
	QToolButton* m_warnIndicator;

	int m_errorCount = 0;
	int m_warnCount = 0;

  public:
	LogStatus(QWidget* parent);

	void incrementErrorCount(int count);
	void incrementWarningCount(int count);
	void clearIndicators();

	void updateTheme();

  private Q_SLOTS:
	void clearStatus();
};
